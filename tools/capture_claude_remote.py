from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

import paramiko


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def exec_cmd(client: paramiko.SSHClient, command: str, timeout: int = 60, get_pty: bool = False) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, get_pty=get_pty, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def drain_channel(channel: paramiko.Channel, sink: list[str], echo: bool) -> None:
    while True:
        try:
            if not channel.recv_ready():
                break
            data = channel.recv(32768)
            if not data:
                break
            text = data.decode("utf-8", "replace")
            sink.append(text)
            if echo:
                sys.stdout.write(ANSI_RE.sub("", text))
                sys.stdout.flush()
        except (socket.timeout, OSError):
            break

    while True:
        try:
            if not channel.recv_stderr_ready():
                break
            data = channel.recv_stderr(32768)
            if not data:
                break
            text = data.decode("utf-8", "replace")
            sink.append(text)
            if echo:
                sys.stdout.write(ANSI_RE.sub("", text))
                sys.stdout.flush()
        except (socket.timeout, OSError):
            break


def sftp_exists(sftp: paramiko.SFTPClient, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except OSError:
        return False


def remote_text(sftp: paramiko.SFTPClient, path: str) -> str:
    try:
        with sftp.open(path, "r") as handle:
            data = handle.read()
        if isinstance(data, str):
            return data
        return data.decode("utf-8", "replace")
    except OSError:
        return ""


def download_tree(sftp: paramiko.SFTPClient, remote_dir: str, local_dir: Path) -> None:
    local_dir.mkdir(parents=True, exist_ok=True)
    for item in sftp.listdir_attr(remote_dir):
        remote_path = remote_dir.rstrip("/") + "/" + item.filename
        local_path = local_dir / item.filename
        if item.st_mode & 0o040000:
            download_tree(sftp, remote_path, local_path)
        else:
            sftp.get(remote_path, str(local_path))


def select_claude_request(capture_dir: Path) -> dict:
    requests_path = capture_dir / "requests.redacted.jsonl"
    captures: list[dict] = []
    for line in requests_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        captures.append(json.loads(line))

    for item in reversed(captures):
        if (item.get("path") or "").startswith("/v1/messages"):
            return item
    for item in reversed(captures):
        if (item.get("path") or "").startswith("/v1/complete"):
            return item
    if not captures:
        raise RuntimeError(f"No parseable captures in {requests_path}")
    return captures[-1]


def summarize_capture(capture: dict, capture_dir: Path, remote_dir: str) -> dict:
    headers = capture.get("headers", {})
    body_preview = capture.get("body_preview") or ""
    model_match = re.search(r'"model"\s*:\s*"([^"]+)"', body_preview)
    return {
        "local_capture_dir": str(capture_dir),
        "remote_capture_dir": remote_dir,
        "selected_file": str(capture_dir / "selected_claude_request.redacted.json"),
        "captured_at": capture.get("captured_at"),
        "host": capture.get("host"),
        "path": capture.get("path"),
        "method": capture.get("method"),
        "model": model_match.group(1) if model_match else None,
        "anthropic_beta": capture.get("anthropic_beta"),
        "anthropic_beta_original": capture.get("anthropic_beta_original"),
        "user_agent": headers.get("User-Agent") or headers.get("user-agent"),
        "x_app": headers.get("x-app") or headers.get("X-App"),
        "stainless_package": headers.get("X-Stainless-Package-Version"),
        "stainless_os": headers.get("X-Stainless-OS"),
        "stainless_arch": headers.get("X-Stainless-Arch"),
        "stainless_runtime": headers.get("X-Stainless-Runtime-Version"),
        "anthropic_version": headers.get("anthropic-version") or headers.get("Anthropic-Version"),
        "body_bytes": capture.get("body_bytes"),
    }


def ensure_remote_mitm(client: paramiko.SSHClient, remote_base: str, install: bool) -> None:
    command = f"""
set -e
mkdir -p {sh_quote(remote_base)}
cd {sh_quote(remote_base)}
if [ ! -x venv/bin/mitmdump ]; then
  if [ {sh_quote('1' if install else '')} != '1' ]; then
    echo 'mitmdump is missing. Re-run with --install-mitm.' >&2
    exit 2
  fi
  python3 -m venv venv || (apt-get update && apt-get install -y python3.12-venv python3-venv && python3 -m venv venv)
  venv/bin/python -m pip install -U pip mitmproxy
fi
venv/bin/mitmdump --version
"""
    rc, out, err = exec_cmd(client, command, timeout=900, get_pty=True)
    if rc != 0:
        raise RuntimeError(f"Failed to prepare mitmproxy:\n{out}\n{err}")
    print(out, end="")


def trust_workspace(client: paramiko.SSHClient, workspace: str) -> None:
    command = f"""
set -e
if [ -f /root/.claude.json ]; then
  cp /root/.claude.json /root/.claude.json.capture-backup-$(date +%Y%m%d-%H%M%S)
  python3 - <<'PY'
import json
from pathlib import Path
workspace = {workspace!r}
p = Path('/root/.claude.json')
data = json.loads(p.read_text())
projects = data.setdefault('projects', {{}})
base = projects.get('/root', {{}})
for key in ['/root', workspace]:
    item = projects.setdefault(key, dict(base))
    item['hasTrustDialogAccepted'] = True
    item['projectOnboardingSeenCount'] = max(int(item.get('projectOnboardingSeenCount') or 0), 1)
p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
PY
fi
"""
    rc, out, err = exec_cmd(client, command, timeout=30)
    if rc != 0:
        raise RuntimeError(f"Failed to trust workspace:\n{out}\n{err}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture Claude Code CLI request headers on a remote host via SSH and mitmproxy.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="CAPTURE_SSH_PASSWORD")
    parser.add_argument("--password", default="", help="SSH password. Prefer --password-env to avoid shell history.")
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--prompt", default="hello")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--remote-base", default="/root/claude-capture")
    parser.add_argument("--capture-root", default="captures/claude-code-headers")
    parser.add_argument("--name", default="")
    parser.add_argument("--timeout", type=int, default=220)
    parser.add_argument("--install-mitm", action="store_true")
    parser.add_argument("--trust-workspace", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    addon_path = repo_root / "tools" / "mitm_capture_claude.py"
    if not addon_path.exists():
        raise RuntimeError(f"Missing addon: {addon_path}")

    password = args.password or os.environ.get(args.password_env) or getpass.getpass(f"SSH password for {args.user}@{args.host}: ")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_model = re.sub(r"[^a-zA-Z0-9._-]+", "-", args.model).strip("-")
    name = args.name or f"server-{args.host.replace('.', '-')}-{safe_model}-python-{stamp}"
    remote_run = f"{args.remote_base}/{name}"
    local_run = repo_root / args.capture_root / name

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    mitm_channel: paramiko.Channel | None = None
    shell: paramiko.Channel | None = None
    mitm_log: list[str] = []
    claude_log: list[str] = []

    try:
        client.connect(args.host, username=args.user, password=password, timeout=20, banner_timeout=20, auth_timeout=20)
        ensure_remote_mitm(client, args.remote_base, args.install_mitm)
        if args.trust_workspace:
            trust_workspace(client, args.remote_base)

        sftp = client.open_sftp()
        try:
            exec_cmd(client, f"mkdir -p {sh_quote(args.remote_base)} {sh_quote(remote_run)}", timeout=30)
            sftp.put(str(addon_path), f"{args.remote_base}/mitm_capture_claude.py")
        finally:
            sftp.close()

        mitm_cmd = (
            f"cd {sh_quote(args.remote_base)}; "
            f"CLAUDE_CAPTURE_DIR={sh_quote(remote_run)} "
            f"{sh_quote(args.remote_base + '/venv/bin/mitmdump')} "
            f"--listen-host 127.0.0.1 --listen-port {args.port} "
            f"--set confdir={sh_quote(args.remote_base + '/.mitmproxy')} "
            f"-s {sh_quote(args.remote_base + '/mitm_capture_claude.py')}"
        )
        _, mitm_stdout, _ = client.exec_command(mitm_cmd, get_pty=True)
        mitm_channel = mitm_stdout.channel
        mitm_channel.settimeout(0.0)

        ready = False
        start = time.time()
        while time.time() - start < 25:
            drain_channel(mitm_channel, mitm_log, not args.quiet)
            if mitm_channel.exit_status_ready():
                break
            rc, out, _ = exec_cmd(
                client,
                "python3 - <<'PY'\n"
                "import socket\n"
                f"s=socket.socket(); s.settimeout(.3); s.connect(('127.0.0.1',{args.port})); s.close(); print('ready')\n"
                "PY",
                timeout=5,
            )
            if rc == 0 and "ready" in out:
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            raise RuntimeError("mitmdump did not become ready:\n" + "".join(mitm_log)[-4000:])

        shell = client.invoke_shell(width=170, height=50)
        shell.settimeout(0.0)
        claude_cmd = (
            f"cd {sh_quote(args.remote_base)}; "
            f"export HTTP_PROXY=http://127.0.0.1:{args.port}; "
            f"export HTTPS_PROXY=http://127.0.0.1:{args.port}; "
            f"export NODE_EXTRA_CA_CERTS={sh_quote(args.remote_base + '/.mitmproxy/mitmproxy-ca-cert.pem')}; "
            f"export SSL_CERT_FILE={sh_quote(args.remote_base + '/.mitmproxy/mitmproxy-ca-cert.pem')}; "
            "export NO_PROXY=; export no_proxy=; "
            f"claude --model {sh_quote(args.model)}\n"
        )
        shell.send(claude_cmd)

        sftp = client.open_sftp()
        sent_prompt = False
        sent_submit = False
        sent_submit_again = False
        seen_api_request = False
        start = time.time()
        try:
            while time.time() - start < args.timeout:
                drain_channel(mitm_channel, mitm_log, not args.quiet)
                drain_channel(shell, claude_log, not args.quiet)
                elapsed = time.time() - start
                plain = ANSI_RE.sub("", "".join(claude_log)[-6000:])
                if not sent_prompt and elapsed > 10 and ("❯" in plain or "shortcuts" in plain or elapsed > 18):
                    shell.send(args.prompt)
                    sent_prompt = True
                    print(f"\n[SENT_TEXT {args.prompt!r}]")
                if sent_prompt and not sent_submit and elapsed > 13:
                    shell.send("\r")
                    sent_submit = True
                    print("\n[SENT_CR]")
                if sent_submit and not sent_submit_again and elapsed > 18:
                    shell.send("\r")
                    sent_submit_again = True
                    print("\n[SENT_CR_2]")
                if sftp_exists(sftp, remote_run + "/requests.redacted.jsonl"):
                    requests_text = remote_text(sftp, remote_run + "/requests.redacted.jsonl")
                    if "/v1/messages" in requests_text or "/v1/complete" in requests_text:
                        seen_api_request = True
                        time.sleep(3)
                        break
                time.sleep(0.5)
        finally:
            sftp.close()

        drain_channel(mitm_channel, mitm_log, not args.quiet)
        drain_channel(shell, claude_log, not args.quiet)
        if not seen_api_request:
            rc, files, _ = exec_cmd(client, f"find {sh_quote(remote_run)} -maxdepth 3 -type f -print -exec wc -c {{}} \\;", timeout=30)
            raise RuntimeError(
                "Timed out waiting for /v1/messages\nFILES:\n"
                + files
                + "\nMITM:\n"
                + "".join(mitm_log)[-6000:]
                + "\nCLAUDE:\n"
                + ANSI_RE.sub("", "".join(claude_log)[-8000:])
            )

        if shell is not None:
            shell.send("\x03")
            time.sleep(0.4)
            shell.close()
        if mitm_channel is not None:
            mitm_channel.close()

        sftp = client.open_sftp()
        try:
            download_tree(sftp, remote_run, local_run)
        finally:
            sftp.close()

        selected = select_claude_request(local_run)
        (local_run / "selected_claude_request.redacted.json").write_text(
            json.dumps(selected, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        summary = summarize_capture(selected, local_run, remote_run)
        print("\nCAPTURE_SUMMARY_JSON")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    finally:
        try:
            if shell is not None:
                shell.close()
        except OSError:
            pass
        try:
            if mitm_channel is not None:
                mitm_channel.close()
        except OSError:
            pass
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
