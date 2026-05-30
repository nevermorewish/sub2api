from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http


OUT_DIR = Path(os.environ.get("CLAUDE_CAPTURE_DIR", "captures/claude-code-headers"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Optional mutation knobs for controlled experiments. Leave unset for passive
# capture of the exact client request.
SET_BETA = os.environ.get("CLAUDE_CAPTURE_SET_BETA", "").strip()
APPEND_BETA = os.environ.get("CLAUDE_CAPTURE_APPEND_BETA", "").strip()
BETA_TAG = os.environ.get("CLAUDE_CAPTURE_BETA_TAG", "").strip()
BLOCK_UPSTREAM = os.environ.get("CLAUDE_CAPTURE_BLOCK_UPSTREAM", "").strip().lower() in {"1", "true", "yes"}

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "anthropic-api-key",
    "proxy-authorization",
}

INTERESTING_HOST_PARTS = (
    "anthropic.com",
    "claude.ai",
    "frogclaw.com",
    "statsig",
    "sentry",
)


def _redact_header(name: str, value: str) -> str:
    if name.lower() in SENSITIVE_HEADERS:
        if not value:
            return ""
        return f"<redacted:{len(value)} chars>"
    return value


def _decode_body(content: bytes) -> str:
    if not content:
        return ""
    text = content[:65536].decode("utf-8", "replace")
    for key in ("access_token", "refresh_token", "api_key", "authorization"):
        text = text.replace(f'"{key}":', f'"{key}_redacted":')
    return text


def _write_jsonl(name: str, payload: dict) -> None:
    path = OUT_DIR / name
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        f.write("\n")


def _split_beta(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _merge_beta(base: str, extra: str) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for token in _split_beta(base) + _split_beta(extra):
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return ",".join(out)


def _beta_slug(value: str) -> str:
    tag = BETA_TAG
    if not tag:
        tokens = _split_beta(value)
        tag = "__".join(tokens[:4]) if tokens else "no-anthropic-beta"
        if len(tokens) > 4:
            tag += f"__plus-{len(tokens) - 4}"
    tag = re.sub(r"[^a-zA-Z0-9._-]+", "_", tag).strip("._-")
    return tag[:120] or "no-anthropic-beta"


def _maybe_mutate_beta(flow: http.HTTPFlow) -> dict:
    original = flow.request.headers.get("anthropic-beta", "")
    final = original
    mode = "passive"

    if SET_BETA:
        final = SET_BETA
        mode = "set"
    elif APPEND_BETA:
        final = _merge_beta(original, APPEND_BETA)
        mode = "append"

    if mode != "passive":
        if final:
            flow.request.headers["anthropic-beta"] = final
        elif "anthropic-beta" in flow.request.headers:
            del flow.request.headers["anthropic-beta"]

    return {
        "mode": mode,
        "original": original,
        "final": final,
        "append_beta": APPEND_BETA,
        "set_beta": SET_BETA,
    }


class ClaudeCapture:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host or flow.request.host or ""
        path = flow.request.path or ""
        is_claude_api_path = path.startswith("/v1/messages") or path.startswith("/v1/models") or path.startswith("/v1/complete")
        has_claude_headers = any(
            name.lower().startswith("anthropic-") or name.lower().startswith("x-stainless-") or name.lower() == "x-app"
            for name in flow.request.headers.keys()
        )
        if not (
            any(part in host.lower() for part in INTERESTING_HOST_PARTS)
            or is_claude_api_path
            or has_claude_headers
        ):
            return

        beta_mutation = _maybe_mutate_beta(flow)

        headers = {
            name: _redact_header(name, value)
            for name, value in flow.request.headers.items(multi=True)
        }
        body = _decode_body(flow.request.raw_content or b"")
        payload = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": host,
            "port": flow.request.port,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "headers": headers,
            "body_preview": body,
            "body_bytes": len(flow.request.raw_content or b""),
            "anthropic_beta": beta_mutation["final"],
            "anthropic_beta_original": beta_mutation["original"],
            "anthropic_beta_capture_mode": beta_mutation["mode"],
        }
        _write_jsonl("requests.redacted.jsonl", payload)

        latest_path = OUT_DIR / "latest_request.redacted.json"
        latest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

        beta_slug = _beta_slug(beta_mutation["final"])
        by_beta_dir = OUT_DIR / "by-beta"
        by_beta_dir.mkdir(parents=True, exist_ok=True)
        _write_jsonl(f"by-beta/{beta_slug}.redacted.jsonl", payload)
        (by_beta_dir / f"{beta_slug}.latest.redacted.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        if BLOCK_UPSTREAM:
            flow.response = http.Response.make(
                599,
                b"captured by mitm_capture_claude.py; upstream request blocked by CLAUDE_CAPTURE_BLOCK_UPSTREAM",
                {"content-type": "text/plain; charset=utf-8"},
            )


addons = [ClaudeCapture()]
