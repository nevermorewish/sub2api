from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http


OUT_DIR = Path(os.environ.get("CLAUDE_CAPTURE_DIR", "captures/claude-code-headers"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

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
        }
        _write_jsonl("requests.redacted.jsonl", payload)

        latest_path = OUT_DIR / "latest_request.redacted.json"
        latest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


addons = [ClaudeCapture()]
