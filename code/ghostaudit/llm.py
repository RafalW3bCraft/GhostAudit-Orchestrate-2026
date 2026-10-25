"""Optional LLM/VLM access with a usage ledger (for evaluation/usage_report.md).

The core pipeline is deterministic; the LLM is used only for (a) ambiguous request
intent and (b) OCR of images when pytesseract is unavailable. Everything is cached."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading

LEDGER: list[dict] = []
_lock = threading.Lock()
_cache: dict[str, str] = {}


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def model_name() -> str:
    return os.environ.get("AUDIT_LLM_MODEL", "claude-haiku-5-5")


def _record(purpose, model, usage):
    with _lock:
        LEDGER.append({"purpose": purpose, "model": model,
                       "input_tokens": getattr(usage, "input_tokens", 0),
                       "output_tokens": getattr(usage, "output_tokens", 0)})


def ask(system: str, user: str, purpose: str, image_path: str | None = None, max_tokens: int = 400) -> str | None:
    if not available():
        return None
    key = hashlib.sha256((system + user + (image_path or "")).encode()).hexdigest()
    if key in _cache:
        return _cache[key]
    import anthropic
    client = anthropic.Anthropic()
    content = []
    if image_path:
        ext = os.path.splitext(image_path)[1].lower().lstrip(".")
        mt = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp",
              "gif": "image/gif"}.get(ext, "image/png")
        with open(image_path, "rb") as fh:
            content.append({"type": "image", "source": {"type": "base64", "media_type": mt,
                                                         "data": base64.b64encode(fh.read()).decode()}})
    content.append({"type": "text", "text": user})
    try:
        resp = client.messages.create(model=model_name(), max_tokens=max_tokens, temperature=0,
                                      system=system, messages=[{"role": "user", "content": content}])
    except Exception:
        return None
    _record(purpose, model_name(), resp.usage)
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    _cache[key] = text
    return text


def ask_json(system: str, user: str, purpose: str) -> dict | None:
    t = ask(system, user, purpose)
    if not t:
        return None
    try:
        return json.loads(t[t.index("{"): t.rindex("}") + 1])
    except ValueError:
        return None
