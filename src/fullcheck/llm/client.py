from __future__ import annotations
import json
import os
import httpx
from pathlib import Path
from typing import Any

# OpenClaw exposes an OpenAI-compatible chat endpoint on the local gateway.
# Configure via env so no secrets live in the repo.
OPENCLAW_BASE = os.environ.get("OPENCLAW_BASE", "http://127.0.0.1:8787/v1")
OPENCLAW_MODEL = os.environ.get("OPENCLAW_MODEL", "glm-4.6")
OPENCLAW_KEY = os.environ.get("OPENCLAW_API_KEY", "sk-local")


class LlmError(RuntimeError):
    pass


class OpenClawClient:
    def __init__(
        self,
        base: str = OPENCLAW_BASE,
        model: str = OPENCLAW_MODEL,
        api_key: str = OPENCLAW_KEY,
        timeout: float = 120.0,
    ):
        self.base = base.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def chat(self, system: str, user: str, temperature: float = 0.2) -> str:
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            r = httpx.post(
                f"{self.base}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout,
            )
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise LlmError(f"OpenClaw request failed: {e}") from e
        data = r.json()
        return data["choices"][0]["message"]["content"]

    def chat_json(self, system: str, user: str) -> Any:
        raw = self.chat(system, user)
        return _extract_json(raw)


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        # strip code fences
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()
    start = text.find("[")
    obj_start = text.find("{")
    if obj_start != -1 and (start == -1 or obj_start < start):
        start = obj_start
    if start == -1:
        raise LlmError(f"no JSON found in LLM output: {text[:200]}")
    # raw_decode parses one JSON value and ignores any trailing prose.
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as e:
        raise LlmError(f"could not parse JSON from LLM output: {e}") from e
    return obj
