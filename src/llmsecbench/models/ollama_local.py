from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

import requests

from .base import Message, ModelClient


class OllamaClient(ModelClient):
    def __init__(self, model: str, host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")

    def generate(
        self,
        messages: List[Message],
        *,
        max_tokens: int = 256,
        temperature: float = 0.0,
    ) -> Tuple[str, Dict[str, Any]]:
        t0 = time.perf_counter()
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        resp = requests.post(f"{self.host}/api/chat", json=payload, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        dt = time.perf_counter() - t0

        text = (data.get("message", {}) or {}).get("content", "") or ""
        return text.strip(), {"latency_s": dt}
