from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Tuple

from openai import OpenAI

from .base import Message, ModelClient


class OpenAIClient(ModelClient):
    def __init__(self, model: str):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY environment variable")
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(
        self,
        messages: List[Message],
        *,
        max_tokens: int = 256,
        temperature: float = 0.0,
    ) -> Tuple[str, Dict[str, Any]]:
        t0 = time.perf_counter()
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        dt = time.perf_counter() - t0

        text = (resp.choices[0].message.content or "").strip()
        usage = getattr(resp, "usage", None)
        meta: Dict[str, Any] = {"latency_s": dt}
        if usage:
            meta["prompt_tokens"] = getattr(usage, "prompt_tokens", None)
            meta["completion_tokens"] = getattr(usage, "completion_tokens", None)
            meta["total_tokens"] = getattr(usage, "total_tokens", None)
        return text, meta
