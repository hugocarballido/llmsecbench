from __future__ import annotations

from typing import Any, Dict, List, Protocol, Tuple


Message = Dict[str, str]  # {"role": "system"|"user"|"assistant", "content": "..."}


class ModelClient(Protocol):
    def generate(
        self,
        messages: List[Message],
        *,
        max_tokens: int = 256,
        temperature: float = 0.0,
    ) -> Tuple[str, Dict[str, Any]]:
        """Returns (text, meta). meta may include token usage, latency, etc."""
        ...
