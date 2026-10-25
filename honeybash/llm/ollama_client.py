from __future__ import annotations

import json
import logging
import re
from os import getenv
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("honeybash.error")

DEFAULT_HOST = "http://127.0.0.1:11434"
# Non-reasoning instruct model: low latency matters more than depth for a fake shell.
DEFAULT_MODEL = "llama3.1:8b"
THINK_REGEX = re.compile(r"<think>.*?(?:</think>|$)", re.DOTALL)


class OllamaClient:
    """Minimal client for a local Ollama server (stdlib only, fully offline)."""

    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
        timeout: float = 20.0,
        max_tokens: int = 256,
        temperature: float = 0.2,
    ):
        self.model = model or getenv("HONEYBASH_LLM_MODEL") or DEFAULT_MODEL
        self.host = (host or getenv("HONEYBASH_OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    def chat(self, messages: list[dict[str, str]]) -> str | None:
        """Return the assistant reply, or None if Ollama is unreachable or fails."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": "30m",  # keep the model warm between attacker commands
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        request = Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                content = json.loads(response.read())["message"]["content"]
        except (URLError, TimeoutError, OSError, KeyError, ValueError) as error:
            logger.debug(f"Ollama request failed: {error}", exc_info=True)
            return None
        # reasoning models (e.g. deepseek-r1) prepend <think> blocks; never show them
        return THINK_REGEX.sub("", content).strip("\n")

    def is_available(self) -> bool:
        try:
            with urlopen(f"{self.host}/api/tags", timeout=2) as response:  # noqa: S310
                names = {m["name"] for m in json.loads(response.read()).get("models", [])}
        except (URLError, TimeoutError, OSError, KeyError, ValueError):
            return False
        return self.model in names or f"{self.model}:latest" in names
