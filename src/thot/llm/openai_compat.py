"""Everything that speaks the OpenAI chat-completions dialect.

One module covers OpenAI itself, Ollama, LM Studio, vLLM and any private
gateway: they differ only by base URL and whether a key is required. Local
servers get no `Authorization` header at all.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx

from thot.llm.base import Message, ProviderError, Reply, ToolCall, ToolSpec, Usage

OPENAI_BASE_URL = "https://api.openai.com/v1"
OLLAMA_BASE_URL = "http://localhost:11434/v1"
LMSTUDIO_BASE_URL = "http://localhost:1234/v1"
TIMEOUT = httpx.Timeout(180.0, connect=10.0)


class OpenAICompatProvider:
    def __init__(
        self,
        *,
        model: str,
        base_url: str = OPENAI_BASE_URL,
        api_key: str = "",
        name: str = "openai",
    ) -> None:
        self.model = model
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        return headers

    @staticmethod
    def _encode(messages: list[Message]) -> list[dict]:
        encoded: list[dict] = []
        for message in messages:
            if message.role == "tool":
                encoded.append(
                    {
                        "role": "tool",
                        "tool_call_id": message.tool_call_id,
                        "content": message.content,
                    }
                )
                continue
            if message.role == "assistant" and message.tool_calls:
                encoded.append(
                    {
                        "role": "assistant",
                        "content": message.content or None,
                        "tool_calls": [
                            {
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": json.dumps(call.arguments),
                                },
                            }
                            for call in message.tool_calls
                        ],
                    }
                )
                continue
            encoded.append({"role": message.role, "content": message.content})
        return encoded

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec],
        on_text: Callable[[str], None] | None = None,
    ) -> Reply:
        wire: list[dict] = []
        if system:
            wire.append({"role": "system", "content": system})
        wire.extend(self._encode(messages))

        payload: dict = {
            "model": self.model,
            "messages": wire,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                }
                for tool in tools
            ]

        text_parts: list[str] = []
        # index -> {id, name, arguments fragments}
        pending: dict[int, dict] = {}
        usage = Usage()

        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                with client.stream(
                    "POST",
                    f"{self._base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        response.read()
                        raise ProviderError(_explain(response, self.name))
                    for line in response.iter_lines():
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            event = json.loads(raw)
                        except json.JSONDecodeError:
                            continue

                        if counts := event.get("usage"):
                            usage.input_tokens = counts.get("prompt_tokens", 0)
                            usage.output_tokens = counts.get("completion_tokens", 0)

                        for choice in event.get("choices", []):
                            delta = choice.get("delta") or {}
                            if chunk := delta.get("content"):
                                text_parts.append(chunk)
                                if on_text:
                                    on_text(chunk)
                            for call in delta.get("tool_calls") or []:
                                index = call.get("index", 0)
                                slot = pending.setdefault(
                                    index, {"id": "", "name": "", "args": []}
                                )
                                if call.get("id"):
                                    slot["id"] = call["id"]
                                function = call.get("function") or {}
                                if function.get("name"):
                                    slot["name"] = function["name"]
                                if function.get("arguments"):
                                    slot["args"].append(function["arguments"])
        except httpx.HTTPError as exc:
            raise ProviderError(f"Connexion à {self.name} impossible : {exc}") from exc

        tool_calls = []
        for index in sorted(pending):
            slot = pending[index]
            if not slot["name"]:
                continue
            raw_args = "".join(slot["args"])
            try:
                arguments = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError:
                arguments = {}
            tool_calls.append(
                ToolCall(
                    id=slot["id"] or f"call_{index}",
                    name=slot["name"],
                    arguments=arguments,
                )
            )

        return Reply(
            message=Message(
                role="assistant",
                content="".join(text_parts),
                tool_calls=tuple(tool_calls),
            ),
            usage=usage,
        )


def list_local_models(base_url: str, timeout: float = 2.0) -> list[str]:
    """Ask a local server what it has loaded. Empty list when unreachable."""
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/models", timeout=timeout)
        response.raise_for_status()
        data = response.json().get("data", [])
        return [entry["id"] for entry in data if isinstance(entry, dict) and "id" in entry]
    except Exception:
        return []


def _explain(response: httpx.Response, provider: str) -> str:
    try:
        detail = response.json().get("error", {}).get("message", "")
    except Exception:
        detail = response.text[:200]

    if response.status_code == 401:
        return f"Clé {provider} refusée. Relance `thot login`."
    if response.status_code == 404:
        return f"Modèle introuvable sur {provider} : {detail}"
    if response.status_code == 429:
        return "Limite de débit atteinte. Réessaie dans un moment."
    return f"{provider} a renvoyé {response.status_code} : {detail}"
