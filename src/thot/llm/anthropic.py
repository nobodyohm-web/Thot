"""Claude, over the Messages API, with an API key.

Subscription tokens are refused on purpose. Anthropic only accepts them from
its own clients; passing one would require Thot to impersonate Claude Code —
spoofing its user agent and prompt — which it will not do. The refusal happens
before any request, so the user gets a clear reason instead of a bare 429.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx

from thot.llm.base import Message, ProviderError, Reply, ToolCall, ToolSpec, Usage

SUBSCRIPTION_REFUSED = (
    "Ce jeton vient d'un abonnement Claude, qui n'est utilisable que depuis "
    "les clients officiels d'Anthropic.\n"
    "   Utilise une clé API (console.anthropic.com/settings/keys), un modèle "
    "local, ou OpenAI."
)

API_VERSION = "2023-06-01"
DEFAULT_BASE_URL = "https://api.anthropic.com"
TIMEOUT = httpx.Timeout(120.0, connect=10.0)


def is_subscription_token(token: str) -> bool:
    """Subscription tokens issued by the Claude CLI start with this prefix."""
    return token.startswith("sk-ant-oat")


def system_blocks(system: str) -> list[dict]:
    """The system prompt, marked as the end of a cacheable prefix.

    `engine/base.py` documents that `AgentTask` keeps `context` apart from
    `instructions` "so an engine that supports prompt caching can cache the
    bulky half without touching the question". The separation was made and
    the breakpoint was never placed — `cache_control` appeared nowhere in
    this package — so the repository map was re-read, and re-billed, on
    every single turn of every session.

    One marker is enough. The API caches everything up to and including the
    block that carries it, and the request order is tools, then system, then
    messages: a breakpoint here covers the tool schemas too. Below the
    minimum cacheable length the header is ignored rather than refused, so a
    short system prompt costs nothing to mark.
    """
    if not system:
        # A breakpoint on an empty prefix is a header the API rejects.
        return []
    return [{
        "type": "text",
        "text": system,
        "cache_control": {"type": "ephemeral"},
    }]


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        *,
        model: str,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        max_tokens: int = 8192,
    ) -> None:
        if is_subscription_token(token):
            raise ProviderError(SUBSCRIPTION_REFUSED)
        self.model = model
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens

    def _headers(self) -> dict[str, str]:
        return {
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
            "accept": "text/event-stream",
            "x-api-key": self._token,
        }

    @staticmethod
    def _encode(messages: list[Message]) -> list[dict]:
        """Turn the neutral history into Anthropic content blocks."""
        encoded: list[dict] = []
        for message in messages:
            if message.role == "tool":
                block = {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id,
                    "content": message.content,
                }
                # Consecutive tool results belong in one user turn.
                if encoded and encoded[-1]["role"] == "user" and isinstance(
                    encoded[-1]["content"], list
                ):
                    encoded[-1]["content"].append(block)
                else:
                    encoded.append({"role": "user", "content": [block]})
                continue

            if message.role == "assistant" and message.tool_calls:
                blocks: list[dict] = []
                if message.content:
                    blocks.append({"type": "text", "text": message.content})
                for call in message.tool_calls:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.id,
                            "name": call.name,
                            "input": call.arguments,
                        }
                    )
                encoded.append({"role": "assistant", "content": blocks})
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
        payload: dict = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "messages": self._encode(messages),
            "stream": True,
        }
        blocks = system_blocks(system)
        if blocks:
            payload["system"] = blocks
        if tools:
            payload["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                }
                for tool in tools
            ]

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        partial_json: dict[int, list[str]] = {}
        blocks: dict[int, dict] = {}
        usage = Usage()

        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                with client.stream(
                    "POST",
                    f"{self._base_url}/v1/messages",
                    headers=self._headers(),
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        response.read()
                        raise ProviderError(_explain(response))
                    for line in response.iter_lines():
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        event = json.loads(raw)
                        kind = event.get("type")

                        if kind == "content_block_start":
                            index = event["index"]
                            blocks[index] = event["content_block"]
                            partial_json[index] = []
                        elif kind == "content_block_delta":
                            delta = event["delta"]
                            if delta.get("type") == "text_delta":
                                chunk = delta["text"]
                                text_parts.append(chunk)
                                if on_text:
                                    on_text(chunk)
                            elif delta.get("type") == "input_json_delta":
                                partial_json.setdefault(event["index"], []).append(
                                    delta["partial_json"]
                                )
                        elif kind == "content_block_stop":
                            index = event["index"]
                            block = blocks.get(index, {})
                            if block.get("type") == "tool_use":
                                raw_args = "".join(partial_json.get(index, []))
                                try:
                                    arguments = json.loads(raw_args) if raw_args else {}
                                except json.JSONDecodeError:
                                    arguments = {}
                                tool_calls.append(
                                    ToolCall(
                                        id=block["id"],
                                        name=block["name"],
                                        arguments=arguments,
                                    )
                                )
                        elif kind == "message_start":
                            counts = event["message"].get("usage", {})
                            usage.input_tokens = counts.get("input_tokens", 0)
                        elif kind == "message_delta":
                            counts = event.get("usage", {})
                            usage.output_tokens = counts.get("output_tokens", 0)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Connexion à Claude impossible : {exc}") from exc

        return Reply(
            message=Message(
                role="assistant",
                content="".join(text_parts),
                tool_calls=tuple(tool_calls),
            ),
            usage=usage,
        )


def _explain(response: httpx.Response) -> str:
    """Turn an API error into something a user can act on."""
    try:
        detail = response.json().get("error", {}).get("message", "")
    except Exception:
        detail = response.text[:200]

    if response.status_code == 401:
        return "Identifiants Claude refusés. Relance `thot login`."
    if response.status_code == 429:
        return "Limite de débit atteinte. Réessaie dans un moment."
    if response.status_code == 400 and "credit balance" in detail.lower():
        return "Crédits Anthropic épuisés."
    return f"Claude a renvoyé {response.status_code} : {detail}"
