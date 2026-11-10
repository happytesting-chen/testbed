"""LLM providers.

OpenAICompatibleProvider talks to any /v1/chat/completions endpoint (e.g. the
internal gateway fronting Bedrock). ScriptedProvider exists for automated tests
only; the running application never uses it.
"""
import json
from dataclasses import dataclass, field
from typing import Callable

import httpx


class LLMError(RuntimeError):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict
    raw_arguments: str = ""
    parse_error: str | None = None


@dataclass
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _parse(data: dict) -> LLMResponse:
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"Unexpected response shape: {str(data)[:500]}") from exc
    calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            err = None
        except json.JSONDecodeError as exc:
            args, err = {}, str(exc)
        calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args,
                              raw_arguments=raw_args if isinstance(raw_args, str) else json.dumps(raw_args),
                              parse_error=err))
    return LLMResponse(content=msg.get("content"), tool_calls=calls, raw=data)


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, api_key: str, model: str, api_key_header: str = "x-api-key",
                 temperature: float = 0.0, timeout_s: float = 90.0):
        if not base_url or not api_key:
            raise LLMError("LLM_BASE_URL and LLM_API_KEY must be set to use the real agent.")
        self.url = f"{base_url}/chat/completions"
        self.headers = {"Content-Type": "application/json", api_key_header: api_key}
        self.model = model
        self.temperature = temperature
        self.timeout_s = timeout_s

    def request_body(self, messages: list[dict], tools: list[dict]) -> dict:
        body = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        return body

    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        body = self.request_body(messages, tools)
        try:
            resp = httpx.post(self.url, headers=self.headers, json=body, timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc
        if resp.status_code != 200:
            raise LLMError(f"LLM returned HTTP {resp.status_code}: {resp.text[:500]}")
        return _parse(resp.json())


class ScriptedProvider:
    """TEST ONLY. Returns responses from a callable so tests can exercise the
    agent loop, tracing and validators without network access."""

    def __init__(self, script: Callable[[list[dict], list[dict]], dict], model: str = "scripted-test-model"):
        self.script = script
        self.model = model

    def request_body(self, messages, tools):
        return {"model": self.model, "messages": messages, "tools": tools}

    def complete(self, messages, tools) -> LLMResponse:
        return _parse(self.script(messages, tools))
