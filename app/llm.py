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
            resp = httpx.post(self.url, headers=self.headers, json=body, timeout=self.timeout_s, verify=False)
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc
        if resp.status_code != 200:
            raise LLMError(f"LLM returned HTTP {resp.status_code}: {resp.text[:500]}")
        return _parse(resp.json())


class BedrockProvider:
    """Amazon Bedrock Converse API provider.

    Translates OpenAI-style messages and tools to the Bedrock Converse
    format and maps Bedrock responses back to LLMResponse.
    """

    def __init__(self, region: str, model_id: str,
                 bearer_token: str | None = None,
                 temperature: float = 0.0, timeout_s: float = 90.0):
        try:
            import boto3
        except ImportError as exc:
            raise LLMError("boto3 is required for Bedrock provider. Install with: pip install boto3>=1.39.0") from exc

        self.model = model_id
        self.temperature = temperature
        self.timeout_s = timeout_s

        from botocore.config import Config
        config = Config(read_timeout=int(timeout_s), connect_timeout=10,
                        retries={"max_attempts": 2, "mode": "adaptive"})

        if bearer_token:
            from botocore.credentials import Credentials
            creds = Credentials(access_key="", secret_key="", token=bearer_token)
            session = boto3.Session(botocore_session=boto3.session.botocore.session.get_session())
            session._session.set_credentials(creds.access_key, creds.secret_key, creds.token)
            self._client = session.client("bedrock-runtime", region_name=region, config=config)
        else:
            self._client = boto3.client("bedrock-runtime", region_name=region, config=config)

    @staticmethod
    def _convert_tools(tools: list[dict]) -> list[dict]:
        """OpenAI tool defs → Bedrock toolSpec format."""
        bedrock_tools = []
        for t in tools:
            fn = t.get("function", {})
            spec = {
                "toolSpec": {
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "inputSchema": {"json": fn.get("parameters", {"type": "object", "properties": {}})},
                }
            }
            bedrock_tools.append(spec)
        return bedrock_tools

    @staticmethod
    def _convert_messages(messages: list[dict]) -> tuple[list[dict], list[dict]]:
        """OpenAI messages → Bedrock (system, messages) tuple.

        Handles: system → separate param, tool results → user message
        with toolResult, assistant tool_calls → toolUse blocks.
        """
        system = []
        bedrock_msgs = []
        pending_tool_results = []

        for msg in messages:
            role = msg.get("role", "")

            if role == "system":
                system.append({"text": msg.get("content", "")})
                continue

            if role == "tool":
                pending_tool_results.append({
                    "toolResult": {
                        "toolUseId": msg.get("tool_call_id", ""),
                        "content": [{"text": msg.get("content", "")}],
                    }
                })
                continue

            if pending_tool_results:
                bedrock_msgs.append({"role": "user", "content": list(pending_tool_results)})
                pending_tool_results = []

            if role == "assistant":
                content_blocks = []
                text = msg.get("content")
                if text:
                    content_blocks.append({"text": text})
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", "{}")
                    try:
                        input_obj = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except json.JSONDecodeError:
                        input_obj = {}
                    content_blocks.append({
                        "toolUse": {
                            "toolUseId": tc.get("id", ""),
                            "name": fn.get("name", ""),
                            "input": input_obj,
                        }
                    })
                if not content_blocks:
                    content_blocks.append({"text": ""})
                bedrock_msgs.append({"role": "assistant", "content": content_blocks})
                continue

            if role == "user":
                bedrock_msgs.append({"role": "user", "content": [{"text": msg.get("content", "")}]})
                continue

        if pending_tool_results:
            bedrock_msgs.append({"role": "user", "content": list(pending_tool_results)})

        return system, bedrock_msgs

    @staticmethod
    def _parse_response(response: dict) -> LLMResponse:
        """Bedrock Converse response → LLMResponse."""
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        text_parts = []
        tool_calls = []
        for block in content_blocks:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                tu = block["toolUse"]
                input_obj = tu.get("input", {})
                raw_args = json.dumps(input_obj)
                tool_calls.append(ToolCall(
                    id=tu.get("toolUseId", ""),
                    name=tu.get("name", ""),
                    arguments=input_obj,
                    raw_arguments=raw_args,
                ))

        content = "\n".join(text_parts) if text_parts else None
        return LLMResponse(content=content, tool_calls=tool_calls, raw=response)

    def request_body(self, messages: list[dict], tools: list[dict]) -> dict:
        system, bedrock_msgs = self._convert_messages(messages)
        body = {"modelId": self.model, "system": system, "messages": bedrock_msgs}
        if tools:
            body["toolConfig"] = {"tools": self._convert_tools(tools)}
        body["inferenceConfig"] = {"temperature": self.temperature}
        return body

    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        system, bedrock_msgs = self._convert_messages(messages)
        kwargs = {
            "modelId": self.model,
            "messages": bedrock_msgs,
            "inferenceConfig": {"temperature": self.temperature},
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["toolConfig"] = {"tools": self._convert_tools(tools)}
        try:
            response = self._client.converse(**kwargs)
        except Exception as exc:
            raise LLMError(f"Bedrock request failed: {exc}") from exc
        return self._parse_response(response)


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
