"""Tests for the Bedrock provider — format conversion and response parsing.

All tests use mocked boto3 clients. No live Bedrock calls.
"""
import json
import pytest
from app.llm import BedrockProvider, LLMResponse, ToolCall


# ── Message conversion ───────────────────────────────────────────────────────

def test_system_message_extracted():
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello"},
    ]
    system, bedrock_msgs = BedrockProvider._convert_messages(messages)
    assert len(system) == 1
    assert system[0]["text"] == "You are a helpful assistant."
    assert len(bedrock_msgs) == 1
    assert bedrock_msgs[0]["role"] == "user"


def test_user_message_converted():
    messages = [{"role": "user", "content": "What is 2+2?"}]
    _, bedrock_msgs = BedrockProvider._convert_messages(messages)
    assert bedrock_msgs[0]["content"] == [{"text": "What is 2+2?"}]


def test_assistant_text_converted():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "Hello!"},
    ]
    _, bedrock_msgs = BedrockProvider._convert_messages(messages)
    assert bedrock_msgs[1]["role"] == "assistant"
    assert bedrock_msgs[1]["content"] == [{"text": "Hello!"}]


def test_assistant_tool_calls_converted():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "Let me check.",
         "tool_calls": [{"id": "tc1", "type": "function",
                         "function": {"name": "get_findings", "arguments": '{"severity": "Critical"}'}}]},
    ]
    _, bedrock_msgs = BedrockProvider._convert_messages(messages)
    assistant = bedrock_msgs[1]
    assert len(assistant["content"]) == 2
    assert assistant["content"][0] == {"text": "Let me check."}
    tu = assistant["content"][1]["toolUse"]
    assert tu["toolUseId"] == "tc1"
    assert tu["name"] == "get_findings"
    assert tu["input"] == {"severity": "Critical"}


def test_tool_results_become_user_messages():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "tc1", "type": "function",
                         "function": {"name": "read_report", "arguments": '{"report_id": "r1"}'}}]},
        {"role": "tool", "tool_call_id": "tc1", "content": '{"filename": "test.md"}'},
    ]
    _, bedrock_msgs = BedrockProvider._convert_messages(messages)
    assert len(bedrock_msgs) == 3
    tool_result_msg = bedrock_msgs[2]
    assert tool_result_msg["role"] == "user"
    tr = tool_result_msg["content"][0]["toolResult"]
    assert tr["toolUseId"] == "tc1"
    assert tr["content"][0]["text"] == '{"filename": "test.md"}'


def test_multiple_tool_results_grouped():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": None,
         "tool_calls": [
             {"id": "tc1", "type": "function", "function": {"name": "a", "arguments": "{}"}},
             {"id": "tc2", "type": "function", "function": {"name": "b", "arguments": "{}"}},
         ]},
        {"role": "tool", "tool_call_id": "tc1", "content": "result1"},
        {"role": "tool", "tool_call_id": "tc2", "content": "result2"},
    ]
    _, bedrock_msgs = BedrockProvider._convert_messages(messages)
    tool_msg = bedrock_msgs[2]
    assert tool_msg["role"] == "user"
    assert len(tool_msg["content"]) == 2
    assert tool_msg["content"][0]["toolResult"]["toolUseId"] == "tc1"
    assert tool_msg["content"][1]["toolResult"]["toolUseId"] == "tc2"


# ── Tool definition conversion ───────────────────────────────────────────────

def test_tool_definitions_converted():
    openai_tools = [
        {"type": "function", "function": {
            "name": "get_findings",
            "description": "Retrieve findings",
            "parameters": {"type": "object", "properties": {
                "severity": {"type": "string"}}}}}
    ]
    bedrock_tools = BedrockProvider._convert_tools(openai_tools)
    assert len(bedrock_tools) == 1
    spec = bedrock_tools[0]["toolSpec"]
    assert spec["name"] == "get_findings"
    assert spec["description"] == "Retrieve findings"
    assert spec["inputSchema"]["json"]["type"] == "object"


# ── Response parsing ─────────────────────────────────────────────────────────

def test_parse_text_response():
    response = {
        "output": {"message": {"role": "assistant", "content": [{"text": "Hello!"}]}},
        "stopReason": "end_turn",
    }
    result = BedrockProvider._parse_response(response)
    assert result.content == "Hello!"
    assert len(result.tool_calls) == 0


def test_parse_tool_use_response():
    response = {
        "output": {"message": {"role": "assistant", "content": [
            {"text": "Let me check."},
            {"toolUse": {"toolUseId": "tu1", "name": "get_findings",
                         "input": {"severity": "Critical"}}},
        ]}},
        "stopReason": "tool_use",
    }
    result = BedrockProvider._parse_response(response)
    assert result.content == "Let me check."
    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.id == "tu1"
    assert tc.name == "get_findings"
    assert tc.arguments == {"severity": "Critical"}
    assert tc.raw_arguments == '{"severity": "Critical"}'


def test_parse_multiple_tool_uses():
    response = {
        "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "tu1", "name": "a", "input": {}}},
            {"toolUse": {"toolUseId": "tu2", "name": "b", "input": {"x": 1}}},
        ]}},
        "stopReason": "tool_use",
    }
    result = BedrockProvider._parse_response(response)
    assert result.content is None
    assert len(result.tool_calls) == 2


def test_parse_empty_content():
    response = {"output": {"message": {"role": "assistant", "content": []}}, "stopReason": "end_turn"}
    result = BedrockProvider._parse_response(response)
    assert result.content is None
    assert len(result.tool_calls) == 0


# ── Request body ─────────────────────────────────────────────────────────────

def test_request_body_includes_tools():
    provider = BedrockProvider.__new__(BedrockProvider)
    provider.model = "test-model"
    provider.temperature = 0.5
    tools = [{"type": "function", "function": {"name": "t", "description": "d", "parameters": {}}}]
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    body = provider.request_body(messages, tools)
    assert body["modelId"] == "test-model"
    assert len(body["system"]) == 1
    assert len(body["messages"]) == 1
    assert "toolConfig" in body
    assert body["inferenceConfig"]["temperature"] == 0.5


def test_request_body_no_tools():
    provider = BedrockProvider.__new__(BedrockProvider)
    provider.model = "test-model"
    provider.temperature = 0.0
    body = provider.request_body([{"role": "user", "content": "hi"}], [])
    assert "toolConfig" not in body
