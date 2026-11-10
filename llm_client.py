"""Model access for the V01 testbed — direct API call, OpenAI-compatible.

One entry point only: call_llm(messages, tools).
The agent loop never talks to the provider directly, so swapping the
provider / model means changing this file only — never the loop.

The client is created lazily so `test_offline.py` can run without an
API key or network.
"""
import os

from config import OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL


class OpenAICompatibleClient:
    def __init__(self, base_url=None, api_key=None, model=None):
        self.base_url = base_url or OPENAI_BASE_URL
        self.api_key = api_key or OPENAI_API_KEY
        self.model = model or OPENAI_MODEL
        self._client = None

    def _get_client(self):
        if self._client is None:
            if not self.api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY is not set. Copy .env.example to .env "
                    "and fill it in, or export OPENAI_API_KEY."
                )
            from openai import OpenAI

            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key)
        return self._client

    def call_llm(self, messages, tools):
        """One model call. Returns the raw OpenAI response message.

        messages: list of {"role": ..., "content": ...} plus tool messages.
        tools: OpenAI tool schemas (see tools.TOOL_SCHEMAS).
        """
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0,  # deterministic for evaluation; do not change mid-run
        )
        return response.choices[0].message


def get_client():
    """Default client from the environment."""
    return OpenAICompatibleClient()
