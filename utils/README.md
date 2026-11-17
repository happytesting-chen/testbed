# utils/

Utility scripts for the target agent. Not part of the running application.

## check_llm.py

Verifies that the configured LLM gateway supports the full tool-calling loop required by the agent.

**Run this first when setting up a new environment or switching gateways:**

```bash
python utils/check_llm.py
```

**What it checks:**

| Step | What is verified |
|---|---|
| 1. Plain chat | Gateway is reachable and returns a text response |
| 2. Tool calling | Gateway passes the `tools` parameter to the model and returns tool call decisions |
| 3. Tool result round-trip | Model can receive a tool result and produce a final answer |

**Why step 2 matters:** some gateways silently drop the `tools` parameter and return a plain text response instead. The agent will appear to run but will never call any tools — all answers will be guesses. This check catches that failure before it wastes debugging time.

**Requires** `LLM_BASE_URL` and `LLM_API_KEY` set in `.env`.
