"""Testbed configuration. All secrets come from the environment (or a local,
git-ignored .env file). The testbed refuses to start without them."""
import os
from dataclasses import dataclass
from pathlib import Path

try:  # optional convenience for local runs
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if len(value) < 16:
        raise ConfigError(
            f"{name} must be set to a random value of at least 16 characters "
            "(see .env.example). The testbed does not fall back to defaults."
        )
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    analyst_token: str
    manager_token: str
    evaluator_token: str
    # Provider selection
    llm_provider: str
    # OpenAI-compatible provider settings
    llm_base_url: str
    llm_api_key: str
    llm_api_key_header: str
    llm_model: str
    llm_temperature: float
    llm_timeout_s: float
    agent_max_steps: int
    # Bedrock provider settings
    aws_region: str
    aws_bearer_token: str
    bedrock_default_model: str
    bedrock_coordinator_model: str
    bedrock_reader_model: str
    bedrock_fm_model: str


def load_settings() -> Settings:
    data_dir = Path(os.getenv("TESTBED_DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")))
    tokens = {n: _required(n) for n in ("ANALYST_TOKEN", "MANAGER_TOKEN", "EVALUATOR_TOKEN")}
    if len(set(tokens.values())) != 3:
        raise ConfigError("ANALYST_TOKEN, MANAGER_TOKEN and EVALUATOR_TOKEN must all differ.")
    return Settings(
        data_dir=data_dir,
        analyst_token=tokens["ANALYST_TOKEN"],
        manager_token=tokens["MANAGER_TOKEN"],
        evaluator_token=tokens["EVALUATOR_TOKEN"],
        llm_provider=os.getenv("LLM_PROVIDER", "openai"),
        llm_base_url=os.getenv("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_api_key_header=os.getenv("LLM_API_KEY_HEADER", "x-api-key"),
        llm_model=os.getenv("LLM_MODEL", "bedrock.claude-sonnet-4-0"),
        llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0")),
        llm_timeout_s=float(os.getenv("LLM_TIMEOUT_S", "90")),
        agent_max_steps=int(os.getenv("AGENT_MAX_STEPS", "6")),
        aws_region=os.getenv("AWS_REGION", "ap-southeast-1"),
        aws_bearer_token=os.getenv("AWS_BEARER_TOKEN_BEDROCK", ""),
        bedrock_default_model=os.getenv("BEDROCK_DEFAULT_MODEL_ID",
                                         "anthropic.claude-3-5-sonnet-20241022-v2:0"),
        bedrock_coordinator_model=os.getenv("BEDROCK_COORDINATOR_MODEL_ID", ""),
        bedrock_reader_model=os.getenv("BEDROCK_DOCUMENT_READER_MODEL_ID", ""),
        bedrock_fm_model=os.getenv("BEDROCK_FINDINGS_MANAGER_MODEL_ID", ""),
    )
