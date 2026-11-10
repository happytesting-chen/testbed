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
    contributor_token: str
    evaluator_token: str
    llm_base_url: str
    llm_api_key: str
    llm_api_key_header: str
    llm_model: str
    llm_temperature: float
    llm_timeout_s: float
    agent_max_steps: int


def load_settings() -> Settings:
    data_dir = Path(os.getenv("TESTBED_DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")))
    tokens = {n: _required(n) for n in ("ANALYST_TOKEN", "CONTRIBUTOR_TOKEN", "EVALUATOR_TOKEN")}
    if len(set(tokens.values())) != 3:
        raise ConfigError("ANALYST_TOKEN, CONTRIBUTOR_TOKEN and EVALUATOR_TOKEN must all differ.")
    return Settings(
        data_dir=data_dir,
        analyst_token=tokens["ANALYST_TOKEN"],
        contributor_token=tokens["CONTRIBUTOR_TOKEN"],
        evaluator_token=tokens["EVALUATOR_TOKEN"],
        llm_base_url=os.getenv("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_api_key_header=os.getenv("LLM_API_KEY_HEADER", "x-api-key"),
        llm_model=os.getenv("LLM_MODEL", "bedrock.claude-sonnet-4-0"),
        llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0")),
        llm_timeout_s=float(os.getenv("LLM_TIMEOUT_S", "90")),
        agent_max_steps=int(os.getenv("AGENT_MAX_STEPS", "6")),
    )
