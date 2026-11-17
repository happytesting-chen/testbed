"""Shared config — loaded from project .env."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent.parent / '.env')
except ImportError:
    pass

TESTBED_URL      = os.getenv('TESTBED_URL',    'http://127.0.0.1:8000').rstrip('/')
EVALUATOR_URL    = os.getenv('EVALUATOR_URL',  'http://127.0.0.1:8001').rstrip('/')
ANALYST_TOKEN    = os.getenv('ANALYST_TOKEN',  '')
EVALUATOR_TOKEN  = os.getenv('EVALUATOR_TOKEN', '')
LLM_BASE_URL     = os.getenv('LLM_BASE_URL',   '').rstrip('/')
LLM_API_KEY      = os.getenv('LLM_API_KEY',    '')
LLM_API_KEY_HEADER = os.getenv('LLM_API_KEY_HEADER', 'x-api-key')
LLM_MODEL        = os.getenv('LLM_MODEL',      'bedrock.claude-sonnet-4-5')
