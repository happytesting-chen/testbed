"""LLM-based finding extraction. Never raises — returns error string on failure."""
import json

_PROMPT = (
    "Extract all security findings from the VAPT report below.\n"
    "Return a JSON array only, no other text. Each element:\n"
    '{"finding_id": "F-001 or null", "title": "...", '
    '"severity": "Critical|High|Medium|Low|Informational", '
    '"status": "Open|In Progress|Resolved|Accepted Risk", "description": "..."}\n'
    "Return [] if no findings are present.\nReport:\n"
)

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_STATUSES = {"Open", "In Progress", "Resolved", "Accepted Risk"}


MAX_EXTRACT_CHARS = 8000


def extract_findings(provider, content: str) -> dict:
    if provider is None:
        return {"findings": [], "error": None}
    truncated = len(content) > MAX_EXTRACT_CHARS
    try:
        resp = provider.complete(
            [{"role": "user", "content": _PROMPT + content[:MAX_EXTRACT_CHARS]}], [])
        raw = (resp.content or "").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return {"findings": [], "error": "Response was not a JSON array"}
        valid = [
            {"finding_id": item.get("finding_id") or None,
             "title": str(item.get("title", ""))[:500],
             "severity": item["severity"],
             "status": item["status"],
             "description": str(item.get("description", ""))[:2000]}
            for item in parsed
            if isinstance(item, dict)
            and item.get("severity") in VALID_SEVERITIES
            and item.get("status") in VALID_STATUSES
        ]
        return {"findings": valid, "error": None, "truncated": truncated,
                "input_chars": min(len(content), MAX_EXTRACT_CHARS)}
    except Exception as exc:
        return {"findings": [], "error": str(exc)[:200],
                "truncated": truncated,
                "input_chars": min(len(content), MAX_EXTRACT_CHARS)}
