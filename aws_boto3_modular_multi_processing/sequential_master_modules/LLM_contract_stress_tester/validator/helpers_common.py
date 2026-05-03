import json
import re
from typing import Any, Dict, List, Optional, Tuple

ALLOWED_ACTIONS = {
    "abort",
    "fallback",
    "cleanup_and_retry",
    "retry_with_modified_command",
}

PLACEHOLDER_PATTERNS = [
    r"<pkg>",
    r"<package>",
    r"<command>",
    r"<service>",
    r"<path>",
]

COMMENT_PATTERNS = [
    r"#",
    r"//",
]


def looks_like_english_sentence(s: str) -> bool:
    if not isinstance(s, str):
        return False
    stripped = s.strip()
    if not stripped:
        return False
    if stripped.endswith(".") and " " in stripped:
        return True
    if re.match(r"^[A-Z][a-z]+", stripped) and " " in stripped:
        if not any(
            tok in stripped
            for tok in [
                "&&",
                "|",
                ";",
                "sudo",
                "apt",
                "yum",
                "dnf",
                "rpm",
                "systemctl",
                "bash",
                "pwsh",
                "Get-",
            ]
        ):
            return True
    return False


def parse_raw_response(raw: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    raw = (raw or "").strip()
    if not raw:
        return None, ["Empty response from LLM"]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, [f"Response is not valid JSON: {e}"]

    if not isinstance(data, dict):
        return None, ["Top-level JSON must be an object"]
    return data, []


def check_placeholders(cmd: str) -> Optional[str]:
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, cmd):
            return f"Command contains placeholder pattern '{pat}': {cmd!r}"
    return None


def check_commentary(cmd: str) -> Optional[str]:
    for pat in COMMENT_PATTERNS:
        if pat in cmd:
            return f"Command appears to contain commentary '{pat}': {cmd!r}"
    return None


def validate_command_literal(cmd: str, field_name: str) -> List[str]:
    errors: List[str] = []
    if not isinstance(cmd, str):
        errors.append(f"{field_name} entry must be a string, got {type(cmd).__name__}")
        return errors

    stripped = cmd.strip()
    if not stripped:
        errors.append(f"{field_name} entry must not be empty")
        return errors

    ph_err = check_placeholders(stripped)
    if ph_err:
        errors.append(f"{field_name} entry invalid: {ph_err}")

    cm_err = check_commentary(stripped)
    if cm_err:
        errors.append(f"{field_name} entry invalid: {cm_err}")

    if looks_like_english_sentence(stripped):
        errors.append(
            f"{field_name} entry appears to be an English sentence, not a shell command: {stripped!r}"
        )

    return errors


def validate_cleanup_field(resp: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    cleanup = resp.get("cleanup", [])
    if not isinstance(cleanup, list):
        errors.append("'cleanup' must be a list of literal shell commands")
        return errors

    for cmd in cleanup:
        errors.extend(validate_command_literal(cmd, "cleanup"))

    return errors


def validate_retry_field_for_cleanup_and_retry(resp: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    retry = resp.get("retry")

    if isinstance(retry, str):
        if not retry.strip():
            errors.append("'retry' string must not be empty for 'cleanup_and_retry'")
        else:
            errors.extend(validate_command_literal(retry, "retry"))
    elif isinstance(retry, list):
        if len(retry) == 0:
            errors.append("'retry' list must not be empty for 'cleanup_and_retry'")
        else:
            for cmd in retry:
                errors.extend(validate_command_literal(cmd, "retry"))
    else:
        errors.append(
            "'cleanup_and_retry' requires 'retry' to be a non-empty string "
            "or a non-empty list of literal shell commands"
        )

    return errors


def validate_retry_field_for_retry_with_modified(resp: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    retry = resp.get("retry")

    if not isinstance(retry, str):
        errors.append("'retry_with_modified_command' requires 'retry' to be a single string")
        return errors

    if not retry.strip():
        errors.append("'retry' string must not be empty for 'retry_with_modified_command'")
        return errors

    errors.extend(validate_command_literal(retry, "retry"))
    return errors


def check_action_and_shape(resp: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    action = resp.get("action")
    if action is None:
        errors.append("Missing required field: 'action'")
        return errors

    if not isinstance(action, str):
        errors.append(f"'action' must be a string, got {type(action).__name__}")
        return errors

    if action not in ALLOWED_ACTIONS:
        errors.append(f"Unsupported action: {action}")
        return errors

    errors.extend(validate_cleanup_field(resp))

    if action == "cleanup_and_retry":
        errors.extend(validate_retry_field_for_cleanup_and_retry(resp))

    elif action == "retry_with_modified_command":
        errors.extend(validate_retry_field_for_retry_with_modified(resp))

    elif action == "fallback":
        if "cleanup" in resp and resp.get("cleanup"):
            errors.append("'fallback' action must not include 'cleanup'")
        if "retry" in resp and resp.get("retry"):
            errors.append("'fallback' action must not include 'retry'")

    elif action == "abort":
        if "cleanup" in resp and resp.get("cleanup"):
            errors.append("'abort' action must not include 'cleanup'")
        if "retry" in resp and resp.get("retry"):
            errors.append("'abort' action must not include 'retry'")

        msg = resp.get("message")
        if not isinstance(msg, str) or not msg.strip():
            errors.append("'abort' action requires a non-empty 'message' field")

    return errors


def check_optional_error_field(resp: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if "error" in resp and not isinstance(resp["error"], str):
        errors.append(
            f"'error' field must be a string if present, got {type(resp['error']).__name__}"
        )
    return errors

