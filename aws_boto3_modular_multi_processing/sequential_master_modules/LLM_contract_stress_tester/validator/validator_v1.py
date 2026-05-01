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

# Very light heuristic: if it ends with a period and has multiple spaces, likely a sentence.
def _looks_like_english_sentence(s: str) -> bool:
    if not isinstance(s, str):
        return False
    stripped = s.strip()
    if not stripped:
        return False
    # obvious sentence markers
    if stripped.endswith(".") and " " in stripped:
        return True
    # starts with a capital letter and contains spaces and no obvious shell tokens
    if re.match(r"^[A-Z][a-z]+", stripped) and " " in stripped:
        if not any(tok in stripped for tok in ["&&", "|", ";", "sudo", "apt", "yum", "dnf", "rpm", "systemctl", "bash", "pwsh", "Get-"]):
            return True
    return False


def _parse_raw_response(raw: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Try to parse the raw LLM response as JSON.
    Returns (parsed_dict_or_None, errors).
    """
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


def _check_placeholders(cmd: str) -> Optional[str]:
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, cmd):
            return f"Command contains placeholder pattern '{pat}': {cmd!r}"
    return None


def _check_commentary(cmd: str) -> Optional[str]:
    for pat in COMMENT_PATTERNS:
        # allow '#' only if clearly part of a shell command (very loose)
        if pat in cmd:
            return f"Command appears to contain commentary '{pat}': {cmd!r}"
    return None


def _validate_command_literal(cmd: str, field_name: str) -> List[str]:
    """
    Validate that a given string looks like a literal shell command, not
    an English sentence, placeholder, or commentary.
    """
    errors: List[str] = []
    if not isinstance(cmd, str):
        errors.append(f"{field_name} entry must be a string, got {type(cmd).__name__}")
        return errors

    stripped = cmd.strip()
    if not stripped:
        errors.append(f"{field_name} entry must not be empty")
        return errors

    # No placeholders like <pkg>, <command>, etc.
    ph_err = _check_placeholders(stripped)
    if ph_err:
        errors.append(f"{field_name} entry invalid: {ph_err}")

    # No commentary markers
    cm_err = _check_commentary(stripped)
    if cm_err:
        errors.append(f"{field_name} entry invalid: {cm_err}")

    # No English sentences
    if _looks_like_english_sentence(stripped):
        errors.append(f"{field_name} entry appears to be an English sentence, not a shell command: {stripped!r}")

    return errors


def _validate_cleanup_field(resp: Dict[str, Any]) -> List[str]:
    """
    Validate the 'cleanup' field according to global contract rules.
    - MUST be a list
    - MAY be empty
    - If non-empty, all entries must be literal shell commands
    """
    errors: List[str] = []

    cleanup = resp.get("cleanup", [])
    if not isinstance(cleanup, list):
        errors.append("'cleanup' must be a list of literal shell commands")
        return errors

    for cmd in cleanup:
        errors.extend(_validate_command_literal(cmd, "cleanup"))

    return errors


def _validate_retry_field_for_cleanup_and_retry(resp: Dict[str, Any]) -> List[str]:
    """
    For action == cleanup_and_retry:
    - retry MUST be a non-empty string OR a non-empty list of strings
    """
    errors: List[str] = []
    retry = resp.get("retry")

    if isinstance(retry, str):
        if not retry.strip():
            errors.append("'retry' string must not be empty for 'cleanup_and_retry'")
        else:
            errors.extend(_validate_command_literal(retry, "retry"))
    elif isinstance(retry, list):
        if len(retry) == 0:
            errors.append("'retry' list must not be empty for 'cleanup_and_retry'")
        else:
            for cmd in retry:
                errors.extend(_validate_command_literal(cmd, "retry"))
    else:
        errors.append(
            "'cleanup_and_retry' requires 'retry' to be a non-empty string "
            "or a non-empty list of literal shell commands"
        )

    return errors


def _validate_retry_field_for_retry_with_modified(resp: Dict[str, Any]) -> List[str]:
    """
    For action == retry_with_modified_command:
    - retry MUST be exactly one corrected command (a single string)
    """
    errors: List[str] = []
    retry = resp.get("retry")

    if not isinstance(retry, str):
        errors.append("'retry_with_modified_command' requires 'retry' to be a single string")
        return errors

    if not retry.strip():
        errors.append("'retry' string must not be empty for 'retry_with_modified_command'")
        return errors

    errors.extend(_validate_command_literal(retry, "retry"))
    return errors


def _check_action_and_shape(resp: Dict[str, Any]) -> List[str]:
    """
    Validate the 'action' field and its basic structure + contract rules.
    """
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

    # Global cleanup validation (type + literal commands)
    errors.extend(_validate_cleanup_field(resp))

    # Action-specific rules
    if action == "cleanup_and_retry":
        errors.extend(_validate_retry_field_for_cleanup_and_retry(resp))

        # message is optional here; no extra checks for v1

    elif action == "retry_with_modified_command":
        errors.extend(_validate_retry_field_for_retry_with_modified(resp))

    elif action == "fallback":
        # Fallback must be bare: no cleanup, no retry
        if "cleanup" in resp and resp.get("cleanup"):
            errors.append("'fallback' action must not include 'cleanup'")
        if "retry" in resp and resp.get("retry"):
            errors.append("'fallback' action must not include 'retry'")

    elif action == "abort":
        # Abort must NOT include cleanup or retry
        if "cleanup" in resp and resp.get("cleanup"):
            errors.append("'abort' action must not include 'cleanup'")
        if "retry" in resp and resp.get("retry"):
            errors.append("'abort' action must not include 'retry'")

        # Abort MUST include message
        msg = resp.get("message")
        if not isinstance(msg, str) or not msg.strip():
            errors.append("'abort' action requires a non-empty 'message' field")

    return errors


def _check_optional_error_field(resp: Dict[str, Any]) -> List[str]:
    """
    If an 'error' field is present, ensure it's a string.
    """
    errors: List[str] = []
    if "error" in resp and not isinstance(resp["error"], str):
        errors.append(f"'error' field must be a string if present, got {type(resp['error']).__name__}")
    return errors


def validate_response(
    schema: Dict[str, Any],
    context: Dict[str, Any],
    raw_response: str,
) -> Dict[str, Any]:
    """
    High-level validator entry point.

    Validator v1 responsibilities:
      - JSON shape checks
      - 'action' field checks
      - global contract rules for cleanup/retry/message
      - literal-command checks (no placeholders, no commentary, no English sentences)
      - basic abort/fallback semantics

    It does NOT yet enforce deep OS-specific semantics.
    That will be layered on later using the domain-primitive logic.

    Returns a dict:
      {
        "status": "PASS" | "FAIL",
        "errors": [...],
        "parsed": <dict or None>,
        "os_name": <str or None>,
        "os_version": <str or None>,
        "command": <original command string>,
      }
    """
    os_name = schema.get("os_name")
    os_version = schema.get("os_version")
    command = context.get("command")

    parsed, parse_errors = _parse_raw_response(raw_response)
    if parsed is None:
        # Hard fail: we couldn't even parse the response
        return {
            "status": "FAIL",
            "errors": parse_errors,
            "parsed": None,
            "os_name": os_name,
            "os_version": os_version,
            "command": command,
        }

    errors: List[str] = []
    errors.extend(_check_action_and_shape(parsed))
    errors.extend(_check_optional_error_field(parsed))

    status = "PASS" if not errors else "FAIL"

    return {
        "status": status,
        "errors": errors,
        "parsed": parsed,
        "os_name": os_name,
        "os_version": os_version,
        "command": command,
    }

