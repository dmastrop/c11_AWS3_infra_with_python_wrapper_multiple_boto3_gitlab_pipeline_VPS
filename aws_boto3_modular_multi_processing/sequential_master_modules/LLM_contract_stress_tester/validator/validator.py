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



# ---------------------------------------------------------------------------
# Ubuntu-specific semantic validation (v2)
# ---------------------------------------------------------------------------

_UBUNTU_WRONG_PM = ("yum", "dnf", "apk", "zypper", "pacman", "brew")


def _cmd_uses_wrong_package_manager(cmd: str) -> bool:
    s = cmd.strip()
    return any(pm in s.split() for pm in _UBUNTU_WRONG_PM)


def _cmd_uses_apt_family(cmd: str) -> bool:
    s = cmd.strip()
    return s.startswith("apt ") or s.startswith("apt-get ")


def _extract_pkg_from_command(cmd: str) -> Optional[str]:
    """
    Very simple heuristic: for 'apt-get install -y <pkg>' or 'apt-get install <pkg>'
    return <pkg>. Used only for Ubuntu-specific rules where we already know the pattern.
    """
    tokens = cmd.strip().split()
    if len(tokens) < 3:
        return None
    # look for 'install' and take the last token as pkg if it doesn't start with '-'
    if "install" in tokens:
        idx = tokens.index("install")
        if idx + 1 < len(tokens):
            candidate = tokens[-1]
            if not candidate.startswith("-"):
                return candidate
    return None


def _stderr_contains(stderr: str, phrase: str) -> bool:
    return phrase in stderr


def _looks_like_network_failure(stderr: str) -> bool:
    s = stderr.lower()
    patterns = [
        "temporary failure resolving",
        "connection refused",
        "connection timed out",
        "no route to host",
        "host unreachable",
        "network unreachable",
        "tls handshake",
        "ssl handshake",
        "proxy error",
        "proxy connection failed",
    ]
    return any(p in s for p in patterns)


def _validate_ubuntu_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Ubuntu-specific semantic checks derived from the Ubuntu domain primitives
    and global Linux rules. This is intentionally focused and conservative so
    it does not break existing validated cases.
    """
    errors: List[str] = []

    command = context.get("command") or ""
    stderr = context.get("stderr") or ""
    exit_status = context.get("exit_status")

    action = resp.get("action")
    cleanup = resp.get("cleanup", [])
    retry = resp.get("retry")

    # 1) Wrong package manager in retry on Ubuntu
    #    Ubuntu uses apt/apt-get; retry MUST NOT use yum/dnf/apk/etc.
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if _cmd_uses_wrong_package_manager(r):
                errors.append("On Ubuntu, retry must not use non-Ubuntu package managers (yum/dnf/apk/etc.).")
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and _cmd_uses_wrong_package_manager(cmd):
                    errors.append("On Ubuntu, retry must not use non-Ubuntu package managers (yum/dnf/apk/etc.).")

    _check_retry_wrong_pm(retry)

    # 2) Malformed pipelines/subshells → fallback (unless destructive, which v1 already handles via abort)
    if "|" in command or "$(" in command or ")" in command:
        if "syntax error" in stderr or "unexpected token" in stderr or "unexpected EOF" in stderr:
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on Ubuntu must result in 'fallback'.")

    # 3) Network failures MUST use fallback
    if _looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Ubuntu must use 'fallback' action.")

    # 4) Hash Sum mismatch MUST use cleanup_and_retry with exact cleanup + apt-get update -y
    if _stderr_contains(stderr, "Hash Sum mismatch"):
        if action != "cleanup_and_retry":
            errors.append("Hash Sum mismatch on Ubuntu must use 'cleanup_and_retry', not other actions.")
        # cleanup must contain the two exact commands
        expected_cleanup = {
            "rm -rf /var/lib/apt/lists/partial/*",
            "rm -rf /var/cache/apt/archives/partial/*",
        }
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if not expected_cleanup.issubset(cleanup_set):
                errors.append("Hash Sum mismatch cleanup must include the exact Ubuntu cleanup commands.")
        else:
            errors.append("Hash Sum mismatch requires 'cleanup' to be a list.")

        # retry must include apt-get update -y, and if a package is present in the failing command,
        # also apt-get install -y <pkg>. We keep this conservative: require at least apt-get update -y.
        def _retry_contains(cmd_sub: str) -> bool:
            if isinstance(retry, str):
                return cmd_sub in retry
            if isinstance(retry, list):
                return any(isinstance(c, str) and cmd_sub in c for c in retry)
            return False

        if not _retry_contains("apt-get update -y"):
            errors.append("Hash Sum mismatch retry must include 'apt-get update -y' on Ubuntu.")

    # 5) dpkg --configure -a suggestion → cleanup_and_retry with dpkg --configure -a then apt-get install -y <pkg>
    if "dpkg --configure -a" in stderr:
        if action != "cleanup_and_retry":
            errors.append("When stderr suggests 'dpkg --configure -a', Ubuntu must use 'cleanup_and_retry'.")
        # retry must include dpkg --configure -a
        def _retry_has(cmd_sub: str) -> bool:
            if isinstance(retry, str):
                return cmd_sub in retry
            if isinstance(retry, list):
                return any(isinstance(c, str) and cmd_sub in c for c in retry)
            return False

        if not _retry_has("dpkg --configure -a"):
            errors.append("dpkg interruption on Ubuntu requires 'dpkg --configure -a' in retry sequence.")

    # 6) held broken packages → MUST NOT run apt --fix-broken install; prefer fallback
    if "held broken packages" in stderr:
        if isinstance(retry, str) and "apt --fix-broken install" in retry:
            errors.append("When 'held broken packages' appears, Ubuntu must NOT run 'apt --fix-broken install'.")
        if isinstance(retry, list):
            for cmd in retry:
                if isinstance(cmd, str) and "apt --fix-broken install" in cmd:
                    errors.append("When 'held broken packages' appears, Ubuntu must NOT run 'apt --fix-broken install'.")

    # 7) apt --fix-broken install suggested → cleanup_and_retry with apt --fix-broken install -y then apt-get install -y <pkg>
    if "apt --fix-broken install" in stderr and "held broken packages" not in stderr:
        if action != "cleanup_and_retry":
            errors.append("When stderr suggests 'apt --fix-broken install', Ubuntu must use 'cleanup_and_retry'.")

    # 8) Unrecognized command (exit_status 127) → fallback allowed (we only fail if action is clearly unsafe)
    if exit_status == 127:
        # If it's some Linux 'show' style command, must be fallback
        if command.strip().startswith("show "):
            if action != "fallback":
                errors.append("Linux-family OSes must use 'fallback' for Cisco-style 'show' commands.")

    # 9) Ubuntu uses apt/apt-get as package managers; if retry uses none of them AND original command was a package install,
    #    that's suspicious. We keep this conservative and only flag if retry uses a known wrong PM (handled above).
    #    So no extra error here for now.

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
    os_name = schema.get("os_name")  # The schema is passed into validator.py from stress_tester.py (loaders.py gets schema).
    #### The schema has the full schema including the os metadata at the top which has os_name and os_version.
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

    # OS-specific semantic checks (starting with Ubuntu)
    if os_name == "Ubuntu":
        errors.extend(_validate_ubuntu_semantics(context, parsed))




    status = "PASS" if not errors else "FAIL"

    return {
        "status": status,
        "errors": errors,
        "parsed": parsed,
        "os_name": os_name,
        "os_version": os_version,
        "command": command,
    }

