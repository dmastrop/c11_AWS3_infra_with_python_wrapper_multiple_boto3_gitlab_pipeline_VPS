from typing import Any, Dict, List

from .helpers_common import (
    parse_raw_response,
    check_action_and_shape,
    check_optional_error_field,
)
from .ubuntu_semantics import validate_ubuntu_semantics


def validate_response(
    schema: Dict[str, Any],
    context: Dict[str, Any],
    raw_response: str,
) -> Dict[str, Any]:
    """
    High-level validator entry point.

    Responsibilities:
      - JSON shape checks
      - 'action' field checks
      - global contract rules for cleanup/retry/message
      - literal-command checks (via helpers_common)
      - basic abort/fallback semantics
      - OS-specific semantic checks (Ubuntu for now)

    Returns:
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

    parsed, parse_errors = parse_raw_response(raw_response)
    if parsed is None:
        return {
            "status": "FAIL",
            "errors": parse_errors,
            "parsed": None,
            "os_name": os_name,
            "os_version": os_version,
            "command": command,
        }

    errors: List[str] = []
    errors.extend(check_action_and_shape(parsed))
    errors.extend(check_optional_error_field(parsed))

    # OS-specific semantic checks
    if os_name == "Ubuntu":
        errors.extend(validate_ubuntu_semantics(context, parsed))

    status = "PASS" if not errors else "FAIL"

    return {
        "status": status,
        "errors": errors,
        "parsed": parsed,
        "os_name": os_name,
        "os_version": os_version,
        "command": command,
    }

