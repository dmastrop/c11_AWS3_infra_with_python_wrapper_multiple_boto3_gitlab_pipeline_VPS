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



    # ------------------------------------------------------------
    # OS-specific semantic checks
    # ------------------------------------------------------------
    if os_name == "Ubuntu":
        errors.extend(validate_ubuntu_semantics(context, parsed))

    elif os_name == "Debian":
        from .debian_semantics import validate_debian_semantics
        errors.extend(validate_debian_semantics(context, parsed))

    elif os_name == "RHEL":
        from .rhel_semantics import validate_rhel_semantics
        errors.extend(validate_rhel_semantics(context, parsed))

     ------------------------------------------------------------
     Placeholders for remaining OS/platform validators
     ------------------------------------------------------------

     elif os_name == "CentOS" and os_version.startswith("7"):
         from .centos7_semantics import validate_centos7_semantics
         errors.extend(validate_centos7_semantics(context, parsed))

     elif os_name == "CentOS" and os_version.startswith("8"):
         from .centos8_semantics import validate_centos8_semantics
         errors.extend(validate_centos8_semantics(context, parsed))

     elif os_name == "Amazon Linux": 
         from .amazonlinux2_semantics import validate_amazonlinux2_semantics
         errors.extend(validate_amazonlinux2_semantics(context, parsed))
    
     elif os_name == "Amazon Linux 2023":
         from .amazonlinux2023_semantics import validate_amazonlinux2023_semantics
         errors.extend(validate_amazonlinux2023_semantics(context, parsed))



     elif os_name == "Fedora":
         from .fedora_semantics import validate_fedora_semantics
         errors.extend(validate_fedora_semantics(context, parsed))

     elif os_name == "Alpine":
         from .alpine_semantics import validate_alpine_semantics
         errors.extend(validate_alpine_semantics(context, parsed))

     elif os_name == "Linux" and os_version == "generic":
         from .linux_generic_semantics import validate_linux_generic_semantics
         errors.extend(validate_linux_generic_semantics(context, parsed))

     elif os_name == "Linux" and os_version == "busybox":
         from .busybox_semantics import validate_busybox_semantics
         errors.extend(validate_busybox_semantics(context, parsed))

     elif os_name == "macOS" and os_version.endswith("-brew"):
         from .macos_brew_semantics import validate_macos_brew_semantics
         errors.extend(validate_macos_brew_semantics(context, parsed))

     elif os_name == "macOS" and os_version.endswith("-zsh"):
         from .macos_zsh_semantics import validate_macos_zsh_semantics
         errors.extend(validate_macos_zsh_semantics(context, parsed))

     elif os_name == "Windows":
         from .windows_semantics import validate_windows_semantics
         errors.extend(validate_windows_semantics(context, parsed))

     elif os_name == "Linux" and os_version == "powershell-core":
         from .pwsh_linux_semantics import validate_pwsh_linux_semantics
         errors.extend(validate_pwsh_linux_semantics(context, parsed))

     elif os_name == "Cisco IOS":
         from .cisco_ios_semantics import validate_cisco_ios_semantics
         errors.extend(validate_cisco_ios_semantics(context, parsed))

     elif os_name == "PAN-OS":
         from .panos_semantics import validate_panos_semantics
         errors.extend(validate_panos_semantics(context, parsed))





    status = "PASS" if not errors else "FAIL"

    return {
        "status": status,
        "errors": errors,
        "parsed": parsed,
        "os_name": os_name,
        "os_version": os_version,
        "command": command,
    }

