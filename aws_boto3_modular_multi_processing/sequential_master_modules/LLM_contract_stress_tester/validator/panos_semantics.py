from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
)


def validate_panos_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    PAN-OS semantic checks derived from:

      - PAN-OS domain primitives (Revision 19)
      - PAN-OS malformed-command rules
      - PAN-OS correction rules
      - PAN-OS mode semantics
      - PAN-OS safe/unsafe command rules
      - PAN-OS fallback rules
      - PAN-OS abort rules

    Applies ONLY when:
        os_name == "PAN-OS"
    """

    errors: List[str] = []

    os_name = context.get("os_name", "")
    #print("DEBUG:", repr(os_name))

    command = (context.get("command") or "").strip()
    stderr = context.get("stderr") or ""
    exit_status = context.get("exit_status")

    action = resp.get("action")
    cleanup = resp.get("cleanup", [])
    retry = resp.get("retry")

    # ------------------------------------------------------------
    # Helper: normalize retry into a list of strings
    # ------------------------------------------------------------
    def _retry_as_list(r: Any) -> List[str]:
        if isinstance(r, str):
            return [r]
        if isinstance(r, list):
            return [c for c in r if isinstance(c, str)]
        return []

    retry_list = _retry_as_list(retry)

    # ------------------------------------------------------------
    # 1) UNSAFE / DESTRUCTIVE PAN-OS COMMANDS → abort
    # ------------------------------------------------------------
    unsafe_patterns = [
        "request system reboot",
        "request system shutdown",
        "delete config saved",
        "delete config version",
        "load config default",
    ]
    if any(command.startswith(p) for p in unsafe_patterns):
        if action != "abort":
            errors.append("Unsafe PAN-OS commands MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) Linux/macOS/Windows/IOS commands → abort
    # ------------------------------------------------------------
    forbidden_shell_tokens = [
        "sudo ", "bash", "sh ", "zsh", "pwsh", "powershell",
        "/usr", "/bin", "/etc", "C:\\", "HKLM:\\", "apt ", "apt-get ",
        "yum ", "dnf ", "apk ", "brew ", "snap "
    ]
    if any(tok in command for tok in forbidden_shell_tokens) or cmd_uses_wrong_package_manager(command, os_name):
        if action != "abort":
            errors.append(
                "PAN-OS does not support Linux/macOS/Windows/IOS commands. MUST use 'abort'."
            )
        return errors

    # ------------------------------------------------------------
    # 3) MODE TRANSITION FAILURES → cleanup_and_retry
    #
    # If a configuration-mode command fails because we are not in config mode,
    # the retry list MUST be: ["configure", "<original command>"]
    # ------------------------------------------------------------
    config_mode_cmds = ["set ", "delete ", "rename ", "commit"]

    mode_failure_signatures = [
        "Invalid syntax",
        "Invalid command",
        "Unknown command",
    ]

    if any(command.startswith(c) for c in config_mode_cmds):
        if any(sig in stderr for sig in mode_failure_signatures):
            # MUST use cleanup_and_retry
            if action != "cleanup_and_retry":
                errors.append(
                    "PAN-OS mode failure MUST use 'cleanup_and_retry' with ['configure', '<cmd>']."
                )
            else:
                if not isinstance(retry, list):
                    errors.append(
                        "PAN-OS mode failure retry MUST be a list: ['configure', '<cmd>']."
                    )
                else:
                    expected = ["configure", command]
                    if retry_list != expected:
                        errors.append(
                            "PAN-OS mode failure retry MUST be exactly ['configure', '<original command>']."
                        )
            return errors

    # ------------------------------------------------------------
    # 4) PAN-OS correction rules (single-command corrections)
    # ------------------------------------------------------------
    correction_map = {
        "show system software stats": "show system software status",
        "show route summary": "show routing summary",
    }

    for bad, good in correction_map.items():
        if command.strip() == bad:
            if action != "retry_with_modified_command":
                errors.append(
                    f"PAN-OS correction for '{bad}' MUST use 'retry_with_modified_command'."
                )
            else:
                if not isinstance(retry, str) or retry.strip() != good:
                    errors.append(
                        f"PAN-OS correction retry MUST be '{good}'."
                    )
            return errors

    # ------------------------------------------------------------
    # 5) Malformed PAN-OS commands → retry_with_modified_command OR fallback
    # ------------------------------------------------------------
    malformed_signatures = [
        "Unknown command",
        "Invalid syntax",
        "Invalid command",
    ]

    if any(sig in stderr for sig in malformed_signatures):
        # If no correction rule applies → fallback
        if action not in ("retry_with_modified_command", "fallback"):
            errors.append(
                "Malformed PAN-OS commands MUST use 'retry_with_modified_command' or 'fallback'."
            )
        return errors

    # ------------------------------------------------------------
    # 6) Safe PAN-OS commands (show, configure, commit)
    # ------------------------------------------------------------
    safe_prefixes = [
        "show ",
        "configure",
        "commit",
    ]

    if any(command.startswith(p) for p in safe_prefixes):
        if action not in ("fallback", "retry_with_modified_command", "cleanup_and_retry"):
            errors.append(
                "Safe PAN-OS commands MUST use fallback or retry logic, not abort."
            )
        return errors

    # ------------------------------------------------------------
    # 7) Unknown commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        if action != "fallback":
            errors.append("Unknown PAN-OS commands MUST use 'fallback'.")
        return errors

    # ------------------------------------------------------------
    # 8) Network failures → fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on PAN-OS MUST use 'fallback'.")
        return errors

    # ------------------------------------------------------------
    # 9) Default: fallback for anything not recognized
    # ------------------------------------------------------------
    if action != "fallback":
        errors.append("Unrecognized PAN-OS commands MUST use 'fallback'.")

    return errors

