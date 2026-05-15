from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
)


def validate_cisco_ios_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Cisco IOS semantic checks derived from:

      - Cisco IOS domain primitives (Revision 3 → 3.4)
      - IOS malformed-command rules
      - IOS correction rules
      - IOS privilege-mode rules
      - IOS safe/unsafe command rules
      - IOS fallback rules
      - IOS abort rules

    Applies ONLY when:
        os_name == "Cisco IOS"
    """

    errors: List[str] = []

    os_name = context.get("os_name", "")

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
    # 1) UNSAFE IOS COMMANDS → abort
    # ------------------------------------------------------------
    unsafe_patterns = [
        "reload",
        "write erase",
        "erase startup-config",
        "format flash:",
    ]
    if any(command.startswith(p) for p in unsafe_patterns):
        if action != "abort":
            errors.append("Unsafe Cisco IOS commands MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) Linux/macOS/Windows commands → abort
    # ------------------------------------------------------------
    if cmd_uses_wrong_package_manager(command, os_name):
        if action != "abort":
            errors.append(
                "Cisco IOS does not support Linux/macOS package managers. MUST use 'abort'."
            )
        return errors

    forbidden_shell_tokens = [
        "sudo ", "bash", "sh ", "zsh", "pwsh", "powershell",
        "/usr", "/bin", "/etc", "C:\\", "HKLM:\\"
    ]
    if any(tok in command for tok in forbidden_shell_tokens):
        if action != "abort":
            errors.append(
                "Cisco IOS does not support Linux/macOS/Windows shell commands. MUST use 'abort'."
            )
        return errors

    # ------------------------------------------------------------
    # 3) Privileged-only commands that fail with '% Invalid input'
    #    MUST use cleanup_and_retry with ['enable', original]
    # ------------------------------------------------------------
    privileged_only_cmds = [
        "configure terminal",
        "show running-config",
        "show startup-config",
        "write memory",
        "copy running-config startup-config",
        "copy startup-config running-config",
        "erase startup-config",
        "reload",
    ]

    if "% Invalid input detected at '^' marker." in stderr:
        for p in privileged_only_cmds:
            if command.startswith(p):
                if action != "cleanup_and_retry":
                    errors.append(
                        "Cisco IOS privilege-mode failure MUST use 'cleanup_and_retry'."
                    )
                else:
                    if not isinstance(retry, list):
                        errors.append(
                            "Cisco IOS privilege-mode retry MUST be a list: ['enable', '<cmd>']."
                        )
                    else:
                        expected = ["enable", command]
                        if retry_list != expected:
                            errors.append(
                                "Cisco IOS privilege-mode retry MUST be exactly ['enable', '<original command>']."
                            )
                return errors

    # ------------------------------------------------------------
    # 4) IOS correction rules (single-command corrections)
    # ------------------------------------------------------------
    correction_map = {
        "show run": "show running-config",
        "show ver": "show version",
        "show ip int br": "show ip interface brief",
        "show route everything": "show ip route",
        "show route all": "show ip route",
    }

    for bad, good in correction_map.items():
        if command.strip() == bad:
            if action != "retry_with_modified_command":
                errors.append(
                    f"Cisco IOS correction for '{bad}' MUST use 'retry_with_modified_command'."
                )
            else:
                if not isinstance(retry, str) or retry.strip() != good:
                    errors.append(
                        f"Cisco IOS correction retry MUST be '{good}'."
                    )
            return errors

    # ------------------------------------------------------------
    # 5) Malformed IOS commands with '% Invalid input'
    #    → retry_with_modified_command (same command)
    # ------------------------------------------------------------
    if "% Invalid input detected at '^' marker." in stderr:
        if action != "retry_with_modified_command":
            errors.append(
                "Malformed Cisco IOS commands MUST use 'retry_with_modified_command' unless privilege-mode rules apply."
            )
        else:
            if not isinstance(retry, str) or retry.strip() != command:
                errors.append(
                    "Malformed IOS retry MUST return the SAME command."
                )
        return errors

    # ------------------------------------------------------------
    # 6) Safe IOS commands (show, configure terminal, interface, enable)
    # ------------------------------------------------------------
    safe_prefixes = [
        "show ",
        "configure terminal",
        "interface ",
        "enable",
    ]

    if any(command.startswith(p) for p in safe_prefixes):
        # If safe command failed but no invalid-input marker → fallback
        if action not in ("fallback", "retry_with_modified_command", "cleanup_and_retry"):
            errors.append(
                "Safe Cisco IOS commands MUST use fallback or retry logic, not abort."
            )
        return errors

    # ------------------------------------------------------------
    # 7) Unknown commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        if action != "fallback":
            errors.append("Unknown Cisco IOS commands MUST use 'fallback'.")
        return errors

    # ------------------------------------------------------------
    # 8) Network failures → fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Cisco IOS MUST use 'fallback'.")
        return errors

    # ------------------------------------------------------------
    # 9) Default: fallback for anything not recognized
    # ------------------------------------------------------------
    if action != "fallback":
        errors.append("Unrecognized Cisco IOS commands MUST use 'fallback'.")

    return errors

