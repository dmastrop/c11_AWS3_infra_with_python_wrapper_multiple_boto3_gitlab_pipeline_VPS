from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
    stderr_contains,
)


def validate_pwsh_linux_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    PowerShell Core on Linux semantic checks derived from:

      - Linux PowerShell Core domain primitives (Revision 18)
      - Revision 6.13 malformed-command hardening
      - Global destructive-command rules
      - Global fallback semantics

    Applies ONLY when:
        os_name == "Linux" AND os_version == "powershell-core"
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
    # 1) Destructive commands (Linux paths + rm -rf) → abort
    # ------------------------------------------------------------
    destructive_patterns = [
        "Remove-Item -Recurse -Force /",
        "Remove-Item -Recurse -Force /bin",
        "Remove-Item -Recurse -Force /sbin",
        "Remove-Item -Recurse -Force /usr",
        "Remove-Item -Recurse -Force /etc",
        "Remove-Item -Recurse -Force /var",
        "Remove-Item -Recurse -Force /home",
        "rm -rf /",
        "rm -rf /bin",
        "rm -rf /etc",
    ]
    if any(p in command for p in destructive_patterns):
        if action != "abort":
            errors.append("Destructive commands on PowerShell Core (Linux) MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) Attempts to kill critical Linux processes → abort
    # ------------------------------------------------------------
    critical_process_signatures = [
        "kill 1",
        "kill -9 1",
        "systemctl stop systemd",
        "systemctl stop init",
    ]
    if any(sig in command for sig in critical_process_signatures):
        if action != "abort":
            errors.append("Attempts to kill critical Linux processes MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 3) Package managers are NOT allowed → fallback
    # ------------------------------------------------------------
    if cmd_uses_wrong_package_manager(command, os_name):
        if action != "fallback":
            errors.append(
                "PowerShell Core on Linux has NO package manager semantics. "
                "Any package-manager usage MUST use 'fallback'."
            )

    for r in retry_list:
        if cmd_uses_wrong_package_manager(r, os_name):
            errors.append(
                "PowerShell Core on Linux retry MUST NOT reference any package manager."
            )

    # ------------------------------------------------------------
    # 4) Windows/macOS paths or tools → fallback
    # ------------------------------------------------------------
    windows_signatures = [
        "C:\\Windows",
        "C:\\Program Files",
        "HKLM:\\",
    ]
    if any(sig in command for sig in windows_signatures):
        if action != "fallback":
            errors.append(
                "Windows-only paths or registry hives in PowerShell Core on Linux MUST use 'fallback'."
            )

    macos_paths = [
        "/System",
        "/Applications",
        "/Library",
    ]
    if any(sig in command for sig in macos_paths):
        if action != "fallback":
            errors.append(
                "macOS-specific paths in PowerShell Core on Linux MUST use 'fallback'."
            )

    # BusyBox-specific semantics must not be activated here
    if "busybox" in command.lower():
        if action != "fallback":
            errors.append(
                "BusyBox-specific semantics MUST NOT be used in powershell-core OS block. Use 'fallback'."
            )

    # ------------------------------------------------------------
    # 5) Unknown cmdlet / unrecognized command → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        if action != "fallback":
            errors.append("Unknown commands on PowerShell Core (Linux) MUST use 'fallback'.")

    if "is not recognized as the name of a cmdlet" in stderr:
        if action != "fallback":
            errors.append("Unrecognized PowerShell Core cmdlet MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 6) Malformed pipelines/subexpressions/script blocks → fallback
    # ------------------------------------------------------------
    if "|" in command or "$(" in command or "{" in command or "}" in command:
        if (
            "Unexpected token" in stderr
            or "Missing argument" in stderr
            or "Unexpected end of input" in stderr
            or "The string is missing the terminator" in stderr
        ):
            if action != "fallback":
                errors.append(
                    "Malformed PowerShell Core pipeline/subexpression on Linux MUST use 'fallback'."
                )

    # ------------------------------------------------------------
    # 7) Network failures → fallback
    # ------------------------------------------------------------
    network_signatures = [
        "The remote name could not be resolved",
        "Unable to connect to the remote server",
        "No such host is known",
    ]
    if any(sig in stderr for sig in network_signatures) or looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on PowerShell Core (Linux) MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 8) cleanup_and_retry (rare, only for explicit safe suggestions)
    # ------------------------------------------------------------
    if action == "cleanup_and_retry":
        if not isinstance(cleanup, list):
            errors.append(
                "PowerShell Core on Linux cleanup_and_retry requires 'cleanup' to be a list."
            )

        if not retry_list:
            errors.append(
                "PowerShell Core on Linux cleanup_and_retry requires a deterministic retry command."
            )

        for r in retry_list:
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "PowerShell Core on Linux cleanup_and_retry MUST NOT introduce package managers."
                )

    # ------------------------------------------------------------
    # 9) retry_with_modified_command (VERY narrow)
    # ------------------------------------------------------------
    if action == "retry_with_modified_command":
        if not isinstance(retry, str):
            errors.append(
                "PowerShell Core on Linux retry_with_modified_command MUST use a single string retry command."
            )
        else:
            if cmd_uses_wrong_package_manager(retry, os_name):
                errors.append(
                    "PowerShell Core on Linux retry_with_modified_command MUST NOT introduce package managers."
                )

            if "Get-Servce" in command and "Get-Service" not in retry:
                errors.append(
                    "PowerShell Core on Linux retry_with_modified_command MUST correct clear cmdlet typos deterministically."
                )

    # ------------------------------------------------------------
    # 10) No sudo allowed in correction/cleanup/retry
    # ------------------------------------------------------------
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if "sudo " in command and action != "fallback":
        errors.append(
            "PowerShell Core on Linux MUST NOT introduce 'sudo'. Use 'fallback' for permission issues."
        )

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("PowerShell Core on Linux MUST NOT use 'sudo' in cleanup or retry.")

    return errors

