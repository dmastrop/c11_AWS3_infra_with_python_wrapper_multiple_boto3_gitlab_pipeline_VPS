from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
    stderr_contains,
)


def validate_windows_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Windows PowerShell semantic checks derived from:

      - Windows PowerShell domain primitives (Revision 17)
      - Revision 6.12 malformed-command hardening
      - Global destructive-command rules
      - Global fallback semantics

    Applies ONLY when:
        os_name == "Windows" AND os_version == "2022"
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
    # 1) Destructive PowerShell commands → abort
    # ------------------------------------------------------------
    destructive_patterns = [
        "Remove-Item -Recurse -Force C:\\Windows",
        "Remove-Item -Recurse -Force C:\\Windows\\System32",
        "Remove-Item -Recurse -Force C:\\Program Files",
        "Remove-Item -Recurse -Force C:\\Users",
        "Remove-Item -Recurse -Force HKLM:\\SYSTEM",
        "Remove-Item -Recurse -Force HKLM:\\SOFTWARE",
        "Stop-Process -Force -Name wininit",
        "Stop-Process -Force -Name lsass",
    ]
    if any(p in command for p in destructive_patterns):
        if action != "abort":
            errors.append("Destructive commands on Windows MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) Linux/macOS package managers or POSIX tools → fallback
    # ------------------------------------------------------------
    if cmd_uses_wrong_package_manager(command, os_name):
        if action != "fallback":
            errors.append(
                "Windows PowerShell MUST use 'fallback' for Linux/macOS package managers."
            )

    posix_only_tools = [
        "/usr/bin", "/etc", "/var/log", "apk ", "yum ", "dnf ", "apt ", "apt-get ",
        "pacman ", "brew "
    ]
    if any(tok in command for tok in posix_only_tools):
        if action != "fallback":
            errors.append(
                "Windows PowerShell MUST use 'fallback' for POSIX-only paths or tools."
            )

    # ------------------------------------------------------------
    # 3) Unknown command → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        if action != "fallback":
            errors.append("Unknown commands on Windows MUST use 'fallback'.")

    # PowerShell-specific "term not recognized"
    if "is not recognized as the name of a cmdlet" in stderr:
        if action != "fallback":
            errors.append("Unrecognized PowerShell cmdlet MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 4) Malformed pipelines/subexpressions/script blocks → fallback
    # ------------------------------------------------------------
    if "|" in command or "$(" in command or "{" in command or "}" in command:
        if (
            "Unexpected token" in stderr
            or "Missing argument" in stderr
            or "Unexpected end of input" in stderr
            or "The string is missing the terminator" in stderr
        ):
            if action != "fallback":
                errors.append("Malformed PowerShell pipeline/subexpression MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 5) Network failures → fallback
    # ------------------------------------------------------------
    network_signatures = [
        "The remote name could not be resolved",
        "Unable to connect to the remote server",
        "No such host is known",
    ]
    if any(sig in stderr for sig in network_signatures):
        if action != "fallback":
            errors.append("Network failures on Windows MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 6) Idempotency → fallback
    # ------------------------------------------------------------
    idempotent_signatures = [
        "The process is already running",
        "The service is already running",
        "Cannot create a file when that file already exists",
        "A positional parameter cannot be found that accepts argument",
    ]
    if any(sig in stderr for sig in idempotent_signatures):
        if action != "fallback":
            errors.append("Idempotent Windows operations MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 7) cleanup_and_retry (rare, only when stderr gives explicit remediation)
    # ------------------------------------------------------------
    if action == "cleanup_and_retry":
        # Must NOT invent multi-step cleanup
        if not isinstance(cleanup, list):
            errors.append("Windows cleanup_and_retry requires 'cleanup' to be a list.")

        # Retry must contain a deterministic suggestion from stderr
        if not retry_list:
            errors.append("Windows cleanup_and_retry requires a deterministic retry command.")

        # No invented package managers or modules
        for r in retry_list:
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append("Windows cleanup_and_retry MUST NOT introduce package managers.")

    # ------------------------------------------------------------
    # 8) retry_with_modified_command (VERY narrow)
    # ------------------------------------------------------------
    if action == "retry_with_modified_command":
        if not isinstance(retry, str):
            errors.append(
                "Windows retry_with_modified_command MUST use a single string retry command."
            )
        else:
            # MUST NOT introduce new tools or package managers
            if cmd_uses_wrong_package_manager(retry, os_name):
                errors.append(
                    "Windows retry_with_modified_command MUST NOT introduce Linux/macOS package managers."
                )

            # Allowed only for clear near-miss cmdlets
            # Example: Get-Servce → Get-Service
            if "Get-Servce" in command and "Get-Service" not in retry:
                errors.append(
                    "Windows retry_with_modified_command MUST correct clear cmdlet typos deterministically."
                )

    # ------------------------------------------------------------
    # 9) No sudo allowed
    # ------------------------------------------------------------
    if "sudo " in command:
        if action != "fallback":
            errors.append("Windows MUST NOT introduce 'sudo'. Use 'fallback' for permission issues.")

    for r in retry_list:
        if "sudo " in r:
            errors.append("Windows MUST NOT use 'sudo' in retry.")

    return errors

