from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
    stderr_contains,
)


def validate_macos_zsh_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    macOS-zsh semantic checks derived from:

      - macOS-zsh domain primitives (Revision 6.11)
      - Bash/ZSH malformed-command hardening
      - Global destructive-command rules
      - Global fallback semantics

    Applies ONLY when:
        os_name == "macOS" AND os_version endswith "-zsh"
    """

    errors: List[str] = []

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
    # 1) Destructive commands → abort
    # ------------------------------------------------------------
    destructive_patterns = [
        "rm -rf /",
        "rm -rf /System",
        "rm -rf /usr",
        "rm -rf /Applications",
        "rm -rf /Library",
        "rm -rf /Users",
    ]
    if any(p in command for p in destructive_patterns):
        if action != "abort":
            errors.append("Destructive commands on macOS-zsh MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) ANY package manager usage → fallback
    #
    # macOS-zsh has NO package manager.
    # ALL package-manager commands MUST result in fallback.
    # ------------------------------------------------------------
    if cmd_uses_wrong_package_manager(command) or command.startswith("brew"):
        if action != "fallback":
            errors.append(
                "macOS-zsh: ALL package-manager commands (apt/yum/dnf/apk/pacman/brew) MUST use 'fallback'."
            )

    for r in retry_list:
        if cmd_uses_wrong_package_manager(r) or (isinstance(r, str) and r.startswith("brew")):
            errors.append(
                "macOS-zsh retry MUST NOT reference any package manager (apt/yum/dnf/apk/pacman/brew)."
            )

    # ------------------------------------------------------------
    # 3) Malformed pipelines/subshells → fallback
    # ------------------------------------------------------------
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "parse error" in stderr
            or "unexpected end of file" in stderr
            or "unmatched quote" in stderr
            or "unexpected token" in stderr
        ):
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on macOS-zsh MUST result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures → fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on macOS-zsh MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 5) Unknown commands (exit_status 127) → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        if action != "fallback":
            errors.append("Unknown commands on macOS-zsh MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 6) zsh-specific syntax errors → fallback
    # ------------------------------------------------------------
    zsh_error_signatures = [
        "zsh: command not found",
        "parse error near",
        "unexpected end of file",
        "unmatched quote",
    ]
    if any(sig in stderr for sig in zsh_error_signatures):
        if action != "fallback":
            errors.append("zsh syntax errors MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 7) Linux-only commands → fallback
    # ------------------------------------------------------------
    linux_only_cmds = ["apk ", "yum ", "dnf ", "apt ", "apt-get ", "pacman "]
    if any(command.startswith(c) for c in linux_only_cmds):
        if action != "fallback":
            errors.append("Linux-only commands on macOS-zsh MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 8) No sudo allowed in correction/cleanup/retry
    # ------------------------------------------------------------
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if "sudo " in command and action != "fallback":
        errors.append(
            "macOS-zsh MUST NOT introduce 'sudo'. Use 'fallback' for permission issues."
        )

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("macOS-zsh MUST NOT use 'sudo' in cleanup or retry.")

    # ------------------------------------------------------------
    # 9) cleanup_and_retry MUST NOT be used
    # ------------------------------------------------------------
    if action == "cleanup_and_retry":
        errors.append("macOS-zsh has NO cleanup-and-retry semantics. MUST NOT use 'cleanup_and_retry'.")

    # ------------------------------------------------------------
    # 10) retry_with_modified_command is extremely rare
    #
    # Allowed ONLY when:
    #   - correction is directly implied
    #   - correction is a built-in macOS utility
    #   - MUST NOT introduce brew or any package manager
    # ------------------------------------------------------------
    if action == "retry_with_modified_command":
        if not isinstance(retry, str):
            errors.append(
                "macOS-zsh retry_with_modified_command MUST use a single string retry command."
            )
        else:
            # MUST NOT introduce package managers
            if cmd_uses_wrong_package_manager(retry) or retry.startswith("brew"):
                errors.append(
                    "macOS-zsh retry_with_modified_command MUST NOT introduce package managers."
                )

    return errors

