from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    stderr_contains,
    looks_like_network_failure,
)


def validate_busybox_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    BusyBox-specific semantic checks derived from the BusyBox domain primitives
    (Revision 14) and BusyBox ash malformed-command hardening (Revision 6.9).

    Applies ONLY when:
        os_name == "Linux" AND os_version == "busybox"

    These rules apply ONLY when BusyBox is the primary OS environment.
    They MUST NOT override Linux-family domain primitives when BusyBox is
    installed as a package or command suite on Ubuntu, Debian, RHEL, CentOS,
    Fedora, Amazon Linux, or Alpine.
    """

    errors: List[str] = []

    os_name = context.get("os_name", "")
    os_version = context.get("os_version", "")

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
    # 1) BusyBox NEVER supports package managers → abort
    # ------------------------------------------------------------
    if cmd_uses_wrong_package_manager(command, os_name):
        if action != "abort":
            errors.append(
                "BusyBox does not support Linux package managers (apt/yum/dnf/apk/brew). "
                "Commands referencing them MUST use 'abort'."
            )

    # Retry must also never use package managers
    for r in retry_list:
        if cmd_uses_wrong_package_manager(r, os_name):
            errors.append(
                "BusyBox retry commands must not reference Linux package managers."
            )

    # ------------------------------------------------------------
    # 2) BusyBox does NOT support dpkg/rpm/apk databases → abort
    # ------------------------------------------------------------
    forbidden_pkg_db_terms = ["dpkg", "rpm", "apk", "apt-get", "yum", "dnf"]
    if any(term in command for term in forbidden_pkg_db_terms):
        if action != "abort":
            errors.append(
                "BusyBox does not support dpkg/rpm/apk or Linux package DBs. "
                "Any reference MUST trigger 'abort'."
            )

    # ------------------------------------------------------------
    # 3) BusyBox ash malformed-command hardening (Rev 6.9)
    # ------------------------------------------------------------
    bash_only_syntax = ["[[", "]]", "{", "}", "<(", ">(", ">( ", "<( "]
    if any(tok in command for tok in bash_only_syntax):
        if action != "fallback":
            errors.append(
                "BusyBox ash does not support bash-only syntax. MUST use 'fallback'."
            )

    # malformed pipelines/subshells
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "unexpected token" in stderr
            or "unexpected EOF" in stderr
        ):
            if action != "fallback":
                errors.append(
                    "Malformed pipeline/subshell in BusyBox ash MUST result in 'fallback'."
                )

    # ------------------------------------------------------------
    # 4) BusyBox does NOT support sudo
    # ------------------------------------------------------------
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if "sudo " in command:
        if action != "fallback":
            errors.append("BusyBox does not support sudo. MUST use 'fallback'.")

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("BusyBox must not use 'sudo' in cleanup or retry.")

    # ------------------------------------------------------------
    # 5) BusyBox destructive commands → abort
    # ------------------------------------------------------------
    destructive_patterns = [
        "rm -rf /",
        "rm -rf /bin",
        "rm -rf /etc",
        "rm -rf /usr",
        "rm -rf /sbin",
    ]
    if any(p in command for p in destructive_patterns):
        if action != "abort":
            errors.append("Destructive commands on BusyBox MUST use 'abort'.")

    # ------------------------------------------------------------
    # 6) BusyBox malformed commands (missing args) → fallback
    # ------------------------------------------------------------
    busybox_applets_requiring_args = ["cp", "mv", "rm", "ln", "mkdir", "touch"]
    for app in busybox_applets_requiring_args:
        if command == app or command.startswith(app + " ") and command.strip() == app:
            if action != "fallback":
                errors.append(
                    f"BusyBox '{app}' with missing arguments MUST use 'fallback'."
                )

    # ------------------------------------------------------------
    # 7) BusyBox unknown commands (exit_status 127) → fallback
    # ------------------------------------------------------------
    if exit_status == 127 and action not in ("fallback", "abort"):
        errors.append(
            "Unknown commands on BusyBox (exit_status 127) must use 'fallback' "
            "(or 'abort' if destructive)."
        )

    # ------------------------------------------------------------
    # 8) BusyBox has NO cleanup_and_retry semantics
    # ------------------------------------------------------------
    if action == "cleanup_and_retry":
        errors.append(
            "BusyBox does not support cleanup_and_retry. No package caches or metadata exist."
        )

    # ------------------------------------------------------------
    # 9) BusyBox retry rules (extremely narrow)
    # ------------------------------------------------------------
    if action == "retry_with_modified_command":
        # Retry must be a single BusyBox-safe command
        if not isinstance(retry, str):
            errors.append(
                "BusyBox retry_with_modified_command MUST use a single string retry command."
            )

        # Retry must NOT introduce package managers or bash syntax
        if cmd_uses_wrong_package_manager(retry, os_name):
            errors.append("BusyBox retry must not reference Linux package managers.")

        if any(tok in retry for tok in bash_only_syntax):
            errors.append("BusyBox retry must not use bash-only syntax.")

    # ------------------------------------------------------------
    # 10) BusyBox rewrite rules
    # ------------------------------------------------------------
    linux_specific_paths = ["/usr/bin/apt", "/usr/bin/yum", "/usr/bin/dnf"]
    if any(p in command for p in linux_specific_paths):
        if action != "fallback":
            errors.append(
                "BusyBox does not support Linux-specific paths. MUST use 'fallback'."
            )

    # ------------------------------------------------------------
    # 11) BusyBox idempotency rules
    # ------------------------------------------------------------
    idempotency_indicators = ["file exists", "directory exists", "not removed"]
    if any(ind in stderr for ind in idempotency_indicators):
        if action != "fallback":
            errors.append(
                "BusyBox idempotency cases MUST use 'fallback' unless a safe cleanup is explicitly implied."
            )

    # ------------------------------------------------------------
    # 12) BusyBox fallback rules (general)
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on BusyBox MUST use 'fallback'.")

    return errors

