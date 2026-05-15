from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    looks_like_network_failure,
)


def validate_linux_generic_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Linux-generic bash semantic checks derived from:

      - Malformed Linux rules (Revision 2, 6.7)
      - Bash malformed-command hardening (Revision 6.8)

    Applies ONLY when:
        os_name == "Linux" AND os_version == "generic"

    This is a testing construct used for dual-schema validation. It represents
    pure bash malformed-command semantics with NO distro-specific package
    manager behavior and NO cleanup_and_retry semantics.
    """

    errors: List[str] = []

    os_name = context.get("os_name", "")
    os_version = context.get("os_version", "")
    print("DEBUG:", repr(os_name))

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
    # 1) Linux generic: NO package manager semantics
    # ------------------------------------------------------------
    # Any reference to apt/yum/dnf/apk/brew is treated as malformed and MUST NOT
    # trigger distro-specific rewrites. We enforce "fallback" here.
    if cmd_uses_wrong_package_manager(command, os_name):
        if action not in ("fallback", "abort"):
            errors.append(
                "Linux generic (bash) has no package manager semantics. "
                "Malformed commands referencing package managers must use 'fallback' "
                "(or 'abort' if destructive)."
            )

    for r in retry_list:
        if cmd_uses_wrong_package_manager(r, os_name):
            errors.append(
                "Linux generic retry commands must not reference package managers "
                "(apt/yum/dnf/apk/brew/etc.)."
            )

    # ------------------------------------------------------------
    # 2) Revision 6.8: bash malformed-command hardening
    # ------------------------------------------------------------
    # - Prefer fallback for malformed commands unless a safe, deterministic
    #   correction is directly implied.
    # - Never guess or hallucinate corrections.
    # - Never introduce sudo as part of correction.
    # - Never attempt to repair pipelines/subshells.
    bash_only_syntax = ["[[", "]]", "{", "}", "<(", ">(", ">( ", "<( "]

    if any(tok in command for tok in bash_only_syntax):
        if action != "fallback":
            errors.append(
                "Linux generic bash does not allow guessing for malformed bash-only syntax. "
                "MUST use 'fallback'."
            )

    # malformed pipelines/subshells
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "unexpected token" in stderr
            or "unexpected EOF" in stderr
            or "syntax error near unexpected token" in stderr
            or "unexpected EOF while looking for matching" in stderr
        ):
            if action != "fallback":
                errors.append(
                    "Malformed pipeline/subshell on Linux generic MUST result in 'fallback'."
                )

    # ------------------------------------------------------------
    # 3) Malformed Linux rules (Revision 2, 6.7)
    # ------------------------------------------------------------
    # - Incomplete commands → fallback (not abort) unless destructive.
    # - Unknown commands (exit_status 127) → fallback allowed.
    # - 'show' commands are NOT Cisco; must not be corrected using IOS rules.
    if command.startswith("show "):
        if action != "fallback":
            errors.append(
                "Linux generic does not support Cisco-style 'show' commands. "
                "MUST use 'fallback'."
            )

    if exit_status == 127 and action not in ("fallback", "abort"):
        errors.append(
            "Unknown commands on Linux generic (exit_status 127) must use 'fallback' "
            "(or 'abort' if destructive)."
        )

    # ------------------------------------------------------------
    # 4) No sudo allowed in correction/cleanup/retry
    # ------------------------------------------------------------
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if "sudo " in command and action != "fallback":
        errors.append(
            "Linux generic malformed-command handling must not introduce 'sudo'. "
            "Use 'fallback' when permission issues occur without deterministic recovery."
        )

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("Linux generic must not use 'sudo' in cleanup or retry.")

    # ------------------------------------------------------------
    # 5) Destructive commands → abort
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
            errors.append("Destructive commands on Linux generic MUST use 'abort'.")

    # ------------------------------------------------------------
    # 6) No cleanup_and_retry semantics for Linux generic
    # ------------------------------------------------------------
    if action == "cleanup_and_retry":
        errors.append(
            "Linux generic (bash) has no package caches or metadata. "
            "'cleanup_and_retry' MUST NOT be used."
        )

    # ------------------------------------------------------------
    # 7) retry_with_modified_command: extremely narrow
    # ------------------------------------------------------------
    if action == "retry_with_modified_command":
        # Retry must be a single string and must not introduce package managers
        if not isinstance(retry, str):
            errors.append(
                "Linux generic retry_with_modified_command MUST use a single string retry command."
            )
        else:
            if cmd_uses_wrong_package_manager(retry, os_name):
                errors.append(
                    "Linux generic retry must not reference package managers."
                )
            if any(tok in retry for tok in bash_only_syntax):
                errors.append(
                    "Linux generic retry must not use bash-only malformed constructs."
                )

    # ------------------------------------------------------------
    # 8) Network failures → fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Linux generic MUST use 'fallback'.")

    return errors

