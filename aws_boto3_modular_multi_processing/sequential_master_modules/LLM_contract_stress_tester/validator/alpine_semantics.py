from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_alpine_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Alpine-specific semantic checks derived from the Alpine APK domain primitives
    (Revision 13 / 13.1) and global Linux malformed-command rules (Revision 6.8).

    Applies ONLY when os_name == "Alpine".
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
    # 1) Wrong package manager in RETRY on Alpine
    # ------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On Alpine, retry must not use non-APK package managers (apt/yum/dnf/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On Alpine, retry must not use non-APK package managers (apt/yum/dnf/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)


    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
    #if cmd_uses_wrong_package_manager(command) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Alpine, when the original command uses a non-APK package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "Alpine wrong-package-manager rewrites must use a single string retry command."
                )
            else:
                expected_sub = f"apk add {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Alpine wrong-package-manager rewrite must include '{expected_sub}' "
                        "in the retry command."
                    )

        return errors

    # ------------------------------------------------------------
    # 3) Malformed pipelines/subshells → fallback
    # ------------------------------------------------------------
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "unexpected token" in stderr
            or "unexpected EOF" in stderr
        ):
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on Alpine must result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures MUST use fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Alpine must use 'fallback' action.")

    # ------------------------------------------------------------
    # 5) Missing package name → malformed
    # ------------------------------------------------------------
    if "apk add" in command and "unable to select packages" not in stderr:
        # Explicit malformed case: 'apk add' with no package and generic error
        if command.strip() == "apk add" or command.strip().startswith("apk add ") and command.strip() == "apk add":
            if action != "fallback":
                errors.append(
                    "Alpine malformed install (missing package name) must use 'fallback'."
                )

    if "apk add" in command and "Need to pass a list of packages" in stderr:
        if action != "fallback":
            errors.append(
                "Alpine malformed install (missing package name) must use 'fallback'."
            )

    # ------------------------------------------------------------
    # 6) APK cache/index corruption → cleanup_and_retry
    # ------------------------------------------------------------
    cache_corruption_indicators = [
        "failed to update apk cache",
        "ERROR: failed to update apk cache",
        "ERROR: repository",
        "repository ... not found",
    ]

    if any(ind in stderr for ind in cache_corruption_indicators):
        if action != "cleanup_and_retry":
            errors.append("APK cache/index corruption on Alpine must use 'cleanup_and_retry'.")

        # cleanup must include rm -rf /var/cache/apk/*
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -rf /var/cache/apk/*" not in cleanup_set:
                errors.append(
                    "Alpine cache corruption cleanup must include 'rm -rf /var/cache/apk/*'."
                )
        else:
            errors.append("Alpine cache corruption requires 'cleanup' to be a list.")

        # retry must include apk update
        if not any("apk update" in c for c in retry_list):
            errors.append("Alpine cache corruption retry must include 'apk update'.")

        # If a package exists, retry must include apk add <pkg>
        if pkg_from_cmd:
            expected_install = f"apk add {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Alpine cache corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 7) Revision 13.1: unable to select packages + prior apk update → cleanup_and_retry
    # ------------------------------------------------------------
    if "unable to select packages:" in stderr:
        # Contract: if history contains prior 'apk update', must use cleanup_and_retry.
        # The stress tester encodes this by choosing scenarios where this rule should fire;
        # we only enforce the action/shape here.
        if action != "cleanup_and_retry":
            errors.append(
                "On Alpine, 'unable to select packages:' with prior 'apk update' must use 'cleanup_and_retry'."
            )

        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -rf /var/cache/apk/*" not in cleanup_set:
                errors.append(
                    "Alpine 'unable to select packages' cleanup must include 'rm -rf /var/cache/apk/*'."
                )
        else:
            errors.append(
                "Alpine 'unable to select packages' scenario requires 'cleanup' to be a list."
            )

        if not any("apk update" in c for c in retry_list):
            errors.append(
                "Alpine 'unable to select packages' retry must include 'apk update'."
            )

        if pkg_from_cmd:
            expected_install = f"apk add {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Alpine 'unable to select packages' retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 8) Destructive commands → abort (global, but we sanity-check)
    # ------------------------------------------------------------
    if "rm -rf /" in command and action != "abort":
        errors.append("Destructive commands on Alpine must use 'abort'.")

    # ------------------------------------------------------------
    # 9) Unknown commands (exit_status 127) → fallback allowed
    # ------------------------------------------------------------
    if exit_status == 127 and action not in ("fallback", "abort"):
        errors.append(
            "Unknown commands on Alpine (exit_status 127) must use 'fallback' (or 'abort' if destructive)."
        )

    # ------------------------------------------------------------
    # 10) No sudo allowed
    # ------------------------------------------------------------
    # Ensure the model does not emit sudo in cleanup/retry
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("Alpine environments in this contract must not use 'sudo' in cleanup or retry.")

    return errors

