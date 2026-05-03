from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    cmd_uses_apt_family,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_ubuntu_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Ubuntu-specific semantic checks derived from the Ubuntu domain primitives
    and global Linux rules. Intentionally conservative so it does not break
    existing validated cases, but enforces the key Ubuntu APT behaviors that
    are already satisfied by the current LLM responses.
    """
    errors: List[str] = []

    command = (context.get("command") or "").strip()
    stderr = context.get("stderr") or ""
    exit_status = context.get("exit_status")

    action = resp.get("action")
    cleanup = resp.get("cleanup", [])
    retry = resp.get("retry")

    # ------------------------------------------------------------------
    # Helper: normalize retry into a list of strings for membership checks
    # ------------------------------------------------------------------
    def _retry_as_list(r: Any) -> List[str]:
        if isinstance(r, str):
            return [r]
        if isinstance(r, list):
            return [c for c in r if isinstance(c, str)]
        return []

    retry_list = _retry_as_list(retry)

    # ------------------------------------------------------------------
    # 1) Wrong package manager in RETRY on Ubuntu
    #    Ubuntu uses apt/apt-get; retry MUST NOT use yum/dnf/apk/etc.
    # ------------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r):
                errors.append(
                    "On Ubuntu, retry must not use non-Ubuntu package managers (yum/dnf/apk/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd):
                    errors.append(
                        "On Ubuntu, retry must not use non-Ubuntu package managers (yum/dnf/apk/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    #
    #    - If the original command uses yum/dnf/apk with a clear package,
    #      the LLM MUST use retry_with_modified_command and rewrite to:
    #          apt-get install -y <pkg>
    #
    #    This matches your current LLM behavior for:
    #      - yum install nginx
    #      - dnf install nginx
    #      - apk add curl
    # ------------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Ubuntu, when the original command uses a non-Ubuntu package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            # retry must be a single string containing the apt-get install -y <pkg> form
            if not isinstance(retry, str):
                errors.append(
                    "For Ubuntu wrong-package-manager rewrites, 'retry_with_modified_command' "
                    "must use a single string command."
                )
            else:
                expected_sub = f"apt-get install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Ubuntu wrong-package-manager rewrite must use '{expected_sub}' "
                        "in the retry command."
                    )

    # ------------------------------------------------------------------
    # 3) Malformed pipelines/subshells → fallback
    #
    #    - If command contains '|' or '$(' or ')' AND stderr shows syntax error,
    #      the LLM MUST return 'fallback'.
    # ------------------------------------------------------------------
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "unexpected token" in stderr
            or "unexpected EOF" in stderr
        ):
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on Ubuntu must result in 'fallback'.")

    # ------------------------------------------------------------------
    # 4) Network failures MUST use fallback (global network semantics)
    # ------------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Ubuntu must use 'fallback' action.")

    # ------------------------------------------------------------------
    # 5) Hash Sum mismatch MUST use cleanup_and_retry with exact cleanup
    #    + apt-get update -y in retry
    # ------------------------------------------------------------------
    if stderr_contains(stderr, "Hash Sum mismatch"):
        if action != "cleanup_and_retry":
            errors.append("Hash Sum mismatch on Ubuntu must use 'cleanup_and_retry', not other actions.")

        expected_cleanup = {
            "rm -rf /var/lib/apt/lists/partial/*",
            "rm -rf /var/cache/apt/archives/partial/*",
        }
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if not expected_cleanup.issubset(cleanup_set):
                errors.append(
                    "Hash Sum mismatch cleanup must include the exact Ubuntu cleanup commands."
                )
        else:
            errors.append("Hash Sum mismatch requires 'cleanup' to be a list.")

        if not any("apt-get update -y" in c for c in retry_list):
            errors.append("Hash Sum mismatch retry must include 'apt-get update -y' on Ubuntu.")

    # ------------------------------------------------------------------
    # 6) dpkg --configure -a suggestion → cleanup_and_retry with dpkg step
    # ------------------------------------------------------------------
    if "dpkg --configure -a" in stderr:
        if action != "cleanup_and_retry":
            errors.append("When stderr suggests 'dpkg --configure -a', Ubuntu must use 'cleanup_and_retry'.")

        if not any("dpkg --configure -a" in c for c in retry_list):
            errors.append("dpkg interruption on Ubuntu requires 'dpkg --configure -a' in retry sequence.")

    # ------------------------------------------------------------------
    # 7) held broken packages → MUST NOT run apt --fix-broken install
    # ------------------------------------------------------------------
    if "held broken packages" in stderr:
        if isinstance(retry, str) and "apt --fix-broken install" in retry:
            errors.append(
                "When 'held broken packages' appears, Ubuntu must NOT run 'apt --fix-broken install'."
            )
        if isinstance(retry, list):
            for cmd in retry:
                if isinstance(cmd, str) and "apt --fix-broken install" in cmd:
                    errors.append(
                        "When 'held broken packages' appears, Ubuntu must NOT run 'apt --fix-broken install'."
                    )

    # ------------------------------------------------------------------
    # 8) apt --fix-broken install suggested (without 'held broken packages')
    #    → cleanup_and_retry
    # ------------------------------------------------------------------
    if "apt --fix-broken install" in stderr and "held broken packages" not in stderr:
        if action != "cleanup_and_retry":
            errors.append(
                "When stderr suggests 'apt --fix-broken install', Ubuntu must use 'cleanup_and_retry'."
            )

    # ------------------------------------------------------------------
    # 9) Unrecognized command (exit_status 127) + Cisco-style 'show'
    #    → fallback
    # ------------------------------------------------------------------
    if exit_status == 127:
        if command.startswith("show "):
            if action != "fallback":
                errors.append(
                    "Linux-family OSes must use 'fallback' for Cisco-style 'show' commands."
                )

    # ------------------------------------------------------------------
    # 10) Ubuntu APT: "Unable to locate package" → cleanup_and_retry
    #
    #     - If stderr contains "Unable to locate package <pkg>" and we can
    #       extract <pkg> from the failing command, the LLM MUST:
    #         * use 'cleanup_and_retry'
    #         * include 'apt-get update -y' in retry
    #         * include 'apt-get install -y <pkg>' in retry
    #
    #     This matches your current LLM behavior for test index 0.
    # ------------------------------------------------------------------
    if "Unable to locate package" in stderr and pkg_from_cmd:
        if action != "cleanup_and_retry":
            errors.append(
                "On Ubuntu, 'Unable to locate package' must use 'cleanup_and_retry' with "
                "apt-get update -y and apt-get install -y <pkg>."
            )
        else:
            if not any("apt-get update -y" in c for c in retry_list):
                errors.append(
                    "Ubuntu 'Unable to locate package' retry must include 'apt-get update -y'."
                )
            expected_install = f"apt-get install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Ubuntu 'Unable to locate package' retry must include '{expected_install}'."
                )

    return errors

