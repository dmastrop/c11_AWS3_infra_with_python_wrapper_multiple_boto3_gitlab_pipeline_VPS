from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    stderr_contains,
    looks_like_network_failure,
)


def validate_ubuntu_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Ubuntu-specific semantic checks derived from the Ubuntu domain primitives
    and global Linux rules. Intentionally conservative to avoid breaking
    existing validated cases.
    """
    errors: List[str] = []

    command = context.get("command") or ""
    stderr = context.get("stderr") or ""
    exit_status = context.get("exit_status")

    action = resp.get("action")
    cleanup = resp.get("cleanup", [])
    retry = resp.get("retry")

    # 1) Wrong package manager in retry on Ubuntu
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

    # 2) Malformed pipelines/subshells → fallback
    if "|" in command or "$(" in command or ")" in command:
        if "syntax error" in stderr or "unexpected token" in stderr or "unexpected EOF" in stderr:
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on Ubuntu must result in 'fallback'.")

    # 3) Network failures MUST use fallback
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Ubuntu must use 'fallback' action.")

    # 4) Hash Sum mismatch MUST use cleanup_and_retry with exact cleanup + apt-get update -y
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

        def _retry_contains(cmd_sub: str) -> bool:
            if isinstance(retry, str):
                return cmd_sub in retry
            if isinstance(retry, list):
                return any(isinstance(c, str) and cmd_sub in c for c in retry)
            return False

        if not _retry_contains("apt-get update -y"):
            errors.append("Hash Sum mismatch retry must include 'apt-get update -y' on Ubuntu.")

    # 5) dpkg --configure -a suggestion
    if "dpkg --configure -a" in stderr:
        if action != "cleanup_and_retry":
            errors.append("When stderr suggests 'dpkg --configure -a', Ubuntu must use 'cleanup_and_retry'.")

        def _retry_has(cmd_sub: str) -> bool:
            if isinstance(retry, str):
                return cmd_sub in retry
            if isinstance(retry, list):
                return any(isinstance(c, str) and cmd_sub in c for c in retry)
            return False

        if not _retry_has("dpkg --configure -a"):
            errors.append("dpkg interruption on Ubuntu requires 'dpkg --configure -a' in retry sequence.")

    # 6) held broken packages → MUST NOT run apt --fix-broken install
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

    # 7) apt --fix-broken install suggested (without 'held broken packages')
    if "apt --fix-broken install" in stderr and "held broken packages" not in stderr:
        if action != "cleanup_and_retry":
            errors.append(
                "When stderr suggests 'apt --fix-broken install', Ubuntu must use 'cleanup_and_retry'."
            )

    # 8) Unrecognized command (exit_status 127) + show
    if exit_status == 127:
        if command.strip().startswith("show "):
            if action != "fallback":
                errors.append(
                    "Linux-family OSes must use 'fallback' for Cisco-style 'show' commands."
                )

    return errors

