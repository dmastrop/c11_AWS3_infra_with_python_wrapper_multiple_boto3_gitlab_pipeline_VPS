from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    cmd_uses_apt_family,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_debian_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Debian-specific semantic checks derived from the Debian APT domain primitives
    and global Linux rules. Closely mirrors Ubuntu semantics, but normalized to
    apt-get and with Debian-specific fix-broken behavior.
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
    # 1) Wrong package manager in RETRY on Debian
    #    Debian uses apt-get; retry MUST NOT use yum/dnf/apk/brew/etc.
    # ------------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On Debian, retry must not use non-Debian package managers (yum/dnf/apk/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On Debian, retry must not use non-Debian package managers (yum/dnf/apk/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    #
    #    - If the original command uses yum/dnf/apk/brew with a clear package,
    #      the LLM MUST use retry_with_modified_command and rewrite to:
    #          apt-get install -y <pkg>
    # ------------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Debian, when the original command uses a non-Debian package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "For Debian wrong-package-manager rewrites, 'retry_with_modified_command' "
                    "must use a single string command."
                )
            else:
                expected_sub = f"apt-get install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Debian wrong-package-manager rewrite must use '{expected_sub}' "
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
                errors.append("Malformed pipeline/subshell on Debian must result in 'fallback'.")

    # ------------------------------------------------------------------
    # 4) Network failures MUST use fallback (global network semantics)
    # ------------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Debian must use 'fallback' action.")

    # ------------------------------------------------------------------
    # 5) Hash Sum mismatch MUST use cleanup_and_retry with exact cleanup
    #    + apt-get update -y in retry, and optional install step depending on <pkg>
    # ------------------------------------------------------------------
    if stderr_contains(stderr, "Hash Sum mismatch"):
        if action != "cleanup_and_retry":
            errors.append("Hash Sum mismatch on Debian must use 'cleanup_and_retry', not other actions.")

        expected_cleanup = {
            "rm -rf /var/lib/apt/lists/partial/*",
            "rm -rf /var/cache/apt/archives/partial/*",
        }
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if not expected_cleanup.issubset(cleanup_set):
                errors.append(
                    "Hash Sum mismatch cleanup must include the exact Debian cleanup commands."
                )
        else:
            errors.append("Hash Sum mismatch requires 'cleanup' to be a list.")

        if not any("apt-get update -y" in c for c in retry_list):
            errors.append("Hash Sum mismatch retry must include 'apt-get update -y' on Debian.")

        # If the failing command includes a package, require apt-get install -y <pkg> after update
        if pkg_from_cmd:
            expected_install = f"apt-get install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Debian Hash Sum mismatch retry must include '{expected_install}' "
                    "when the failing command includes a package."
                )

    # ------------------------------------------------------------------
    # 6) dpkg --configure -a suggestion → cleanup_and_retry with dpkg step
    # ------------------------------------------------------------------
    if "dpkg --configure -a" in stderr:
        if action != "cleanup_and_retry":
            errors.append("When stderr suggests 'dpkg --configure -a', Debian must use 'cleanup_and_retry'.")

        if not any("dpkg --configure -a" in c for c in retry_list):
            errors.append("dpkg interruption on Debian requires 'dpkg --configure -a' in retry sequence.")

        # If a package is present in the failing command, require apt-get install -y <pkg> as well
        if pkg_from_cmd:
            expected_install = f"apt-get install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"dpkg interruption on Debian with a package requires '{expected_install}' "
                    "in the retry sequence."
                )

    # ------------------------------------------------------------------
    # 7) held broken packages → MUST NOT run apt --fix-broken install or apt-get -f install
    #    and MUST use fallback (non-deterministic condition)
    # ------------------------------------------------------------------
    if "held broken packages" in stderr:
        if action != "fallback":
            errors.append(
                "When 'held broken packages' appears on Debian, the LLM must use 'fallback' "
                "due to non-deterministic recovery."
            )

        forbidden_subs = ("apt --fix-broken install", "apt-get -f install")
        if isinstance(retry, str):
            if any(sub in retry for sub in forbidden_subs):
                errors.append(
                    "When 'held broken packages' appears, Debian must NOT run "
                    "'apt --fix-broken install' or 'apt-get -f install'."
                )
        if isinstance(retry, list):
            for cmd in retry:
                if isinstance(cmd, str) and any(sub in cmd for sub in forbidden_subs):
                    errors.append(
                        "When 'held broken packages' appears, Debian must NOT run "
                        "'apt --fix-broken install' or 'apt-get -f install'."
                    )

    # ------------------------------------------------------------------
    # 8) fix-broken suggestions (apt --fix-broken install OR apt-get -f install)
    #    → cleanup_and_retry with canonical Debian sequence:
    #        apt-get -f install -y
    #        apt-get install -y <pkg>   (if <pkg> present)
    # ------------------------------------------------------------------
    fix_broken_suggested = (
        "apt --fix-broken install" in stderr or "apt-get -f install" in stderr
    )
    if fix_broken_suggested and "held broken packages" not in stderr:
        if action != "cleanup_and_retry":
            errors.append(
                "When stderr suggests 'apt --fix-broken install' or 'apt-get -f install', "
                "Debian must use 'cleanup_and_retry'."
            )
        else:
            # Must include apt-get -f install -y
            if not any("apt-get -f install -y" in c for c in retry_list):
                errors.append(
                    "Debian fix-broken recovery must include 'apt-get -f install -y' in the retry sequence."
                )

            # If a package is present, must also include apt-get install -y <pkg>
            if pkg_from_cmd:
                expected_install = f"apt-get install -y {pkg_from_cmd}"
                if not any(expected_install in c for c in retry_list):
                    errors.append(
                        f"Debian fix-broken recovery with a package must include '{expected_install}' "
                        "in the retry sequence."
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
    # 10) Debian APT: "Unable to locate package" (with or without quotes)
    #     → cleanup_and_retry with apt-get update -y + apt-get install -y <pkg>
    # ------------------------------------------------------------------
    unable_to_locate = "Unable to locate package" in stderr
    if unable_to_locate and pkg_from_cmd:
        if action != "cleanup_and_retry":
            errors.append(
                "On Debian, 'Unable to locate package' must use 'cleanup_and_retry' with "
                "apt-get update -y and apt-get install -y <pkg>."
            )
        else:
            if not any("apt-get update -y" in c for c in retry_list):
                errors.append(
                    "Debian 'Unable to locate package' retry must include 'apt-get update -y'."
                )
            expected_install = f"apt-get install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Debian 'Unable to locate package' retry must include '{expected_install}'."
                )

    # ------------------------------------------------------------------
    # 11) Missing arguments for apt-get install (e.g., 'apt-get install')
    #     → treat as malformed and prefer fallback (no guessing <pkg>)
    # ------------------------------------------------------------------
    if cmd_uses_apt_family(command) and "install" in command.split():
        # If we cannot extract a package, it's an incomplete install
        if pkg_from_cmd is None and exit_status is not None and exit_status != 0:
            if action != "fallback":
                errors.append(
                    "On Debian, incomplete 'apt-get install' without a package name must use 'fallback' "
                    "to avoid guessing a package."
                )

    return errors

