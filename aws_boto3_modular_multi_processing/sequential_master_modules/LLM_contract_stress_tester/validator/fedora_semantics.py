from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_fedora_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Fedora-specific semantic checks derived from the Fedora DNF domain primitives
    (Revision 12) and global Linux malformed-command rules (Revision 6.8).

    Applies ONLY when os_name == "Fedora".
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
    # 1) Wrong package manager in RETRY on Fedora
    # ------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On Fedora, retry must not use non-DNF package managers (apt/yum/apk/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On Fedora, retry must not use non-DNF package managers (apt/yum/apk/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Fedora, when the original command uses a non-DNF package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "Fedora wrong-package-manager rewrites must use a single string retry command."
                )
            else:
                expected_sub = f"dnf install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Fedora wrong-package-manager rewrite must include '{expected_sub}' "
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
                errors.append("Malformed pipeline/subshell on Fedora must result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures MUST use fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Fedora must use 'fallback' action.")

    # ------------------------------------------------------------
    # 5) Missing package name → malformed
    # ------------------------------------------------------------
    if ("dnf install" in command or "yum install" in command) and "Need to pass a list of packages" in stderr:
        if action != "fallback":
            errors.append(
                "Fedora malformed install (missing package name) must use 'fallback'."
            )

    # ------------------------------------------------------------
    # 6) DNF metadata or mirrorlist failures → cleanup_and_retry
    # ------------------------------------------------------------
    metadata_indicators = [
        "Failed to download metadata for repo",
        "Cannot prepare internal mirrorlist",
        "No URLs in mirrorlist",
        "Error: failed to download metadata for repo",
    ]

    if any(ind in stderr for ind in metadata_indicators):
        if action != "cleanup_and_retry":
            errors.append("DNF metadata corruption on Fedora must use 'cleanup_and_retry'.")

        # cleanup must include dnf clean all
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "dnf clean all" not in cleanup_set:
                errors.append(
                    "Fedora metadata corruption cleanup must include 'dnf clean all'."
                )
        else:
            errors.append("Fedora metadata corruption requires 'cleanup' to be a list.")

        # retry must include dnf makecache
        if not any("dnf makecache" in c for c in retry_list):
            errors.append("Fedora metadata corruption retry must include 'dnf makecache'.")

        # If a package exists, retry must include dnf install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"dnf install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Fedora metadata corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 7) rpmdb corruption → cleanup_and_retry
    # ------------------------------------------------------------
    if "rpmdb open failed" in stderr:
        if action != "cleanup_and_retry":
            errors.append("rpmdb corruption on Fedora must use 'cleanup_and_retry'.")

        # cleanup must include rm -f /var/lib/rpm/.rpm.lock
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -f /var/lib/rpm/.rpm.lock" not in cleanup_set:
                errors.append(
                    "Fedora rpmdb corruption cleanup must include 'rm -f /var/lib/rpm/.rpm.lock'."
                )
        else:
            errors.append("Fedora rpmdb corruption requires 'cleanup' to be a list.")

        # retry must include rpm --rebuilddb
        if not any("rpm --rebuilddb" in c for c in retry_list):
            errors.append("Fedora rpmdb corruption retry must include 'rpm --rebuilddb'.")

        # If a package exists, retry must include dnf install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"dnf install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Fedora rpmdb corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 8) Package already installed → fallback
    # ------------------------------------------------------------
    if "already installed" in stderr or "Nothing to do" in stderr:
        if action != "fallback":
            errors.append("Fedora idempotent install/update must use 'fallback'.")

    # ------------------------------------------------------------
    # 9) Cisco-style 'show' commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127 and command.startswith("show "):
        if action != "fallback":
            errors.append("Fedora must use 'fallback' for Cisco-style 'show' commands.")

    return errors

