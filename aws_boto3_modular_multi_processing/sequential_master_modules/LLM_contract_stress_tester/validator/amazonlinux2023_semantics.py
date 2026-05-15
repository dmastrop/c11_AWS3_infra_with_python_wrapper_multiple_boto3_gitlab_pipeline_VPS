from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_amazonlinux2023_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Amazon Linux 2023–specific semantic checks derived from the Amazon Linux 2023
    DNF domain primitives (Revision 1) and global Linux malformed-command rules (Revision 6.8).

    Applies ONLY when os_name == "Amazon Linux 2023".
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
    # 1) Wrong package manager in RETRY on Amazon Linux 2023
    # ------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On Amazon Linux 2023, retry must not use non-DNF package managers (apt/yum/apk/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On Amazon Linux 2023, retry must not use non-DNF package managers (apt/yum/apk/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Amazon Linux 2023, when the original command uses a non-DNF package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "Amazon Linux 2023 wrong-package-manager rewrites must use a single string retry command."
                )
            else:
                expected_sub = f"dnf install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Amazon Linux 2023 wrong-package-manager rewrite must include '{expected_sub}' "
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
                errors.append("Malformed pipeline/subshell on Amazon Linux 2023 must result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures MUST use fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Amazon Linux 2023 must use 'fallback' action.")

    # ------------------------------------------------------------
    # 5) Missing package name → malformed
    # ------------------------------------------------------------
    if ("dnf install" in command or "yum install" in command) and "Need to pass a list of packages" in stderr:
        if action != "fallback":
            errors.append(
                "Amazon Linux 2023 malformed install (missing package name) must use 'fallback'."
            )

    ## ------------------------------------------------------------
    ## 6) DNF metadata / mirrorlist failures → cleanup_and_retry
    ## ------------------------------------------------------------
    #metadata_indicators = [
    #    "Failed to download metadata for repo",
    #    "Cannot prepare internal mirrorlist",
    #    "No URLs in mirrorlist",
    #    "Error: failed to download metadata for repo",
    #    "Error: No matching repo",
    #]

    #if any(ind in stderr for ind in metadata_indicators):
    #    if action != "cleanup_and_retry":
    #        errors.append("DNF metadata corruption on Amazon Linux 2023 must use 'cleanup_and_retry'.")

    #    # cleanup must include dnf clean all
    #    if isinstance(cleanup, list):
    #        cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
    #        if "dnf clean all" not in cleanup_set:
    #            errors.append(
    #                "Amazon Linux 2023 metadata corruption cleanup must include 'dnf clean all'."
    #            )
    #    else:
    #        errors.append("Amazon Linux 2023 metadata corruption requires 'cleanup' to be a list.")

    #    # retry must include dnf makecache
    #    if not any("dnf makecache" in c for c in retry_list):
    #        errors.append("Amazon Linux 2023 metadata corruption retry must include 'dnf makecache'.")

    #    # If a package exists, retry must include dnf install -y <pkg>
    #    if pkg_from_cmd:
    #        expected_install = f"dnf install -y {pkg_from_cmd}"
    #        if not any(expected_install in c for c in retry_list):
    #            errors.append(
    #                f"Amazon Linux 2023 metadata corruption retry must include '{expected_install}' "
    #                "when a package is present."
    #            )


    # ------------------------------------------------------------
    # 6) DNF metadata / mirrorlist failures → cleanup_and_retry
    # ------------------------------------------------------------
    metadata_indicators = [
        "Failed to download metadata for repo",
        "Cannot prepare internal mirrorlist",
        "No URLs in mirrorlist",
        "Error: failed to download metadata for repo",
    ]

    # "Error: No matching repo" is metadata corruption ONLY when accompanied
    # by one of the above indicators.
    is_metadata_corruption = (
        any(ind in stderr for ind in metadata_indicators)
        or (
            "Error: No matching repo" in stderr
            and any(ind in stderr for ind in metadata_indicators)
        )
    )

    if is_metadata_corruption:
        if action != "cleanup_and_retry":
            errors.append("DNF metadata corruption on Amazon Linux 2023 must use 'cleanup_and_retry'.")

        # cleanup must include dnf clean all
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "dnf clean all" not in cleanup_set:
                errors.append(
                    "Amazon Linux 2023 metadata corruption cleanup must include 'dnf clean all'."
                )
        else:
            errors.append("Amazon Linux 2023 metadata corruption requires 'cleanup' to be a list.")

        # retry must include dnf makecache
        if not any("dnf makecache" in c for c in retry_list):
            errors.append("Amazon Linux 2023 metadata corruption retry must include 'dnf makecache'.")

        # If a package exists, retry must include dnf install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"dnf install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Amazon Linux 2023 metadata corruption retry must include '{expected_install}' "
                    "when a package is present."
                )


    # ------------------------------------------------------------
    # 6b) Missing or invalid repo → fallback
    # ------------------------------------------------------------
    if (
        "Error: No matching repo" in stderr
        and not is_metadata_corruption
    ):
        if action != "fallback":
            errors.append(
                "Non-deterministic repo errors on Amazon Linux 2023 must use 'fallback'."
            )





    # ------------------------------------------------------------
    # 7) rpmdb corruption → cleanup_and_retry
    # ------------------------------------------------------------
    rpmdb_indicators = [
        "rpmdb open failed",
        "BDB0113",
        "db5 error",
        "BDB1507",
    ]

    if any(ind in stderr for ind in rpmdb_indicators):
        if action != "cleanup_and_retry":
            errors.append("rpmdb corruption on Amazon Linux 2023 must use 'cleanup_and_retry'.")

        # cleanup must include rm -f /var/lib/rpm/.rpm.lock
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -f /var/lib/rpm/.rpm.lock" not in cleanup_set:
                errors.append(
                    "Amazon Linux 2023 rpmdb corruption cleanup must include 'rm -f /var/lib/rpm/.rpm.lock'."
                )
        else:
            errors.append("Amazon Linux 2023 rpmdb corruption requires 'cleanup' to be a list.")

        # retry must include rpm --rebuilddb
        if not any("rpm --rebuilddb" in c for c in retry_list):
            errors.append("Amazon Linux 2023 rpmdb corruption retry must include 'rpm --rebuilddb'.")

        # If a package exists, retry must include dnf install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"dnf install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Amazon Linux 2023 rpmdb corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 8) Repo errors without deterministic fix → fallback
    # ------------------------------------------------------------
    nondeterministic_repo_indicators = [
        "No matching repo",
        "repository not found",
        "Cannot find a valid baseurl",
        "Skipping disabled repository",
    ]

    if any(ind in stderr for ind in nondeterministic_repo_indicators):
        if action != "fallback":
            errors.append("Non-deterministic repo errors on Amazon Linux 2023 must use 'fallback'.")

    # ------------------------------------------------------------
    # 9) Idempotency messages
    # ------------------------------------------------------------
    idempotency_indicators = [
        "Nothing to do",
        "already installed",
        "No packages marked for update",
    ]

    if any(ind in stderr for ind in idempotency_indicators):
        if action not in ("fallback", "cleanup_and_retry"):
            errors.append(
                "Idempotency on Amazon Linux 2023 must use 'fallback' unless partial state is indicated."
            )

    # ------------------------------------------------------------
    # 10) Cisco-style 'show' commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127 and command.startswith("show "):
        if action != "fallback":
            errors.append("Amazon Linux 2023 must use 'fallback' for Cisco-style 'show' commands.")

    return errors

