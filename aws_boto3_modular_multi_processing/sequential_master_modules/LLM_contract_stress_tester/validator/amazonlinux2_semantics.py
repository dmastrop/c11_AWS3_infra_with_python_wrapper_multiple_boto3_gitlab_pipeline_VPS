from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_amazonlinux2_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    Amazon Linux 1/2–specific semantic checks derived from the Amazon Linux YUM
    domain primitives (Revision 9) and global Linux malformed-command rules (Revision 6.8).

    Applies ONLY when os_name == "Amazon Linux".
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
    # 1) Wrong package manager in RETRY on Amazon Linux
    # ------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On Amazon Linux, retry must not use non-YUM package managers (apt/dnf/apk/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On Amazon Linux, retry must not use non-YUM package managers (apt/dnf/apk/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On Amazon Linux, when the original command uses a non-YUM package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "Amazon Linux wrong-package-manager rewrites must use a single string retry command."
                )
            else:
                expected_sub = f"yum install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"Amazon Linux wrong-package-manager rewrite must include '{expected_sub}' "
                        "in the retry command."
                    )

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
                errors.append("Malformed pipeline/subshell on Amazon Linux must result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures MUST use fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on Amazon Linux must use 'fallback' action.")

    # ------------------------------------------------------------
    # 5) Missing package name → malformed
    # ------------------------------------------------------------
    if "yum install" in command and "Need to pass a list of packages" in stderr:
        if action != "fallback":
            errors.append(
                "Amazon Linux malformed install (missing package name) must use 'fallback'."
            )

    # ------------------------------------------------------------
    # 6) Amazon Linux Extras handling
    # ------------------------------------------------------------
    extras_indicators = [
        "available in amazon-linux-extras",
        "amazon-linux-extras install",
    ]

    if any(ind in stderr for ind in extras_indicators):
        if action != "cleanup_and_retry":
            errors.append("Amazon Linux Extras availability must use 'cleanup_and_retry'.")

        # retry must include amazon-linux-extras install <pkg> -y
        if pkg_from_cmd:
            expected_extras = f"amazon-linux-extras install {pkg_from_cmd} -y"
            if not any(expected_extras in c for c in retry_list):
                errors.append(
                    f"Amazon Linux Extras retry must include '{expected_extras}'."
                )

            # and then yum install -y <pkg>
            expected_yum = f"yum install -y {pkg_from_cmd}"
            if not any(expected_yum in c for c in retry_list):
                errors.append(
                    f"Amazon Linux Extras retry must include '{expected_yum}' after extras installation."
                )

    # ------------------------------------------------------------
    # 7) YUM metadata / repo corruption (Amazon Linux wording)
    # ------------------------------------------------------------
    metadata_indicators = [
        "Error: failed to download metadata",
        "repomd.xml is damaged",
        "cannot prepare internal mirrorlist",
        "no URLs in mirrorlist",
    ]

    if any(ind in stderr for ind in metadata_indicators):
        if action != "cleanup_and_retry":
            errors.append("YUM metadata corruption on Amazon Linux must use 'cleanup_and_retry'.")

        # cleanup must include yum clean all + yum makecache
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "yum clean all" not in cleanup_set:
                errors.append("Amazon Linux metadata cleanup must include 'yum clean all'.")
            if "yum makecache" not in cleanup_set:
                errors.append("Amazon Linux metadata cleanup must include 'yum makecache'.")
        else:
            errors.append("Amazon Linux metadata corruption requires 'cleanup' to be a list.")

        # retry must include yum clean all + yum makecache
        if not any("yum clean all" in c for c in retry_list):
            errors.append("Amazon Linux metadata retry must include 'yum clean all'.")
        if not any("yum makecache" in c for c in retry_list):
            errors.append("Amazon Linux metadata retry must include 'yum makecache'.")

        # If a package exists, retry must include yum install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"yum install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Amazon Linux metadata corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 8) rpmdb corruption → cleanup_and_retry
    # ------------------------------------------------------------
    rpmdb_indicators = [
        "rpmdb open failed",
        "BDB0113",
        "db5 error",
        "BDB1507",
    ]

    if any(ind in stderr for ind in rpmdb_indicators):
        if action != "cleanup_and_retry":
            errors.append("rpmdb corruption on Amazon Linux must use 'cleanup_and_retry'.")

        # cleanup must include rm -f /var/lib/rpm/.rpm.lock
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -f /var/lib/rpm/.rpm.lock" not in cleanup_set:
                errors.append(
                    "Amazon Linux rpmdb corruption cleanup must include 'rm -f /var/lib/rpm/.rpm.lock'."
                )
        else:
            errors.append("Amazon Linux rpmdb corruption requires 'cleanup' to be a list.")

        # retry must include rpm --rebuilddb
        if not any("rpm --rebuilddb" in c for c in retry_list):
            errors.append("Amazon Linux rpmdb corruption retry must include 'rpm --rebuilddb'.")

        # If a package exists, retry must include yum install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"yum install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"Amazon Linux rpmdb corruption retry must include '{expected_install}' "
                    "when a package is present."
                )

    # ------------------------------------------------------------
    # 9) Repo errors without deterministic fix → fallback
    # ------------------------------------------------------------
    nondeterministic_repo_indicators = [
        "No matching repo",
        "repository not found",
        "Cannot find a valid baseurl",
        "Skipping disabled repository",
        "missing amazon-linux-extras metadata",
    ]

    if any(ind in stderr for ind in nondeterministic_repo_indicators):
        if action != "fallback":
            errors.append("Non-deterministic repo errors on Amazon Linux must use 'fallback'.")

    # ------------------------------------------------------------
    # 10) Idempotency messages
    # ------------------------------------------------------------
    idempotency_indicators = [
        "Nothing to do",
        "already installed",
        "No packages marked for update",
    ]

    if any(ind in stderr for ind in idempotency_indicators):
        if action not in ("fallback", "cleanup_and_retry"):
            errors.append(
                "Idempotency on Amazon Linux must use 'fallback' unless partial state is indicated."
            )

    # ------------------------------------------------------------
    # 11) Cisco-style 'show' commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127 and command.startswith("show "):
        if action != "fallback":
            errors.append("Amazon Linux must use 'fallback' for Cisco-style 'show' commands.")

    return errors

