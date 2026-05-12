from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_rhel_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    RHEL-specific semantic checks derived from the RHEL YUM domain primitives
    (Revision 8) and global Linux malformed-command rules (Revision 6.8).

    Applies to ALL RHEL versions (normalization handled by OS-discovery).
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
    # 1) Wrong package manager in RETRY on RHEL
    #    RHEL uses yum; retry MUST NOT use apt/dnf/apk/brew/etc.
    # ------------------------------------------------------------
    def _check_retry_wrong_pm(r: Any) -> None:
        if isinstance(r, str):
            if cmd_uses_wrong_package_manager(r, os_name):
                errors.append(
                    "On RHEL, retry must not use non-YUM package managers (apt/dnf/apk/brew/etc.)."
                )
        elif isinstance(r, list):
            for cmd in r:
                if isinstance(cmd, str) and cmd_uses_wrong_package_manager(cmd, os_name):
                    errors.append(
                        "On RHEL, retry must not use non-YUM package managers (apt/dnf/apk/brew/etc.)."
                    )

    _check_retry_wrong_pm(retry)

    # ------------------------------------------------------------
    # 2) Wrong package manager in ORIGINAL command → deterministic rewrite
    #
    #    If the original command uses apt/dnf/apk/brew with a clear package,
    #    the LLM MUST use retry_with_modified_command and rewrite to:
    #         yum install -y <pkg>
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name) and pkg_from_cmd:
        if action != "retry_with_modified_command":
            errors.append(
                "On RHEL, when the original command uses a non-YUM package manager "
                "with a clear package name, the LLM must use 'retry_with_modified_command'."
            )
        else:
            if not isinstance(retry, str):
                errors.append(
                    "RHEL wrong-package-manager rewrites must use a single string retry command."
                )
            else:
                expected_sub = f"yum install -y {pkg_from_cmd}"
                if expected_sub not in retry:
                    errors.append(
                        f"RHEL wrong-package-manager rewrite must include '{expected_sub}' "
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
                errors.append("Malformed pipeline/subshell on RHEL must result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures MUST use fallback (global network semantics)
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on RHEL must use 'fallback' action.")

    # ------------------------------------------------------------
    # 5) YUM metadata / repo corruption → cleanup_and_retry
    #
    #    Required retry sequence:
    #       yum clean all
    #       yum makecache
    #       yum install -y <pkg>   (only if <pkg> exists)
    # ------------------------------------------------------------
    yum_metadata_indicators = [
        "Metadata file does not match checksum",
        "repomd.xml signature could not be verified",
        "failed to retrieve repodata",
        "Error: failed to download metadata",
    ]

    if any(ind in stderr for ind in yum_metadata_indicators):
        if action != "cleanup_and_retry":
            errors.append("YUM metadata corruption must use 'cleanup_and_retry' on RHEL.")

        # cleanup must include yum clean all + yum makecache
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "yum clean all" not in cleanup_set or "yum makecache" not in cleanup_set:
                errors.append(
                    "YUM metadata corruption cleanup must include 'yum clean all' and 'yum makecache'."
                )
        else:
            errors.append("YUM metadata corruption requires 'cleanup' to be a list.")

        # retry must include yum clean all + yum makecache
        if not any("yum clean all" in c for c in retry_list):
            errors.append("YUM metadata corruption retry must include 'yum clean all'.")
        if not any("yum makecache" in c for c in retry_list):
            errors.append("YUM metadata corruption retry must include 'yum makecache'.")

        # If a package exists, retry must include yum install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"yum install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"YUM metadata corruption retry must include '{expected_install}' when a package is present."
                )

    # ------------------------------------------------------------
    # 6) rpmdb corruption → cleanup_and_retry with rpmdb recovery
    # ------------------------------------------------------------
    rpmdb_indicators = [
        "rpmdb open failed",
        "BDB0113",
        "db5 error",
        "BDB1507",
    ]

    if any(ind in stderr for ind in rpmdb_indicators):
        if action != "cleanup_and_retry":
            errors.append("rpmdb corruption on RHEL must use 'cleanup_and_retry'.")

        # cleanup must include rpmdb recovery steps
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if "rm -f /var/lib/rpm/.rpm.lock" not in cleanup_set:
                errors.append("rpmdb corruption cleanup must include 'rm -f /var/lib/rpm/.rpm.lock'.")
            if "rpm --rebuilddb" not in cleanup_set:
                errors.append("rpmdb corruption cleanup must include 'rpm --rebuilddb'.")
        else:
            errors.append("rpmdb corruption requires 'cleanup' to be a list.")

        # retry must include rpm --rebuilddb
        if not any("rpm --rebuilddb" in c for c in retry_list):
            errors.append("rpmdb corruption retry must include 'rpm --rebuilddb'.")

        # If a package exists, retry must include yum install -y <pkg>
        if pkg_from_cmd:
            expected_install = f"yum install -y {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"rpmdb corruption retry must include '{expected_install}' when a package is present."
                )

    # ------------------------------------------------------------
    # 7) Repo errors without deterministic fix → fallback
    # ------------------------------------------------------------
    nondeterministic_repo_indicators = [
        "No matching repo",
        "repository not found",
        "Cannot find a valid baseurl",
        "This repository does not have a release file",
        "Skipping disabled repository",
    ]

    if any(ind in stderr for ind in nondeterministic_repo_indicators):
        if action != "fallback":
            errors.append("Non-deterministic repo errors on RHEL must use 'fallback'.")

    # ------------------------------------------------------------
    # 8) Idempotency messages
    # ------------------------------------------------------------
    idempotency_indicators = [
        "Nothing to do",
        "already installed",
        "No packages marked for update",
    ]

    if any(ind in stderr for ind in idempotency_indicators):
        # fallback is acceptable unless partial state is indicated
        if action not in ("fallback", "cleanup_and_retry"):
            errors.append(
                "Idempotency on RHEL must use 'fallback' unless partial state is indicated."
            )

    # ------------------------------------------------------------
    # 9) Cisco-style 'show' commands → fallback
    # ------------------------------------------------------------
    if exit_status == 127 and command.startswith("show "):
        if action != "fallback":
            errors.append("RHEL must use 'fallback' for Cisco-style 'show' commands.")

    return errors

