from typing import Any, Dict, List

from .helpers_linux import (
    cmd_uses_wrong_package_manager,
    extract_pkg_from_command,
    stderr_contains,
    looks_like_network_failure,
)


def validate_macos_brew_semantics(context: Dict[str, Any], resp: Dict[str, Any]) -> List[str]:
    """
    macOS Homebrew semantic checks derived from:

      - macOS-brew domain primitives (Revision 15)
      - Revision 6.10 malformed-command hardening
      - Global destructive-command rules
      - Global fallback semantics
      - Deterministic rewrite rules for wrong package managers

    Applies ONLY when:
        os_name == "macOS" AND os_version endswith "-brew"
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
    # 1) Destructive commands → abort
    # ------------------------------------------------------------
    destructive_patterns = [
        "rm -rf /",
        "rm -rf /System",
        "rm -rf /usr/local/Homebrew",
    ]
    if any(p in command for p in destructive_patterns):
        if action != "abort":
            errors.append("Destructive commands on macOS-brew MUST use 'abort'.")
        return errors

    # ------------------------------------------------------------
    # 2) Wrong package manager → rewrite to brew install <pkg>
    #
    #    Only allowed when:
    #      - a concrete package name is present
    #      - rewrite is deterministic
    # ------------------------------------------------------------
    pkg_from_cmd = extract_pkg_from_command(command)

    if cmd_uses_wrong_package_manager(command, os_name):
        if pkg_from_cmd:
            if action != "retry_with_modified_command":
                errors.append(
                    "macOS-brew: wrong package manager with a clear package name "
                    "requires 'retry_with_modified_command'."
                )
            else:
                if not isinstance(retry, str):
                    errors.append(
                        "macOS-brew wrong-package-manager rewrite must use a single string retry command."
                    )
                else:
                    expected = f"brew install {pkg_from_cmd}"
                    if expected not in retry:
                        errors.append(
                            f"macOS-brew rewrite must include '{expected}' in retry."
                        )
        else:
            if action != "fallback":
                errors.append(
                    "macOS-brew: wrong package manager with NO package name must use 'fallback'."
                )

    # ------------------------------------------------------------
    # 3) Malformed pipelines/subshells → fallback
    # ------------------------------------------------------------
    if "|" in command or "$(" in command or ")" in command:
        if (
            "syntax error" in stderr
            or "unexpected token" in stderr
            or "unexpected EOF" in stderr
            or "syntax error near unexpected token" in stderr
        ):
            if action != "fallback":
                errors.append("Malformed pipeline/subshell on macOS-brew MUST result in 'fallback'.")

    # ------------------------------------------------------------
    # 4) Network failures → fallback
    # ------------------------------------------------------------
    if looks_like_network_failure(stderr):
        if action != "fallback":
            errors.append("Network failures on macOS-brew MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 5) Unknown commands (exit_status 127) → fallback
    # ------------------------------------------------------------
    if exit_status == 127:
        # If it's not obviously a brew primitive, fallback is required
        brew_primitives = ["brew ", "brew\n", "brew\t"]
        if not any(command.startswith(p) for p in brew_primitives):
            if action != "fallback":
                errors.append("Unknown commands on macOS-brew MUST use 'fallback'.")
    
    # ------------------------------------------------------------
    # 6) Malformed brew install commands → fallback
    # ------------------------------------------------------------
    malformed_brew = [
        "brew install",
        "brew install -y",
        "brew install --force",
    ]
    if any(command == m or command.startswith(m + " ") for m in malformed_brew):
        if action != "fallback":
            errors.append("Malformed 'brew install' commands MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 7) Brew metadata/cache corruption → cleanup_and_retry
    # ------------------------------------------------------------
    brew_corruption_signatures = [
        "Error: failed to download",
        "Error: Fetching /usr/local/Homebrew",
        "Error: SHA256 mismatch",
        "Error: No available formula",
        "Error: Corrupt cache",
    ]
    if any(sig in stderr for sig in brew_corruption_signatures):
        if action != "cleanup_and_retry":
            errors.append("Brew metadata corruption MUST use 'cleanup_and_retry'.")

        # Cleanup must include brew cleanup + cache removal
        expected_cleanup = {
            "brew cleanup",
            "rm -rf ~/Library/Caches/Homebrew/*",
        }
        if isinstance(cleanup, list):
            cleanup_set = set(c.strip() for c in cleanup if isinstance(c, str))
            if not expected_cleanup.issubset(cleanup_set):
                errors.append(
                    "macOS-brew cleanup must include 'brew cleanup' and "
                    "'rm -rf ~/Library/Caches/Homebrew/*'."
                )
        else:
            errors.append("macOS-brew cleanup must be a list.")

        # Retry must include brew update
        if not any("brew update" in c for c in retry_list):
            errors.append("macOS-brew retry must include 'brew update'.")

        # Retry must include brew install <pkg> ONLY if pkg exists
        if pkg_from_cmd:
            expected_install = f"brew install {pkg_from_cmd}"
            if not any(expected_install in c for c in retry_list):
                errors.append(
                    f"macOS-brew retry must include '{expected_install}' when a package name is present."
                )

    # ------------------------------------------------------------
    # 8) Formula not found → fallback
    # ------------------------------------------------------------
    if (
        "No available formula" in stderr
        or "No formulae found in taps" in stderr
        or "No available formula with the name" in stderr
    ):
        if action != "fallback":
            errors.append("Formula-not-found errors on macOS-brew MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 9) Brew doctor warnings → fallback
    # ------------------------------------------------------------
    if "brew doctor" in command or "brew doctor" in stderr:
        if action != "fallback":
            errors.append("brew doctor warnings MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 10) Idempotency rules → fallback
    # ------------------------------------------------------------
    idempotent_signatures = [
        "is already installed",
        "Nothing to do",
        "Already up-to-date",
    ]
    if any(sig in stderr for sig in idempotent_signatures):
        if action != "fallback":
            errors.append("Idempotent brew operations MUST use 'fallback'.")

    # ------------------------------------------------------------
    # 11) No sudo allowed in correction/cleanup/retry
    # ------------------------------------------------------------
    def _contains_sudo(cmds: Any) -> bool:
        if isinstance(cmds, str):
            return "sudo " in cmds
        if isinstance(cmds, list):
            return any(isinstance(c, str) and "sudo " in c for c in cmds)
        return False

    if "sudo " in command and action != "fallback":
        errors.append("macOS-brew MUST NOT introduce 'sudo'. Use 'fallback' for permission issues.")

    if _contains_sudo(cleanup) or _contains_sudo(retry):
        errors.append("macOS-brew MUST NOT use 'sudo' in cleanup or retry.")

    return errors

