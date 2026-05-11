from typing import Any, Dict, List, Optional

# ------------------------------------------------------------
# OS-specific wrong package manager sets. NOTE these are WRONG. For right PM the semantics file will handle that. 
# ------------------------------------------------------------
WRONG_PM_BY_OS = {
    "Ubuntu": {"yum", "dnf", "apk", "zypper", "pacman", "brew"},
    "Debian": {"yum", "dnf", "apk", "zypper", "pacman", "brew"},

    "RHEL": {"apt", "apt-get", "apk", "zypper", "pacman", "brew"},
    "CentOS": {"apt", "apt-get", "apk", "zypper", "pacman", "brew"},
    "Fedora": {"apt", "apt-get", "apk", "zypper", "pacman", "brew"},

    "Amazon Linux": {"apt", "apt-get", "apk", "zypper", "pacman", "brew"},
    "Amazon Linux 2023": {"apt", "apt-get", "apk", "zypper", "pacman", "brew"},

    "Alpine": {"apt", "apt-get", "yum", "dnf", "zypper", "pacman", "brew"},

    "macOS": {"apt", "apt-get", "yum", "dnf", "apk", "zypper", "pacman"},
    "Windows": {"apt", "apt-get", "yum", "dnf", "apk", "zypper", "pacman", "brew"},
}

# ------------------------------------------------------------
# Corrected wrong-PM detector (tokenized, OS-specific)
# ------------------------------------------------------------
def cmd_uses_wrong_package_manager(cmd: str, os_name: str) -> bool:
    tokens = cmd.strip().split()
    wrong = WRONG_PM_BY_OS.get(os_name, set())
    return any(tok in wrong for tok in tokens)


# ------------------------------------------------------------
# Existing helpers (unchanged)
# ------------------------------------------------------------
def cmd_uses_apt_family(cmd: str) -> bool:
    s = cmd.strip()
    return s.startswith("apt ") or s.startswith("apt-get ")


def extract_pkg_from_command(cmd: str) -> Optional[str]:
    tokens = cmd.strip().split()
    if len(tokens) < 3:
        return None
    if "install" in tokens:
        idx = tokens.index("install")
        if idx + 1 < len(tokens):
            candidate = tokens[-1]
            if not candidate.startswith("-"):
                return candidate
    return None


def stderr_contains(stderr: str, phrase: str) -> bool:
    return phrase in stderr


def looks_like_network_failure(stderr: str) -> bool:
    s = stderr.lower()
    patterns = [
        "temporary failure resolving",
        "connection refused",
        "connection timed out",
        "no route to host",
        "host unreachable",
        "network unreachable",
        "tls handshake",
        "ssl handshake",
        "proxy error",
        "proxy connection failed",
    ]
    return any(p in s for p in patterns)

