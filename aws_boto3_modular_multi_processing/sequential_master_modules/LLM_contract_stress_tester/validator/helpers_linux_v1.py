from typing import Any, Dict, List, Optional

_UBUNTU_WRONG_PM = ("yum", "dnf", "apk", "zypper", "pacman", "brew")


def cmd_uses_wrong_package_manager(cmd: str) -> bool:
    s = cmd.strip()
    return any(pm in s.split() for pm in _UBUNTU_WRONG_PM)


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

