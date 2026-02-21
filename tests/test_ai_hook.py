import pytest
import types

# Import your real module2f
from sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
    resurrection_install_tomcat,
)

# ---------------------------------------------------------------------
# Fake SSH object — prevents real SSH connections or commands
# ---------------------------------------------------------------------
class FakeSSH:
    def __init__(self, stdout_data="", stderr_data="", exit_status=1):
        self.stdout_data = stdout_data
        self.stderr_data = stderr_data
        self.exit_status = exit_status
        self.closed = False

    def exec_command(self, command, timeout=None):
        # Return fake stdin, stdout, stderr
        stdout = types.SimpleNamespace(read=lambda: self.stdout_data.encode())
        stderr = types.SimpleNamespace(read=lambda: self.stderr_data.encode())
        return None, stdout, stderr

    def get_transport(self):
        return None

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------
# Helper: minimal replayed_commands list
# ---------------------------------------------------------------------
MINIMAL_COMMANDS = ["echo test"]


# ---------------------------------------------------------------------
# TEST 1 — AI FIXED → install_success
# ---------------------------------------------------------------------
def test_ai_hook_ai_fixed(monkeypatch):
    """
    Forces the top-level AI hook to return ai_fixed=True.
    This should cause:
      - command_succeeded = True
      - break out of retry loop
      - final install_success registry entry
    """

    # Monkeypatch SSH to always fail until AI fixes it
    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._create_ssh_client",
        lambda *args, **kwargs: fake_ssh,
    )

    # Monkeypatch the AI hook to simulate a successful repair
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": True,
            "new_stdout": "AI repaired stdout",
            "new_stderr": "",
            "new_exit_status": 0,
        }

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._invoke_ai_hook",
        fake_ai_hook,
    )

    # Monkeypatch metadata builder
    def fake_meta():
        return ({"ai_invoked": True}, ["ai_fixed_tag"])

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._build_ai_metadata_and_tags",
        fake_meta,
    )

    # Run the real function
    ip = "1.2.3.4"
    private_ip = "10.0.0.1"
    instance_id = "i-test"

    result = resurrection_install_tomcat(
        ip=ip,
        private_ip=private_ip,
        instance_id=instance_id,
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # Assert install_success
    assert isinstance(result, tuple)
    _, _, registry = result
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_fixed_tag" in registry["tags"]
    assert "installation_completed" in registry["tags"]


# ---------------------------------------------------------------------
# TEST 2 — AI FAILED → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_ai_failed(monkeypatch):
    """
    Forces the top-level AI hook to return ai_fixed=False.
    This should cause:
      - command_succeeded remains False
      - natural install_failed block executes
      - ai_metadata + ai_tags appear in registry
    """

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._create_ssh_client",
        lambda *args, **kwargs: fake_ssh,
    )

    # AI hook fails to fix the command
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": False,
            "new_stdout": "",
            "new_stderr": "still failing",
            "new_exit_status": 1,
        }

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._invoke_ai_hook",
        fake_ai_hook,
    )

    # Metadata builder
    def fake_meta():
        return ({"ai_invoked": True}, ["ai_failed_tag"])

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._build_ai_metadata_and_tags",
        fake_meta,
    )

    # Run the real function
    ip = "1.2.3.4"
    private_ip = "10.0.0.1"
    instance_id = "i-test"

    result = resurrection_install_tomcat(
        ip=ip,
        private_ip=private_ip,
        instance_id=instance_id,
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # Assert install_failed
    assert isinstance(result, tuple)
    _, _, registry = result
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_failed_tag" in registry["tags"]

