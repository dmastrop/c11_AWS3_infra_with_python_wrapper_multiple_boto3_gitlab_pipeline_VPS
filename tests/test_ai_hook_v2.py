import pytest
import types
import paramiko

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
        stdout = types.SimpleNamespace(read=lambda: self.stdout_data.encode())
        stderr = types.SimpleNamespace(read=lambda: self.stderr_data.encode())
        return None, stdout, stderr

    def get_transport(self):
        return None

    def close(self):
        self.closed = True


MINIMAL_COMMANDS = ["echo test"]


# ---------------------------------------------------------------------
# TEST 1 — AI FIXED → install_success
# ---------------------------------------------------------------------
def test_ai_hook_ai_fixed(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    # Monkeypatch Paramiko SSHClient constructor
    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    # Fake AI hook: AI successfully repairs the command
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": True,
            "ai_failed": False,
            "ai_fallback": False,
            "new_stdout": "AI repaired stdout",
            "new_stderr": "",
            "new_exit_status": 0,
        }

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._invoke_ai_hook",
        fake_ai_hook,
    )

    # Fake metadata builder
    def fake_meta():
        ai_meta = {
            "ai_invoked": True,
            "ai_fallback": False,
            "ai_plan_action": None,
            "ai_commands": [],
        }
        ai_tags = ["ai_invoked_true", "ai_fixed_true"]
        return ai_meta, ai_tags

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._build_ai_metadata_and_tags",
        fake_meta,
    )

    result = resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_invoked_true" in registry["tags"]
    assert "ai_fixed_true" in registry["tags"]
    assert "installation_completed" in registry["tags"]


# ---------------------------------------------------------------------
# TEST 2 — AI FAILED → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_ai_failed(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    # Fake AI hook: AI fails to repair the command
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": False,
            "ai_failed": True,
            "ai_fallback": False,
            "new_stdout": "",
            "new_stderr": "still failing",
            "new_exit_status": 1,
        }

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._invoke_ai_hook",
        fake_ai_hook,
    )

    # Fake metadata builder
    def fake_meta():
        ai_meta = {
            "ai_invoked": True,
            "ai_fallback": False,
            "ai_plan_action": None,
            "ai_commands": [],
        }
        ai_tags = ["ai_invoked_true", "ai_failed_true"]
        return ai_meta, ai_tags

    monkeypatch.setattr(
        "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._build_ai_metadata_and_tags",
        fake_meta,
    )

    result = resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_invoked_true" in registry["tags"]
    assert "ai_failed_true" in registry["tags"]

