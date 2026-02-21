import pytest
import types
import paramiko

#from sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
#    resurrection_install_tomcat,
#)

#from aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
#    resurrection_install_tomcat,
#)

import aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP as m2f

from aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
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


# ---------------------------------------------------------------------
# IMPORTANT PATH SELECTION NOTE
# ---------------------------------------------------------------------
# FakeSSH(stderr="synthetic error") is NOT whitelisted by default.
#
# This means:
#   - non_whitelisted_lines will NOT be empty
#   - Heuristic Block #4 (non-strace fatal_exit_nonzero) WILL fire
#   - The ORIGINAL HOOK will NOT run
#
# To test the ORIGINAL HOOK instead of Heuristic 4:
#   Option A: Add a whitelist regex such as:
#       r"synthetic error"
#       r".*synthetic.*"
#       r".*error.*"
#
#   Option B: Change FakeSSH stderr to a whitelisted apt string:
#       stderr_data="Reading state information..."
#
# This gives full control over which path pytest exercises.
# ---------------------------------------------------------------------

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

    monkeypatch.setattr(m2f, "_invoke_ai_hook", fake_ai_hook)



    #monkeypatch.setattr(
    #    "sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP._invoke_ai_hook",
    #    fake_ai_hook,
    #)






    # Fake metadata builder — aligned with your real persistent state semantics
    def fake_meta():
        ai_meta = {
            "ai_invoked": True,
            "ai_fallback": False,
            "ai_plan_action": None,
            "ai_commands": [],
        }
        ai_tags = ["ai_invoked_true"]
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

    # install_success block assertions
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_invoked_true" in registry["tags"]
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

    # Fake metadata builder — aligned with your real persistent state semantics
    def fake_meta():
        ai_meta = {
            "ai_invoked": True,
            "ai_fallback": False,
            "ai_plan_action": None,
            "ai_commands": [],
        }
        ai_tags = ["ai_invoked_true"]
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

    # install_failed block assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_invoked_true" in registry["tags"]

    # The natural install_failed block adds:
    #   "install_failed_command_0"
    #   original_command
    assert any(tag.startswith("install_failed_command_") for tag in registry["tags"])

