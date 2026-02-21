import types
import paramiko
import sys

# ---------------------------------------------------------------------
# 0. Import module2f cleanly
# ---------------------------------------------------------------------
import aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP as m2f

from aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
    resurrection_install_tomcat,
)

## ---------------------------------------------------------------------
## Fake SSH object — prevents real SSH connections or commands
## ---------------------------------------------------------------------
#class FakeSSH:
#    def __init__(self, stdout_data="", stderr_data="", exit_status=1):
#        self.stdout_data = stdout_data
#        self.stderr_data = stderr_data
#        self.exit_status = exit_status
#        self.closed = False
#
#    def exec_command(self, command, timeout=None):
#        # stdout/stderr objects with .read() and .channel.recv_exit_status()
#        stdout = types.SimpleNamespace(
#            read=lambda: self.stdout_data.encode(),
#        )
#        stderr = types.SimpleNamespace(
#            read=lambda: self.stderr_data.encode(),
#        )
#
#        # Simulate Paramiko's channel with recv_exit_status()
#        channel = types.SimpleNamespace(
#            recv_exit_status=lambda: self.exit_status,
#            settimeout=lambda *_args, **_kwargs: None,
#        )
#        stdout.channel = channel
#        stderr.channel = channel
#
#        return None, stdout, stderr
#
#    def get_transport(self):
#        return None
#
#    def close(self):
#        self.closed = True


#class FakeSSH:
#    """
#    FakeSSH_v2:
#    - Fails the ORIGINAL command ("echo test")
#    - Succeeds the AI retry command ("echo AI_FIXED")
#    - Implements enough of Paramiko's channel API to avoid watchdog triggers
#    """
#
#    def __init__(self):
#        self.call_count = 0  # track original vs retry
#
#    def exec_command(self, command, timeout=None):
#        self.call_count += 1
#
#        # -------------------------------
#        # ORIGINAL COMMAND (first call)
#        # -------------------------------
#        if "AI_FIXED" not in command:
#            stdout_data = ""
#            stderr_data = "synthetic error"
#            exit_status = 1
#
#        # -------------------------------
#        # AI RETRY COMMAND (second call)
#        # -------------------------------
#        else:
#            stdout_data = "AI repaired stdout"
#            stderr_data = ""
#            exit_status = 0
#
#        # Build stdout/stderr objects
#        stdout = types.SimpleNamespace(
#            read=lambda: stdout_data.encode(),
#        )
#        stderr = types.SimpleNamespace(
#            read=lambda: stderr_data.encode(),
#        )
#
#        # Build a realistic channel object
#        channel = types.SimpleNamespace(
#            recv_exit_status=lambda: exit_status,
#            exit_status_ready=lambda: True,
#            recv_ready=lambda: True,
#            settimeout=lambda *_args, **_kwargs: None,
#        )
#
#        stdout.channel = channel
#        stderr.channel = channel
#
#        return None, stdout, stderr
#
#    def get_transport(self):
#        return None
#
#    def close(self):
#        pass



class FakeSSH:
    """
    FakeSSH_v4:
    - ORIGINAL command ("echo test") → fail
    - AI retry command ("echo AI_FIXED") → succeed
    - Implements enough of Paramiko's channel API to avoid watchdog triggers
    """

    def __init__(self):
        self.call_count = 0

    def exec_command(self, command, timeout=None):
        self.call_count += 1

        # ORIGINAL COMMAND (first call)
        if "AI_FIXED" not in command:
            stdout_data = ""
            stderr_data = "synthetic error"
            exit_status = 1

        # AI RETRY COMMAND (second call)
        else:
            stdout_data = "AI repaired stdout"
            stderr_data = ""
            exit_status = 0

        # -----------------------------
        # stdout object + channel
        # -----------------------------
        stdout_channel = types.SimpleNamespace(
            recv_exit_status=lambda: exit_status,
            exit_status_ready=lambda: True,
            recv_ready=lambda: True,
            recv=lambda size: stdout_data.encode(),   # ⭐ REQUIRED
            settimeout=lambda *_args, **_kwargs: None,
        )

        stdout = types.SimpleNamespace(
            read=lambda: stdout_data.encode(),
            channel=stdout_channel,
        )

        # -----------------------------
        # stderr object + channel
        # -----------------------------
        stderr_channel = types.SimpleNamespace(
            recv_exit_status=lambda: exit_status,
            exit_status_ready=lambda: True,
            recv_ready=lambda: True,
            recv=lambda size: stderr_data.encode(),   # ⭐ REQUIRED
            settimeout=lambda *_args, **_kwargs: None,
        )

        stderr = types.SimpleNamespace(
            read=lambda: stderr_data.encode(),
            channel=stderr_channel,
        )

        return None, stdout, stderr

    def get_transport(self):
        return None

    def close(self):
        pass



# ---------------------------------------------------------------------
# IMPORTANT PATH SELECTION NOTE
# ---------------------------------------------------------------------
# FakeSSH(stderr="synthetic error") is NOT whitelisted by default.
#
# This means:
#   - non_whitelisted_lines will NOT be empty
#   - Heuristic Block #4 (non-strace fatal_exit_nonzero) WILL fire
#   - The ORIGINAL HOOK will NOT run from the top-level location
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
# Helper: build a fake AI plan for different scenarios
# ---------------------------------------------------------------------
def make_plan_ai_fixed():
    # Use retry_with_modified_command → hook will run retry path and see success
    return {
        "action": "retry_with_modified_command",
        "retry": "echo AI_FIXED",
    }


def make_plan_ai_failed():
    # Use retry_with_modified_command → hook will run retry path and see failure
    return {
        "action": "retry_with_modified_command",
        "retry": "echo AI_FAILED",
    }


def make_plan_fallback():
    # Direct fallback → no retry, native logic continues
    return {
        "action": "fallback",
    }


def make_plan_abort():
    return {
        "action": "abort",
    }


def make_plan_unknown():
    return {
        "action": "some_unknown_action",
    }


# ---------------------------------------------------------------------
# TEST 1 — AI FIXED → install_success
# ---------------------------------------------------------------------
def test_ai_hook_ai_fixed(monkeypatch):

    # Fake SSH: retry succeeds (exit_status=0, no stderr)
    #fake_ssh = FakeSSH(stdout_data="AI repaired stdout", stderr_data="", exit_status=0)
    # Fix the FakeSSH to use new SSH class above. First fail then succeed based upon the AI_FIXED in the AI command retry
    fake_ssh = FakeSSH()


    # Monkeypatch Paramiko SSHClient constructor
    #monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)
    monkeypatch.setattr(m2f.paramiko, "SSHClient", lambda *args, **kwargs: fake_ssh)


    # Monkeypatch ask_ai_for_recovery to return a "fixed" plan
    def fake_ask_ai_for_recovery(context):
        return make_plan_ai_fixed()

    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)

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
    assert "installation_completed" in registry["tags"]
    # We expect at least one AI tag
    assert any(tag.startswith("ai_") for tag in registry["tags"])


# ---------------------------------------------------------------------
# TEST 2 — AI FAILED → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_ai_failed(monkeypatch):

    # Fake SSH: retry fails (exit_status=1, stderr present)
    fake_ssh = FakeSSH(stdout_data="", stderr_data="still failing", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    def fake_ask_ai_for_recovery(context):
        return make_plan_ai_failed()

    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)

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
    # The natural install_failed block adds tags like:
    #   "install_failed_command_0"
    assert any(tag.startswith("install_failed_command_") for tag in registry["tags"])


# ---------------------------------------------------------------------
# TEST 3 — AI FALLBACK → native failure classification
# ---------------------------------------------------------------------
def test_ai_hook_ai_fallback(monkeypatch):

    # Fake SSH: original failure persists, AI falls back
    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    def fake_ask_ai_for_recovery(context):
        return make_plan_fallback()

    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)

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

    # We expect a failure classification, but with ai_fallback metadata
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True


# ---------------------------------------------------------------------
# TEST 4 — AI ABORT → tagged failure
# ---------------------------------------------------------------------
def test_ai_hook_ai_abort(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    def fake_ask_ai_for_recovery(context):
        return make_plan_abort()

    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)

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

    # Abort should still be a failure, but with AI metadata present
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "ai_" in "".join(registry["tags"])


# ---------------------------------------------------------------------
# TEST 5 — UNKNOWN ACTION → fallback tagging
# ---------------------------------------------------------------------
def test_ai_hook_ai_unknown_action(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    def fake_ask_ai_for_recovery(context):
        return make_plan_unknown()

    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)

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

    # Unknown action should set ai_fallback True
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True

