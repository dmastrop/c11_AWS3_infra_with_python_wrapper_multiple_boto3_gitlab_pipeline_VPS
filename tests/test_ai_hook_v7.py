import types
import importlib




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
    import sys
    import paramiko
    import importlib
    import my_mcp_client   #NEW: patch the MCP client directly

    # Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # 1. Fake SSH client
    fake_ssh = FakeSSH()

    # 2. Fake Paramiko module
    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # NEW: Patch MCPClient.send so _invoke_ai_hook receives the correct plan
    # Doing the monkeypatch here is ideal as it is the lowest level possible for whitebox testing of module2f code
    # It also is necessary because _invoke_ai_hook cannot be monkeypatched as it is nested inside of 
    # def resurrection_install_tomcat, and ask_ai_for_recovery, which is called inside _invoke_ai_hook also has issues 
    # because even though ask_ai_for_recovery is NOT nested in any function inside module2f, monkeypatching it is still 
    # not working becasue it is called from inside nested _invoke_ai_hook.  my_mcp_client.py is a dummy for pytest (the 
    # real MCPClient AI Request Sender is in the module directory for production code) and that works fine for this
    # monkeypatch!

    def fake_send(self, context):
        return make_plan_ai_fixed()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # 3. Import module2f AFTER patching global paramiko + MCPClient
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    print("DEBUG: ask_ai_for_recovery =", m2f.ask_ai_for_recovery)
    print("DEBUG: _invoke_ai_hook =", getattr(m2f, "_invoke_ai_hook", None))
    print("DEBUG: _create_ssh_client =", getattr(m2f, "_create_ssh_client", None))

    print("DEBUG: calling resurrection_install_tomcat now")

    # 5. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # 6. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry =", registry)

    # ⭐ Your original assertions restored
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "installation_completed" in registry["tags"]
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

