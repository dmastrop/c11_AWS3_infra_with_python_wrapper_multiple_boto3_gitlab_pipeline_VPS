import types
import importlib



## This FakeSSH class is used for pytest test cases 1-5
class FakeSSH:
    """
    FakeSSH_v4:
    - ORIGINAL command ("echo test") → fail
    - AI retry command ("echo AI_FIXED") → succeed
    - Implements enough of Paramiko's channel API to avoid watchdog triggers
    """

    def __init__(self):
        self.call_count = 0

    def set_missing_host_key_policy(self, policy):
        # Paramiko normally stores the policy; we don't need it. This fixes an SSH execption that is encounted during module2f
        # SSH connection setup loop.
        self._policy = policy

    def connect(self, *args, **kwargs):
        # No-op: FakeSSH doesn't need to establish a real connection
        return None

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

## This more advance FakeSSH2 class is used for the cleanup_and_retry pytest test cases 6-7
class FakeSSH2:
    """
    FakeSSH2 — designed specifically for cleanup_and_retry tests. Pytest6 and pytest7 test cases

    Why a second class?
    -------------------
    - FakeSSH_v4 is intentionally simple:
        * ORIGINAL command ("echo test") → fail
        * AI retry command ("echo AI_FIXED") → succeed
      That works perfectly for tests 1–5, which only need a single
      "original vs AI retry" distinction.

    - cleanup_and_retry is fundamentally different:
        * It may execute MULTIPLE cleanup commands.
        * It may execute MULTIPLE retry commands.
        * We want to control success/failure per SSH call, in sequence.

    Design:
    -------
    - FakeSSH2 is initialized with a "script": a list of
      (stdout_data, stderr_data, exit_status) tuples.
    - Each call to exec_command() consumes the next tuple in the script.
    - This lets us simulate:
        * all cleanup commands succeeding
        * retry commands succeeding (pytest6)
        * retry commands failing (pytest7)
    - We do NOT parse the command string here; module2f already knows
      which command it is running. FakeSSH2 only controls the outcome.
    """

    def __init__(self, script):
        """
        :param script: list of (stdout_data, stderr_data, exit_status)
                       one entry per SSH exec_command() call.
        """
        self.call_count = 0
        self.script = script

    def set_missing_host_key_policy(self, policy):
        self._policy = policy

    def connect(self, *args, **kwargs):
        return None

    def exec_command(self, command, timeout=None):
        self.call_count += 1

        # Select the tuple for this call. If more calls are made than
        # entries in the script, we reuse the last entry to avoid IndexError.
        idx = min(self.call_count - 1, len(self.script) - 1)
        stdout_data, stderr_data, exit_status = self.script[idx]

        # stdout channel
        stdout_channel = types.SimpleNamespace(
            recv_exit_status=lambda: exit_status,
            exit_status_ready=lambda: True,
            recv_ready=lambda: True,
            recv=lambda size: stdout_data.encode(),
            settimeout=lambda *_args, **_kwargs: None,
        )

        stdout = types.SimpleNamespace(
            read=lambda: stdout_data.encode(),
            channel=stdout_channel,
        )

        # stderr channel
        stderr_channel = types.SimpleNamespace(
            recv_exit_status=lambda: exit_status,
            exit_status_ready=lambda: True,
            recv_ready=lambda: True,
            recv=lambda size: stderr_data.encode(),
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
# Helper: build a fake AI plan for different scenarios. These are used for pytest test cases 1-5
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


## These helpers are used for pytest test cases 6-7 with the cleanup_and_retry actions

# pytest6 There are the plan cleanup and retry commands sent to the node
def make_plan_cleanup_and_retry_success():
    # Multiple cleanup commands + multiple retry commands
    return {
        "action": "cleanup_and_retry",
        "cleanup": [
            "rm -f /var/lib/dpkg/lock",
            "rm -f /var/lib/dpkg/lock-frontend",
        ],
        "retry": [
            "echo AI_RETRY_1",
            "echo AI_RETRY_2",
        ],
    }

# pytest7 These are the plan cleanup and retry commands sent to the node
def make_plan_cleanup_and_retry_failure():
    # Same plan shape; FakeSSH2 script will control failure vs success
    return {
        "action": "cleanup_and_retry",
        "cleanup": [
            "rm -f /var/lib/dpkg/lock",
            "rm -f /var/lib/dpkg/lock-frontend",
        ],
        "retry": [
            "echo AI_RETRY_1",
            "echo AI_RETRY_2",
        ],
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

    # original assertions restored
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "installation_completed" in registry["tags"]
    assert any(tag.startswith("ai_") for tag in registry["tags"])







## ---------------------------------------------------------------------
## TEST 2 — AI FAILED → install_failed
## ---------------------------------------------------------------------
#def test_ai_hook_ai_failed(monkeypatch):
#
#    # Fake SSH: retry fails (exit_status=1, stderr present)
#    fake_ssh = FakeSSH(stdout_data="", stderr_data="still failing", exit_status=1)
#
#    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)
#
#    def fake_ask_ai_for_recovery(context):
#        return make_plan_ai_failed()
#
#    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)
#
#    result = resurrection_install_tomcat(
#        ip="1.2.3.4",
#        private_ip="10.0.0.1",
#        instance_id="i-test",
#        WATCHDOG_TIMEOUT=5,
#        replayed_commands=MINIMAL_COMMANDS,
#        extra_tags=["from_module2e"],
#    )
#
#    assert isinstance(result, tuple)
#    _, _, registry = result
#
#    # install_failed block assertions
#    assert registry["status"] == "install_failed"
#    assert registry["ai_metadata"]["ai_invoked"] is True
#    # The natural install_failed block adds tags like:
#    #   "install_failed_command_0"
#    assert any(tag.startswith("install_failed_command_") for tag in registry["tags"])




# ---------------------------------------------------------------------
# TEST 2 — AI FAILED → install_failed refactored to use the MCPClient (my_mcp_client.py) as the monkeypatched point
# ---------------------------------------------------------------------
def test_ai_hook_ai_failed(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client   # NEW: patch the MCP client directly

    # Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # 1. Fake SSH client: same FakeSSH as Test 1
    #    For this test, the AI retry command ("echo AI_FAILED") should still fail,
    #    and our FakeSSH already treats anything NOT containing "AI_FIXED" as a failure.
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

    # Patch MCPClient.send so _invoke_ai_hook receives the "failed" plan
    # This enables injection at the lowest python code level prior to actual rollout of the AI/MCP actual call to the
    # AI Gateway Service and call to LLM. 
    def fake_send(self, context):
        return make_plan_ai_failed()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # 3. Import module2f AFTER patching global paramiko + MCPClient
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # 4. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )


    # 5. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry =", registry)

    # install_failed block assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags

    # The original command should appear
    assert "echo test" in tags

    # Retry count tag (command_retry_3 for RETRY_LIMIT=3)
    assert any(tag.startswith("command_retry_") for tag in tags)

    # Exit status tag
    assert any(tag.startswith("exit_status_") for tag in tags)

    # Non‑whitelisted stderr material
    assert any(tag.startswith("nonwhitelisted_material:") for tag in tags)

    # Raw stderr snapshot lines (synthetic error)
    assert any("synthetic error" in tag for tag in tags)




## ---------------------------------------------------------------------
## TEST 3 — AI FALLBACK → native failure classification
## ---------------------------------------------------------------------
#def test_ai_hook_ai_fallback(monkeypatch):
#
#    # Fake SSH: original failure persists, AI falls back
#    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)
#
#    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)
#
#    def fake_ask_ai_for_recovery(context):
#        return make_plan_fallback()
#
#    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)
#
#    result = resurrection_install_tomcat(
#        ip="1.2.3.4",
#        private_ip="10.0.0.1",
#        instance_id="i-test",
#        WATCHDOG_TIMEOUT=5,
#        replayed_commands=MINIMAL_COMMANDS,
#        extra_tags=["from_module2e"],
#    )
#
#    assert isinstance(result, tuple)
#    _, _, registry = result
#
#    # We expect a failure classification, but with ai_fallback metadata
#    assert registry["ai_metadata"]["ai_invoked"] is True
#    assert registry["ai_metadata"]["ai_fallback"] is True


# ---------------------------------------------------------------------
# TEST 3 — AI FALLBACK → native failure classification; refactored to use the MCPClient (my_mcp_client.py) as monkeypatch
# ---------------------------------------------------------------------
def test_ai_hook_ai_fallback(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client   # NEW: patch the MCP client directly

    # Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # 1. Fake SSH client (same behavior as Test 1 & 2)
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

    # Patch MCPClient.send to return a FALLBACK plan
    def fake_send(self, context):
        return make_plan_fallback()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # 3. Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # 4. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # 5. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry =", registry)

    # AI metadata checks
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags
    assert "echo test" in tags
    assert any(tag.startswith("command_retry_") for tag in tags)
    assert any(tag.startswith("exit_status_") for tag in tags)
    assert any(tag.startswith("nonwhitelisted_material:") for tag in tags)
    assert any("synthetic error" in tag for tag in tags)






## ---------------------------------------------------------------------
## TEST 4 — AI ABORT → tagged failure
## ---------------------------------------------------------------------
#def test_ai_hook_ai_abort(monkeypatch):
#
#    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)
#
#    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)
#
#    def fake_ask_ai_for_recovery(context):
#        return make_plan_abort()
#
#    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)
#
#    result = resurrection_install_tomcat(
#        ip="1.2.3.4",
#        private_ip="10.0.0.1",
#        instance_id="i-test",
#        WATCHDOG_TIMEOUT=5,
#        replayed_commands=MINIMAL_COMMANDS,
#        extra_tags=["from_module2e"],
#    )
#
#    assert isinstance(result, tuple)
#    _, _, registry = result
#
#    # Abort should still be a failure, but with AI metadata present
#    assert registry["ai_metadata"]["ai_invoked"] is True
#    assert "ai_" in "".join(registry["tags"])


# ---------------------------------------------------------------------
# TEST 4 — AI ABORT → tagged failure
# ---------------------------------------------------------------------
def test_ai_hook_ai_abort(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client   # NEW: patch the MCP client directly

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # 1. Fake SSH client (same behavior as Test 1–3)
    fake_ssh = FakeSSH()

    # 2. Fake Paramiko module
    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # ⭐ Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # ⭐ Patch MCPClient.send to return an ABORT plan
    def fake_send(self, context):
        return make_plan_abort()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # 3. Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # 4. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # 5. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry =", registry)

    # AI metadata checks
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_plan_action"] == "abort"

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags
    assert "echo test" in tags
    assert any(tag.startswith("command_retry_") for tag in tags)
    assert any(tag.startswith("exit_status_") for tag in tags)
    assert any(tag.startswith("nonwhitelisted_material:") for tag in tags)
    assert any("synthetic error" in tag for tag in tags)

    # AI abort tag
    assert any("ai_plan_action:abort" in tag for tag in tags)





## ---------------------------------------------------------------------
## TEST 5 — UNKNOWN ACTION → fallback tagging
## ---------------------------------------------------------------------
#def test_ai_hook_ai_unknown_action(monkeypatch):
#
#    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)
#
#    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)
#
#    def fake_ask_ai_for_recovery(context):
#        return make_plan_unknown()
#
#    monkeypatch.setattr(m2f, "ask_ai_for_recovery", fake_ask_ai_for_recovery)
#
#    result = resurrection_install_tomcat(
#        ip="1.2.3.4",
#        private_ip="10.0.0.1",
#        instance_id="i-test",
#        WATCHDOG_TIMEOUT=5,
#        replayed_commands=MINIMAL_COMMANDS,
#        extra_tags=["from_module2e"],
#    )
#
#    assert isinstance(result, tuple)
#    _, _, registry = result
#
#    # Unknown action should set ai_fallback True
#    assert registry["ai_metadata"]["ai_invoked"] is True
#    assert registry["ai_metadata"]["ai_fallback"] is True





# ---------------------------------------------------------------------
# TEST 5 — UNKNOWN ACTION → fallback tagging (refactored)
# ---------------------------------------------------------------------
def test_ai_hook_ai_unknown_action(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client   # patch MCPClient directly

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # 1. Fake SSH client (same behavior as Tests 1–4)
    fake_ssh = FakeSSH()

    # 2. Fake Paramiko module
    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # ⭐ Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # ⭐ Patch MCPClient.send to return UNKNOWN ACTION
    def fake_send(self, context):
        return make_plan_unknown()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # 3. Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # 4. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # 5. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry =", registry)

    # Unknown action → fallback
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags
    assert "echo test" in tags
    assert any(tag.startswith("command_retry_") for tag in tags)
    assert any(tag.startswith("exit_status_") for tag in tags)
    assert any(tag.startswith("nonwhitelisted_material:") for tag in tags)
    assert any("synthetic error" in tag for tag in tags)

    # Unknown action tag
    assert any("ai_plan_action:some_unknown_action" in tag for tag in tags)



# ---------------------------------------------------------------------
# TEST 6 — CLEANUP_AND_RETRY → success after cleanup + multi-command retry
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_success(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script for FakeSSH2:
   # This has the stdout, stderr and exit_code tuple in response to the corresponding commands that are sent by using the fake plan
    # - First N calls: original command failures (heuristic4 trigger)
    # - Next calls: cleanup commands (success)
    # - Final calls: retry commands (success)
    #
    # For simplicity, we assume:
    #   * 3 original attempts (like other tests) → all fail
    #   * 2 cleanup commands → both succeed
    #   * 2 retry commands → both succeed
    script = [
        # Original command failures (3 attempts)
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        # Cleanup commands (2 commands) → success
        ("", "", 0),
        ("", "", 0),
        # Retry commands (2 commands) → success
        ("AI_RETRY_1 ok", "", 0),
        ("AI_RETRY_2 ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # Patch MCPClient.send to return cleanup_and_retry SUCCESS plan
    def fake_send(self, context):
        return make_plan_cleanup_and_retry_success()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry success) =", registry)

    # We expect overall success
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"

    # Forensic check: all AI commands (cleanup + retry) should be recorded
    ai_commands = registry["ai_metadata"]["ai_commands"]
    # We expect 4 commands: 2 cleanup + 2 retry
    assert len(ai_commands) == 4
    # Optional: sanity check that retry commands are present
    assert any("AI_RETRY_1" in cmd for cmd in ai_commands)
    assert any("AI_RETRY_2" in cmd for cmd in ai_commands)

    tags = registry["tags"]
    assert "installation_completed" in tags
    assert any("ai_plan_action:cleanup_and_retry" in tag for tag in tags)


# ---------------------------------------------------------------------
# TEST 7 — CLEANUP_AND_RETRY → cleanup succeeds, retry second command (last command) fails
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_failure(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script for FakeSSH2:
    # This has the stdout, stderr and exit_code tuple in response to the corresponding commands that are sent by using the fake plan
    # - 3 original failures
    # - 2 cleanup successes
    # - 2 retry commands, last one fails
    script = [
        # Original command failures (3 attempts)
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        # Cleanup commands (2 commands) → success
        ("", "", 0),
        ("", "", 0),
        # Retry commands (2 commands) → first ok, second fails
        ("AI_RETRY_1 ok", "", 0),
        ("AI_RETRY_2 still failing", "cleanup retry failed", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # Patch MCPClient.send to return cleanup_and_retry FAILURE plan
    def fake_send(self, context):
        return make_plan_cleanup_and_retry_failure()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry failure) =", registry)

    # We expect overall failure
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"

    ai_commands = registry["ai_metadata"]["ai_commands"]
    # Still expect all cleanup + retry commands to be recorded
    assert len(ai_commands) == 4
    assert any("AI_RETRY_1" in cmd for cmd in ai_commands)
    assert any("AI_RETRY_2" in cmd for cmd in ai_commands)

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present (final retry failed)
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags
    assert any(tag.startswith("command_retry_") for tag in tags)
    assert any(tag.startswith("exit_status_") for tag in tags)
    #assert any("cleanup retry failed" in tag for tag in tags)

    # AI tagging
    assert any("ai_plan_action:cleanup_and_retry" in tag for tag in tags)





# ---------------------------------------------------------------------
# TEST 7B — CLEANUP_AND_RETRY → cleanup succeeds, retry first command fails
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_failure_command1(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script for FakeSSH2:
    # This has the stdout, stderr and exit_code tuple in response to the corresponding commands that are sent by using the fake plan
    # - 3 original failures
    # - 2 cleanup successes
    # - 2 retry commands, last one fails
    script = [
        # Original command failures (3 attempts)
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        # Cleanup commands (2 commands) → success
        ("", "", 0),
        ("", "", 0),
        
        ("AI_RETRY_1 still failing", "cleanup retry failed", 1), # First retry command fails
        ("AI_RETRY_2 ok", "", 0),   # this will never be executed

        ## Retry commands (2 commands) → first ok, second fails
        #("AI_RETRY_1 ok", "", 0),
        #("AI_RETRY_2 still failing", "cleanup retry failed", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # Patch GLOBAL paramiko BEFORE importing module2f
    monkeypatch.setattr(paramiko, "SSHClient", fake_paramiko.SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", fake_paramiko.AutoAddPolicy)

    # Patch MCPClient.send to return cleanup_and_retry FAILURE plan
    def fake_send(self, context):
        return make_plan_cleanup_and_retry_failure()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry failure) =", registry)

    # We expect overall failure
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"

    ai_commands = registry["ai_metadata"]["ai_commands"]
    # Still expect all cleanup + retry commands to be recorded
    assert len(ai_commands) == 4
    assert any("AI_RETRY_1" in cmd for cmd in ai_commands)
    assert any("AI_RETRY_2" in cmd for cmd in ai_commands)

    tags = registry["tags"]

    # Heuristic 4 tags MUST be present (final retry failed)
    assert "fatal_exit_nonzero" in tags
    assert "stderr_present" in tags
    assert any(tag.startswith("command_retry_") for tag in tags)
    assert any(tag.startswith("exit_status_") for tag in tags)
    #assert any("cleanup retry failed" in tag for tag in tags)

    # AI tagging
    assert any("ai_plan_action:cleanup_and_retry" in tag for tag in tags)





# ---------------------------------------------------------------------
# TEST 7C — CLEANUP_AND_RETRY → cleanup fails, retry succeeds → install_success
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_cleanup_failure_retry_success(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # - 3 original failures
    # - cleanup1 fails, cleanup2 succeeds
    # - retry1 succeeds, retry2 succeeds
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "cleanup failed", 1),
        ("", "", 0),
        ("AI_RETRY_1 ok", "", 0),
        ("AI_RETRY_2 ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    def fake_send(self, context):
        return make_plan_cleanup_and_retry_success()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry cleanup failure + retry success) =", registry)

    # Expect overall success
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_failed_command"] is None

    # All cleanup + retry commands recorded
    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 4
    assert "rm -f /var/lib/dpkg/lock" in ai_commands[0]
    assert "rm -f /var/lib/dpkg/lock-frontend" in ai_commands[1]
    assert "echo AI_RETRY_1" in ai_commands[2]
    assert "echo AI_RETRY_2" in ai_commands[3]

    # FakeSSH2.call_count should be 3 original + 2 cleanup + 2 retry = 7
    assert fake_ssh.call_count == 7



# ---------------------------------------------------------------------
# TEST 7D — CLEANUP_AND_RETRY → cleanup fails, retry fails → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_cleanup_failure_retry_failure(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # - 3 original failures
    # - cleanup1 fails, cleanup2 succeeds
    # - retry1 succeeds, retry2 fails
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "cleanup failed", 1),
        ("", "", 0),
        ("AI_RETRY_1 ok", "", 0),
        ("AI_RETRY_2 still failing", "cleanup retry failed", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    def fake_send(self, context):
        return make_plan_cleanup_and_retry_failure()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry cleanup failure + retry failure) =", registry)

    # Expect overall failure
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"

    # ai_failed_command must be the failing retry command
    assert registry["ai_metadata"]["ai_failed_command"] == "echo AI_RETRY_2"

    # All cleanup + retry commands recorded
    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 4

    # FakeSSH2.call_count should be 3 original + 2 cleanup + 2 retry = 7
    assert fake_ssh.call_count == 7

    


# ---------------------------------------------------------------------
# TEST 7E — CLEANUP_AND_RETRY → cleanup fails, retry1 fails → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_cleanup_failure_retry1_failure(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # - 3 original failures
    # - cleanup1 fails, cleanup2 succeeds
    # - retry1 fails, retry2 never runs
    script = [
        ("", "synthetic error", 1),   # original 1
        ("", "synthetic error", 1),   # original 2
        ("", "synthetic error", 1),   # original 3
        ("", "cleanup failed", 1),    # cleanup1 fails
        ("", "", 0),                  # cleanup2 succeeds
        ("AI_RETRY_1 still failing", "cleanup retry failed", 1),  # retry1 fails
        # retry2 never executed
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Use same plan as pytest7d (cleanup + retry)
    def fake_send(self, context):
        return make_plan_cleanup_and_retry_failure()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    assert isinstance(result, tuple)
    _, _, registry = result

    print("DEBUG: registry (cleanup_and_retry cleanup failure + retry1 failure) =", registry)

    # Expect overall failure
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"

    # ai_failed_command must be retry1
    assert registry["ai_metadata"]["ai_failed_command"] == "echo AI_RETRY_1"

    # All cleanup + retry commands recorded
    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 4
    assert "rm -f /var/lib/dpkg/lock" in ai_commands[0]
    assert "rm -f /var/lib/dpkg/lock-frontend" in ai_commands[1]
    assert "echo AI_RETRY_1" in ai_commands[2]
    assert "echo AI_RETRY_2" in ai_commands[3]

    # FakeSSH2.call_count should be:
    # 3 original + 2 cleanup + 1 retry = 6
    assert fake_ssh.call_count == 6

