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


# pytest7f, 7g.1 7g.2 and 7h plan helper functions
def make_plan_cleanup_only():
    return {
        "action": "cleanup_and_retry",
        "cleanup": [
            "rm -f /var/lib/dpkg/lock",
            "rm -f /var/lib/dpkg/lock-frontend",
        ],
        "retry": [],
    }

# pytest7i
def make_plan_retry_only():
    return {
        "action": "cleanup_and_retry",
        "cleanup": [],
        "retry": [
            "echo AI_RETRY_1",
            "echo AI_RETRY_2",
        ],
    }

# pytest8 retry_with_modified_command with no command
def make_plan_retry_modified_empty():
    return {
        "action": "retry_with_modified_command",
        "retry": ""
    }


# pytest8b, 8c, 8d helper fake plans are included with the pytest test case function (see below)







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
    

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest1) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest2) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")
    
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
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest3) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest4) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest5) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest6) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7B) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")

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

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7C) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7D) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")


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

    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7e) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")

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





# ---------------------------------------------------------------------
# TEST 7F — CLEANUP_AND_RETRY → cleanup succeeds, retry empty → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_fallback_cleanup_only(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # 3 original failures + 2 cleanup successes
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → cleanup only
    def fake_send(self, context):
        return make_plan_cleanup_only()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7F) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None

    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 2
    assert "rm -f /var/lib/dpkg/lock" in ai_commands[0]
    assert "rm -f /var/lib/dpkg/lock-frontend" in ai_commands[1]

    # 3 original + 2 cleanup
    assert fake_ssh.call_count == 5





# ---------------------------------------------------------------------
# TEST 7G.1 — CLEANUP_AND_RETRY → cleanup empty, retry succeeds → install_success
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_retry_only_success(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script:
    # 3 original failures + retry1 success + retry2 success
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
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

    # Patch MCPClient.send → retry only
    def fake_send(self, context):
        return make_plan_retry_only()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7G.1) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")

    # Assertions
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_failed_command"] is None

    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 2
    assert "echo AI_RETRY_1" in ai_commands[0]
    assert "echo AI_RETRY_2" in ai_commands[1]

    # 3 original + 2 retry
    assert fake_ssh.call_count == 5


# ---------------------------------------------------------------------
# TEST 7G.2 — CLEANUP_AND_RETRY → cleanup empty, retry1 fails → install_failed
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_retry_only_failure(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script:
    # 3 original failures + retry1 failure (retry2 never runs)
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("retry1 fail", "synthetic error", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry only
    def fake_send(self, context):
        return make_plan_retry_only()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7G.2) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")
    
    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_failed_command"] == "echo AI_RETRY_1"

    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 2
    assert "echo AI_RETRY_1" in ai_commands[0]
    assert "echo AI_RETRY_2" in ai_commands[1]

    # 3 original + 1 retry
    assert fake_ssh.call_count == 4



# ---------------------------------------------------------------------
# TEST 7H — CLEANUP_AND_RETRY → cleanup present, retry empty → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_cleanup_present_retry_empty(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Script:
    # 3 original failures + 2 cleanup successes
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → cleanup only
    def fake_send(self, context):
        return make_plan_cleanup_only()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result
    
    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7H) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None

    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 2
    assert "rm -f /var/lib/dpkg/lock" in ai_commands[0]
    assert "rm -f /var/lib/dpkg/lock-frontend" in ai_commands[1]

    # 3 original + 2 cleanup
    assert fake_ssh.call_count == 5





# ---------------------------------------------------------------------
# TEST 7I — CLEANUP_AND_RETRY → cleanup empty, retry empty → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_empty_cleanup_empty_retry(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # 3 original failures only — no cleanup, no retry
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    # Patch paramiko
    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → cleanup_and_retry with BOTH lists empty
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [],
            "retry": [],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
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

    _, _, registry = result

    # Print registry for debugging
    print("\n===== REGISTRY ENTRY (pytest7I) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("================================\n")
    
    # -------------------------
    # Assertions
    # -------------------------

    # Natural failure classification
    assert registry["status"] == "install_failed"

    # AI metadata
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None

    # No cleanup or retry commands
    ai_commands = registry["ai_metadata"]["ai_commands"]
    assert len(ai_commands) == 0

    # Only the 3 original attempts should have executed
    assert fake_ssh.call_count == 3




# ---------------------------------------------------------------------
# TEST 7J — CLEANUP_AND_RETRY → cleanup empty, retry key missing → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_missing_retry_key(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: 3 original failures only
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    # Patch paramiko
    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry key missing
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [],
            # retry key intentionally omitted
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
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

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7J) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None
    assert registry["ai_metadata"]["ai_commands"] == []

    # Only original 3 attempts executed
    assert fake_ssh.call_count == 3



# ---------------------------------------------------------------------
# TEST 7K — CLEANUP_AND_RETRY → cleanup empty, retry=None → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_retry_none(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: 3 original failures only
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    # Patch paramiko
    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry=None
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [],
            "retry": None,
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
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

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7K) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None
    assert registry["ai_metadata"]["ai_commands"] == []

    # Only original 3 attempts executed
    assert fake_ssh.call_count == 3


# ---------------------------------------------------------------------
# TEST 7L — CLEANUP_AND_RETRY → cleanup empty, retry=["   "] → fallback
# ---------------------------------------------------------------------

def test_ai_hook_cleanup_and_retry_retry_whitespace(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force a clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: 3 original failures only
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    # Patch paramiko
    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry=["   "]
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [],
            "retry": ["   "],   # whitespace-only retry command
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
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

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7L) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "cleanup_and_retry"
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_failed_command"] is None
    assert registry["ai_metadata"]["ai_commands"] == []

    # Only original 3 attempts executed
    assert fake_ssh.call_count == 3


#####  end of TEST 7L

# ---------------------------------------------------------------------
# TEST 7M — CLEANUP_AND_RETRY → mixed retry commands, valid first → SUCCESS
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_mixed_success_valid_first(monkeypatch):
    """
    This test validates the core rule of cleanup_and_retry normalization:

        Derived fallback occurs ONLY when *all* retry commands are invalid
        after normalization. If ANY retry command is valid, fallback must NOT occur.

    Normalization removes:
        - whitespace-only commands
        - empty strings
        - None
        - strings that become empty after strip()

    Valid commands remain.

    Therefore:
        retry=["echo OK", "   "]  → normalized_retry_cmds=["echo OK"]
        → NOT fallback
        → retry sequence MUST execute
        → FakeSSH2 controls success/failure
        → ai_fallback=False
        → ai_commands must contain ONLY the valid command ("echo OK")

    This test includes cleanup commands as well, so the full pipeline is exercised.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # ⭐ Force clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # 3 original failures + 2 cleanup successes + 1 valid retry success
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("echo OK", "", 0),   # retry succeeds
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan: cleanup + mixed retry commands
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo OK",   # valid
                "   ",       # whitespace → removed by normalization
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7M) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False

    # ai_commands must contain ONLY the valid retry command
    ai_cmds = registry["ai_metadata"]["ai_commands"]
    #assert ai_cmds == ["echo OK"]
    assert ai_cmds == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
        "echo OK",
    ]

    # No ai_failed_command
    assert registry["ai_metadata"]["ai_failed_command"] is None




# ---------------------------------------------------------------------
# TEST 7N — CLEANUP_AND_RETRY → mixed retry commands, valid first → FAILURE
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_mixed_failure_valid_first(monkeypatch):
    """
    Same normalization rule as 7M:

        retry=["echo FAIL", "   "] → normalized_retry_cmds=["echo FAIL"]

    Because at least one valid command remains:
        → NOT fallback
        → retry sequence MUST execute
        → FakeSSH2 determines failure
        → install_failed
        → ai_fallback=False
        → ai_failed_command="echo FAIL"
        → ai_commands=["echo FAIL"]
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: retry fails
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("echo FAIL", "synthetic error", 1),   # retry fails
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo FAIL",  # valid
                "   ",        # whitespace → removed
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7N) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT FAILURE
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False

    # ai_commands must contain ONLY the valid retry command
    #assert registry["ai_metadata"]["ai_commands"] == ["echo FAIL"] 
    ai_cmds = registry["ai_metadata"]["ai_commands"]
    assert ai_cmds == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
        "echo FAIL",
    ]

    # ai_failed_command must be the valid retry command
    assert registry["ai_metadata"]["ai_failed_command"] == "echo FAIL"




# ---------------------------------------------------------------------
# TEST 7O — CLEANUP_AND_RETRY → mixed retry commands, whitespace first → SUCCESS
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_mixed_success_valid_second(monkeypatch):
    """
    Same normalization rule:

        retry=["   ", "echo OK"] → normalized_retry_cmds=["echo OK"]

    Because at least one valid command remains:
        → NOT fallback
        → retry sequence MUST execute
        → FakeSSH2 determines success
        → install_success
        → ai_fallback=False
        → ai_commands=["echo OK"]
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: retry succeeds
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("echo OK", "", 0),   # retry succeeds
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "   ",       # whitespace → removed
                "echo OK",   # valid
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7O) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False

    # ai_commands must contain ONLY the valid retry command and the cleanup commands
    #assert registry["ai_metadata"]["ai_commands"] == ["echo OK"]
    ai_cmds = registry["ai_metadata"]["ai_commands"]
    #assert ai_cmds == ["echo OK"]
    assert ai_cmds == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
        "echo OK",
    ]
    # ai_failed_command must be None
    assert registry["ai_metadata"]["ai_failed_command"] is None







# ---------------------------------------------------------------------
# TEST 7P — CLEANUP_AND_RETRY → whitespace cleanup + whitespace retry + valid commands → SUCCESS
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_whitespace_cleanup_and_retry_success(monkeypatch):
    """
    This test validates the NEW cleanup normalization symmetry.

    Cleanup list:
        ["   ", "rm -f /var/lib/dpkg/lock", "rm -f /var/lib/dpkg/lock-frontend"]
        → normalized_cleanup_cmds = ["rm -f /var/lib/dpkg/lock",
                                     "rm -f /var/lib/dpkg/lock-frontend"]

    Retry list:
        ["   ", "echo OK"]
        → normalized_retry_cmds = ["echo OK"]

    Because at least one valid retry command remains:
        → NOT fallback
        → retry sequence MUST execute
        → FakeSSH2 determines success
        → install_success
        → ai_fallback=False

    ai_commands must contain ONLY:
        - the 2 valid cleanup commands
        - the 1 valid retry command
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # 3 original failures + 2 cleanup successes + 1 retry success = 6 calls
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("echo OK", "", 0),
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "   ",  # whitespace → removed
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "   ",      # whitespace → removed
                "echo OK",  # valid
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7P) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False

    # ai_commands must contain ONLY valid cleanup + valid retry
    assert registry["ai_metadata"]["ai_commands"] == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
        "echo OK",
    ]

    assert registry["ai_metadata"]["ai_failed_command"] is None



# ---------------------------------------------------------------------
# TEST 7Q — CLEANUP_AND_RETRY → whitespace cleanup + whitespace retry → FALLBACK
# ---------------------------------------------------------------------
def test_ai_hook_cleanup_and_retry_whitespace_cleanup_and_retry_fallback(monkeypatch):
    """
    This test validates cleanup normalization + derived fallback.

    Cleanup list:
        ["   ", "rm -f /var/lib/dpkg/lock", "rm -f /var/lib/dpkg/lock-frontend"]
        → normalized_cleanup_cmds = ["rm -f /var/lib/dpkg/lock",
                                     "rm -f /var/lib/dpkg/lock-frontend"]

    Retry list:
        ["   ", "   "] → normalized_retry_cmds = []

    Because ALL retry commands are invalid:
        → derived fallback MUST trigger
        → ai_fallback=True
        → install_failed
        → ai_commands contains ONLY valid cleanup commands
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    # 3 original failures + 2 cleanup successes = 5 calls
    script = [
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("", "synthetic error", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
    ]
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "   ",  # whitespace → removed
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "   ",  # whitespace → removed
                "   ",  # whitespace → removed
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest7Q) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT FALLBACK
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True

    # ai_commands must contain ONLY valid cleanup commands
    assert registry["ai_metadata"]["ai_commands"] == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
    ]

    assert registry["ai_metadata"]["ai_failed_command"] is None




#### End of Test7 suite

# ---------------------------------------------------------------------
# TEST 8 — retry_with_modified_command with no command  → install_failed with fallback
# ---------------------------------------------------------------------
def make_plan_retry_modified_empty():
    return {
        "action": "retry_with_modified_command",
        "retry": ""
    }

def test_ai_hook_retry_modified_empty(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH1: original command fails, but no retry command will be executed
    fake_ssh = FakeSSH()   # <-- FIXED

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry_with_modified_command but empty retry
    def fake_send(self, context):
        return make_plan_retry_modified_empty()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest8) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "retry_with_modified_command"
    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None

    tags = registry["tags"]
    assert "ai_fallback_true" in tags
    assert "ai_fallback" in tags
    assert "ai_plan_action:retry_with_modified_command" in tags





# ---------------------------------------------------------------------
# TEST 8B — retry_with_modified_command with missing retry key → install_failed with fallback
# ---------------------------------------------------------------------
def make_plan_retry_modified_missing():
    return {
        "action": "retry_with_modified_command"
        # no "retry" key at all
    }

def test_ai_hook_retry_modified_missing(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH1: original command fails, but no retry command will be executed
    fake_ssh = FakeSSH()

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry_with_modified_command but missing retry key
    def fake_send(self, context):
        return make_plan_retry_modified_missing()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest8B) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    # Assertions
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "retry_with_modified_command"
    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None

    tags = registry["tags"]
    assert "ai_fallback_true" in tags
    assert "ai_fallback" in tags
    assert "ai_plan_action:retry_with_modified_command" in tags





# ---------------------------------------------------------------------
# TEST 8C — retry_with_modified_command with retry=None → install_failed with fallback
# ---------------------------------------------------------------------
def make_plan_retry_modified_none():
    return {
        "action": "retry_with_modified_command",
        "retry": None
    }

def test_ai_hook_retry_modified_none(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    fake_ssh = FakeSSH()

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → retry=None
    def fake_send(self, context):
        return make_plan_retry_modified_none()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest8C) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "retry_with_modified_command"
    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None

    tags = registry["tags"]
    assert "ai_fallback_true" in tags
    assert "ai_fallback" in tags
    assert "ai_plan_action:retry_with_modified_command" in tags



# ---------------------------------------------------------------------
# TEST 8D — retry_with_modified_command with whitespace retry → install_failed with fallback
# ---------------------------------------------------------------------
def make_plan_retry_modified_whitespace():
    return {
        "action": "retry_with_modified_command",
        "retry": "   "   # whitespace only
    }

def test_ai_hook_retry_modified_whitespace(monkeypatch):
    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    fake_ssh = FakeSSH()

    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh
        class AutoAddPolicy:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Patch MCPClient.send → whitespace retry
    def fake_send(self, context):
        return make_plan_retry_modified_whitespace()

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest8D) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("====================================\n")

    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_plan_action"] == "retry_with_modified_command"
    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None

    tags = registry["tags"]
    assert "ai_fallback_true" in tags
    assert "ai_fallback" in tags
    assert "ai_plan_action:retry_with_modified_command" in tags





# ---------------------------------------------------------------------
# TEST 9A — CLEANUP_AND_RETRY (heuristic#4 stub case that is reovered with AI) → mixed retry commands → SUCCESS
# ---------------------------------------------------------------------
def test_ai_hook_passthrough_cleanup_and_retry_success(monkeypatch):
    """
    Heuristic#4 stub case which is then recovered with AI.

    stderr is blank

    Behavior mirrors pytest7O:
        retry=["   ", "echo OK"] → normalized_retry_cmds=["echo OK"]
        cleanup succeeds
        retry succeeds
        install_success
        ai_fallback=False
        ai_failed_command=None
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script: retry succeeds, stderr whitelisted
   

    # Need to remove all stderr output to hit the fallback and not heuristic#4
    script = [
        ("", "", 1),
        ("", "", 1),
        ("", "", 1),
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("echo OK", "", 0),
    ]

    ## This will still hit the heuristic#4
    #script = [
    #    ("", "Reading state information...", 1),
    #    ("", "Reading state information...", 1),
    #    ("", "Reading state information...", 1),
    #    ("cleanup1 ok", "", 0),
    #    ("cleanup2 ok", "", 0),
    #    ("echo OK", "", 0),
    #]
    
    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # Fake plan
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "   ",      # whitespace → removed
                "echo OK",  # valid
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4", private_ip="10.0.0.1",
        instance_id="i-test", WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9A) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False

    # ai_commands must contain ONLY valid cleanup + valid retry
    assert registry["ai_metadata"]["ai_commands"] == [
        "rm -f /var/lib/dpkg/lock",
        "rm -f /var/lib/dpkg/lock-frontend",
        "echo OK",
    ]

    assert registry["ai_metadata"]["ai_failed_command"] is None



# ---------------------------------------------------------------------
# TEST 9A.2 — CLEANUP_AND_RETRY (heuristic#4 stub case) → AI FAIL → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_passthrough_cleanup_and_retry_fail(monkeypatch):
    """
    Heuristic#4 stub case where AI is invoked but FAILS to repair the issue.

    stderr is blank → triggers the stub branch of heuristic#4.
    AI plan = cleanup_and_retry with VALID retry commands.
    Cleanup succeeds.
    Retry FAILS (exit_status=1).
    AI returns ai_fixed=False, ai_fallback=False.
    Final result = install_failed (native fallthrough block).
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    #   - 3 stub attempts (exit=1, stderr="")
    #   - 2 cleanup successes
    #   - 1 retry FAILURE (exit=1)
    script = [
        ("", "", 1),   # attempt 1 → stub
        ("", "", 1),   # attempt 2 → stub
        ("", "", 1),   # attempt 3 → stub → HOOK invoked
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry failed", "some retry error", 1),   # retry fails → ai_fixed=False
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: VALID retry command → NOT fallback
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo WILL_NOT_FIX",   # valid → hook will execute it
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=["echo test"],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9A.2) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=======================================\n")

    # EXPECT stub and not install_failed. This is because this case is where there is no stderr output and exit status is 1
    # So the organic registry_entry of stub status has to be retained if AI/MCP HOOK is unable to recover and fix the command. Stub
    # is for failed commands that have no apparent cause (no stderr output is one case of a valid stub case).
    #assert registry["status"] == "install_failed"
    assert registry["status"] == "stub"


    # AI metadata checks
    ai_meta = registry["ai_metadata"]
    assert ai_meta["ai_invoked"] is True
    assert ai_meta["ai_fallback"] is False
    assert ai_meta["ai_failed_command"] == "echo WILL_NOT_FIX"

    # Stub forensic tags must be present
    tags = registry["tags"]
    assert "silent_failure" in tags
    assert "exit_status_nonzero_stderr_blank" in tags
    assert "echo test" in tags




# ---------------------------------------------------------------------
# TEST 9B — Heuristic5 (exit 0 + non‑whitelisted stderr) + AI success
# ---------------------------------------------------------------------
def test_ai_hook_heuristic5_success(monkeypatch):
    """
    Heuristic5: exit_status=0 + non‑whitelisted stderr.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry succeeds.
    Final result = install_success.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:
    #   - original command: exit=0 + dirty stderr 3 times→ heuristic5
    #   - cleanup1 ok
    #   - cleanup2 ok
    #   - retry ok

    script = [
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 1
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 2
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 3 → HOOK
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: valid cleanup + retry → AI success
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo AI_RETRY_OK",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=["echo test"],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9B) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] is None

    # Heuristic5 tags must be merged into success tags
    tags = registry["tags"]
    assert "stderr_detected" in tags
    assert "non_whitelisted_stderr" in tags
    assert "exit_status_zero" in tags



# ---------------------------------------------------------------------
# TEST 9B.2 — Heuristic5 + AI fail → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_heuristic5_fail(monkeypatch):
    """
    Heuristic5: exit_status=0 + non‑whitelisted stderr.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry FAILS.
    AI returns ai_fixed=False, ai_fallback=False.
    Final result = install_failed.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # FakeSSH2 script:

    script = [
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 1
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 2
        ("", "DIRTY_ERROR_LINE", 0),   # attempt 3 → HOOK
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry failed", "retry error", 1),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: valid retry → NOT fallback
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo WILL_NOT_FIX",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=["echo test"],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9B.2) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=======================================\n")

    # EXPECT FAILURE
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] == "echo WILL_NOT_FIX"

    # Heuristic5 tags must be present
    tags = registry["tags"]
    assert "stderr_detected" in tags
    assert "non_whitelisted_stderr" in tags
    assert "exit_status_zero" in tags





# ---------------------------------------------------------------------
# TEST 9C — Heuristic3 + AI success → install_success
# ---------------------------------------------------------------------
def test_ai_hook_heuristic3_success(monkeypatch):
    """
    Heuristic3: strace-wrapped command, exit=0, stderr empty,
    but trace log contains non-whitelisted lines.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry succeeds.
    Final result = install_success.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Synthetic dirty trace log (non-whitelisted)
    dirty_trace = "1234 write(2, \"FATAL: bad thing\\n\", 18) = 18\n"

    # FakeSSH2 script:
    #   - 3 attempts of the strace wrapper → exit=0, stderr=""
    #   - 3 trace reads (cat <trace_path>) → dirty trace
    #   - cleanup1 ok
    #   - cleanup2 ok
    #   - retry ok
    script = [
        ("", "", 0),  # attempt 1: strace wrapper
        (dirty_trace, "", 0),  # attempt 1: cat trace, note it is nonwhitelisted as dirty_trace
        ("", "", 0),  # attempt 2: strace wrapper
        (dirty_trace, "", 0),  # attempt 2: cat trace
        ("", "", 0),  # attempt 3: strace wrapper
        (dirty_trace, "", 0),  # attempt 3: cat trace
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: valid cleanup + retry → AI success
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo AI_RETRY_OK",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=[
            # This MUST be a strace-wrapped command otherwise heuristic3 will not be hit
            "strace -f -e write,execve -o /tmp/trace.log bash -c 'fail' 2>/dev/null && cat /tmp/trace.log >&2"
        ],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9C) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] is None

    # Heuristic3 tags must be merged into success tags
    tags = registry["tags"]
    #assert "strace_detected" in tags
    #assert "exit_status_zero" in tags
    #assert "non_whitelisted_trace" in tags
    assert "stderr_detected" in tags
    assert "non_whitelisted_stderr" in tags
    assert "exit_status_zero" in tags






# ---------------------------------------------------------------------
# TEST 9C.2 — Heuristic3 + AI fail → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_heuristic3_fail(monkeypatch):
    """
    Heuristic3: strace-wrapped command, exit=0, stderr empty,
    but trace log contains non-whitelisted lines.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry FAILS.
    Final result = install_failed.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    dirty_trace = "1234 write(2, \"FATAL: bad thing\\n\", 18) = 18\n"

    script = [
        ("", "", 0),  # attempt 1: strace wrapper
        (dirty_trace, "", 0),  # attempt 1: cat trace, note that this is nonwhitelisted as dirty_trace
        ("", "", 0),  # attempt 2: strace wrapper
        (dirty_trace, "", 0),  # attempt 2: cat trace
        ("", "", 0),  # attempt 3: strace wrapper
        (dirty_trace, "", 0),  # attempt 3: cat trace
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry failed", "retry error", 1),  # retry fails
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: valid retry → NOT fallback
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo WILL_NOT_FIX",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=[
            # This MUST be a strace-wrapped command otherwise heuristic3 will not be hit
            "strace -f -e write,execve -o /tmp/trace.log bash -c 'fail' 2>/dev/null && cat /tmp/trace.log >&2"
        ],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9C.2) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=======================================\n")

    # EXPECT FAILURE
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] == "echo WILL_NOT_FIX"

    tags = registry["tags"]
    #assert "strace_detected" in tags
    #assert "exit_status_zero" in tags
    #assert "non_whitelisted_trace" in tags
    assert "stderr_detected" in tags
    assert "non_whitelisted_stderr" in tags
    assert "exit_status_zero" in tags






# ---------------------------------------------------------------------
# TEST 9D — Heuristic2 + AI success → install_success (stderr is present with the strace log error information)
# ---------------------------------------------------------------------
def test_ai_hook_heuristic2_success(monkeypatch):
    """
    Heuristic2: strace-wrapped command, exit=1, stderr initially empty,
    but trace log contains non-whitelisted lines.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry succeeds.
    Final result = install_success.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # Synthetic dirty trace log (non-whitelisted)
    dirty_trace = '1234 write(2, "FATAL: bad thing\\n", 18) = 18\n'

    # FakeSSH2 script:
    #   - 3 attempts of the strace wrapper → exit=1, stderr=""
    #   - 3 trace reads (cat <trace_path>) → dirty trace
    #   - cleanup1 ok
    #   - cleanup2 ok
    #   - retry ok
    script = [
        ("", "", 1),          # attempt 1: strace wrapper (exit=1, stderr empty)
        (dirty_trace, "", 0), # attempt 1: cat trace
        ("", "", 1),          # attempt 2: strace wrapper
        (dirty_trace, "", 0), # attempt 2: cat trace
        ("", "", 1),          # attempt 3: strace wrapper
        (dirty_trace, "", 0), # attempt 3: cat trace
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry ok", "", 0),
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: valid cleanup + retry → AI success
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo AI_RETRY_OK",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=[
            # This MUST be a strace-wrapped command
            "strace -f -e write,execve -o /tmp/trace.log bash -c 'fail' 2>/dev/null && cat /tmp/trace.log >&2"
        ],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9D) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=====================================\n")

    # EXPECT SUCCESS
    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] is None

    # Heuristic2 tags must be present in the final success tags
    tags = registry["tags"]
    assert "fatal_exit_nonzero" in tags
    assert "exit_status_1" in tags
    assert "stderr_present" in tags
    # nonwhitelisted material should be captured
    assert any("nonwhitelisted_material" in t for t in tags)







# ---------------------------------------------------------------------
# TEST 9D.2 — Heuristic2 + AI fail → install_failed (not a stub because stderr is not empty; it has the strace log error data in it)
# ---------------------------------------------------------------------
def test_ai_hook_heuristic2_fail(monkeypatch):
    """
    Heuristic2: strace-wrapped command, exit=1, stderr initially empty,
    but trace log contains non-whitelisted lines.
    AI plan = cleanup_and_retry.
    Cleanup succeeds.
    Retry FAILS.
    Final result = install_failed.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    dirty_trace = '1234 write(2, "FATAL: bad thing\\n", 18) = 18\n'

    script = [
        ("", "", 1),          # attempt 1: strace wrapper (exit=1, stderr empty)
        (dirty_trace, "", 0), # attempt 1: cat trace
        ("", "", 1),          # attempt 2: strace wrapper
        (dirty_trace, "", 0), # attempt 2: cat trace
        ("", "", 1),          # attempt 3: strace wrapper
        (dirty_trace, "", 0), # attempt 3: cat trace
        ("cleanup1 ok", "", 0),
        ("cleanup2 ok", "", 0),
        ("retry failed", "retry error", 1),  # retry fails
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # MCP plan: cleanup_and_retry, but retry will fail
    def fake_send(self, context):
        return {
            "action": "cleanup_and_retry",
            "cleanup": [
                "rm -f /var/lib/dpkg/lock",
                "rm -f /var/lib/dpkg/lock-frontend",
            ],
            "retry": [
                "echo WILL_NOT_FIX",
            ],
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=[
            "strace -f -e write,execve -o /tmp/trace.log bash -c 'fail' 2>/dev/null && cat /tmp/trace.log >&2"
        ],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest9D.2) =====")
    for k, v in registry.items(): print(f"{k}: {v}")
    print("=======================================\n")

    # EXPECT FAILURE
    assert registry["status"] == "install_failed"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is False
    assert registry["ai_metadata"]["ai_failed_command"] == "echo WILL_NOT_FIX"

    tags = registry["tags"]
    assert "fatal_exit_nonzero" in tags
    assert "exit_status_1" in tags
    assert "stderr_present" in tags
    assert any("nonwhitelisted_material" in t for t in tags)





# ---------------------------------------------------------------------
# TEST 10A — AI returns {} → unknown action → fallback → install_failed
# ---------------------------------------------------------------------
def test_ai_hook_cornercase_empty_dict(monkeypatch):
    """
    Corner Case 10A:
    AI/MCP HOOK returns {}.
    Expected: Unknown action → fallback → install_failed.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # --------------------------------------------------------
    # FakeSSH2 script:
    # We force the native command to fail 3 times so AI HOOK fires.
    # stderr empty, exit=1 → triggers retry loop → AI HOOK invoked.
    # --------------------------------------------------------
    script = [
        ("", "", 1),  # attempt 1
        ("", "", 1),  # attempt 2
        ("", "", 1),  # attempt 3
        # After AI HOOK runs, since action is unknown, no cleanup/retry is executed.
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # --------------------------------------------------------
    # AI/MCP HOOK returns {}  → triggers Unknown Action path
    # --------------------------------------------------------
    def fake_send(self, context):
        print("FAKE_AI_HOOK: returning empty dict {}")
        return {}

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # --------------------------------------------------------
    # Run the function
    # --------------------------------------------------------
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=["echo test"],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest10A) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("=======================================\n")



    # EXPECT FAILURE (fallback) Rev3
    assert registry["status"] == "stub"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True
    assert registry["ai_metadata"]["ai_plan_action"] is None
    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None


    assert "ai_fallback" in registry["tags"]
    assert "ai_fallback_true" in registry["tags"]





# ---------------------------------------------------------------------
# TEST 10B — AI returns wrong types → unknown action → fallback → stub
# ---------------------------------------------------------------------
def test_ai_hook_cornercase_wrong_types(monkeypatch):
    """
    Corner Case 10B:
    AI/MCP HOOK returns a dict with wrong types.
    Expected: Unknown action → fallback → stub.
    """

    import sys
    import paramiko
    import importlib
    import my_mcp_client

    # Force clean import of module2f
    sys.modules.pop(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP",
        None
    )

    # --------------------------------------------------------
    # FakeSSH2 script:
    # Force native command to fail 3 times so AI HOOK fires.
    # --------------------------------------------------------
    script = [
        ("", "", 1),  # attempt 1
        ("", "", 1),  # attempt 2
        ("", "", 1),  # attempt 3
    ]

    fake_ssh = FakeSSH2(script)

    class FakeParamikoModule:
        def SSHClient(self): return fake_ssh
        class AutoAddPolicy: pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeParamikoModule().SSHClient)
    monkeypatch.setattr(paramiko, "AutoAddPolicy", FakeParamikoModule().AutoAddPolicy)

    # --------------------------------------------------------
    # AI/MCP HOOK returns WRONG TYPES
    # Examples:
    #   {"action": 123}
    #   {"cleanup": "not a list"}
    #   {"retry": {"nested": "object"}}
    # Any of these should trigger unknown action → fallback.
    # --------------------------------------------------------
    def fake_send(self, context):
        print("FAKE_AI_HOOK: returning wrong types")
        return {
            "action": 123,              # invalid type
            "cleanup": "not-a-list",    # invalid type
            "retry": {"bad": "object"}  # invalid type
        }

    monkeypatch.setattr(my_mcp_client.MCPClient, "send", fake_send)

    # Import module2f AFTER patching
    m2f = importlib.import_module(
        "aws_boto3_modular_multi_processing.sequential_master_modules."
        "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
    )

    # --------------------------------------------------------
    # Run the function
    # --------------------------------------------------------
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=["echo test"],
        extra_tags=["from_module2e"],
    )

    _, _, registry = result

    print("\n===== REGISTRY ENTRY (pytest10B) =====")
    for k, v in registry.items():
        print(f"{k}: {v}")
    print("=======================================\n")

    # --------------------------------------------------------
    # EXPECT NATIVE FALLBACK → stub
    # --------------------------------------------------------
    assert registry["status"] == "stub"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert registry["ai_metadata"]["ai_fallback"] is True

    #assert registry["ai_metadata"]["ai_plan_action"] is None
    assert registry["ai_metadata"]["ai_plan_action"] == 123

    assert registry["ai_metadata"]["ai_commands"] == []
    assert registry["ai_metadata"]["ai_failed_command"] is None

    tags = registry["tags"]
    assert "ai_fallback" in tags
    assert "ai_fallback_true" in tags

