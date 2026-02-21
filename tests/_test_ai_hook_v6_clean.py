def test_ai_hook_ai_fixed(monkeypatch):
    from aws_boto3_modular_multi_processing.sequential_master_modules.tests.test_ai_hook_v6 import FakeSSH, MINIMAL_COMMANDS, make_plan_ai_fixed

    # 1. Fake SSH client
    fake_ssh = FakeSSH()

    # 2. Fake Paramiko module
    class FakeParamikoModule:
        def SSHClient(self):
            return fake_ssh

        class AutoAddPolicy:
            pass

    fake_paramiko = FakeParamikoModule()

    # 3. Patch module2f's paramiko BEFORE importing module2f
    monkeypatch.setattr(
        "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP.paramiko",
        fake_paramiko,
        raising=False,
    )

    # 4. Import module2f AFTER patching paramiko
    import importlib
    m2f = importlib.reload(
        importlib.import_module(
            "aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP"
        )
    )

    # 5. Patch ask_ai_for_recovery
    monkeypatch.setattr(m2f, "ask_ai_for_recovery", lambda ctx: make_plan_ai_fixed())

    # 6. Run the function
    result = m2f.resurrection_install_tomcat(
        ip="1.2.3.4",
        private_ip="10.0.0.1",
        instance_id="i-test",
        WATCHDOG_TIMEOUT=5,
        replayed_commands=MINIMAL_COMMANDS,
        extra_tags=["from_module2e"],
    )

    # 7. Assertions
    assert isinstance(result, tuple)
    _, _, registry = result

    assert registry["status"] == "install_success"
    assert registry["ai_metadata"]["ai_invoked"] is True
    assert "installation_completed" in registry["tags"]
    assert any(tag.startswith("ai_") for tag in registry["tags"])

