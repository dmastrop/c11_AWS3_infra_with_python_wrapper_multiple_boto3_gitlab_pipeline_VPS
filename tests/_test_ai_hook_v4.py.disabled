import sys
import inspect

# ----------------------------------------------------------------------
# 1. Remove ALL previously loaded copies of module2f to avoid shadowing
# ----------------------------------------------------------------------
for key in list(sys.modules.keys()):
    if "module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP" in key:
        del sys.modules[key]

# ----------------------------------------------------------------------
# 2. Import the module cleanly and deterministically
# ----------------------------------------------------------------------
import aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP as m2f

# Import the function under test
from aws_boto3_modular_multi_processing.sequential_master_modules.module2f_resurrection_install_tomcat_multi_threaded_version4d_MCP import (
    resurrection_install_tomcat,
)

# ----------------------------------------------------------------------
# 3. Fake SSH client for controlled testing
# ----------------------------------------------------------------------
class FakeSSH:
    def __init__(self, stdout_data, stderr_data, exit_status):
        self.stdout_data = stdout_data
        self.stderr_data = stderr_data
        self.exit_status = exit_status

    def exec_command(self, *args, **kwargs):
        return (None, self.stdout_data, self.stderr_data)

    def close(self):
        pass


# ----------------------------------------------------------------------
# 4. Tests
# ----------------------------------------------------------------------
def test_ai_hook_ai_fixed(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    # Patch SSHClient
    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    # Fake AI hook
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": True,
            "ai_failed": False,
            "ai_fallback": False,
            "new_stdout": "AI repaired stdout",
            "new_stderr": "",
            "new_exit_status": 0,
        }

    # Fake metadata builder
    def fake_meta(*args, **kwargs):
        return {"meta": "stubbed"}

    # Patch both helpers directly on the module object
    monkeypatch.setattr(m2f, "_invoke_ai_hook", fake_ai_hook)
    monkeypatch.setattr(m2f, "_build_ai_metadata_and_tags", fake_meta)

    # Run the function under test
    result = resurrection_install_tomcat(
        instance_id="i-123",
        ip="1.2.3.4",
        extra_tags={},
    )

    assert result["exit_status"] == 0
    assert result["stdout"] == "AI repaired stdout"


def test_ai_hook_ai_failed(monkeypatch):

    fake_ssh = FakeSSH(stdout_data="", stderr_data="synthetic error", exit_status=1)

    monkeypatch.setattr("paramiko.SSHClient", lambda *args, **kwargs: fake_ssh)

    # Fake AI hook: fails to repair
    def fake_ai_hook(**kwargs):
        return {
            "ai_fixed": False,
            "ai_failed": True,
            "ai_fallback": False,
            "new_stdout": "",
            "new_stderr": "still failing",
            "new_exit_status": 1,
        }

    def fake_meta(*args, **kwargs):
        return {"meta": "stubbed"}

    monkeypatch.setattr(m2f, "_invoke_ai_hook", fake_ai_hook)
    monkeypatch.setattr(m2f, "_build_ai_metadata_and_tags", fake_meta)

    result = resurrection_install_tomcat(
        instance_id="i-123",
        ip="1.2.3.4",
        extra_tags={},
    )

    assert result["exit_status"] == 1
    assert result["stderr"] == "still failing"

