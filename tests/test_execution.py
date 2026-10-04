import pytest

from policypilot.execution import AllowlistedSandboxAdapter, ExecutionDisabled, Simulator


def test_default_simulator_never_executes():
    result = Simulator().execute("rm -rf fixture")
    assert result.simulated is True
    assert result.executed is False


def test_sandbox_is_disabled_by_default(tmp_path):
    adapter = AllowlistedSandboxAdapter(tmp_path)
    with pytest.raises(ExecutionDisabled, match="disabled"):
        adapter.execute("python --version")


def test_sandbox_rejects_non_allowlisted_command_even_when_enabled(tmp_path):
    adapter = AllowlistedSandboxAdapter(tmp_path, enabled=True)
    with pytest.raises(ExecutionDisabled, match="allowlist"):
        adapter.execute("rm -rf fixture")
