from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class ExecutionDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class SimulationResult:
    simulated: bool = True
    executed: bool = False
    message: str = "Request was evaluated and audited; no command was executed."


class Simulator:
    def execute(self, _command: str) -> SimulationResult:
        return SimulationResult()


class AllowlistedSandboxAdapter:
    """Optional toy subprocess adapter. It is disabled unless constructed with enabled=True."""

    ALLOWLIST = {"python --version", "node --version", "git status"}

    def __init__(self, root: str | Path, *, enabled: bool = False):
        self.root = Path(root).resolve(strict=True)
        self.enabled = enabled
        if not self.root.is_dir():
            raise ValueError("sandbox root must be an existing directory")

    def execute(self, command: str) -> subprocess.CompletedProcess[str]:
        if not self.enabled:
            raise ExecutionDisabled("sandbox adapter is disabled")
        if command not in self.ALLOWLIST:
            raise ExecutionDisabled("command is not in the sandbox allowlist")
        argv = command.split()
        return subprocess.run(
            argv,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
