"""Code Sandbox Executor"""
import subprocess
from dataclasses import dataclass
from typing import Optional

@dataclass
class ExecutionResult:
    """Result of code execution."""
    success: bool
    stdout: str
    stderr: str
    error: Optional[str] = None

@dataclass
class SandboxConfig:
    """Sandbox configuration."""
    use_docker: bool = False
    timeout: int = 5
    max_memory: int = 128

class SandboxExecutor:
    """Executes code in isolated environment."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    def execute_python(self, code: str, timeout: Optional[int] = None) -> ExecutionResult:
        """Execute Python code in sandbox."""
        timeout = timeout or self.config.timeout

        try:
            result = subprocess.run(
                ["python", "-c", code],
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            return ExecutionResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Execution timeout",
                error="Timeout",
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                error=str(type(e).__name__),
            )
