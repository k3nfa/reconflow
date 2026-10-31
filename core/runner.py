"""Ejecución controlada de comandos externos.

Se ejecuta SIEMPRE como lista de argumentos (sin shell=True) para evitar
inyección de comandos, con timeout y captura de salida.
"""

import subprocess
from dataclasses import dataclass, field
from typing import List


@dataclass
class CmdResult:
    cmd: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    skipped: str = ""              # motivo si no se ejecutó

    @property
    def cmdline(self) -> str:
        return " ".join(self.cmd)


def run(cmd: List[str], timeout: int = 120) -> CmdResult:
    """Ejecuta un comando (lista de argumentos). Nunca usa shell."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CmdResult(cmd, proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError:
        return CmdResult(cmd, 127, skipped=f"binario no encontrado: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return CmdResult(cmd, -1, timed_out=True,
                         skipped=f"timeout tras {timeout}s")
