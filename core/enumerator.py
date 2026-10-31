"""Motor de enumeración: mapea servicios detectados a acciones concretas.

Lee rules.json y, para cada puerto abierto, decide qué comandos de
enumeración aplican. Con run=True ejecuta los marcados run_default cuyo
binario esté disponible; el resto quedan como sugerencias.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from .runner import run as run_cmd, CmdResult
from .scanner import Port
from .utils import have


@dataclass
class Action:
    service: str
    port: int
    tool: str
    cmdline: str
    note: str
    run_default: bool
    available: bool
    result: Optional[CmdResult] = None


def load_rules(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _canonical(service: str, port: int, aliases: dict) -> Optional[str]:
    """Normaliza el nombre de servicio de nmap a una clave de reglas."""
    s = (service or "").lower()
    if s in aliases:
        s = aliases[s]
    return s


# Mapa de respaldo por puerto cuando nmap no identifica el servicio.
_PORT_FALLBACK = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "smb", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 8080: "http", 8443: "https",
}


def plan(ports: List[Port], target: str, rules: dict) -> List[Action]:
    """Genera la lista de acciones de enumeración para los puertos dados."""
    aliases = rules.get("aliases", {})
    services = rules.get("services", {})
    actions: List[Action] = []

    for p in ports:
        key = _canonical(p.service, p.port, aliases)
        if key not in services:
            key = _PORT_FALLBACK.get(p.port)
        if not key or key not in services:
            continue
        for entry in services[key]:
            cmdline = entry["cmd"].format(target=target, port=p.port)
            tool = entry["tool"]
            actions.append(Action(
                service=key,
                port=p.port,
                tool=tool,
                cmdline=cmdline,
                note=entry.get("note", ""),
                run_default=entry.get("run_default", False),
                available=have(tool),
            ))
    return actions


def execute(actions: List[Action], timeout: int = 120) -> None:
    """Ejecuta in situ las acciones run_default disponibles (con --run)."""
    for a in actions:
        if a.run_default and a.available:
            a.result = run_cmd(a.cmdline.split(), timeout=timeout)
