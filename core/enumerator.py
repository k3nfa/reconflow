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
    """Carga rules.json validando su estructura básica."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "services" not in data:
        raise ValueError("rules.json no tiene la clave 'services' esperada.")
    if not isinstance(data.get("services"), dict):
        raise ValueError("'services' en rules.json debe ser un objeto.")
    return data


def _service_key(port, aliases: dict, services: dict) -> Optional[str]:
    """Clave de reglas para un puerto, resolviendo alias, TLS y fallback.

    Un servicio HTTP sobre TLS (p.ej. nmap 'http' con tunnel='ssl' en el 443)
    se mapea a 'https' para que las recomendaciones usen el esquema correcto.
    """
    s = (port.service or "").lower()
    if s in aliases:
        s = aliases[s]
    if getattr(port, "is_tls", False) and s == "http":
        s = "https"
    if s in services:
        return s
    # Fallback por número de puerto cuando nmap no identifica el servicio.
    fb = _PORT_FALLBACK.get(port.port)
    if fb and getattr(port, "is_tls", False) and fb == "http":
        fb = "https"
    return fb if fb in services else None


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
        key = _service_key(p, aliases, services)
        if not key:
            continue
        for entry in services[key]:
            tool = entry.get("tool")
            cmd = entry.get("cmd")
            if not tool or not cmd:
                continue  # entrada de regla mal formada: la saltamos
            try:
                cmdline = cmd.format(target=target, port=p.port)
            except (KeyError, IndexError):
                # placeholder desconocido en la plantilla: no rompemos el plan
                cmdline = cmd
            actions.append(Action(
                service=key,
                port=p.port,
                tool=tool,
                cmdline=cmdline,
                note=entry.get("note", ""),
                run_default=bool(entry.get("run_default", False)),
                available=have(tool),
            ))
    return actions


def execute(actions: List[Action], timeout: int = 120) -> None:
    """Ejecuta in situ las acciones run_default disponibles (con --run)."""
    for a in actions:
        if a.run_default and a.available:
            a.result = run_cmd(a.cmdline.split(), timeout=timeout)
