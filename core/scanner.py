"""Escaneo con nmap por fases y parseo de su salida XML.

Fase 1 (rápida): descubre puertos abiertos.
Fase 2 (detallada): -sCV sobre los puertos abiertos para versión/servicio.

parse_nmap_xml() está separado para poder probarlo sin ejecutar nmap.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List

from .runner import run
from .utils import C, have


@dataclass
class Port:
    port: int
    proto: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    tunnel: str = ""          # p.ej. "ssl" cuando el servicio va sobre TLS

    @property
    def banner(self) -> str:
        bits = [b for b in (self.product, self.version, self.extra) if b]
        return " ".join(bits)

    @property
    def is_tls(self) -> bool:
        """True si el servicio corre sobre TLS/SSL (para elegir http vs https)."""
        if self.tunnel.lower() == "ssl":
            return True
        s = self.service.lower()
        return s in ("https", "ssl") or s.startswith("ssl/") or "https" in s


@dataclass
class HostScan:
    target: str
    ports: List[Port] = field(default_factory=list)


def parse_nmap_xml(xml_text: str, target: str = "") -> HostScan:
    """Convierte la salida XML de nmap en un HostScan.

    Lanza RuntimeError si el XML está vacío o es inválido, en vez de
    propagar un ParseError poco claro.
    """
    scan = HostScan(target=target)
    if not xml_text or not xml_text.strip():
        raise RuntimeError("nmap no devolvió salida XML (vacía).")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"XML de nmap inválido: {exc}")

    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for p in ports.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                try:
                    portid = int(p.get("portid"))
                except (TypeError, ValueError):
                    continue  # puerto sin id numérico: lo saltamos
                scan.ports.append(Port(
                    port=portid,
                    proto=p.get("protocol", "tcp"),
                    service=(svc.get("name") if svc is not None else "") or "",
                    product=(svc.get("product") if svc is not None else "") or "",
                    version=(svc.get("version") if svc is not None else "") or "",
                    extra=(svc.get("extrainfo") if svc is not None else "") or "",
                    tunnel=(svc.get("tunnel") if svc is not None else "") or "",
                ))
    scan.ports.sort(key=lambda x: x.port)
    return scan


def _nmap_xml(args: list, timeout: int) -> str:
    """Corre nmap pidiendo salida XML a stdout (-oX -)."""
    res = run(["nmap"] + args + ["-oX", "-"], timeout=timeout)
    if res.skipped:
        raise RuntimeError(res.skipped)
    return res.stdout


def scan(target: str, full: bool = False, timeout: int = 900) -> HostScan:
    """Ejecuta las dos fases de nmap y devuelve el HostScan combinado."""
    if not have("nmap"):
        raise RuntimeError("nmap no está instalado o no está en el PATH.")

    # Fase 1: descubrir puertos abiertos.
    port_flag = "-p-" if full else "--top-ports=1000"
    print(f"{C.GREY}[*] Fase 1: descubriendo puertos ({port_flag})...{C.RESET}")
    xml1 = _nmap_xml([target, port_flag, "-T4", "--open", "-n", "-Pn"], timeout)
    discovery = parse_nmap_xml(xml1, target)

    open_ports = [str(p.port) for p in discovery.ports]
    if not open_ports:
        return discovery

    # Fase 2: versión + scripts por defecto sobre los puertos abiertos.
    # Si la fase 2 falla (timeout, XML raro), NO perdemos la fase 1: devolvemos
    # al menos los puertos descubiertos, con un aviso.
    plist = ",".join(open_ports)
    print(f"{C.GREY}[*] Fase 2: versiones en {plist}...{C.RESET}")
    try:
        xml2 = _nmap_xml([target, "-p", plist, "-sCV", "-n", "-Pn"], timeout)
        detailed = parse_nmap_xml(xml2, target)
        if detailed.ports:
            return detailed
        return discovery  # fase 2 vacía: nos quedamos con el descubrimiento
    except RuntimeError as exc:
        print(f"{C.YELLOW}[!] Fase 2 falló ({exc}); uso los puertos de la "
              f"fase 1 sin versión.{C.RESET}")
        return discovery
