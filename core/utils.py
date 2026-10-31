"""Utilidades: colores, detección de binarios y validación de objetivo."""

import ipaddress
import os
import re
import shutil
import sys


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for a in ("GREEN", "RED", "YELLOW", "CYAN", "BLUE", "GREY", "BOLD", "RESET"):
            setattr(cls, a, "")


def init_colors(no_color: bool = False):
    if no_color or not sys.stdout.isatty():
        C.disable()
        return
    if os.name == "nt":
        try:
            import colorama  # type: ignore
            colorama.just_fix_windows_console()
        except Exception:
            C.disable()


def have(binary: str) -> bool:
    """True si el binario existe en el PATH."""
    return shutil.which(binary) is not None


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_target(target: str) -> bool:
    """Acepta IPv4, IPv6 o hostname válido."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(target))


def is_private_or_lab(target: str) -> bool:
    """True si la IP es privada/loopback (típico de un lab).

    Para hostnames o IPs públicas devuelve False, de modo que el programa
    pueda avisar y pedir confirmación explícita antes de escanear.
    """
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False  # hostname: no podemos asegurarlo sin resolver


def banner() -> str:
    return (
        f"{C.CYAN}{C.BOLD}"
        "  ___ ___ __ ___ _ _  ___ _    _____ _ _ _ \n"
        " | _ \\ __/ _/ _ \\ \\| |/ __| |  / _ \\ \\ \\ / /\n"
        " |   / _| (_| (_) | .` | (__| |_| (_) \\ \\ /\\ / \n"
        " |_|_\\___\\__\\___/|_|\\_|\\___|____\\___/ \\_/\\_/  \n"
        f"{C.RESET}{C.GREY}     orquestador de recon para labs  ·  by K3NFA{C.RESET}\n"
    )
