#!/usr/bin/env python3
"""
reconflow - orquestador de reconocimiento para labs autorizados.

Dado un objetivo (IP o host de un lab que CONTROLAS o tienes autorización
para probar), ejecuta nmap por fases y, según los servicios detectados,
sugiere o lanza la enumeración específica, generando un reporte.

Uso solo autorizado: HTB, Vulnlab, Cyber Warfare Labs, TryHackMe, máquinas
propias... Nunca contra sistemas sin permiso explícito. Lee el README.

Ejemplos:
    python reconflow.py 10.10.11.23
    python reconflow.py 10.10.11.23 --full --run
    python reconflow.py 10.10.11.23 -o html --output box.html
"""

import argparse
import sys

from core import __version__
from core.scanner import scan
from core.enumerator import load_rules, plan, execute
from core.reporter import print_console, save_markdown, save_html
from core.utils import (init_colors, banner, is_valid_target,
                        is_private_or_lab, C)


def parse_args():
    p = argparse.ArgumentParser(
        prog="reconflow",
        description="Orquesta nmap + enumeración por servicio en labs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="IP o hostname del objetivo (lab autorizado)")
    p.add_argument("-r", "--rules", default="rules.json",
                   help="archivo de reglas de enumeración (def: rules.json)")
    p.add_argument("--full", action="store_true",
                   help="escaneo de los 65535 puertos (más lento)")
    p.add_argument("--run", action="store_true",
                   help="ejecuta la enumeración ligera (run_default); sin esto, solo sugiere")
    p.add_argument("--timeout", type=int, default=900,
                   help="timeout de nmap en segundos (def: 900)")
    p.add_argument("--enum-timeout", type=int, default=120,
                   help="timeout por comando de enumeración (def: 120)")
    p.add_argument("-o", "--format", choices=["console", "md", "html"],
                   default="console", help="formato de salida (def: console)")
    p.add_argument("--output", help="ruta del archivo de reporte (md/html)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="asume autorización (salta la confirmación)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("-v", "--version", action="version",
                   version=f"reconflow {__version__}")
    return p.parse_args()


def confirm_authorized(target: str, assume_yes: bool) -> bool:
    """Pide confirmación de autorización salvo que sea claramente un lab."""
    if assume_yes or is_private_or_lab(target):
        return True
    print(f"{C.YELLOW}[!] {target} no parece una IP privada de lab.{C.RESET}")
    print(f"{C.YELLOW}    Escanear sistemas sin autorización es ilegal.{C.RESET}")
    try:
        ans = input(f"{C.BOLD}    ¿Tienes autorización para probarlo? [y/N] {C.RESET}")
    except EOFError:
        return False
    return ans.strip().lower() in ("y", "yes", "s", "si", "sí")


def main():
    args = parse_args()
    init_colors(args.no_color)
    if not args.no_banner:
        print(banner())

    if not is_valid_target(args.target):
        print(f"{C.RED}[!] Objetivo no válido: {args.target}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if not confirm_authorized(args.target, args.yes):
        print(f"{C.RED}[!] Cancelado. Solo objetivos autorizados.{C.RESET}")
        sys.exit(1)

    try:
        rules = load_rules(args.rules)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{C.RED}[!] No pude cargar las reglas: {exc}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        result = scan(args.target, full=args.full, timeout=args.timeout)
    except RuntimeError as exc:
        print(f"{C.RED}[!] {exc}{C.RESET}", file=sys.stderr)
        sys.exit(2)

    actions = plan(result.ports, args.target, rules)

    if args.run and actions:
        print(f"{C.GREY}[*] Ejecutando enumeración ligera...{C.RESET}")
        execute(actions, timeout=args.enum_timeout)

    print_console(result, actions, ran=args.run)

    if args.format != "console":
        out = args.output or f"reconflow_{args.target}.{args.format}"
        saver = {"md": save_markdown, "html": save_html}[args.format]
        saver(result, actions, args.run, out)
        print(f"{C.GREEN}[+] Reporte guardado en {out}{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrumpido.{C.RESET}")
        sys.exit(130)
