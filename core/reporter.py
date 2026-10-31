"""Salida por consola y reportes en Markdown / HTML."""

from datetime import datetime, timezone

from .utils import C


def print_console(scan, actions, ran: bool):
    print(f"\n{C.BOLD}Objetivo:{C.RESET} {C.CYAN}{scan.target}{C.RESET}")
    print(f"{C.GREY}{'=' * 56}{C.RESET}")

    if not scan.ports:
        print(f"{C.YELLOW}  No se encontraron puertos abiertos.{C.RESET}\n")
        return

    print(f"{C.BOLD}Puertos abiertos ({len(scan.ports)}):{C.RESET}")
    for p in scan.ports:
        banner = f"  {C.GREY}{p.banner}{C.RESET}" if p.banner else ""
        print(f"  {C.GREEN}{p.port:>5}/{p.proto}{C.RESET}  "
              f"{C.BLUE}{p.service or '?':<14}{C.RESET}{banner}")

    print(f"\n{C.BOLD}Enumeración sugerida:{C.RESET}")
    by_port = {}
    for a in actions:
        by_port.setdefault(a.port, []).append(a)

    for port in sorted(by_port):
        print(f"\n  {C.CYAN}:{port}{C.RESET}")
        for a in by_port[port]:
            if a.result is not None:
                tag = f"{C.GREEN}[ejecutado]{C.RESET}"
            elif not a.available:
                tag = f"{C.YELLOW}[falta {a.tool}]{C.RESET}"
            else:
                tag = f"{C.GREY}[sugerido]{C.RESET}"
            print(f"    {tag} {a.cmdline}")
            if a.note:
                print(f"              {C.GREY}# {a.note}{C.RESET}")

    if ran:
        print(f"\n{C.GREY}[*] Las acciones ejecutadas van completas en el "
              f"reporte (usa -o md/html).{C.RESET}")
    print()


def _md(scan, actions, ran) -> str:
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# reconflow — reporte de {scan.target}",
        f"*Generado: {now}*",
        "",
        "## Puertos abiertos",
        "",
        "| Puerto | Servicio | Versión |",
        "|---|---|---|",
    ]
    for p in scan.ports:
        lines.append(f"| {p.port}/{p.proto} | {p.service or '?'} | {p.banner or ''} |")
    lines += ["", "## Enumeración", ""]

    by_port = {}
    for a in actions:
        by_port.setdefault(a.port, []).append(a)
    for port in sorted(by_port):
        lines.append(f"### Puerto {port}")
        for a in by_port[port]:
            status = ("ejecutado" if a.result is not None
                      else ("falta " + a.tool if not a.available else "sugerido"))
            lines.append(f"- **[{status}]** `{a.cmdline}`  \n  _{a.note}_")
            if a.result is not None:
                out = (a.result.stdout or a.result.skipped or "").strip()
                if out:
                    snippet = "\n".join(out.splitlines()[:30])
                    lines.append("")
                    lines.append("```")
                    lines.append(snippet)
                    lines.append("```")
        lines.append("")
    return "\n".join(lines)


def save_markdown(scan, actions, ran, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_md(scan, actions, ran))


def save_html(scan, actions, ran, path):
    rows = "\n".join(
        f"<tr><td>{p.port}/{p.proto}</td><td>{p.service or '?'}</td>"
        f"<td>{p.banner or ''}</td></tr>"
        for p in scan.ports
    )
    blocks = []
    by_port = {}
    for a in actions:
        by_port.setdefault(a.port, []).append(a)
    for port in sorted(by_port):
        items = []
        for a in by_port[port]:
            status = ("ejecutado" if a.result is not None
                      else ("falta " + a.tool if not a.available else "sugerido"))
            out = ""
            if a.result is not None:
                txt = (a.result.stdout or a.result.skipped or "").strip()
                if txt:
                    esc = (txt.replace("&", "&amp;").replace("<", "&lt;")
                           .replace(">", "&gt;"))
                    snippet = "\n".join(esc.splitlines()[:30])
                    out = f"<pre>{snippet}</pre>"
            items.append(
                f'<li><span class="tag {status.split()[0]}">{status}</span> '
                f'<code>{a.cmdline}</code><div class="note">{a.note}</div>{out}</li>'
            )
        blocks.append(f"<h3>Puerto {port}</h3><ul>{''.join(items)}</ul>")

    now = datetime.now(timezone.utc).isoformat()
    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>reconflow · {scan.target}</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem;line-height:1.5}}
 h1{{color:#58a6ff}} h3{{color:#58a6ff;margin-top:1.5rem}}
 .muted{{color:#8b949e;font-size:.9rem}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{text-align:left;padding:.4rem .7rem;border-bottom:1px solid #30363d}}
 th{{color:#8b949e}} code{{color:#7ee787}} ul{{list-style:none;padding-left:0}}
 li{{margin:.6rem 0;border-left:2px solid #30363d;padding-left:.8rem}}
 .note{{color:#8b949e;font-size:.85rem}}
 .tag{{font-size:.7rem;padding:.1rem .4rem;border-radius:4px;margin-right:.4rem;background:#30363d}}
 .tag.ejecutado{{background:#1a7f37}} .tag.falta{{background:#9e6a03}}
 pre{{background:#161b22;padding:.6rem;border-radius:6px;overflow-x:auto;font-size:.8rem}}
</style></head><body>
<h1>reconflow</h1>
<p class="muted">Objetivo: <strong>{scan.target}</strong> · {len(scan.ports)} puertos abiertos · {now}</p>
<table><thead><tr><th>Puerto</th><th>Servicio</th><th>Versión</th></tr></thead>
<tbody>{rows}</tbody></table>
{''.join(blocks)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
