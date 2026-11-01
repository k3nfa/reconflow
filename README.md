# reconflow

> Orquestador de reconocimiento para labs: `nmap` por fases + enumeración específica por servicio, con reporte automático.

`reconflow` automatiza el recon inicial que haces a mano en cada máquina: descubre puertos, identifica servicios y versiones, y según lo que encuentre te **sugiere o ejecuta** la enumeración apropiada (web, SMB, FTP, LDAP, bases de datos…). Al final te deja un reporte ordenado con los vectores a investigar.

![Python](https://img.shields.io/badge/python-3.8+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## ⚠️ Disclaimer legal

Herramienta **exclusivamente para sistemas que controlas o para los que tienes autorización escrita**: Hack The Box, Vulnlab, Cyber Warfare Labs, TryHackMe, tus propias máquinas virtuales, etc.

- Escanear o enumerar sistemas de terceros **sin permiso explícito es ilegal** en la mayoría de jurisdicciones.
- `reconflow` pide confirmación de autorización cuando el objetivo no es una IP de lab privada.
- El uso de esta herramienta es **tu entera responsabilidad**.

---

## ✨ Características

- 🛰️ Escaneo **en dos fases** con nmap (descubrimiento rápido → versión `-sCV`)
- 🧠 **Motor de reglas** que mapea cada servicio a su enumeración (editable en `rules.json`)
- 🧪 Modo **sugerir** (por defecto) o **ejecutar** (`--run`) la enumeración ligera
- 🔎 Detecta qué herramientas tienes instaladas; las que falten quedan como sugerencia
- 📄 Reporte en **consola**, **Markdown** y **HTML**
- 🪶 **Cero dependencias de Python** (solo stdlib); orquesta binarios externos
- 🔒 Comandos ejecutados **sin shell** (lista de argumentos) — sin inyección
- 🔐 **Detección de TLS**: un servicio HTTP sobre SSL (p.ej. el 443) usa `https` en las recomendaciones
- 🧯 **Robusto**: rutas basadas en la ubicación del proyecto (`pathlib`); un fallo en la fase 2 de nmap no tira la fase 1; XML inválido se reporta con claridad

---

## 📦 Instalación

```bash
git clone https://github.com/K3NFA/reconflow.git
cd reconflow
python reconflow.py --help
```

Requiere **Python 3.8+**. Las herramientas externas que orquesta (nmap, whatweb, feroxbuster, enum4linux-ng, netexec, etc.) ya vienen en Parrot/Kali o se instalan por separado. `reconflow` usa las que tengas y sugiere el resto.

---

## 🚀 Uso

```bash
# Recon básico (solo sugiere los comandos de enumeración)
python reconflow.py 10.10.11.23

# Escaneo completo (-p-) y ejecutando la enumeración ligera
python reconflow.py 10.10.11.23 --full --run

# Generar reporte HTML o Markdown
python reconflow.py 10.10.11.23 --run -o html --output box.html
python reconflow.py 10.10.11.23 -o md
```

### Opciones

| Opción | Descripción |
|---|---|
| `target` | IP o hostname del objetivo (lab autorizado) |
| `--full` | Escanea los 65535 puertos (más lento) |
| `--run` | Ejecuta la enumeración ligera; sin esto solo la sugiere |
| `-r, --rules` | Archivo de reglas (def: `rules.json`) |
| `--timeout` | Timeout de nmap en segundos (def: 900) |
| `--enum-timeout` | Timeout por comando de enumeración (def: 120) |
| `-o, --format` | `console` \| `md` \| `html` |
| `--output` | Ruta del reporte |
| `-y, --yes` | Asume autorización (salta la confirmación) |

---

## 🔁 Cómo funciona

```
          ┌─────────────┐   puertos    ┌──────────────┐  servicios  ┌───────────┐
 target → │  Fase 1     │ ───────────► │   Fase 2     │ ──────────► │  Motor de │
          │  nmap top   │   abiertos   │  nmap -sCV   │  +versión   │  reglas   │
          └─────────────┘              └──────────────┘             └─────┬─────┘
                                                                          │
                                        reporte (consola/md/html) ◄───────┘
                                        con comandos sugeridos/ejecutados
```

El **modo sugerir** (por defecto) no toca el objetivo más allá del nmap: te da la lista de comandos exactos a correr. Con `--run`, ejecuta solo los marcados como ligeros en `rules.json` (whatweb, cabeceras, info SMB…) y deja los ruidosos (nikto, fuzzing) como sugerencia para que los lances tú cuando quieras.

---

## 🧩 Añadir o cambiar reglas

Edita `rules.json`. Cada servicio tiene una lista de acciones con `{target}` y `{port}`:

```json
"http": [
  { "tool": "whatweb", "cmd": "whatweb -a3 http://{target}:{port}", "note": "Fingerprint web", "run_default": true },
  { "tool": "nikto",   "cmd": "nikto -h http://{target}:{port}",     "note": "Vulns web (ruidoso)", "run_default": false }
]
```

- `run_default: true` → se ejecuta con `--run` (debe ser ligero).
- `aliases` normaliza nombres de nmap (`microsoft-ds` → `smb`, etc.).

---

## 🗂️ Estructura

```
reconflow/
├── reconflow.py          # CLI / punto de entrada
├── rules.json            # reglas de enumeración (editable)
├── core/
│   ├── scanner.py        # nmap por fases + parseo XML
│   ├── enumerator.py     # aplica reglas a los servicios
│   ├── runner.py         # ejecución segura de comandos (sin shell)
│   ├── reporter.py       # salida consola/md/html
│   └── utils.py          # colores, detección de binarios, validación
├── LICENSE · README.md
```

---

## 🧪 Pruebas

Tests unitarios con `unittest` (XML simulado, sin ejecutar nmap):

```bash
python -m unittest discover -s tests -v
```

Cubren: parseo de XML (puertos abiertos, versión, detección de TLS por `tunnel`), manejo de XML vacío/inválido, resolución de `rules.json` desde cualquier directorio, mapeo de servicios a `https` sobre TLS, alias y fallback por puerto, y reglas mal formadas.

---

## 🛣️ Roadmap

- [ ] Paralelizar la enumeración entre puertos
- [ ] Integrar el CVE/exploit launcher (siguiente herramienta) sobre las versiones detectadas
- [ ] Perfiles de ruido (sigiloso / agresivo)
- [ ] Export a JSON para encadenar con otras herramientas

---

## 📄 Licencia

MIT — ver [LICENSE](LICENSE). Hecho para aprender seguridad ofensiva · **K3NFA**
