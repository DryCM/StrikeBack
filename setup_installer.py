"""
StrikeBack — Instalador gráfico de consola.
Se compila a setup.exe con PyInstaller.
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

# ── Rich para interfaz bonita ────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

console = Console() if _RICH else None

LOGO = """[bold cyan]
  ╔═╗╔╦╗╦═╗╦╦╔═╔═╗╔╗ ╔═╗╔═╗╦╔═
  ╚═╗ ║ ╠╦╝║╠╩╗║╣ ╠╩╗╠═╣║  ╠╩╗
  ╚═╝ ╩ ╩╚═╩╩ ╩╚═╝╚═╝╩ ╩╚═╝╩ ╩[/bold cyan]
[dim]  Agente IA de Ciberseguridad para Windows — Instalador v1.0[/dim]"""

BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent


def say(msg: str, style: str = ""):
    if _RICH:
        console.print(msg)
    else:
        # Strip Rich markup for plain fallback
        import re
        print(re.sub(r"\[/?[^\]]+\]", "", msg))


def run_step(label: str, cmd: list[str]) -> bool:
    say(f"[bold yellow]►[/bold yellow] {label}...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(BASE_DIR),
        )
        if result.returncode != 0:
            say(f"[bold red]  ✗ Error:[/bold red] {result.stderr.strip()[:300]}")
            return False
        say(f"[bold green]  ✓ {label} completado.[/bold green]")
        return True
    except FileNotFoundError as e:
        say(f"[bold red]  ✗ Comando no encontrado: {e}[/bold red]")
        return False


def main():
    os.chdir(BASE_DIR)

    if _RICH:
        console.print(Panel(Text.from_markup(LOGO), border_style="bold cyan", box=box.DOUBLE_EDGE))
    else:
        print("=" * 60)
        print("  STRIKEBACK - Instalador")
        print("=" * 60)

    say("")
    say("[bold]Directorio:[/bold] " + str(BASE_DIR))
    say("")

    # ── Paso 1: Detectar Python ────────────────────────────────────────────
    python = sys.executable
    say(f"[bold]Python detectado:[/bold] {python}")

    # ── Paso 2: Crear entorno virtual si no existe ────────────────────────
    venv_dir = BASE_DIR / ".venv"
    pip_exe  = venv_dir / "Scripts" / "pip.exe"

    if not venv_dir.exists():
        # Intentar con uv primero, luego venv nativo
        uv = shutil.which("uv")
        if uv:
            ok = run_step("Creando entorno virtual (uv)", [uv, "venv", str(venv_dir)])
        else:
            ok = run_step("Creando entorno virtual", [python, "-m", "venv", str(venv_dir)])
        if not ok:
            say("[bold red]No se pudo crear el entorno virtual.[/bold red]")
            input("\nPresiona ENTER para salir...")
            sys.exit(1)
    else:
        say("[bold green]  ✓ Entorno virtual ya existe.[/bold green]")

    # ── Paso 3: Instalar dependencias ─────────────────────────────────────
    req_file = BASE_DIR / "requirements.txt"
    if not req_file.exists():
        say("[bold red]No se encontró requirements.txt[/bold red]")
        input("\nPresiona ENTER para salir...")
        sys.exit(1)

    ok = run_step(
        "Instalando dependencias (puede tardar ~1 minuto)",
        [str(pip_exe), "install", "-r", str(req_file), "--quiet"],
    )
    if not ok:
        say("[bold red]Fallo la instalación de dependencias.[/bold red]")
        input("\nPresiona ENTER para salir...")
        sys.exit(1)

    # ── Paso 4: Instalar PyInstaller y compilar StrikeBack.exe ───────────
    ok = run_step(
        "Instalando PyInstaller",
        [str(pip_exe), "install", "pyinstaller", "--quiet"],
    )
    if not ok:
        say("[bold red]Fallo la instalación de PyInstaller.[/bold red]")
        input("\nPresiona ENTER para salir...")
        sys.exit(1)

    # Convertir PNG a ICO
    ico_path = BASE_DIR / "StrikeBack.ico"
    png_path  = BASE_DIR / "StrikeBack.png"
    if png_path.exists() and not ico_path.exists():
        run_step(
            "Generando icono StrikeBack.ico",
            [
                python, "-c",
                "from PIL import Image; img=Image.open(r'" + str(png_path) + "').convert('RGBA'); "
                "img.save(r'" + str(ico_path) + "', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"
            ],
        )

    pyinstaller_exe = venv_dir / "Scripts" / "pyinstaller.exe"
    main_py = BASE_DIR / "main.py"
    dist_exe = BASE_DIR / "dist" / "StrikeBack.exe"

    pyinstaller_cmd = [
        str(pyinstaller_exe),
        "--onefile", "--console",
        "--name=StrikeBack",
        "--add-data=StrikeBack.png;.",
        "--add-data=config.py;.",
        "--hidden-import=win32evtlog",
        "--hidden-import=win32security",
        "--hidden-import=win32api",
        "--hidden-import=pystray",
        "--hidden-import=PIL",
        "--hidden-import=openai",
        "--hidden-import=psutil",
        "--hidden-import=watchdog",
        "--hidden-import=rich",
        str(main_py),
    ]
    if ico_path.exists():
        pyinstaller_cmd.insert(4, f"--icon={ico_path}")

    ok = run_step(
        "Compilando StrikeBack.exe (esto tarda ~1 minuto, por favor espera...)",
        pyinstaller_cmd,
    )
    if not ok or not dist_exe.exists():
        say("[bold red]Fallo la compilación del ejecutable.[/bold red]")
        input("\nPresiona ENTER para salir...")
        sys.exit(1)

    # Verificar el .exe generado
    size_mb = dist_exe.stat().st_size / 1024 / 1024
    say(f"[bold green]  ✓ StrikeBack.exe generado: {size_mb:.1f} MB → [cyan]{dist_exe}[/cyan][/bold green]")

    # ── Paso 5: Verificar config.py ───────────────────────────────────────
    cfg = BASE_DIR / "config.py"
    api_configurada = False
    if cfg.exists():
        content = cfg.read_text(encoding="utf-8", errors="ignore")
        api_configurada = "TU_API_KEY_AQUI" not in content

    say("")
    if _RICH:
        console.print(Panel(
            Text.from_markup(
                "[bold green]✓ Instalación y compilación completadas[/bold green]\n\n"
                + (
                    "[bold yellow]⚠  API Key pendiente:[/bold yellow] edita [cyan]config.py[/cyan] "
                    "y sustituye [dim]TU_API_KEY_AQUI[/dim] por tu clave Groq/OpenAI.\n"
                    if not api_configurada else
                    "[bold green]✓ API Key configurada.[/bold green]\n"
                )
                + f"\n[bold]Ejecutable listo:[/bold]\n"
                + f"  [bold cyan]dist\\StrikeBack.exe[/bold cyan]  ({size_mb:.1f} MB)\n"
            ),
            border_style="green",
            box=box.ROUNDED,
            title="[bold green]StrikeBack listo[/bold green]",
        ))
    else:
        print("\n[OK] Instalacion y compilacion completadas.")
        if not api_configurada:
            print("[!] Edita config.py y añade tu API key de Groq/OpenAI.")
        print(f"\nEjecuta: dist\\StrikeBack.exe  ({size_mb:.1f} MB)")

    say("")
    input("Presiona ENTER para salir...")


if __name__ == "__main__":
    main()
