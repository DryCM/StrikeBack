"""
Dashboard en tiempo real con Rich — estilo Kali Linux.
Muestra: estado, cobertura ATT&CK, amenazas con % confianza, conexiones, procesos.
"""
import time
import threading
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.progress import BarColumn, Progress, TextColumn

import config


# ── Colores por severidad ─────────────────────────────────────────────────────
def _sev_style(sev: int) -> tuple[str, str]:
    if sev >= 9:  return ("bold red",        "⬟")
    if sev >= 7:  return ("bold orange3",    "▲")
    if sev >= 5:  return ("bold yellow",     "◆")
    return              ("dim white",        "●")

# ── Barra de confianza ASCII ──────────────────────────────────────────────────
def _conf_bar(pct: int, width: int = 8) -> Text:
    filled = int(pct / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    if pct >= 85:   style = "bold red"
    elif pct >= 65: style = "bold yellow"
    else:           style = "dim green"
    return Text(f"{bar} {pct:3d}%", style=style)

HEADER_ART = (
    "[bold cyan]"
    "  ╔═╗╔╦╗╦═╗╦╦╔═╔═╗╔╗ ╔═╗╔═╗╦╔═\n"
    "  ╚═╗ ║ ╠╦╝║╠╩╗║╣ ╠╩╗╠═╣║  ╠╩╗\n"
    "  ╚═╝ ╩ ╩╚═╩╩ ╩╚═╝╚═╝╩ ╩╚═╝╩ ╩[/bold cyan]"
    "  [dim]Agente IA de Ciberseguridad · MITRE ATT&CK · Kali Signatures[/dim]"
)


class Dashboard:
    def __init__(self, network_monitor=None, process_monitor=None, db=None):
        self.network_monitor  = network_monitor
        self.process_monitor  = process_monitor
        self.db               = db
        self._stop_event      = threading.Event()
        self._recent_threats: list = []
        self._lock            = threading.Lock()
        self._start_time      = datetime.now()
        self._total_threats   = 0
        self._critical_count  = 0

    # ------------------------------------------------------------------
    def add_threat(self, threat: dict):
        with self._lock:
            self._recent_threats.insert(0, threat)
            self._recent_threats = self._recent_threats[:200]
            self._total_threats += 1
            if threat.get("severity", 0) >= 8:
                self._critical_count += 1

    # ------------------------------------------------------------------
    def run(self):
        console = Console()
        with Live(
            self._build_layout(),
            console=console,
            refresh_per_second=0.5,
            screen=True,
        ) as live:
            while not self._stop_event.is_set():
                try:
                    live.update(self._build_layout())
                except Exception:
                    pass
                self._stop_event.wait(timeout=2)

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=6),
            Layout(name="body",    ratio=1),
            Layout(name="footer",  size=3),
        )
        layout["body"].split_row(
            Layout(name="left",   ratio=5),
            Layout(name="right",  ratio=7),
        )
        layout["left"].split_column(
            Layout(name="status",   size=11),
            Layout(name="coverage", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="threats",   ratio=3),
            Layout(name="bottom",    ratio=2),
        )
        layout["bottom"].split_row(
            Layout(name="network",  ratio=1),
            Layout(name="procs",    ratio=1),
        )

        layout["header"].update(self._render_header())
        layout["status"].update(self._render_status())
        layout["coverage"].update(self._render_coverage())
        layout["threats"].update(self._render_threats())
        layout["network"].update(self._render_network())
        layout["procs"].update(self._render_processes())
        layout["footer"].update(self._render_footer())

        return layout

    # ------------------------------------------------------------------
    def _render_header(self) -> Panel:
        return Panel(
            Align.center(Text.from_markup(HEADER_ART)),
            border_style="bold cyan",
            box=box.DOUBLE_EDGE,
        )

    # ------------------------------------------------------------------
    def _render_status(self) -> Panel:
        uptime = datetime.now() - self._start_time
        h, rem = divmod(int(uptime.total_seconds()), 3600)
        m, s   = divmod(rem, 60)

        with self._lock:
            total    = self._total_threats
            critical = self._critical_count

        if critical > 0:
            estado = Text.from_markup("[bold red]⬟ BAJO ATAQUE[/bold red]")
        elif total > 0:
            estado = Text.from_markup("[bold yellow]⚠  AMENAZAS DETECTADAS[/bold yellow]")
        else:
            estado = Text.from_markup("[bold green]●  SISTEMA SEGURO[/bold green]")

        # Firmas cargadas
        n_proc_sigs = len(config.ATTACK_TOOL_SIGNATURES)
        n_port_sigs = len(config.SUSPICIOUS_PORT_SIGNATURES)

        grid = Table.grid(padding=(0, 1))
        grid.add_column(style="dim", min_width=16)
        grid.add_column()
        grid.add_row("Estado:",       estado)
        grid.add_row("Tiempo activo:", f"{h:02d}:{m:02d}:{s:02d}")
        grid.add_row("Amenazas:",     f"[yellow]{total}[/yellow] total  [red]{critical}[/red] críticas")
        grid.add_row("Firmas proceso:", f"[cyan]{n_proc_sigs}[/cyan] herramientas Kali/RAT")
        grid.add_row("Firmas puerto:", f"[cyan]{n_port_sigs}[/cyan] puertos de ataque")

        return Panel(grid, title="[bold]● StrikeBack[/bold]",
                     border_style="cyan", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_coverage(self) -> Panel:
        """Panel MITRE ATT&CK coverage con barras de porcentaje."""
        table = Table(box=box.SIMPLE, show_header=False, expand=True, padding=(0, 0))
        table.add_column("Táctica",  ratio=1)
        table.add_column("Cobertura", width=18)
        table.add_column("Pct", width=6, justify="right")

        for tactic, data in config.ATTACK_COVERAGE.items():
            covered    = data["covered"]
            techniques = data["techniques"]
            pct        = int(covered / techniques * 100) if techniques else 0

            bar_len = 12
            filled  = int(pct / 100 * bar_len)
            bar     = "█" * filled + "░" * (bar_len - filled)

            if pct >= 80:   bar_style = "bold green"
            elif pct >= 50: bar_style = "yellow"
            else:           bar_style = "dim red"

            # Nombre corto de la táctica
            short = tactic.split("(")[0].strip()
            table.add_row(
                Text(short, style="dim", overflow="ellipsis"),
                Text(f"[{bar}]", style=bar_style),
                Text(f"{pct}%", style=bar_style),
            )

        return Panel(table, title="[bold]MITRE ATT&CK Coverage[/bold]",
                     border_style="blue", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_threats(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold red")
        table.add_column("Sev",      width=4,  justify="center")
        table.add_column("Conf %",   width=12)
        table.add_column("Fuente",   width=10)
        table.add_column("Amenaza · Técnica MITRE", ratio=1)
        table.add_column("IA",       width=4, justify="center")
        table.add_column("Hora",     width=8)

        with self._lock:
            threats = self._recent_threats[:18]

        if not threats:
            table.add_row("", "", "", "[dim green]Sin amenazas detectadas — sistema limpio[/dim green]", "", "")
        else:
            for t in threats:
                sev    = t.get("severity", 5)
                conf   = t.get("confidence", 50)
                style, icon = _sev_style(sev)

                ai      = t.get("ai_analysis")
                ai_conf = ai.get("confirmed_severity", sev) * 10 if ai else None
                if ai_conf:
                    conf = max(conf, ai_conf)

                ai_badge = (
                    "[green]✓[/green]" if ai and ai.get("is_threat") else
                    "[dim]○[/dim]"     if not t.get("ai_analyzed")   else
                    "[dim]✗[/dim]"
                )

                ts   = t.get("timestamp", "")
                hora = ts[11:19] if len(ts) >= 19 else "-"

                title_raw = t.get("title", "?")
                # Extraer código MITRE del título para resaltarlo
                import re
                mitre_match = re.search(r"\[T\d{4}(?:\.\d{3})?\]", title_raw)
                if mitre_match:
                    mitre_tag   = mitre_match.group()
                    title_clean = title_raw.replace(mitre_tag, "").strip()
                    display_title = f"[bold cyan]{mitre_tag}[/bold cyan] {title_clean[:45]}"
                else:
                    display_title = title_raw[:55]

                ai_summary = ai.get("summary", "") if ai else ""
                if ai_summary:
                    display_title += f"\n[dim]{ai_summary[:55]}[/dim]"

                table.add_row(
                    Text(f"{icon}{sev}", style=style),
                    _conf_bar(conf),
                    t.get("source", "?"),
                    Text.from_markup(display_title),
                    Text.from_markup(ai_badge),
                    hora,
                )

        return Panel(table, title="[bold red]▲ Amenazas Detectadas[/bold red]",
                     border_style="red", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_network(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold cyan")
        table.add_column("Proceso",    max_width=13)
        table.add_column("IP:Puerto",  max_width=22)
        table.add_column("Firma",      ratio=1)

        connections = []
        if self.network_monitor:
            try:
                connections = self.network_monitor.get_active_connections()
            except Exception:
                pass

        shown = 0
        for c in connections:
            if shown >= 10:
                break
            port      = c.get("remote_port", 0)
            is_susp   = c.get("suspicious", False)
            sig_desc  = c.get("sig_desc", "")

            addr = f"{c.get('remote_ip', '-')}:{port}"
            if is_susp:
                addr_text = Text(addr, style="bold red")
                sig_text  = Text(sig_desc[:30], style="red")
            else:
                addr_text = Text(addr, style="white")
                sig_text  = Text("", style="dim")

            table.add_row(c.get("process", "?")[:13], addr_text, sig_text)
            shown += 1

        if not connections:
            table.add_row("[dim]Sin conexiones[/dim]", "", "")

        return Panel(table, title="[bold]Conexiones[/bold]",
                     border_style="blue", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_processes(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold green")
        table.add_column("PID",   width=6, justify="right")
        table.add_column("Proceso", ratio=1)
        table.add_column("CPU%",  width=6, justify="right")
        table.add_column("MB",    width=7, justify="right")

        procs = []
        if self.process_monitor:
            try:
                procs = self.process_monitor.get_top_processes(8)
            except Exception:
                pass

        for p in procs:
            cpu   = p.get("cpu", 0) or 0
            style = "red bold" if cpu > 70 else ("yellow" if cpu > 40 else "green")
            table.add_row(
                str(p.get("pid", "-")),
                p.get("name", "?")[:18],
                Text(f"{cpu:.0f}", style=style),
                str(p.get("mem_mb", 0)),
            )

        return Panel(table, title="[bold]Procesos Top CPU[/bold]",
                     border_style="green", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_footer(self) -> Panel:
        now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        n_sigs  = len(config.ATTACK_TOOL_SIGNATURES) + len(config.SUSPICIOUS_PORT_SIGNATURES)
        text = Text.from_markup(
            f"[dim]{now}  |  "
            f"[cyan]{n_sigs}[/cyan] firmas activas  |  "
            f"[bold cyan]StrikeBack v1.0[/bold cyan]  |  "
            f"Ctrl+C para salir[/dim]"
        )
        return Panel(Align.center(text), border_style="dim", box=box.ROUNDED)

    from monitors import NetworkMonitor, ProcessMonitor


SEVERITY_STYLE = {
    range(1, 4):  ("dim white",   "●"),
    range(4, 6):  ("yellow",      "◆"),
    range(6, 8):  ("bold orange3","▲"),
    range(8, 11): ("bold red",    "⬟"),
}


def _sev_style(sev: int) -> tuple[str, str]:
    for r, (style, icon) in SEVERITY_STYLE.items():
        if sev in r:
            return style, icon
    return "white", "●"


HEADER_ART = """[bold cyan]
  ██████ ████████ ██████  ██ ██   ██ ███████ ██████   █████   ██████ ██   ██
 ██         ██    ██   ██ ██ ██  ██  ██      ██   ██ ██   ██ ██      ██  ██
 ╚█████     ██    ██████  ██ █████   █████   ██████  ███████ ██      █████
      ██    ██    ██   ██ ██ ██  ██  ██      ██   ██ ██   ██ ██      ██  ██
 ██████     ██    ██   ██ ██ ██   ██ ███████ ██████  ██   ██  ██████ ██   ██
[/bold cyan][dim]  Agente IA de Ciberseguridad para Windows[/dim]"""


class Dashboard:
    """
    Dashboard interactivo en terminal que se refresca cada 2 segundos.
    Muestra: estado, amenazas recientes, conexiones, top procesos.
    """

    def __init__(
        self,
        network_monitor=None,
        process_monitor=None,
        db=None,
    ):
        self.network_monitor  = network_monitor
        self.process_monitor  = process_monitor
        self.db               = db
        self._stop_event      = threading.Event()
        self._recent_threats: list = []
        self._lock            = threading.Lock()
        self._start_time      = datetime.now()
        self._total_threats   = 0
        self._critical_count  = 0

    # ------------------------------------------------------------------
    def add_threat(self, threat: dict):
        with self._lock:
            self._recent_threats.insert(0, threat)
            self._recent_threats = self._recent_threats[:100]  # keep last 100
            self._total_threats += 1
            if threat.get("severity", 0) >= 8:
                self._critical_count += 1

    # ------------------------------------------------------------------
    def run(self):
        console = Console()

        with Live(
            self._build_layout(),
            console  = console,
            refresh_per_second = 0.5,
            screen   = True,
        ) as live:
            while not self._stop_event.is_set():
                try:
                    live.update(self._build_layout())
                except Exception:
                    pass
                self._stop_event.wait(timeout=2)

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header",  size=9),
            Layout(name="body",    ratio=1),
            Layout(name="footer",  size=3),
        )
        layout["body"].split_row(
            Layout(name="left",  ratio=2),
            Layout(name="right", ratio=3),
        )
        layout["left"].split_column(
            Layout(name="status",  size=10),
            Layout(name="network", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="threats",    ratio=2),
            Layout(name="processes",  ratio=1),
        )

        layout["header"].update(self._render_header())
        layout["status"].update(self._render_status())
        layout["network"].update(self._render_network())
        layout["threats"].update(self._render_threats())
        layout["processes"].update(self._render_processes())
        layout["footer"].update(self._render_footer())

        return layout

    # ------------------------------------------------------------------
    def _render_header(self) -> Panel:
        return Panel(
            Align.center(Text.from_markup(HEADER_ART)),
            border_style="bold cyan",
            box=box.DOUBLE_EDGE,
        )

    # ------------------------------------------------------------------
    def _render_status(self) -> Panel:
        uptime = datetime.now() - self._start_time
        h, m   = divmod(int(uptime.total_seconds()), 3600)
        m, s   = divmod(m, 60)

        with self._lock:
            total    = self._total_threats
            critical = self._critical_count

        status_icon = "[bold green]● ACTIVO[/bold green]" if total == 0 else "[bold yellow]⚠ ALERTA[/bold yellow]"
        if critical > 0:
            status_icon = "[bold red]⬟ CRÍTICO[/bold red]"

        grid = Table.grid(padding=1)
        grid.add_column(style="dim")
        grid.add_column()
        grid.add_row("Estado:",     Text.from_markup(status_icon))
        grid.add_row("Tiempo act.:", f"{h:02d}:{m:02d}:{s:02d}")
        grid.add_row("Amenazas:",   f"[yellow]{total}[/yellow] total  [red]{critical}[/red] críticas")

        return Panel(grid, title="[bold]Sistema[/bold]", border_style="cyan", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_network(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold cyan")
        table.add_column("Proceso",    max_width=14)
        table.add_column("IP Remota",  max_width=16)
        table.add_column("Puerto", justify="right", max_width=7)
        table.add_column("Estado",     max_width=12)

        connections = []
        if self.network_monitor:
            try:
                connections = self.network_monitor.get_active_connections()
            except Exception:
                pass

        for c in connections[:12]:
            port    = str(c.get("remote_port", "-"))
            is_susp = int(c.get("remote_port", 0)) in __import__("config").SUSPICIOUS_PORTS
            port_str = f"[red bold]{port}[/red bold]" if is_susp else port

            table.add_row(
                c.get("process", "?")[:14],
                c.get("remote_ip", "-"),
                port_str,
                c.get("status", ""),
            )

        if not connections:
            table.add_row("[dim]Sin conexiones activas[/dim]", "", "", "")

        return Panel(table, title="[bold]Conexiones de Red[/bold]",
                     border_style="blue", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_threats(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold red")
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Fuente",  width=10)
        table.add_column("Amenaza", ratio=1)
        table.add_column("IA",      width=4, justify="center")
        table.add_column("Hora",    width=8)

        with self._lock:
            threats = self._recent_threats[:15]

        if not threats:
            table.add_row("", "", "[dim green]Sin amenazas detectadas — sistema limpio[/dim green]", "", "")
        else:
            for t in threats:
                sev    = t.get("severity", 5)
                style, icon = _sev_style(sev)
                sev_text = Text(f"{icon}{sev}", style=style)

                ai = t.get("ai_analysis")
                ai_badge = (
                    "[green]✓[/green]" if ai and ai.get("is_threat") else
                    "[dim]○[/dim]"     if not t.get("ai_analyzed")  else
                    "[dim]✗[/dim]"
                )

                ts = t.get("timestamp", "")[:19]
                hora = ts[11:19] if len(ts) >= 19 else "-"

                title_short = t.get("title", "?")[:55]
                ai_summary  = ai.get("summary", "") if ai else ""
                display     = f"{title_short}\n[dim]{ai_summary[:60]}[/dim]" if ai_summary else title_short

                table.add_row(
                    sev_text,
                    t.get("source", "?"),
                    display,
                    Text.from_markup(ai_badge),
                    hora,
                )

        return Panel(table, title="[bold red]Amenazas Detectadas[/bold red]",
                     border_style="red", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_processes(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True,
                      header_style="bold green")
        table.add_column("PID",     width=7,  justify="right")
        table.add_column("Proceso", ratio=1)
        table.add_column("CPU%",    width=7,  justify="right")
        table.add_column("RAM MB",  width=8,  justify="right")

        procs = []
        if self.process_monitor:
            try:
                procs = self.process_monitor.get_top_processes(8)
            except Exception:
                pass

        for p in procs:
            cpu = p.get("cpu", 0) or 0
            cpu_style = "red bold" if cpu > 70 else ("yellow" if cpu > 40 else "green")
            table.add_row(
                str(p.get("pid", "-")),
                p.get("name", "?")[:22],
                Text(f"{cpu:.0f}", style=cpu_style),
                str(p.get("mem_mb", 0)),
            )

        return Panel(table, title="[bold]Top Procesos (CPU)[/bold]",
                     border_style="green", box=box.ROUNDED)

    # ------------------------------------------------------------------
    def _render_footer(self) -> Panel:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = Text.from_markup(
            f"[dim]Última actualización: {now}  |  "
            f"[bold cyan]StrikeBack v1.0[/bold cyan]  |  "
            f"Ctrl+C para salir[/dim]"
        )
        return Panel(Align.center(text), border_style="dim", box=box.ROUNDED)
