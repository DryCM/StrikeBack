"""
ForensicCollector — Recolección de evidencias digitales y análisis forense.

Marco de referencia:
  - NIST SP 800-86: Integration of Forensic Techniques into Incident Response
  - RFC 3227: Guidelines for Evidence Collection and Archiving
  - ISO/IEC 27037: Digital Evidence Identification, Collection, Acquisition

Módulos de recolección:
  1. VOLATILE DATA (orden de volatilidad RFC 3227):
     - Procesos activos + argumentos + conexiones
     - Conexiones de red activas + puertos escuchando
     - Usuarios logueados + sesiones RDP
     - Variables de entorno del sistema

  2. ARTEFACTOS DE SISTEMA:
     - Prefetch (últimos programas ejecutados)
     - Tareas programadas sospechosas
     - Servicios instalados recientemente
     - Entradas del registro de persistencia

  3. ARTEFACTOS DE NAVEGADOR:
     - Historial Chrome / Edge / Firefox
     - Descargas recientes
     - Extensiones instaladas

  4. TIMELINE DE ACTIVIDAD:
     - Archivos creados/modificados en las últimas N horas
     - Eventos críticos del Event Log (4624, 4625, 4688, 4698, 7045)
     - Comandos PowerShell recientes

  5. INTEGRIDAD DE EVIDENCIAS:
     - Hash SHA-256 de cada archivo recolectado
     - Cadena de custodia (timestamp, hostname, usuario)
     - Compresión ZIP de toda la evidencia

Uso:
    fc = ForensicCollector()
    report = fc.collect_all(output_dir="evidence/")
    fc.collect_volatile(output_dir="evidence/")
    fc.collect_artifacts(output_dir="evidence/")
"""

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from utils.logger import get_logger

logger = get_logger("ForensicCollector")

_EVIDENCE_BASE  = Path("data/forensics")
_MAX_HIST_LINES = 5000   # máximo líneas de historial de navegador

# ── Eventos críticos del Event Log ───────────────────────────────────────────
_CRITICAL_EVENT_IDS = {
    4624: "Logon exitoso",
    4625: "Logon fallido",
    4648: "Logon con credenciales explícitas",
    4656: "Acceso a objeto sensible",
    4672: "Privilegios especiales asignados",
    4688: "Proceso creado",
    4698: "Tarea programada creada",
    4702: "Tarea programada modificada",
    4719: "Política de auditoría cambiada",
    4720: "Cuenta de usuario creada",
    4728: "Miembro añadido a grupo privilegiado",
    4732: "Miembro añadido a Administrators",
    4756: "Miembro añadido a Universal group",
    7045: "Servicio instalado",
    1102: "Log de auditoría limpiado",
}


class ForensicCollector:
    """Recolector de evidencias digitales para análisis forense en Windows."""

    def __init__(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ):
        self._progress = progress_callback or (lambda msg: logger.info(msg))

    # ── Recolección completa ──────────────────────────────────────────────────
    def collect_all(self, output_dir: str | None = None) -> dict:
        """
        Recolecta TODAS las categorías de evidencia.
        Genera un ZIP firmado con hash SHA-256 (cadena de custodia).

        Returns:
            Dict con rutas de archivos generados y hashes
        """
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir   = Path(output_dir or _EVIDENCE_BASE / ts)
        out_dir.mkdir(parents=True, exist_ok=True)

        self._progress(f"Iniciando recolección forense en {out_dir}")

        results = {
            "case_id":    ts,
            "hostname":   socket.gethostname(),
            "collector":  os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USERNAME", "?"),
            "start_time": datetime.now().isoformat(),
            "platform":   platform.platform(),
            "files":      [],
            "errors":     [],
        }

        collectors = [
            ("volatile",   self.collect_volatile),
            ("artifacts",  self.collect_artifacts),
            ("browser",    self.collect_browser_artifacts),
            ("timeline",   self.collect_timeline),
            ("eventlog",   self.collect_eventlog),
        ]

        for name, fn in collectors:
            self._progress(f"  Recolectando: {name}…")
            try:
                sub_result = fn(output_dir=str(out_dir))
                results["files"].extend(sub_result.get("files", []))
                results["errors"].extend(sub_result.get("errors", []))
            except Exception as exc:
                results["errors"].append(f"{name}: {exc}")
                logger.error(f"ForensicCollector error en {name}: {exc}")

        # Cadena de custodia
        custody_file = out_dir / "chain_of_custody.json"
        results["end_time"] = datetime.now().isoformat()
        results["total_files"] = len(results["files"])
        custody_file.write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Comprimir todo en ZIP con hash SHA-256
        zip_path = self._create_evidence_zip(out_dir, ts)
        if zip_path:
            zip_hash = self._sha256_file(zip_path)
            results["zip_path"]  = str(zip_path)
            results["zip_sha256"] = zip_hash
            self._progress(f"ZIP de evidencias: {zip_path} (SHA-256: {zip_hash[:16]}…)")

        self._progress(
            f"Recolección completada: {results['total_files']} archivos, "
            f"{len(results['errors'])} errores."
        )
        return results

    # ── 1. Datos volátiles ────────────────────────────────────────────────────
    def collect_volatile(self, output_dir: str = ".") -> dict:
        """Captura datos volátiles del sistema (orden RFC 3227)."""
        out   = Path(output_dir) / "volatile"
        out.mkdir(parents=True, exist_ok=True)
        files = []
        errors = []

        tasks = {
            "processes.json":   self._get_processes,
            "network_conns.json": self._get_network_connections,
            "logged_users.txt": self._get_logged_users,
            "env_vars.json":    self._get_env_vars,
            "arp_table.txt":    self._get_arp_table,
            "dns_cache.txt":    self._get_dns_cache,
            "routing_table.txt":self._get_routing_table,
        }

        for filename, fn in tasks.items():
            try:
                data = fn()
                fpath = out / filename
                if isinstance(data, (dict, list)):
                    fpath.write_text(
                        json.dumps(data, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8"
                    )
                else:
                    fpath.write_text(str(data), encoding="utf-8", errors="replace")
                files.append({
                    "path":   str(fpath),
                    "sha256": self._sha256_file(fpath),
                    "category": "volatile",
                })
            except Exception as exc:
                errors.append(f"{filename}: {exc}")

        return {"files": files, "errors": errors}

    def _get_processes(self) -> list[dict]:
        """Lista completa de procesos con PID, nombre, ruta y conexiones."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username", "create_time",
                 "memory_info", "cpu_percent"]
            ):
                try:
                    info = p.info
                    procs.append({
                        "pid":          info["pid"],
                        "name":         info["name"],
                        "exe":          info.get("exe", ""),
                        "cmdline":      " ".join(info.get("cmdline") or []),
                        "username":     info.get("username", ""),
                        "create_time":  datetime.fromtimestamp(
                            info["create_time"]
                        ).isoformat() if info.get("create_time") else "",
                        "memory_mb":    round(
                            (info.get("memory_info") or type("x", (), {"rss": 0})()).rss
                            / 1024 / 1024, 1
                        ),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return sorted(procs, key=lambda x: x["pid"])
        except Exception as exc:
            return [{"error": str(exc)}]

    def _get_network_connections(self) -> list[dict]:
        """Conexiones de red activas y puertos en escucha."""
        try:
            import psutil
            conns = []
            for c in psutil.net_connections(kind="inet"):
                conns.append({
                    "pid":    c.pid,
                    "status": c.status,
                    "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "proto":  "TCP" if c.type.name == "SOCK_STREAM" else "UDP",
                })
            return conns
        except Exception as exc:
            return [{"error": str(exc)}]

    def _get_logged_users(self) -> str:
        """Usuarios actualmente logueados."""
        return self._run_cmd(["query", "user"], "No se pudo obtener usuarios")

    def _get_env_vars(self) -> dict:
        """Variables de entorno (filtradas — sin valores sensibles completos)."""
        env = {}
        for k, v in os.environ.items():
            # Ofuscar valores que parezcan tokens/contraseñas
            if re.search(r"(password|secret|token|key|api)", k, re.I):
                env[k] = "[REDACTED]"
            else:
                env[k] = v[:200]  # max 200 chars por valor
        return env

    def _get_arp_table(self) -> str:
        return self._run_cmd(["arp", "-a"], "No se pudo obtener tabla ARP")

    def _get_dns_cache(self) -> str:
        return self._run_cmd(
            ["ipconfig", "/displaydns"],
            "No se pudo obtener caché DNS"
        )

    def _get_routing_table(self) -> str:
        return self._run_cmd(["route", "print"], "No se pudo obtener tabla de rutas")

    # ── 2. Artefactos de sistema ──────────────────────────────────────────────
    def collect_artifacts(self, output_dir: str = ".") -> dict:
        """Recolecta artefactos del sistema (tareas, servicios, prefetch)."""
        out   = Path(output_dir) / "artifacts"
        out.mkdir(parents=True, exist_ok=True)
        files  = []
        errors = []

        tasks = {
            "scheduled_tasks.xml": self._get_scheduled_tasks,
            "installed_services.json": self._get_services,
            "prefetch_list.txt": self._get_prefetch,
            "startup_items.json": self._get_startup_items,
            "recent_files.json":  self._get_recent_files,
        }

        for filename, fn in tasks.items():
            try:
                data  = fn()
                fpath = out / filename
                if isinstance(data, (dict, list)):
                    fpath.write_text(
                        json.dumps(data, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8"
                    )
                else:
                    fpath.write_text(str(data), encoding="utf-8", errors="replace")
                files.append({"path": str(fpath), "sha256": self._sha256_file(fpath),
                               "category": "artifacts"})
            except Exception as exc:
                errors.append(f"{filename}: {exc}")

        return {"files": files, "errors": errors}

    def _get_scheduled_tasks(self) -> str:
        return self._run_cmd(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            "No se pudo obtener tareas programadas"
        )

    def _get_services(self) -> list[dict]:
        out = self._run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "Get-Service | Select-Object Name,Status,StartType,DisplayName | "
             "ConvertTo-Json"],
            "[]"
        )
        try:
            return json.loads(out)
        except Exception:
            return [{"raw": out[:2000]}]

    def _get_prefetch(self) -> str:
        """Lista archivos Prefetch (últimos programas ejecutados)."""
        prefetch_dir = Path(r"C:\Windows\Prefetch")
        if not prefetch_dir.exists():
            return "Prefetch deshabilitado o inaccesible"
        files = sorted(
            prefetch_dir.glob("*.pf"),
            key=lambda f: f.stat().st_mtime, reverse=True
        )[:100]
        lines = []
        for f in files:
            mt = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{mt}  {f.name}")
        return "\n".join(lines) if lines else "Sin archivos Prefetch"

    def _get_startup_items(self) -> list[dict]:
        """Entradas de autoarranque del registro."""
        items = []
        try:
            import winreg
            run_keys = [
                (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ]
            hive_names = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}
            for hive, key_path in run_keys:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            items.append({
                                "hive":  hive_names.get(hive, "?"),
                                "key":   key_path,
                                "name":  name,
                                "value": value,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
        except Exception as exc:
            items.append({"error": str(exc)})
        return items

    def _get_recent_files(self) -> list[dict]:
        """Archivos creados/modificados en las últimas 24 horas."""
        recent = []
        cutoff = time.time() - 86400
        scan_dirs = [
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            Path.home() / "Documents",
            Path.home() / "AppData" / "Local" / "Temp",
        ]
        for d in scan_dirs:
            if not d.exists():
                continue
            try:
                for f in d.rglob("*"):
                    if f.is_file() and f.stat().st_mtime > cutoff:
                        recent.append({
                            "path":     str(f),
                            "size":     f.stat().st_size,
                            "modified": datetime.fromtimestamp(
                                f.stat().st_mtime
                            ).isoformat(),
                        })
                        if len(recent) >= 500:
                            break
            except Exception:
                pass
        return sorted(recent, key=lambda x: x["modified"], reverse=True)

    # ── 3. Artefactos de navegadores ──────────────────────────────────────────
    def collect_browser_artifacts(self, output_dir: str = ".") -> dict:
        """Recolecta historial y descargas de Chrome, Edge y Firefox."""
        out   = Path(output_dir) / "browser"
        out.mkdir(parents=True, exist_ok=True)
        files  = []
        errors = []

        profiles = {
            "Chrome": Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
            "Edge":   Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
        }

        for browser, base_path in profiles.items():
            for profile_dir in [base_path / "Default", base_path / "Profile 1"]:
                hist_file = profile_dir / "History"
                if hist_file.exists():
                    try:
                        dest = out / f"{browser}_history.db"
                        shutil.copy2(str(hist_file), str(dest))
                        files.append({
                            "path":     str(dest),
                            "sha256":   self._sha256_file(dest),
                            "category": "browser",
                            "browser":  browser,
                        })
                        break
                    except Exception as exc:
                        errors.append(f"{browser} history: {exc}")

        # Firefox profiles
        ff_base = Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        if ff_base.exists():
            for profile in ff_base.iterdir():
                places = profile / "places.sqlite"
                if places.exists():
                    try:
                        dest = out / "Firefox_history.db"
                        shutil.copy2(str(places), str(dest))
                        files.append({
                            "path":     str(dest),
                            "sha256":   self._sha256_file(dest),
                            "category": "browser",
                            "browser":  "Firefox",
                        })
                        break
                    except Exception as exc:
                        errors.append(f"Firefox places: {exc}")

        return {"files": files, "errors": errors}

    # ── 4. Timeline ───────────────────────────────────────────────────────────
    def collect_timeline(self, output_dir: str = ".", hours: int = 48) -> dict:
        """Timeline de actividad del sistema en las últimas N horas."""
        out   = Path(output_dir) / "timeline"
        out.mkdir(parents=True, exist_ok=True)
        files  = []
        errors = []

        try:
            events = self._build_timeline(hours)
            fpath  = out / f"timeline_{hours}h.json"
            fpath.write_text(
                json.dumps(events, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
            files.append({"path": str(fpath), "sha256": self._sha256_file(fpath),
                           "category": "timeline"})
        except Exception as exc:
            errors.append(f"timeline: {exc}")

        return {"files": files, "errors": errors}

    def _build_timeline(self, hours: int) -> list[dict]:
        """Construye timeline con archivos modificados + procesos recientes."""
        cutoff  = time.time() - hours * 3600
        events  = []

        # Archivos recientes en dirs críticos
        watch_dirs = [
            Path.home() / "Desktop", Path.home() / "Downloads",
            Path(r"C:\Windows\System32"), Path(r"C:\Windows\Temp"),
            Path.home() / "AppData" / "Local" / "Temp",
        ]
        for d in watch_dirs:
            if not d.exists():
                continue
            try:
                for f in d.iterdir():
                    if f.is_file() and f.stat().st_mtime > cutoff:
                        events.append({
                            "timestamp": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                            "type":      "FILE_MODIFIED",
                            "path":      str(f),
                            "size":      f.stat().st_size,
                        })
            except Exception:
                pass

        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events[:2000]

    # ── 5. Event Log ─────────────────────────────────────────────────────────
    def collect_eventlog(self, output_dir: str = ".", hours: int = 48) -> dict:
        """Extrae eventos críticos del Event Log de Windows."""
        out   = Path(output_dir) / "eventlog"
        out.mkdir(parents=True, exist_ok=True)
        files  = []
        errors = []

        try:
            events = self._get_critical_events(hours)
            fpath  = out / f"critical_events_{hours}h.json"
            fpath.write_text(
                json.dumps(events, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
            files.append({"path": str(fpath), "sha256": self._sha256_file(fpath),
                           "category": "eventlog"})
        except Exception as exc:
            errors.append(f"eventlog: {exc}")

        return {"files": files, "errors": errors}

    def _get_critical_events(self, hours: int) -> list[dict]:
        """Lee eventos críticos usando win32evtlog."""
        events  = []
        ids_str = ",".join(str(i) for i in _CRITICAL_EVENT_IDS)
        cutoff  = datetime.now() - timedelta(hours=hours)

        try:
            import win32evtlog
            import win32evtlogutil
            import pywintypes

            handle = win32evtlog.OpenEventLog(None, "Security")
            flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for r in records:
                    if r.EventID not in _CRITICAL_EVENT_IDS:
                        continue
                    evt_time = r.TimeGenerated
                    if hasattr(evt_time, "replace"):
                        if evt_time.replace(tzinfo=None) < cutoff:
                            break
                    events.append({
                        "id":       r.EventID,
                        "type":     _CRITICAL_EVENT_IDS.get(r.EventID, "?"),
                        "time":     str(r.TimeGenerated),
                        "source":   r.SourceName,
                        "computer": r.ComputerName,
                    })
                    if len(events) >= 2000:
                        break
                if len(events) >= 2000:
                    break
            win32evtlog.CloseEventLog(handle)
        except Exception as exc:
            logger.debug(f"_get_critical_events: {exc}")
            # Fallback con PowerShell
            try:
                ps_cmd = (
                    f"Get-EventLog -LogName Security -Newest 500 "
                    f"| Where-Object {{@({ids_str}) -contains $_.EventID}} "
                    f"| Select-Object EventID,TimeGenerated,Source,Message "
                    f"| ConvertTo-Json"
                )
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stderr=subprocess.DEVNULL,
                )
                parsed = json.loads(out)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                events = parsed or []
            except Exception:
                pass

        return events

    # ── Empaquetado de evidencias ─────────────────────────────────────────────
    def _create_evidence_zip(self, evidence_dir: Path, case_id: str) -> Path | None:
        """Empaqueta toda la evidencia en un ZIP con hash SHA-256."""
        zip_path = evidence_dir.parent / f"evidence_{case_id}.zip"
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for fpath in evidence_dir.rglob("*"):
                    if fpath.is_file():
                        zf.write(fpath, fpath.relative_to(evidence_dir.parent))
            return zip_path
        except Exception as exc:
            logger.error(f"Error creando ZIP de evidencias: {exc}")
            return None

    # ── Utilidades ────────────────────────────────────────────────────────────
    @staticmethod
    def _sha256_file(path: Path | str) -> str:
        """Calcula SHA-256 de un archivo para cadena de custodia."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except Exception:
            return "error"
        return h.hexdigest()

    @staticmethod
    def _run_cmd(args: list[str], fallback: str = "") -> str:
        """Ejecuta un comando del sistema y retorna su salida."""
        try:
            return subprocess.check_output(
                args,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as exc:
            return f"{fallback} ({exc})"
