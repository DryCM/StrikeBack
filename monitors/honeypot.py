"""
Honeypot Monitor — Archivos señuelo para detección temprana.

Crea archivos con nombres atractivos para atacantes (contraseñas, credenciales,
backups) en las carpetas del usuario. Cualquier acceso o modificación dispara
una alerta de severidad 10 con 0% de falsos positivos.

Técnica usada en entornos corporativos reales (Deception Technology · T1083).
Detecta:
  - Ransomware (modifica los archivos antes que los reales)
  - Spyware / credential stealers (leen archivos de contraseñas)
  - Movimiento lateral (acceso desde otra cuenta o proceso)
  - Insiders maliciosos
"""

import os
import time
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from utils.logger import get_logger

logger = get_logger("HoneypotMonitor")

# ── Archivos señuelo a crear ──────────────────────────────────────────────────
# Nombres diseñados para atraer a atacantes y malware que busca credenciales
_HONEYPOT_FILES: list[tuple[str, str]] = [
    # (nombre_archivo,  contenido_falso)
    ("contraseñas.txt",
     "Gmail: jaime@gmail.com / pass123\nBanco: IBAN ES76 ...\nWifi: MiCasa2024\n"),
    ("credentials.txt",
     "[AWS]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = FAKE_SECRET\n"),
    ("passwords_backup.txt",
     "VPN: usuario=admin pass=Admin2024!\nRDP: 192.168.1.1 admin/Admin123\n"),
    ("ssh_keys_backup.txt",
     "-----BEGIN RSA PRIVATE KEY-----\nFAKE_HONEYPOT_KEY_DO_NOT_USE\n-----END RSA PRIVATE KEY-----\n"),
    ("database_credentials.txt",
     "DB_HOST=localhost\nDB_USER=root\nDB_PASS=Str0ng@Pass!\nDB_NAME=produccion\n"),
]

# Carpetas donde se crean los señuelos (las más revisadas por malware)
_HONEYPOT_DIRS: list[Path] = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]


class _HoneypotEventHandler(FileSystemEventHandler):
    def __init__(self, honeypot_paths: set[str], callback: Callable):
        super().__init__()
        self._honeypot_paths = honeypot_paths
        self._callback       = callback
        self._alerted: set[str] = set()

    def _check(self, path: str, event_type: str):
        norm = os.path.normcase(os.path.abspath(path))
        if norm not in self._honeypot_paths:
            return
        if norm in self._alerted:
            return
        self._alerted.add(norm)

        # Obtener info del proceso que accedió (best-effort)
        accessing_proc = _get_accessing_process(path)

        self._callback({
            "source":      "HoneypotMonitor",
            "title":       f"[T1083] SEÑUELO ACCEDIDO: {os.path.basename(path)}",
            "description": (
                f"Archivo señuelo '{os.path.basename(path)}' fue {event_type}. "
                f"Nadie debería tocar este archivo. "
                f"Proceso sospechoso: {accessing_proc}"
            ),
            "severity":    10,
            "confidence":  99,
            "timestamp":   datetime.now().isoformat(),
            "details": {
                "honeypot_path":    path,
                "event_type":       event_type,
                "accessing_process": accessing_proc,
                "mitre":            "T1083",
                "tactic":           "Discovery / Credential Access",
                "zero_fp":          True,
                "recommendation":   "Aislar equipo y revisar proceso inmediatamente",
            },
        })
        logger.critical(f"[HONEYPOT] ¡SEÑUELO TOCADO! {path} — evento: {event_type} — proceso: {accessing_proc}")

    def on_accessed(self, event: FileSystemEvent):
        if not event.is_directory:
            self._check(event.src_path, "leído")

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._check(event.src_path, "modificado")

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._check(event.src_path, "eliminado")

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._check(event.src_path, "movido")


def _get_accessing_process(path: str) -> str:
    """Intenta identificar el proceso que accedió al archivo."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                files = proc.info.get("open_files") or []
                for f in files:
                    if os.path.normcase(f.path) == os.path.normcase(path):
                        return f"{proc.info['name']} (PID {proc.info['pid']})"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception:
        pass
    return "desconocido"


class HoneypotMonitor:
    """
    Crea archivos señuelo en carpetas del usuario y dispara alertas
    de severidad 10 ante cualquier acceso. 0 falsos positivos.
    """

    def __init__(self, threat_callback: Callable):
        self._callback    = threat_callback
        self._stop_event  = threading.Event()
        self._observer: Optional[Observer] = None
        self._honeypot_paths: set[str] = set()
        self._created_files: list[Path] = []

    # ─────────────────────────────────────────────────────────────────────────
    def start(self):
        self._create_honeypot_files()
        if not self._honeypot_paths:
            logger.warning("[Honeypot] No se pudieron crear archivos señuelo.")
            return

        handler  = _HoneypotEventHandler(self._honeypot_paths, self._callback)
        self._observer = Observer()

        watched_dirs: set[str] = {str(Path(p).parent) for p in self._honeypot_paths}
        for d in watched_dirs:
            try:
                self._observer.schedule(handler, d, recursive=False)
                logger.info(f"[Honeypot] Vigilando señuelos en: {d}")
            except Exception as e:
                logger.error(f"[Honeypot] Error programando watchdog en {d}: {e}")

        self._observer.start()
        logger.info(f"[Honeypot] {len(self._honeypot_paths)} archivos señuelo activos.")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
        self._cleanup_honeypot_files()

    # ─────────────────────────────────────────────────────────────────────────
    def _create_honeypot_files(self):
        """Crea los archivos señuelo si no existen."""
        for directory in _HONEYPOT_DIRS:
            if not directory.exists():
                continue
            for filename, content in _HONEYPOT_FILES:
                path = directory / filename
                try:
                    if not path.exists():
                        path.write_text(content, encoding="utf-8")
                        # Ocultar el archivo (atributo Hidden en Windows)
                        try:
                            import ctypes
                            FILE_ATTRIBUTE_HIDDEN = 0x02
                            ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
                        except Exception:
                            pass
                        self._created_files.append(path)
                        logger.debug(f"[Honeypot] Creado señuelo: {path}")

                    norm = os.path.normcase(os.path.abspath(str(path)))
                    self._honeypot_paths.add(norm)

                except Exception as e:
                    logger.error(f"[Honeypot] Error creando {path}: {e}")

    def _cleanup_honeypot_files(self):
        """Elimina los archivos señuelo creados por esta sesión al cerrar."""
        for path in self._created_files:
            try:
                if path.exists():
                    path.unlink()
                    logger.debug(f"[Honeypot] Eliminado señuelo: {path}")
            except Exception:
                pass

    def get_honeypot_count(self) -> int:
        return len(self._honeypot_paths)
