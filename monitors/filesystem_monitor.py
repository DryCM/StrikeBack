"""
Monitor de sistema de archivos — detecta ransomware, malware y cambios sospechosos.
"""
import threading
import os
from datetime import datetime
from typing import Callable, Optional
from pathlib import Path
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from utils.logger import get_logger

logger = get_logger("FileMonitor")

# Ventana de tiempo para detectar ráfaga de cambios (ransomware)
# Valores conservadores para evitar falsos positivos en entornos de desarrollo.
# El ransomware real cifra >50 archivos/min; aquí exigimos ≥30 en 5s sobre
# archivos de DATOS (los de código fuente están excluidos por BURST_IGNORE_EXTENSIONS).
RANSOMWARE_WINDOW_SECONDS = 5
RANSOMWARE_MIN_EVENTS     = 30


class _ThreatHandler(FileSystemEventHandler):
    """Handler de watchdog que analiza cada evento del sistema de archivos."""

    def __init__(self, threat_callback: Callable):
        super().__init__()
        self.threat_callback = threat_callback
        self._recent_events: deque = deque()  # para detectar ráfagas (ransomware)
        self._alerted_paths: set = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._analyze(event.src_path, "creado")

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._analyze(event.src_path, "modificado")

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        # La extensión destino puede ser la de ransomware
        self._analyze(getattr(event, "dest_path", event.src_path), "renombrado")

    # ------------------------------------------------------------------
    def _analyze(self, path: str, action: str):
        # Ignorar rutas excluidas
        path_lower = path.lower()
        for ignore in config.IGNORE_PATHS:
            if ignore.lower() in path_lower:
                return

        ext = Path(path).suffix.lower()
        now = datetime.now()

        # --- Regla 1: Extensión ransomware ---
        if ext in config.RANSOMWARE_EXTENSIONS:
            if path not in self._alerted_paths:
                self._alerted_paths.add(path)
                self._emit(
                    severity=10,
                    title=f"[T1486] RANSOMWARE — Extensión cifrada: {ext}",
                    description=(
                        f"Archivo '{Path(path).name}' {action} con extensión de ransomware conocida ({ext}). "
                        f"Ruta: {path}"
                    ),
                    details={"path": path, "ext": ext, "action": action, "confidence": 97},
                    confidence=97,
                )

        # --- Regla 2: Ejecutable sospechoso en carpeta de usuario ---
        if ext in config.SUSPICIOUS_EXTENSIONS and action == "creado":
            if path not in self._alerted_paths:
                self._alerted_paths.add(path)
                confidence = 78 if ext in {".exe", ".dll", ".scr", ".cpl"} else 60
                self._emit(
                    severity=7,
                    title=f"[T1105] Archivo ejecutable creado: {Path(path).name}",
                    description=(
                        f"Nuevo ejecutable '{Path(path).name}' en {Path(path).parent}. "
                        f"Extensión de riesgo: {ext}"
                    ),
                    details={"path": path, "ext": ext, "confidence": confidence},
                    confidence=confidence,
                )

        # --- Regla 3: Ráfaga de modificaciones = posible cifrado ransomware ---
        # Omitir extensiones de código fuente/desarrollo — no son objetivo de ransomware
        # y los editores generan muchos eventos legítimos sobre ellas
        if ext in config.BURST_IGNORE_EXTENSIONS:
            return

        with self._lock:
            self._recent_events.append(now)
            cutoff = now.timestamp() - RANSOMWARE_WINDOW_SECONDS
            while self._recent_events and self._recent_events[0].timestamp() < cutoff:
                self._recent_events.popleft()

            if len(self._recent_events) >= RANSOMWARE_MIN_EVENTS:
                count = len(self._recent_events)
                self._recent_events.clear()
                confidence = min(60 + count * 2, 96)
                self._emit(
                    severity=9,
                    title=f"[T1486] Ráfaga masiva de archivos — posible ransomware ({count}/{RANSOMWARE_WINDOW_SECONDS}s)",
                    description=(
                        f"{count} modificaciones en {RANSOMWARE_WINDOW_SECONDS}s. "
                        f"Patrón consistente con cifrado masivo por ransomware."
                    ),
                    details={"count": count, "last_path": path, "confidence": confidence},
                    confidence=confidence,
                )

    # ------------------------------------------------------------------
    def _emit(self, severity: int, title: str, description: str,
               details: dict, confidence: int = 70):
        threat = {
            "source":      "Archivos",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA {confidence}%] {title}")
        self.threat_callback(threat)


class FileSystemMonitor:
    """
    Vigila los directorios configurados en busca de actividad sospechosa.
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._handler  = _ThreatHandler(threat_callback)
        self._observer = Observer()
        self.name = "Archivos"

    # ------------------------------------------------------------------
    def start(self):
        paths_watched = 0
        for path in config.WATCH_PATHS:
            if os.path.isdir(path):
                try:
                    self._observer.schedule(self._handler, path, recursive=True)
                    paths_watched += 1
                    logger.info(f"Vigilando: {path}")
                except PermissionError:
                    logger.warning(f"Sin acceso a {path} (se requiere Admin).")
                except Exception as exc:
                    logger.warning(f"No se puede vigilar {path}: {exc}")
            else:
                logger.warning(f"Ruta no encontrada, omitida: {path}")

        if paths_watched:
            self._observer.start()
            logger.info(f"Monitor de archivos iniciado ({paths_watched} rutas).")
        else:
            logger.warning("Monitor de archivos: ninguna ruta válida. Verifica WATCH_PATHS en config.py.")

    def stop(self):
        self._observer.stop()
        self._observer.join()
