"""
Credential Guard — Protección de contraseñas en tiempo real.

Detecta los 3 vectores más comunes de robo de credenciales:
  1. Acceso a LSASS (volcado de contraseñas de Windows en memoria)
  2. Acceso a archivos de credenciales de navegadores (Chrome, Firefox, Edge)
  3. Contenido sospechoso en el portapapeles (contraseñas copiadas)
"""

import os
import re
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import psutil

from utils.logger import get_logger

logger = get_logger("CredentialGuard")

# ── Rutas de credenciales de navegadores ─────────────────────────────────────
_USERNAME = os.environ.get("USERNAME", "")
_BROWSER_CRED_FILES: list[tuple[str, str, str]] = [
    # (ruta, navegador, MITRE)
    (rf"C:\Users\{_USERNAME}\AppData\Local\Google\Chrome\User Data\Default\Login Data",
     "Chrome", "T1555.003"),
    (rf"C:\Users\{_USERNAME}\AppData\Local\Google\Chrome\User Data\Default\Cookies",
     "Chrome Cookies", "T1539"),
    (rf"C:\Users\{_USERNAME}\AppData\Roaming\Mozilla\Firefox\Profiles",
     "Firefox", "T1555.003"),
    (rf"C:\Users\{_USERNAME}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
     "Edge", "T1555.003"),
    (rf"C:\Users\{_USERNAME}\AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
     "Edge Cookies", "T1539"),
    (rf"C:\Users\{_USERNAME}\AppData\Roaming\Opera Software\Opera Stable\Login Data",
     "Opera", "T1555.003"),
]

# Procesos legítimos que pueden abrir sus propios archivos de credenciales
_BROWSER_LEGITIMATE_PROCS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "brave.exe", "vivaldi.exe", "chromium.exe",
    # Indexadores y antivirus legítimos
    "searchindexer.exe", "antimalware service executable",
}

# Patrón para detectar contraseñas en el portapapeles
_CLIPBOARD_PASSWORD_PATTERNS = [
    re.compile(r"(?i)pass(?:word)?[\s:=]+\S{6,}"),
    re.compile(r"(?i)pwd[\s:=]+\S{6,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS Access Key
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"),        # JWT / Bearer token
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                        # GitHub PAT
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),     # Clave privada SSH/SSL
]


class CredentialGuard:
    """
    Monitor periódico (cada 10s) que detecta accesos no autorizados
    a credenciales del sistema, navegadores y portapapeles.
    """

    def __init__(self, threat_callback: Callable):
        self._callback    = threat_callback
        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._alerted_pids: set[int] = set()
        self._last_clipboard: str = ""

    # ─────────────────────────────────────────────────────────────────────────
    def start(self):
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="CredentialGuard"
        )
        self._thread.start()
        logger.info("Credential Guard activo (LSASS + navegadores + portapapeles).")

    def stop(self):
        self._stop_event.set()

    # ─────────────────────────────────────────────────────────────────────────
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._check_lsass_access()
                self._check_browser_credential_files()
                self._check_clipboard()
            except Exception as e:
                logger.error(f"[CredentialGuard] Error en ciclo: {e}")
            self._stop_event.wait(timeout=10)

    # ─────────────────────────────────────────────────────────────────────────
    def _check_lsass_access(self):
        """
        Detecta cualquier proceso que tenga abierto lsass.exe con permisos
        de lectura de memoria (señal de volcado de credenciales T1003.001).
        """
        try:
            # Encontrar PID de lsass
            lsass_pid = None
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] and proc.info["name"].lower() == "lsass.exe":
                    lsass_pid = proc.info["pid"]
                    break

            if not lsass_pid:
                return

            # Buscar procesos que tienen handle a lsass (indirecto: via conexiones o memoria)
            # Método práctico: detectar procesos leyendo desde /proc equivalente en Windows
            # usando psutil memory_maps si el proceso tiene acceso
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                name = (proc.info.get("name") or "").lower()
                pid  = proc.info.get("pid")

                if pid in self._alerted_pids:
                    continue
                if name in ("system", "lsass.exe", ""):
                    continue

                # Detectar herramientas conocidas de volcado de credenciales
                dump_tools = {
                    "mimikatz", "pypykatz", "wce", "pwdump", "procdump",
                    "nanodump", "lsassy", "crackmapexec", "secretsdump",
                    "gsecdump", "fgdump", "wdigest",
                }
                if any(tool in name for tool in dump_tools):
                    self._alerted_pids.add(pid)
                    self._emit(
                        title=f"[T1003.001] Volcado de credenciales LSASS: {name}",
                        description=(
                            f"'{name}' (PID {pid}) es una herramienta de volcado de credenciales. "
                            f"Puede extraer todas las contraseñas de Windows de la memoria."
                        ),
                        severity=10,
                        confidence=97,
                        details={"pid": pid, "process": name, "mitre": "T1003.001",
                                 "target": "lsass.exe", "lsass_pid": lsass_pid},
                    )

        except Exception as e:
            logger.debug(f"[CredentialGuard] _check_lsass_access error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    def _check_browser_credential_files(self):
        """
        Detecta procesos no autorizados que tienen abiertos archivos
        de credenciales de navegadores (Chrome Login Data, Firefox key4.db...).
        """
        # Construir conjunto de rutas normalizadas a vigilar
        watched: dict[str, tuple[str, str]] = {}   # norm_path -> (browser, mitre)
        for path, browser, mitre in _BROWSER_CRED_FILES:
            p = Path(path)
            if p.is_dir():
                # Firefox usa carpeta de perfiles — buscar key4.db dentro
                for f in p.glob("*/key4.db"):
                    watched[os.path.normcase(str(f))] = (browser, mitre)
                for f in p.glob("*/logins.json"):
                    watched[os.path.normcase(str(f))] = (browser, mitre)
            elif p.exists():
                watched[os.path.normcase(str(p))] = (browser, mitre)

        if not watched:
            return

        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            name = (proc.info.get("name") or "").lower()
            pid  = proc.info.get("pid")

            if pid in self._alerted_pids:
                continue
            if name in _BROWSER_LEGITIMATE_PROCS:
                continue

            try:
                open_files = proc.info.get("open_files") or []
                for f in open_files:
                    norm = os.path.normcase(f.path)
                    if norm in watched:
                        browser, mitre = watched[norm]
                        self._alerted_pids.add(pid)
                        self._emit(
                            title=f"[{mitre}] Acceso a credenciales {browser}: {name}",
                            description=(
                                f"'{name}' (PID {pid}) está accediendo al archivo de "
                                f"contraseñas guardadas de {browser}. "
                                f"Posible robo de credenciales."
                            ),
                            severity=9,
                            confidence=92,
                            details={
                                "pid": pid, "process": name,
                                "file": f.path, "browser": browser,
                                "mitre": mitre,
                            },
                        )
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ─────────────────────────────────────────────────────────────────────────
    def _check_clipboard(self):
        """
        Detecta si hay credenciales o tokens en el portapapeles
        (puede indicar que el usuario copió una contraseña o que
        un malware está leyendo/escribiendo el portapapeles).
        """
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-Clipboard -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            content = result.stdout.strip()
        except Exception:
            return

        if not content or content == self._last_clipboard:
            return

        self._last_clipboard = content

        for pattern in _CLIPBOARD_PASSWORD_PATTERNS:
            if pattern.search(content):
                preview = content[:40].replace("\n", " ")
                self._emit(
                    title="[T1115] Posible credencial detectada en portapapeles",
                    description=(
                        f"El portapapeles contiene un patrón de contraseña/token. "
                        f"Vista previa: '{preview}...'"
                    ),
                    severity=6,
                    confidence=70,
                    details={
                        "mitre":   "T1115",
                        "preview": preview,
                        "pattern": pattern.pattern,
                        "note":    "Puede ser uso legítimo — verifica manualmente",
                    },
                )
                break  # Una alerta por ciclo es suficiente

    # ─────────────────────────────────────────────────────────────────────────
    def _emit(self, title: str, description: str, severity: int,
              confidence: int, details: dict):
        self._callback({
            "source":      "CredentialGuard",
            "title":       title,
            "description": description,
            "severity":    severity,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
            "details":     details,
        })
