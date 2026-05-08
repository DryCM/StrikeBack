"""
YARA Scanner — Detección de malware mediante reglas de firma.

Analiza archivos nuevos y modificados en las rutas de usuario más
expuestas (Escritorio, Descargas, Documentos, Temp) usando el motor
YARA-X con reglas integradas que cubren:

  - Cobalt Strike Beacon / Sleep Mask        (T1059.003 / T1027)
  - Mimikatz                                 (T1003.001)
  - Metasploit / Meterpreter / Shellcode     (T1059 / T1055)
  - Ransomware: WannaCry, LockBit, Ryuk     (T1486)
  - RATs: AsyncRAT, NjRAT, QuasarRAT        (T1219)
  - Loaders: GuLoader, PrivateLoader         (T1105)
  - Post-explotación: BloodHound, Rubeus,    (T1069.002 / T1558)
    Impacket
  - Evasión: AMSI bypass, ETW bypass,       (T1562)
    PowerShell codificado
  - Keyloggers / Spyware                     (T1056.001)
  - Cryptominers: XMRig                      (T1496)

Integración con watchdog: detecta archivos nuevos/modificados en
tiempo real y los analiza de inmediato. Además realiza un escaneo
completo de las rutas vigiladas al arrancar.

Tamaño máximo de archivo analizado: 5 MB.
"""

import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import yara_x
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from utils.logger import get_logger

logger = get_logger("YaraScanner")

# ─────────────────────────────────────────────────────────────────────────────
_RULES_FILE       = Path("data") / "yara_rules" / "strikeback.yar"
_MAX_FILE_BYTES   = 5 * 1024 * 1024   # 5 MB
_SCAN_ON_START    = True

_USERNAME = os.environ.get("USERNAME", "")

_WATCH_DIRS: list[Path] = [
    Path(rf"C:\Users\{_USERNAME}\Desktop"),
    Path(rf"C:\Users\{_USERNAME}\Downloads"),
    Path(rf"C:\Users\{_USERNAME}\Documents"),
    Path(r"C:\Windows\Temp"),
    Path(rf"C:\Users\{_USERNAME}\AppData\Local\Temp"),
]

# Extensiones de interés para el análisis YARA
_SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".py", ".sh", ".hta", ".msi", ".scr", ".pif",
    ".lnk", ".iso", ".zip", ".rar", ".7z", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx", ".rtf", ".txt", ".html", ".htm",
}

# Metadatos de severidad extraídos de las reglas (por nombre)
_RULE_SEVERITY: dict[str, int] = {
    "CobaltStrike_Beacon":        10,
    "CobaltStrike_SleepMask":      9,
    "Mimikatz_Generic":           10,
    "Metasploit_Meterpreter":     10,
    "Metasploit_Shellcode":        9,
    "Ransomware_Generic_Note":    10,
    "Ransomware_WannaCry":        10,
    "Ransomware_LockBit":         10,
    "Ransomware_Ryuk":            10,
    "RAT_AsyncRAT":                9,
    "RAT_NjRAT":                   9,
    "RAT_QuasarRAT":               9,
    "Loader_GuLoader":             8,
    "Loader_PrivateLoader":        8,
    "PostExploit_BloodHound":      8,
    "PostExploit_Rubeus":          9,
    "PostExploit_Impacket":        8,
    "Evasion_AMSI_Bypass":         8,
    "Evasion_ETW_Bypass":          8,
    "Evasion_Powershell_Encoded":  7,
    "Spyware_Keylogger":           8,
    "Cryptominer_XMRig":           7,
}

_RULE_MITRE: dict[str, str] = {
    "CobaltStrike_Beacon":        "T1059.003",
    "CobaltStrike_SleepMask":     "T1027",
    "Mimikatz_Generic":           "T1003.001",
    "Metasploit_Meterpreter":     "T1059",
    "Metasploit_Shellcode":       "T1055",
    "Ransomware_Generic_Note":    "T1486",
    "Ransomware_WannaCry":        "T1486",
    "Ransomware_LockBit":         "T1486",
    "Ransomware_Ryuk":            "T1486",
    "RAT_AsyncRAT":               "T1219",
    "RAT_NjRAT":                  "T1219",
    "RAT_QuasarRAT":              "T1219",
    "Loader_GuLoader":            "T1105",
    "Loader_PrivateLoader":       "T1105",
    "PostExploit_BloodHound":     "T1069.002",
    "PostExploit_Rubeus":         "T1558",
    "PostExploit_Impacket":       "T1021.002",
    "Evasion_AMSI_Bypass":        "T1562.001",
    "Evasion_ETW_Bypass":         "T1562.006",
    "Evasion_Powershell_Encoded": "T1027",
    "Spyware_Keylogger":          "T1056.001",
    "Cryptominer_XMRig":          "T1496",
}


# ─────────────────────────────────────────────────────────────────────────────
class _FileEventHandler(FileSystemEventHandler):
    """Watchdog handler que encola archivos creados/modificados para análisis."""

    def __init__(self, scanner: "YaraScanner"):
        super().__init__()
        self._scanner = scanner

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._scanner.scan_file(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._scanner.scan_file(Path(event.src_path))


# ─────────────────────────────────────────────────────────────────────────────
class YaraScanner:
    """
    Escáner YARA en tiempo real para detección de malware por firma.

    Combina watchdog (alertas instantáneas al crear/modificar archivos)
    con un escaneo inicial de las rutas configuradas al arrancar.
    """

    def __init__(self, callback: Callable[[dict], None]):
        self._callback   = callback
        self._rules      = None          # yara_x.Rules compiladas
        self._observer   = None          # watchdog Observer
        self._alerted: set[str] = set()  # rutas ya alertadas

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self):
        if not _YARA_AVAILABLE:
            logger.warning("yara-x no disponible. YARA Scanner desactivado.")
            return

        self._rules = self._load_rules()
        if not self._rules:
            return

        # Watchdog — vigilancia en tiempo real
        handler        = _FileEventHandler(self)
        self._observer = Observer()
        watched = 0
        for watch_dir in _WATCH_DIRS:
            if not watch_dir.exists():
                continue
            try:
                # Probar acceso antes de agendar watchdog (el handle real se abre en observer.start())
                with os.scandir(str(watch_dir)):
                    pass
                self._observer.schedule(handler, str(watch_dir), recursive=False)
                watched += 1
            except PermissionError:
                logger.warning("YaraScanner: sin acceso a %s (se requiere Admin).", watch_dir)
            except Exception as exc:
                logger.warning("YaraScanner: no se puede vigilar %s: %s", watch_dir, exc)

        if watched == 0:
            logger.warning("YaraScanner: ningún directorio accesible. Scanner desactivado.")
            return

        self._observer.start()

        # Escaneo inicial en hilo aparte para no bloquear el arranque
        if _SCAN_ON_START:
            t = threading.Thread(target=self._initial_scan,
                                 name="YaraScanner-Init", daemon=True)
            t.start()

        logger.info(
            "YaraScanner iniciado. Vigilando %d directorios.",
            watched,
        )

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        logger.info("YaraScanner detenido.")

    # ── Carga de reglas ───────────────────────────────────────────────────────
    def _load_rules(self):
        if not _RULES_FILE.exists():
            logger.error("Archivo de reglas YARA no encontrado: %s", _RULES_FILE)
            return None
        try:
            source = _RULES_FILE.read_text(encoding="utf-8")
            rules  = yara_x.compile(source)
            logger.info("Reglas YARA compiladas desde %s.", _RULES_FILE)
            return rules
        except Exception as exc:
            logger.error("Error compilando reglas YARA: %s", exc)
            return None

    # ── Escaneo inicial ───────────────────────────────────────────────────────
    def _initial_scan(self):
        """Escanea todas las rutas vigiladas al arrancar."""
        logger.info("Iniciando escaneo YARA inicial...")
        count = 0
        for watch_dir in _WATCH_DIRS:
            if not watch_dir.exists():
                continue
            try:
                for entry in watch_dir.iterdir():
                    if entry.is_file():
                        self.scan_file(entry)
                        count += 1
            except PermissionError:
                continue
        logger.info("Escaneo YARA inicial completado: %d archivos analizados.", count)

    # ── Análisis de un archivo ────────────────────────────────────────────────
    def scan_file(self, file_path: Path):
        """Analiza un archivo con las reglas YARA compiladas."""
        if not self._rules:
            return

        # Filtrar por extensión
        if file_path.suffix.lower() not in _SCAN_EXTENSIONS:
            return

        # Comprobar tamaño
        try:
            if not file_path.exists() or file_path.stat().st_size > _MAX_FILE_BYTES:
                return
        except OSError:
            return

        # Leer el contenido
        try:
            data = file_path.read_bytes()
        except (PermissionError, OSError):
            return

        # Ejecutar las reglas YARA
        try:
            results = self._rules.scan(data)
            matching = list(results.matching_rules)
        except Exception as exc:
            logger.debug("Error escaneando %s: %s", file_path, exc)
            return

        for rule in matching:
            rule_name = rule.identifier
            alert_key = f"{file_path}::{rule_name}"
            if alert_key in self._alerted:
                continue
            self._alerted.add(alert_key)

            severity = _RULE_SEVERITY.get(rule_name, 7)
            mitre    = _RULE_MITRE.get(rule_name, "T1204")

            logger.warning(
                "YARA match: regla '%s' en archivo '%s' (sev %d)",
                rule_name, file_path, severity,
            )
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "YaraScanner",
                "type": "yara_match",
                "severity": severity,
                "confidence": 90,
                "description": (
                    f"Firma YARA '{rule_name}' detectada en: {file_path}"
                ),
                "details": {
                    "file": str(file_path),
                    "yara_rule": rule_name,
                    "file_size_kb": len(data) // 1024,
                },
                "mitre_technique": mitre,
                "mitre_tactic": "Execution / Defense Evasion / Impact",
            })
