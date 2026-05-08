"""
Registry Monitor — Detección de persistencia en el registro de Windows.

Vigila las claves de registro más usadas para que un atacante
sobreviva a reinicios o secuestre procesos del sistema:

  1. Run / RunOnce keys  (T1547.001) — programas que arrancan con Windows
  2. IFEO (Image File Execution Options) (T1546.012) — Debugger hijacking;
     atacante redirige notepad.exe → su malware
  3. Servicios nuevos  (T1543.003) — instalación de servicio malicioso

Compara snapshots cada 30 s; solo alerta en cambios NUEVOS (no en los
valores ya existentes cuando StrikeBack arranca).
"""

import winreg
import time
import threading
from datetime import datetime
from typing import Callable

from utils.logger import get_logger

logger = get_logger("RegistryMonitor")

# ── Claves Run ────────────────────────────────────────────────────────────────
_RUN_KEYS: list[tuple[int, str]] = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    # Wow6432Node (32-bit apps en Windows 64-bit)
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# ── IFEO ──────────────────────────────────────────────────────────────────────
_IFEO_KEY = (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")

# ── Servicios ─────────────────────────────────────────────────────────────────
_SERVICES_KEY = (winreg.HKEY_LOCAL_MACHINE,
                 r"SYSTEM\CurrentControlSet\Services")

# Nombres de servicios legítimos de Windows que pueden aparecer como "nuevos"
# tras una actualización; los ignoramos para reducir falsos positivos.
_SERVICE_WHITELIST_PREFIXES = (
    "cbdhsvc_", "WpnUserService_", "UnistoreSvc_", "UserDataSvc_",
    "PimIndexMaintenanceSvc_", "OneSyncSvc_",  # servicios por-usuario con sufijo
)

_POLL_INTERVAL = 30  # segundos entre comprobaciones


# ─────────────────────────────────────────────────────────────────────────────
def _read_key_values(hive: int, subkey: str) -> dict[str, str]:
    """Lee todos los valores nombre→dato de una clave; devuelve {} si no existe."""
    result: dict[str, str] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    result[name] = str(data)
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return result


def _read_subkey_names(hive: int, subkey: str) -> set[str]:
    """Devuelve el conjunto de nombres de subclaves de una clave."""
    result: set[str] = set()
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    result.add(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return result


def _read_ifeo_debuggers() -> dict[str, str]:
    """
    Lee todos los debuggers instalados en IFEO.
    Devuelve {exe_name: debugger_value}.
    """
    hive, subkey = _IFEO_KEY
    result: dict[str, str] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as ifeo_key:
            i = 0
            while True:
                try:
                    exe_name = winreg.EnumKey(ifeo_key, i)
                    try:
                        with winreg.OpenKey(ifeo_key, exe_name, 0,
                                            winreg.KEY_READ) as exe_key:
                            try:
                                val, _ = winreg.QueryValueEx(exe_key, "Debugger")
                                result[exe_name] = str(val)
                            except OSError:
                                pass  # no tiene Debugger
                    except OSError:
                        pass
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return result


# ─────────────────────────────────────────────────────────────────────────────
class RegistryMonitor:
    """Monitor de persistencia en el Registro de Windows."""

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Snapshots iniciales (se toman en start())
        self._run_snapshot: dict[str, dict[str, str]] = {}
        self._ifeo_snapshot: dict[str, str] = {}
        self._services_snapshot: set[str] = set()

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self):
        self._take_initial_snapshots()
        self._thread = threading.Thread(target=self._run_loop,
                                        name="RegistryMonitor", daemon=True)
        self._thread.start()
        logger.info("RegistryMonitor iniciado (intervalo %ds).", _POLL_INTERVAL)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("RegistryMonitor detenido.")

    # ── Snapshot inicial ──────────────────────────────────────────────────────
    def _take_initial_snapshots(self):
        for hive, subkey in _RUN_KEYS:
            key_id = f"{hive}\\{subkey}"
            self._run_snapshot[key_id] = _read_key_values(hive, subkey)

        self._ifeo_snapshot = _read_ifeo_debuggers()
        self._services_snapshot = _read_subkey_names(*_SERVICES_KEY)
        logger.debug(
            "Snapshots: %d Run entries, %d IFEO debuggers, %d services.",
            sum(len(v) for v in self._run_snapshot.values()),
            len(self._ifeo_snapshot),
            len(self._services_snapshot),
        )

    # ── Bucle principal ───────────────────────────────────────────────────────
    def _run_loop(self):
        while not self._stop_event.wait(_POLL_INTERVAL):
            self._check_run_keys()
            self._check_ifeo()
            self._check_new_services()

    # ── Comprobaciones ────────────────────────────────────────────────────────
    def _check_run_keys(self):
        for hive, subkey in _RUN_KEYS:
            key_id = f"{hive}\\{subkey}"
            current = _read_key_values(hive, subkey)
            baseline = self._run_snapshot.get(key_id, {})

            for name, value in current.items():
                if name not in baseline:
                    logger.warning("Nueva entrada Run detectada: [%s] = %s", name, value)
                    self._callback({
                        "timestamp": datetime.now().isoformat(),
                        "source": "RegistryMonitor",
                        "type": "registry_persistence",
                        "severity": 8,
                        "confidence": 85,
                        "description": (
                            f"Nueva entrada de arranque automático detectada: "
                            f'"{name}" → {value[:120]}'
                        ),
                        "details": {
                            "key": f"{key_id}\\{name}",
                            "value": value,
                        },
                        "mitre_technique": "T1547.001",
                        "mitre_tactic": "Persistence",
                    })
                    # Actualizar snapshot para no re-alertar
                    self._run_snapshot[key_id][name] = value

    def _check_ifeo(self):
        current = _read_ifeo_debuggers()
        for exe, debugger in current.items():
            if exe not in self._ifeo_snapshot:
                logger.warning("IFEO Debugger hijack detectado: %s → %s", exe, debugger)
                self._callback({
                    "timestamp": datetime.now().isoformat(),
                    "source": "RegistryMonitor",
                    "type": "ifeo_hijack",
                    "severity": 9,
                    "confidence": 92,
                    "description": (
                        f"Debugger IFEO instalado en '{exe}': al ejecutar {exe} "
                        f"se lanzará '{debugger[:80]}' en su lugar."
                    ),
                    "details": {
                        "target_exe": exe,
                        "debugger": debugger,
                        "key": rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                               rf"\Image File Execution Options\{exe}\Debugger",
                    },
                    "mitre_technique": "T1546.012",
                    "mitre_tactic": "Privilege Escalation / Persistence",
                })
                self._ifeo_snapshot[exe] = debugger

    def _check_new_services(self):
        current = _read_subkey_names(*_SERVICES_KEY)
        new_services = current - self._services_snapshot

        for svc in new_services:
            # Ignorar servicios por-usuario de Windows (sufijo numérico)
            if any(svc.startswith(p) for p in _SERVICE_WHITELIST_PREFIXES):
                self._services_snapshot.add(svc)
                continue

            logger.warning("Nuevo servicio instalado: %s", svc)
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "RegistryMonitor",
                "type": "new_service",
                "severity": 7,
                "confidence": 75,
                "description": (
                    f"Nuevo servicio de Windows instalado durante la sesión: '{svc}'. "
                    f"Los atacantes instalan servicios para persistir tras reinicios."
                ),
                "details": {
                    "service_name": svc,
                    "key": rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
                },
                "mitre_technique": "T1543.003",
                "mitre_tactic": "Persistence / Privilege Escalation",
            })
            self._services_snapshot.add(svc)
