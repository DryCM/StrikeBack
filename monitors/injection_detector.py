"""
Injection Detector — Detección de inyección de código en procesos de Windows.

Cubre las técnicas de inyección más prevalentes según MITRE ATT&CK:

  T1055.001  DLL Injection          — DLL cargada desde ruta no confiable
  T1055.002  Portable Executable    — PE reflectivo en región anónima RWX
  T1055.012  Process Hollowing      — imagen del proceso vaciada y reemplazada
  T1055.004  Asynchronous Procedure Call (APC) — memoria ejecutable en procesos críticos

Métodos de detección utilizados (sin driver de kernel):
  1. Regiones de memoria RWX anónimas en procesos críticos del sistema
     (svchost, lsass, explorer, winlogon, csrss) → indicio de shellcode
  2. DLLs cargadas desde directorios no confiables (Temp, Downloads, AppData
     fuera de Microsoft/Windows) en procesos del sistema
  3. Process Hollowing básico: el módulo principal del proceso no coincide
     con el ejecutable real en disco (tamaños muy distintos)
  4. Parent Process Spoofing: proceso del sistema con padre inusual

El detector escanea cada 60 segundos. Usa ctypes + psutil, sin dependencias
adicionales.
"""

import os
import ctypes
import ctypes.wintypes
import threading
import struct
from datetime import datetime
from pathlib import Path
from typing import Callable

import psutil

from utils.logger import get_logger

logger = get_logger("InjectionDetector")

# ─────────────────────────────────────────────────────────────────────────────
# Constantes de la API de Windows
# ─────────────────────────────────────────────────────────────────────────────
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ           = 0x0010
_MEM_COMMIT                = 0x1000
_PAGE_EXECUTE_READWRITE    = 0x40          # RWX — región muy sospechosa
_PAGE_EXECUTE_WRITECOPY    = 0x80          # variante RWX
_MEM_IMAGE                 = 0x1000000    # región respaldada por imagen (módulo legítimo)
_MEM_PRIVATE               = 0x20000      # memoria privada (anónima) — sin respaldo en disco

_POLL_INTERVAL = 60  # segundos

# ─────────────────────────────────────────────────────────────────────────────
# Procesos de alto valor que los atacantes suelen elegir como host de inyección
# ─────────────────────────────────────────────────────────────────────────────
_HIGH_VALUE_PROCS = frozenset({
    "svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe",
    "csrss.exe", "services.exe", "wininit.exe", "dwm.exe",
    "taskhostw.exe", "spoolsv.exe", "dllhost.exe",
})

# Directorios confiables para DLLs del sistema
_TRUSTED_DLL_DIRS = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
)

# Padres legítimos para procesos críticos del sistema
# {proceso: {padres válidos}}
_LEGITIMATE_PARENTS: dict[str, frozenset[str]] = {
    "lsass.exe":    frozenset({"wininit.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "winlogon.exe": frozenset({"wininit.exe", "smss.exe"}),
    "csrss.exe":    frozenset({"smss.exe"}),
    "svchost.exe":  frozenset({"services.exe", "msiexec.exe"}),
    "explorer.exe": frozenset({"userinit.exe", "explorer.exe", ""}),
}

# ─────────────────────────────────────────────────────────────────────────────
# Estructuras de la API de Windows para VirtualQueryEx
# ─────────────────────────────────────────────────────────────────────────────
class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             ctypes.wintypes.DWORD),
        ("Protect",           ctypes.wintypes.DWORD),
        ("Type",              ctypes.wintypes.DWORD),
    ]


_kernel32 = ctypes.windll.kernel32
_psapi    = ctypes.windll.psapi


# ─────────────────────────────────────────────────────────────────────────────
def _open_process(pid: int) -> int | None:
    """Abre un handle con permisos de lectura de memoria y query."""
    handle = _kernel32.OpenProcess(
        _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid
    )
    return handle if handle else None


def _close_handle(handle: int):
    _kernel32.CloseHandle(handle)


def _iter_memory_regions(handle: int):
    """
    Itera sobre todas las regiones de memoria de un proceso mediante
    VirtualQueryEx. Genera objetos _MEMORY_BASIC_INFORMATION.
    """
    mbi  = _MEMORY_BASIC_INFORMATION()
    addr = ctypes.c_ulonglong(0)

    while True:
        ret = _kernel32.VirtualQueryEx(
            handle,
            ctypes.cast(addr, ctypes.c_void_p),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not ret:
            break
        yield mbi
        addr.value = mbi.BaseAddress + mbi.RegionSize


def _get_loaded_dlls(pid: int) -> list[str]:
    """
    Devuelve la lista de rutas de módulos cargados en el proceso (PSAPI).
    Usa EnumProcessModulesEx para obtener tanto módulos de 32 como 64 bits.
    """
    try:
        proc = psutil.Process(pid)
        return [m.path.lower() for m in proc.memory_maps() if m.path]
    except (psutil.NoSuchProcess, psutil.AccessDenied, NotImplementedError):
        return []


# ─────────────────────────────────────────────────────────────────────────────
class InjectionDetector:
    """Monitor de inyección de código en procesos de Windows."""

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Claves ya alertadas para evitar repeticiones
        self._alerted: set[str] = set()

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self):
        self._thread = threading.Thread(
            target=self._run_loop, name="InjectionDetector", daemon=True
        )
        self._thread.start()
        logger.info("InjectionDetector iniciado (intervalo %ds).", _POLL_INTERVAL)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("InjectionDetector detenido.")

    # ── Bucle principal ───────────────────────────────────────────────────────
    def _run_loop(self):
        # Breve espera inicial para no sobrecargar el arranque
        if self._stop_event.wait(10):
            return
        while not self._stop_event.is_set():
            self._scan_all_processes()
            self._stop_event.wait(_POLL_INTERVAL)

    def _scan_all_processes(self):
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
                if self._stop_event.is_set():
                    return
                try:
                    self._inspect_process(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            logger.debug("Error en escaneo de procesos: %s", exc)

    # ── Inspección de proceso individual ─────────────────────────────────────
    def _inspect_process(self, proc: psutil.Process):
        name = (proc.info.get("name") or "").lower()
        pid  = proc.info["pid"]

        # 1. Regiones RWX anónimas en procesos de alto valor
        if name in _HIGH_VALUE_PROCS:
            self._check_rwx_regions(pid, name)

        # 2. DLLs cargadas desde rutas no confiables en procesos del sistema
        if name in _HIGH_VALUE_PROCS:
            self._check_suspicious_dlls(pid, name)

        # 3. Process hollowing (diferencia de tamaño exe en disco vs memoria)
        if name in _HIGH_VALUE_PROCS:
            self._check_process_hollowing(proc, name)

        # 4. Parent process spoofing en procesos críticos
        if name in _LEGITIMATE_PARENTS:
            self._check_parent_spoofing(proc, name)

    # ── Método 1: Regiones RWX anónimas ──────────────────────────────────────
    def _check_rwx_regions(self, pid: int, proc_name: str):
        handle = _open_process(pid)
        if not handle:
            return
        try:
            for mbi in _iter_memory_regions(handle):
                if mbi.State != _MEM_COMMIT:
                    continue
                # Región RWX + privada (no respaldada por un módulo en disco)
                if (mbi.Protect in (_PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY)
                        and mbi.Type == _MEM_PRIVATE
                        and mbi.RegionSize >= 4096):

                    alert_key = f"rwx:{pid}:{mbi.BaseAddress:#x}"
                    if alert_key in self._alerted:
                        continue
                    self._alerted.add(alert_key)

                    size_kb = mbi.RegionSize // 1024
                    logger.warning(
                        "Región RWX anónima en %s (PID %d): 0x%x (%d KB)",
                        proc_name, pid, mbi.BaseAddress, size_kb,
                    )
                    self._callback({
                        "timestamp": datetime.now().isoformat(),
                        "source": "InjectionDetector",
                        "type": "rwx_anonymous_region",
                        "severity": 9,
                        "confidence": 88,
                        "description": (
                            f"Región de memoria RWX anónima detectada en proceso "
                            f"crítico '{proc_name}' (PID {pid}). "
                            f"Dirección 0x{mbi.BaseAddress:x}, tamaño {size_kb} KB. "
                            f"Indicador de shellcode o PE reflectivo inyectado."
                        ),
                        "details": {
                            "process": proc_name,
                            "pid": pid,
                            "address": hex(mbi.BaseAddress),
                            "size_kb": size_kb,
                            "protection": hex(mbi.Protect),
                        },
                        "mitre_technique": "T1055.002",
                        "mitre_tactic": "Defense Evasion / Privilege Escalation",
                    })
        finally:
            _close_handle(handle)

    # ── Método 2: DLLs desde rutas no confiables ──────────────────────────────
    def _check_suspicious_dlls(self, pid: int, proc_name: str):
        for dll_path in _get_loaded_dlls(pid):
            if not dll_path or not dll_path.endswith(".dll"):
                continue
            if any(dll_path.startswith(trusted) for trusted in _TRUSTED_DLL_DIRS):
                continue

            alert_key = f"dll:{pid}:{dll_path}"
            if alert_key in self._alerted:
                continue
            self._alerted.add(alert_key)

            logger.warning(
                "DLL no confiable en %s (PID %d): %s", proc_name, pid, dll_path
            )
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "InjectionDetector",
                "type": "untrusted_dll_injection",
                "severity": 8,
                "confidence": 82,
                "description": (
                    f"DLL cargada desde ruta no confiable en proceso crítico "
                    f"'{proc_name}' (PID {pid}): {dll_path}"
                ),
                "details": {
                    "process": proc_name,
                    "pid": pid,
                    "dll_path": dll_path,
                },
                "mitre_technique": "T1055.001",
                "mitre_tactic": "Defense Evasion / Privilege Escalation",
            })

    # ── Método 3: Process Hollowing ───────────────────────────────────────────
    def _check_process_hollowing(self, proc: psutil.Process, proc_name: str):
        try:
            exe_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return

        if not exe_path or not Path(exe_path).exists():
            return

        try:
            disk_size = Path(exe_path).stat().st_size
        except OSError:
            return

        try:
            mem_info = proc.memory_info()
            # Heurística: si el RSS es más de 20× el tamaño en disco, posible hollowing
            if disk_size > 0 and mem_info.rss > disk_size * 20 and mem_info.rss > 50_000_000:
                alert_key = f"hollow:{proc.pid}"
                if alert_key in self._alerted:
                    return
                self._alerted.add(alert_key)

                ratio = mem_info.rss // disk_size
                logger.warning(
                    "Posible process hollowing en %s (PID %d): "
                    "disco=%dKB, RSS=%dKB (ratio x%d)",
                    proc_name, proc.pid, disk_size // 1024,
                    mem_info.rss // 1024, ratio,
                )
                self._callback({
                    "timestamp": datetime.now().isoformat(),
                    "source": "InjectionDetector",
                    "type": "process_hollowing",
                    "severity": 9,
                    "confidence": 75,
                    "description": (
                        f"Posible Process Hollowing en '{proc_name}' (PID {proc.pid}): "
                        f"el uso de memoria RSS ({mem_info.rss // 1024} KB) supera en "
                        f"x{ratio} el tamaño del ejecutable en disco "
                        f"({disk_size // 1024} KB)."
                    ),
                    "details": {
                        "process": proc_name,
                        "pid": proc.pid,
                        "exe": exe_path,
                        "disk_size_kb": disk_size // 1024,
                        "rss_kb": mem_info.rss // 1024,
                        "ratio": ratio,
                    },
                    "mitre_technique": "T1055.012",
                    "mitre_tactic": "Defense Evasion / Privilege Escalation",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # ── Método 4: Parent Process Spoofing ─────────────────────────────────────
    def _check_parent_spoofing(self, proc: psutil.Process, proc_name: str):
        try:
            ppid = proc.ppid()
            if not ppid:
                return
            parent = psutil.Process(ppid)
            parent_name = (parent.name() or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        legitimate = _LEGITIMATE_PARENTS.get(proc_name, frozenset())
        if legitimate and parent_name not in legitimate:
            alert_key = f"ppid:{proc.pid}:{ppid}"
            if alert_key in self._alerted:
                return
            self._alerted.add(alert_key)

            logger.warning(
                "Parent spoofing: %s (PID %d) lanzado por %s (PID %d) — padre esperado: %s",
                proc_name, proc.pid, parent_name, ppid, legitimate,
            )
            self._callback({
                "timestamp": datetime.now().isoformat(),
                "source": "InjectionDetector",
                "type": "parent_process_spoofing",
                "severity": 8,
                "confidence": 80,
                "description": (
                    f"Parent Process Spoofing: '{proc_name}' (PID {proc.pid}) fue "
                    f"iniciado por '{parent_name}' (PID {ppid}), cuando el padre "
                    f"legítimo debería ser: {', '.join(legitimate) or 'desconocido'}."
                ),
                "details": {
                    "process": proc_name,
                    "pid": proc.pid,
                    "actual_parent": parent_name,
                    "actual_parent_pid": ppid,
                    "expected_parents": list(legitimate),
                },
                "mitre_technique": "T1055.004",
                "mitre_tactic": "Defense Evasion / Privilege Escalation",
            })
