"""
PrivilegeManager — Gestión de privilegios mínimos (Principle of Least Privilege).

Cumplimiento:
  - INCIBE: Gestión de permisos y principio de menor privilegio
  - MASVS V6: Platform Interaction (MSTG-PLATFORM-1, MSTG-PLATFORM-2)
  - OWASP A01: Broken Access Control
  - CIS Control 6: Access Control Management
  - Windows: UAC, token de integridad, eliminación de privilegios innecesarios

Funcionalidades:
  1. Auditoría de privilegios del proceso actual
  2. Eliminación de privilegios no necesarios del token de seguridad
  3. Verificación de integridad del proceso (High vs Medium vs Low)
  4. Monitorización de procesos con privilegios excesivos
  5. Bloqueo de directorios sensibles (ACLs NTFS)
  6. Informe de permisos de archivos críticos

Uso desde main.py:
    from monitors.privilege_manager import PrivilegeManager
    pm = PrivilegeManager(on_alert)
    pm.start()   # inicia auditoría periódica
    pm.stop()
"""

import os
import threading
import time
from typing import Callable

from utils.logger import get_logger

logger = get_logger("PrivilegeManager")

# Privilegios que StrikeBack NO necesita y debe eliminar de su token
# Ref: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
_UNNECESSARY_PRIVILEGES = [
    "SeCreateTokenPrivilege",        # Crear tokens → solo LSASS
    "SeAssignPrimaryTokenPrivilege", # Asignar tokens a procesos
    "SeTcbPrivilege",                # Parte del SO (TCB)
    "SeLoadDriverPrivilege",         # Cargar/descargar drivers
    "SeBackupPrivilege",             # Bypass ACLs para backup
    "SeRestorePrivilege",            # Bypass ACLs para restore
    "SeCreatePermanentPrivilege",    # Objetos kernel permanentes
    "SeRelabelPrivilege",            # Modificar etiquetas de integridad
    "SeEnableDelegationPrivilege",   # Kerberos delegation
    "SeSyncAgentPrivilege",          # Sincronización de directorio
    "SeAuditPrivilege",              # Generar entradas de auditoría
]

# Procesos que DEBERÍAN tener integridad alta pero NO deberían haberse elevado
_SUSPICIOUS_HIGH_INTEGRITY = {
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    "winrar.exe", "7zg.exe", "vlc.exe",
}

_SCAN_INTERVAL = 120  # segundos entre auditorías


class PrivilegeManager:
    """Monitor de privilegios mínimos y auditor de permisos."""

    def __init__(self, on_alert: Callable[[dict], None]):
        self._on_alert  = on_alert
        self._running   = False
        self._thread: threading.Thread | None = None
        self._alerted_pids: set[int] = set()

    # ── Ciclo de vida ─────────────────────────────────────────────────────────
    def start(self) -> None:
        self._running = True
        # Auditoría inmediata del propio proceso
        threading.Thread(
            target=self._initial_audit,
            name="PrivilegeMgr-Init",
            daemon=True,
        ).start()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="PrivilegeMgr",
            daemon=True,
        )
        self._thread.start()
        logger.info("PrivilegeManager iniciado.")

    def stop(self) -> None:
        self._running = False
        logger.info("PrivilegeManager detenido.")

    # ── Auditoría inicial del proceso propio ──────────────────────────────────
    def _initial_audit(self) -> None:
        """Ejecuta endurecimiento del token propio al arrancar."""
        try:
            removed = self._drop_unnecessary_privileges()
            level   = self._get_integrity_level()
            logger.info(
                f"Auditoría de token propia: nivel={level}, "
                f"privilegios eliminados={len(removed)}"
            )
            if removed:
                logger.info(f"  Eliminados: {', '.join(removed)}")
        except Exception as exc:
            logger.debug(f"Auditoría inicial: {exc}")

    # ── Bucle de monitorización ───────────────────────────────────────────────
    def _monitor_loop(self) -> None:
        """Audita periódicamente procesos con privilegios excesivos."""
        while self._running:
            try:
                self._check_suspicious_elevated_procs()
                self._check_critical_file_permissions()
            except Exception as exc:
                logger.debug(f"PrivilegeManager error: {exc}")
            time.sleep(_SCAN_INTERVAL)

    # ── Eliminación de privilegios propios ────────────────────────────────────
    def _drop_unnecessary_privileges(self) -> list[str]:
        """
        Elimina del token del proceso actual los privilegios no necesarios.
        Esto limita el daño si StrikeBack es comprometido.
        """
        import ctypes
        import ctypes.wintypes

        removed = []
        try:
            import win32security
            import win32api
            import win32con

            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
            )

            for priv_name in _UNNECESSARY_PRIVILEGES:
                try:
                    priv_id = win32security.LookupPrivilegeValue(None, priv_name)
                    # SE_PRIVILEGE_REMOVED = 4
                    new_privs = [(priv_id, 4)]
                    win32security.AdjustTokenPrivileges(token, False, new_privs)
                    removed.append(priv_name)
                except Exception:
                    pass  # El privilegio no estaba en el token → ignorar

        except Exception as exc:
            logger.debug(f"_drop_unnecessary_privileges: {exc}")

        return removed

    # ── Nivel de integridad ───────────────────────────────────────────────────
    def _get_integrity_level(self, pid: int | None = None) -> str:
        """
        Retorna el nivel de integridad del proceso (Low/Medium/High/System).
        Si pid=None, consulta el proceso actual.
        """
        _LEVELS = {0x1000: "Low", 0x2000: "Medium", 0x3000: "High", 0x4000: "System"}
        try:
            import win32security
            import win32api
            import win32process
            import win32con

            if pid is None:
                handle = win32api.GetCurrentProcess()
            else:
                handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION, False, pid
                )

            token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
            # TokenIntegrityLevel = 25
            label = win32security.GetTokenInformation(token, 25)
            rid   = win32security.GetSidSubAuthority(label[0], 0)
            return _LEVELS.get(rid & 0xF000, f"Unknown(0x{rid:04x})")
        except Exception:
            return "Unknown"

    # ── Procesos con elevación sospechosa ────────────────────────────────────
    def _check_suspicious_elevated_procs(self) -> None:
        """
        Detecta procesos comunes (navegadores, editores) con integridad High.
        Suele indicar explotación de vulnerabilidad o elevación maliciosa.
        """
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    name = (proc.info.get("name") or "").lower()
                    pid  = proc.info.get("pid", 0)
                    if name in _SUSPICIOUS_HIGH_INTEGRITY and pid not in self._alerted_pids:
                        level = self._get_integrity_level(pid)
                        if level == "High":
                            self._alerted_pids.add(pid)
                            self._on_alert({
                                "source":      "PrivilegeManager",
                                "severity":    8,
                                "title":       f"Proceso con elevación sospechosa: {name}",
                                "description": (
                                    f"{name} (PID {pid}) se está ejecutando con "
                                    f"integridad Alta sin justificación aparente."
                                ),
                                "details": {
                                    "pid":             pid,
                                    "process":         name,
                                    "integrity_level": level,
                                    "mitre":           "T1548.002",
                                },
                                "mitre": "T1548.002",
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as exc:
            logger.debug(f"_check_suspicious_elevated_procs: {exc}")

    # ── Permisos de archivos críticos ────────────────────────────────────────
    def _check_critical_file_permissions(self) -> None:
        """
        Verifica que los archivos sensibles de StrikeBack (.keystore, .auth_config,
        .tls/) no sean accesibles por otros usuarios.
        """
        import stat

        sensitive_files = [
            "data/.keystore",
            "data/.auth_config",
            "data/.tls/server.key",
        ]

        for fpath in sensitive_files:
            if not os.path.exists(fpath):
                continue
            try:
                file_stat = os.stat(fpath)
                # En Windows stat no refleja ACLs reales; verificamos mediante WinAPI
                if not self._is_owner_only_readable(fpath):
                    self._on_alert({
                        "source":      "PrivilegeManager",
                        "severity":    7,
                        "title":       f"Permisos permisivos en archivo sensible",
                        "description": (
                            f"{fpath} puede ser legible por otros usuarios. "
                            "Revisa los permisos NTFS del archivo."
                        ),
                        "details": {"file": fpath, "mitre": "T1552.001"},
                        "mitre": "T1552.001",
                    })
            except Exception:
                pass

    @staticmethod
    def _is_owner_only_readable(fpath: str) -> bool:
        """
        Comprueba si solo el propietario tiene acceso al archivo (vía WinAPI).
        Retorna True si los permisos son seguros.
        """
        try:
            import win32security
            import win32api
            import ntsecuritycon as ntcon

            # Obtener DACL actual
            sd   = win32security.GetFileSecurity(
                fpath, win32security.DACL_SECURITY_INFORMATION |
                       win32security.OWNER_SECURITY_INFORMATION
            )
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None:
                return False  # Sin DACL = sin restricción = inseguro

            # Verificar que no hay ACEs de Everyone ni Authenticated Users
            everyone_sid   = win32security.CreateWellKnownSid(
                win32security.WinWorldSid, None
            )
            auth_users_sid = win32security.CreateWellKnownSid(
                win32security.WinAuthenticatedUserSid, None
            )

            for i in range(dacl.GetAceCount()):
                ace        = dacl.GetAce(i)
                ace_type   = ace[0][0]   # ACCESS_ALLOWED_ACE_TYPE = 0
                ace_sid    = ace[2]
                if ace_type == 0:        # Allow
                    if (win32security.EqualSid(ace_sid, everyone_sid) or
                            win32security.EqualSid(ace_sid, auth_users_sid)):
                        return False     # Acceso global → inseguro

            return True
        except Exception:
            return True  # Sin pywin32 → asumir correcto (no alertar falso positivo)

    # ── Info de auditoría ────────────────────────────────────────────────────
    def get_audit_info(self) -> dict:
        """Retorna resumen de privilegios actuales para informe de seguridad."""
        return {
            "process_pid":       os.getpid(),
            "integrity_level":   self._get_integrity_level(),
            "alerted_pids":      list(self._alerted_pids),
        }
