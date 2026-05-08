"""
Monitor de Event Log de Windows — detecta ataques de fuerza bruta,
escalada de privilegios, instalación de servicios maliciosos, etc.
"""
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Optional
from collections import defaultdict

import config
from utils.logger import get_logger

logger = get_logger("EventLogMonitor")

# Eventos de seguridad relevantes (Windows Security Event IDs)
EVENT_IDS = {
    4625: "Intento de inicio de sesión fallido",
    4648: "Intento de inicio de sesión con credenciales explícitas",
    4720: "Cuenta de usuario creada",
    4722: "Cuenta de usuario habilitada",
    4724: "Intento de restablecer contraseña",
    4728: "Miembro añadido a grupo privilegiado",
    4732: "Miembro añadido a grupo local",
    4756: "Miembro añadido a grupo universal",
    4672: "Privilegios especiales asignados al inicio de sesión",
    4697: "Servicio instalado en el sistema",
    7045: "Nuevo servicio instalado (System log)",
    4698: "Tarea programada creada",
    4702: "Tarea programada modificada",
    1102: "Registro de auditoría borrado",
    4946: "Regla de Windows Firewall añadida",
    4954: "Configuración de firewall modificada",
}


class EventLogMonitor:
    """
    Lee el Event Log de Windows Security y detecta eventos críticos.
    Requiere permisos de administrador para leer Security log.
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._failed_logins: dict = defaultdict(list)   # user -> [timestamps]
        self._last_check   = datetime.now() - timedelta(minutes=5)
        self.name = "EventLog"
        self._available = False   # se establece en start()

    # ------------------------------------------------------------------
    def start(self):
        try:
            import win32evtlog  # noqa: F401
            self._available = True
        except ImportError:
            logger.warning("pywin32 no disponible. Monitor de Event Log desactivado.")
            return

        self._thread = threading.Thread(target=self._run, daemon=True, name="EventLogMon")
        self._thread.start()
        logger.info("Monitor de Event Log iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                logger.error(f"Error en Event Log: {e}")
            self._stop_event.wait(timeout=config.EVENTLOG_SCAN_INTERVAL)

    # ------------------------------------------------------------------
    def _scan(self):
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con
            import pywintypes
        except ImportError:
            return

        logs_to_check = [
            ("Security",   [4625, 4648, 4720, 4722, 4724, 4728, 4732, 4756,
                            4672, 4697, 4698, 4702, 1102, 4946, 4954]),
            ("System",     [7045]),
        ]

        since = self._last_check
        self._last_check = datetime.now()

        for log_name, target_ids in logs_to_check:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                    for ev in events:
                        try:
                            ev_time = datetime(*ev.TimeGenerated.timetuple()[:6])
                        except Exception:
                            continue

                        if ev_time < since:
                            break  # Leemos hacia atrás; ya pasamos el rango

                        ev_id = ev.EventID & 0xFFFF
                        if ev_id not in target_ids:
                            continue

                        self._process_event(ev_id, ev_time, ev, log_name)

                win32evtlog.CloseEventLog(hand)

            except Exception as e:
                if "Access is denied" in str(e):
                    logger.warning(f"Sin acceso a {log_name} log. Ejecuta como Administrador.")
                else:
                    logger.debug(f"EventLog {log_name}: {e}")

    # ------------------------------------------------------------------
    def _process_event(self, ev_id: int, ev_time: datetime, ev, log_name: str):
        import win32evtlogutil

        desc = EVENT_IDS.get(ev_id, f"Evento {ev_id}")

        try:
            msg = win32evtlogutil.SafeFormatMessage(ev, log_name)
        except Exception:
            msg = str(getattr(ev, "StringInserts", ""))

        # --- Regla: Fuerza bruta (múltiples 4625 en poco tiempo) ---
        if ev_id == 4625:
            inserts = ev.StringInserts or []
            username = inserts[5] if len(inserts) > 5 else "desconocido"
            self._failed_logins[username].append(ev_time)

            cutoff = ev_time - timedelta(minutes=5)
            self._failed_logins[username] = [
                t for t in self._failed_logins[username] if t > cutoff
            ]

            count = len(self._failed_logins[username])
            if count >= config.MAX_FAILED_LOGINS:
                confidence = min(60 + count * 5, 95)
                self._emit(
                    severity=8,
                    title=f"[T1110] Fuerza bruta — {count} fallos de login en 5 min",
                    description=(
                        f"Usuario '{username}' falló {count} veces en 5 minutos. "
                        f"Técnica T1110 - Brute Force."
                    ),
                    details={"event_id": ev_id, "user": username, "count": count,
                             "confidence": confidence},
                    confidence=confidence,
                )
                self._failed_logins[username].clear()
            return

        # --- Eventos críticos directos ---
        event_map = {
            4720: (7,  "T1136", 85),   # Cuenta creada
            4722: (6,  "T1078", 75),   # Cuenta habilitada
            4724: (6,  "T1531", 72),   # Reset contraseña
            4728: (8,  "T1098", 88),   # Miembro grupo privilegiado
            4732: (7,  "T1098", 82),   # Miembro grupo local
            4672: (5,  "T1134", 70),   # Privilegios especiales
            4697: (9,  "T1543", 92),   # Servicio instalado
            7045: (9,  "T1543", 92),   # Servicio instalado (System)
            4698: (7,  "T1053", 85),   # Tarea programada creada
            4702: (6,  "T1053", 80),   # Tarea programada modificada
            1102: (10, "T1070", 98),   # Log de auditoría borrado
            4946: (6,  "T1562", 78),   # Regla firewall añadida
            4954: (7,  "T1562", 80),   # Configuración firewall modificada
            4648: (7,  "T1550", 78),   # Login con credenciales explícitas
        }

        row = event_map.get(ev_id, (5, "T1078", 55))
        severity, mitre, confidence = row

        self._emit(
            severity=severity,
            title=f"[{mitre}] Event Log: {desc}",
            description=(
                f"{desc} detectado en {log_name} log a las {ev_time.strftime('%H:%M:%S')}.\n"
                f"{msg[:300]}"
            ),
            details={"event_id": ev_id, "log": log_name, "time": ev_time.isoformat(),
                     "mitre": mitre, "confidence": confidence},
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    def _emit(self, severity: int, title: str, description: str,
               details: dict, confidence: int = 70):
        threat = {
            "source":      "EventLog",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA {confidence}%] {title}")
        self.threat_callback(threat)
