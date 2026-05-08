"""
Monitor de red — detecta conexiones sospechosas en tiempo real.
"""
import threading
import time
from datetime import datetime
from typing import Callable, Optional
import psutil

import config
from utils.logger import get_logger

logger = get_logger("NetworkMonitor")


def _port_confidence(port: int, proc_name: str) -> int:
    """Confianza base según el puerto y nombre del proceso."""
    sig = config.SUSPICIOUS_PORT_SIGNATURES.get(port)
    if not sig:
        return 50
    sev, _desc, _mitre = sig
    score = 40 + sev * 5
    # Proceso desconocido o svchost conectando a puerto sospechoso sube la alerta
    if proc_name.lower() in ("desconocido", "svchost.exe", "rundll32.exe"):
        score = min(score + 15, 98)
    return min(score, 98)


class NetworkMonitor:
    """
    Escanea periódicamente las conexiones de red activas y detecta:
    - Conexiones a puertos RAT/backdoor/C2/miner (firmas por puerto)
    - IPs maliciosas conocidas
    - Picos inusuales de conexiones (port scan, C2 beacon)
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_connections: set = set()
        self.name = "Red"

    # ------------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="NetworkMon")
        self._thread.start()
        logger.info("Monitor de red iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                logger.error(f"Error en escaneo de red: {e}")
            self._stop_event.wait(timeout=config.NETWORK_SCAN_INTERVAL)

    # ------------------------------------------------------------------
    def _scan(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Acceso denegado a net_connections. Ejecuta como Administrador.")
            return

        current_conns = set()
        outgoing_ips: dict = {}

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port
            pid         = conn.pid
            proc_name   = self._get_proc_name(pid)

            key = (remote_ip, remote_port, pid)
            current_conns.add(key)
            outgoing_ips[remote_ip] = outgoing_ips.get(remote_ip, 0) + 1

            # --- Regla 1: Puerto con firma de ataque ---
            sig = config.SUSPICIOUS_PORT_SIGNATURES.get(remote_port)
            if sig and key not in self._prev_connections:
                sev, desc, mitre = sig
                confidence = _port_confidence(remote_port, proc_name)
                self._emit_threat(
                    severity=sev,
                    title=f"[{mitre}] Conexión sospechosa puerto {remote_port}: {desc}",
                    description=(
                        f"Proceso '{proc_name}' (PID {pid}) conectado a "
                        f"{remote_ip}:{remote_port}. Firma: {desc}"
                    ),
                    details={"ip": remote_ip, "port": remote_port, "pid": pid,
                             "process": proc_name, "mitre": mitre, "confidence": confidence},
                    confidence=confidence,
                )

            # --- Regla 2: IP maliciosa conocida ---
            if remote_ip in config.KNOWN_MALICIOUS_IPS:
                self._emit_threat(
                    severity=10,
                    title="[T1071] Conexión a IP maliciosa conocida",
                    description=(
                        f"Proceso '{proc_name}' (PID {pid}) conectado a IP en lista negra: {remote_ip}"
                    ),
                    details={"ip": remote_ip, "port": remote_port, "pid": pid,
                             "process": proc_name, "confidence": 99},
                    confidence=99,
                )

        # --- Regla 3: Muchas IPs distintas = posible C2 beacon / escaneo ---
        for ip, count in outgoing_ips.items():
            if count >= 20:
                confidence = min(50 + count, 90)
                self._emit_threat(
                    severity=6,
                    title=f"[T1046] Actividad inusual — {count} conexiones a {ip}",
                    description=(
                        f"Se detectaron {count} conexiones simultáneas a {ip}. "
                        f"Posible port-scan saliente o beacon C2."
                    ),
                    details={"ip": ip, "count": count, "confidence": confidence},
                    confidence=confidence,
                )

        self._prev_connections = current_conns

    # ------------------------------------------------------------------
    def get_active_connections(self) -> list[dict]:
        result = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status not in ("ESTABLISHED", "LISTEN"):
                    continue
                if not conn.raddr:
                    continue
                port     = conn.raddr.port
                is_susp  = port in config.SUSPICIOUS_PORTS
                sig_desc = config.SUSPICIOUS_PORT_SIGNATURES.get(port, (0, "", ""))[1] if is_susp else ""
                result.append({
                    "pid":         conn.pid,
                    "process":     self._get_proc_name(conn.pid),
                    "local_port":  conn.laddr.port if conn.laddr else "-",
                    "remote_ip":   conn.raddr.ip,
                    "remote_port": port,
                    "status":      conn.status,
                    "suspicious":  is_susp,
                    "sig_desc":    sig_desc,
                })
        except psutil.AccessDenied:
            pass
        return result[:30]

    # ------------------------------------------------------------------
    def _emit_threat(self, severity: int, title: str, description: str,
                     details: dict, confidence: int = 70):
        threat = {
            "source":      "Red",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "confidence":  confidence,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA {confidence}%] {title}")
        self.threat_callback(threat)

    @staticmethod
    def _get_proc_name(pid: Optional[int]) -> str:
        if not pid:
            return "desconocido"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"PID-{pid}"



class NetworkMonitor:
    """
    Escanea periódicamente las conexiones de red activas y detecta:
    - Conexiones a puertos asociados a RAT/backdoors
    - IPs maliciosas conocidas
    - Picos inusuales de conexiones salientes
    """

    def __init__(self, threat_callback: Callable):
        self.threat_callback = threat_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_connections: set = set()
        self._connection_counts: dict = {}   # IP -> count (para detectar escaneo)
        self.name = "Red"

    # ------------------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="NetworkMon")
        self._thread.start()
        logger.info("Monitor de red iniciado.")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                logger.error(f"Error en escaneo de red: {e}")
            self._stop_event.wait(timeout=config.NETWORK_SCAN_INTERVAL)

    # ------------------------------------------------------------------
    def _scan(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Acceso denegado a net_connections. Ejecuta como Administrador.")
            return

        current_conns = set()
        outgoing_ips: dict = {}

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port  = conn.laddr.port if conn.laddr else 0
            pid         = conn.pid

            # Resolver nombre del proceso
            proc_name = self._get_proc_name(pid)

            key = (remote_ip, remote_port, pid)
            current_conns.add(key)

            # Contar IPs salientes para detectar port-scanning
            outgoing_ips[remote_ip] = outgoing_ips.get(remote_ip, 0) + 1

            # --- Regla 1: Puerto sospechoso ---
            if remote_port in config.SUSPICIOUS_PORTS:
                self._emit_threat(
                    severity=8,
                    title="Conexión a puerto sospechoso (RAT/Backdoor)",
                    description=(
                        f"Proceso '{proc_name}' (PID {pid}) conectado a "
                        f"{remote_ip}:{remote_port}. Puerto asociado a herramientas de acceso remoto."
                    ),
                    details={"ip": remote_ip, "port": remote_port, "pid": pid, "process": proc_name},
                    is_new=key not in self._prev_connections,
                )

            # --- Regla 2: IP maliciosa conocida ---
            if remote_ip in config.KNOWN_MALICIOUS_IPS:
                self._emit_threat(
                    severity=10,
                    title="Conexión a IP maliciosa conocida",
                    description=(
                        f"Proceso '{proc_name}' (PID {pid}) conectado a IP en lista negra: {remote_ip}"
                    ),
                    details={"ip": remote_ip, "port": remote_port, "pid": pid, "process": proc_name},
                    is_new=True,
                )

        # --- Regla 3: Muchas conexiones a IPs distintas (posible escaneo/C2) ---
        for ip, count in outgoing_ips.items():
            if count >= 20:
                self._emit_threat(
                    severity=6,
                    title="Actividad de red inusual — posible escaneo o C2",
                    description=f"Se detectaron {count} conexiones simultáneas a {ip}. Posible comunicación C2 o port-scan.",
                    details={"ip": ip, "count": count},
                    is_new=True,
                )

        self._prev_connections = current_conns

    # ------------------------------------------------------------------
    def get_active_connections(self) -> list[dict]:
        """Retorna lista resumida de conexiones activas para el dashboard."""
        result = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status not in ("ESTABLISHED", "LISTEN"):
                    continue
                if not conn.raddr:
                    continue
                result.append({
                    "pid":         conn.pid,
                    "process":     self._get_proc_name(conn.pid),
                    "local_port":  conn.laddr.port if conn.laddr else "-",
                    "remote_ip":   conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "status":      conn.status,
                })
        except psutil.AccessDenied:
            pass
        return result[:30]  # máximo 30 para el dashboard

    # ------------------------------------------------------------------
    def _emit_threat(self, severity: int, title: str, description: str,
                     details: dict, is_new: bool):
        if not is_new:
            return
        threat = {
            "source":      "Red",
            "severity":    severity,
            "title":       title,
            "description": description,
            "details":     details,
            "timestamp":   datetime.now().isoformat(),
        }
        logger.warning(f"[AMENAZA] {title}")
        self.threat_callback(threat)

    @staticmethod
    def _get_proc_name(pid: Optional[int]) -> str:
        if not pid:
            return "desconocido"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"PID-{pid}"
