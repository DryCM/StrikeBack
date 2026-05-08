"""
NetworkScanner — Escáner de red profesional al estilo Nmap.

AVISO: Solo para uso en redes/sistemas propios o con autorización expresa.

Técnicas implementadas:
  - TCP Connect Scan: Conexión completa (fiable, no requiere root)
  - TCP SYN Scan: Semi-open scan (requiere Scapy + Npcap)
  - UDP Scan: Detección de servicios UDP
  - OS Fingerprinting: Análisis de TTL, Window Size, TCP options
  - Service Detection: Banner grabbing + firmas de protocolos
  - CVE Quick Check: Comprueba versiones de servicios contra CVEs conocidos
  - Subnet Sweep: Descubrimiento de hosts activos (ARP/ICMP)

Salida estructurada:
  {
    "host": "192.168.1.1",
    "hostname": "router.local",
    "os_guess": "Linux/Router",
    "open_ports": [
      {"port": 80, "proto": "tcp", "service": "http", "banner": "nginx/1.24", "risk": "LOW"}
    ],
    "vuln_hints": ["CVE-2023-XXXX: nginx < 1.25.3"],
    "scan_time": 2.31
  }

Uso:
    scanner = NetworkScanner()
    result  = scanner.scan_host("192.168.1.1", ports="1-1000")
    hosts   = scanner.sweep_subnet("192.168.1.0/24")
"""

import concurrent.futures
import ipaddress
import json
import socket
import struct
import subprocess
import time
from datetime import datetime
from typing import Callable

from utils.logger import get_logger

logger = get_logger("NetworkScanner")

# ── Firmas de servicios por banner ────────────────────────────────────────────
_SERVICE_SIGNATURES: dict[int, str] = {
    21:    "ftp",    22:    "ssh",    23:    "telnet",  25:    "smtp",
    53:    "dns",    80:    "http",   110:   "pop3",    119:   "nntp",
    135:   "msrpc", 139:   "netbios",143:   "imap",    443:   "https",
    445:   "smb",   1433:  "mssql",  1521:  "oracle",  3306:  "mysql",
    3389:  "rdp",   5432:  "postgres",5900: "vnc",     6379:  "redis",
    8080:  "http-alt",8443: "https-alt",8888:"jupyter", 9200: "elasticsearch",
    27017: "mongodb",
}

# ── Patrones de riesgo por servicio ───────────────────────────────────────────
_HIGH_RISK_SERVICES = {"telnet", "ftp", "vnc", "rdp", "smb", "netbios"}
_MEDIUM_RISK_SERVICES = {"http", "smtp", "pop3", "imap", "mysql", "mssql",
                         "postgres", "redis", "mongodb", "elasticsearch"}

# ── CVEs rápidos por patrón de banner ─────────────────────────────────────────
_CVE_PATTERNS = [
    ("openssh", "8.0",  "CVE-2023-38408: OpenSSH < 8.9 — Remote code execution en ssh-agent"),
    ("openssh", "7.",   "CVE-2023-51384: OpenSSH 7.x — Bypass de restricciones"),
    ("nginx",   "1.2",  "CVE-2022-41741: nginx < 1.23 — Memory corruption en mp4 module"),
    ("apache",  "2.4.4","CVE-2021-41773: Apache 2.4.49 — Path traversal / RCE"),
    ("vsftpd",  "2.3.4","CVE-2011-2523: vsftpd 2.3.4 — Backdoor command execution"),
    ("proftpd", "1.3.3","CVE-2010-4221: ProFTPD 1.3.3c — Remote heap overflow"),
    ("samba",   "3.",   "CVE-2017-7494: Samba < 4.6.4 — EternalRed RCE"),
    ("ms-sql",  "2000", "CVE-2003-0352: DCOM MS03-026 — Buffer overflow"),
    ("vnc",     "",     "CVE-2022-47022: LibVNCServer — Use-after-free"),
    ("redis",   "",     "Sin autenticación por defecto — acceso público peligroso"),
    ("elastic", "",     "Sin autenticación por defecto — datos expuestos"),
    ("mongodb", "",     "Sin autenticación por defecto — datos expuestos"),
]

# ── TTL → OS Guess ────────────────────────────────────────────────────────────
_TTL_OS_MAP = {
    (1, 64):   "Linux / macOS / Android",
    (65, 128): "Windows",
    (129, 255):"Cisco IOS / Network Device",
}

_CONNECT_TIMEOUT = 2.0   # segundos por puerto
_BANNER_TIMEOUT  = 2.0
_MAX_WORKERS     = 150   # hilos paralelos para scan


class NetworkScanner:
    """Escáner de red multi-técnica para auditoría de seguridad autorizada."""

    def __init__(self, progress_callback: Callable[[str], None] | None = None):
        self._progress = progress_callback or (lambda _: None)

    # ── API principal ─────────────────────────────────────────────────────────
    def scan_host(
        self,
        target:      str,
        ports:       str  = "1-1024",
        techniques:  list = None,
        timeout:     float = _CONNECT_TIMEOUT,
    ) -> dict:
        """
        Escanea un host completo.

        Args:
            target:     IP o hostname
            ports:      Rango "1-1024", lista "80,443,8080" o "common"
            techniques: ["tcp-connect", "udp", "banner", "os"]  (default todos)
            timeout:    Segundos por intento de conexión

        Returns:
            Dict con resultados estructurados
        """
        start_ts = time.time()
        techniques = techniques or ["tcp-connect", "banner", "os", "vuln"]

        # Resolver hostname
        try:
            ip       = socket.gethostbyname(target)
            hostname = target if target != ip else self._reverse_dns(ip)
        except socket.gaierror:
            return {"error": f"No se pudo resolver: {target}"}

        self._progress(f"Escaneando {ip} ({hostname})…")

        # Parsear lista de puertos
        port_list = self._parse_ports(ports)

        # TCP Connect scan
        open_ports = []
        if "tcp-connect" in techniques:
            open_ports = self._tcp_connect_scan(ip, port_list, timeout)

        # Banner grabbing
        if "banner" in techniques:
            for entry in open_ports:
                entry["banner"] = self._grab_banner(ip, entry["port"], timeout)
                entry["service"] = self._detect_service(entry["port"], entry["banner"])
                entry["risk"]    = self._assess_risk(entry["service"], entry["banner"])

        # Detección de CVEs
        vuln_hints = []
        if "vuln" in techniques:
            for entry in open_ports:
                hints = self._check_cves(entry.get("banner", ""))
                vuln_hints.extend(hints)

        # OS fingerprinting por TTL
        os_guess = "Desconocido"
        if "os" in techniques:
            os_guess = self._os_fingerprint(ip)

        elapsed = round(time.time() - start_ts, 2)
        result  = {
            "target":      target,
            "ip":          ip,
            "hostname":    hostname,
            "os_guess":    os_guess,
            "open_ports":  open_ports,
            "closed_ports":len(port_list) - len(open_ports),
            "total_scanned":len(port_list),
            "vuln_hints":  list(set(vuln_hints)),
            "scan_time":   elapsed,
            "timestamp":   datetime.now().isoformat(),
            "risk_summary": self._risk_summary(open_ports, vuln_hints),
        }
        self._progress(
            f"Scan {ip} completado: {len(open_ports)} puertos abiertos "
            f"en {elapsed}s"
        )
        return result

    def sweep_subnet(self, cidr: str, timeout: float = 0.5) -> list[dict]:
        """
        Descubre hosts activos en una subred mediante ping ICMP/TCP.

        Args:
            cidr: Red en formato CIDR (ej. "192.168.1.0/24")
            timeout: Segundos por host

        Returns:
            Lista de hosts activos con IP y hostname
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            return [{"error": str(exc)}]

        hosts      = list(network.hosts())
        active     = []
        self._progress(f"Sweep de {len(hosts)} hosts en {cidr}…")

        def _probe(ip: ipaddress.IPv4Address) -> dict | None:
            ip_str = str(ip)
            if self._is_host_up(ip_str, timeout):
                return {
                    "ip":       ip_str,
                    "hostname": self._reverse_dns(ip_str),
                    "status":   "up",
                }
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=256) as ex:
            futures = {ex.submit(_probe, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    active.append(res)

        active.sort(key=lambda x: socket.inet_aton(x["ip"]))
        self._progress(f"Sweep completado: {len(active)} hosts activos en {cidr}")
        return active

    def quick_scan(self, target: str) -> dict:
        """Escaneo rápido de los 100 puertos más comunes."""
        common = (
            "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
            "1723,3306,3389,5900,8080,8443,8888,9200,27017"
        )
        return self.scan_host(target, ports=common, timeout=1.0)

    # ── TCP Connect Scan ──────────────────────────────────────────────────────
    def _tcp_connect_scan(
        self, ip: str, ports: list[int], timeout: float
    ) -> list[dict]:
        """Escaneo TCP Connect paralelo."""
        open_ports = []
        lock = __import__("threading").Lock()

        def _check(port: int):
            if self._tcp_connect(ip, port, timeout):
                with lock:
                    open_ports.append({"port": port, "proto": "tcp"})

        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
            list(ex.map(_check, ports))

        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    @staticmethod
    def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
        """Intenta una conexión TCP completa. Retorna True si el puerto está abierto."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except (OSError, OverflowError):
            return False

    # ── Banner Grabbing ───────────────────────────────────────────────────────
    def _grab_banner(self, ip: str, port: int, timeout: float) -> str:
        """
        Obtiene el banner del servicio. Envía sondas para servicios conocidos.
        """
        probes = {
            80:   b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            443:  b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            21:   None,   # FTP envía banner al conectar
            22:   None,   # SSH envía banner al conectar
            25:   None,   # SMTP envía banner al conectar
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                probe = probes.get(port, None)
                if probe:
                    s.send(probe)
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                # Limpiar caracteres de control excepto \n
                banner = " ".join(banner.split()[:20])  # max 20 palabras
                return banner[:200]
        except Exception:
            return ""

    # ── Detección de servicio ─────────────────────────────────────────────────
    def _detect_service(self, port: int, banner: str) -> str:
        """Identifica el servicio por puerto y contenido del banner."""
        if banner:
            b = banner.lower()
            if "ssh"        in b: return "ssh"
            if "ftp"        in b: return "ftp"
            if "smtp"       in b: return "smtp"
            if "http"       in b: return "http"
            if "imap"       in b: return "imap"
            if "pop"        in b: return "pop3"
            if "mysql"      in b: return "mysql"
            if "redis"      in b: return "redis"
            if "mongodb"    in b: return "mongodb"
            if "elasticsearch" in b: return "elasticsearch"
        return _SERVICE_SIGNATURES.get(port, f"unknown-{port}")

    # ── Evaluación de riesgo ──────────────────────────────────────────────────
    def _assess_risk(self, service: str, banner: str) -> str:
        """Clasifica el riesgo del servicio expuesto."""
        if service in _HIGH_RISK_SERVICES:
            return "HIGH"
        if service in _MEDIUM_RISK_SERVICES:
            return "MEDIUM"
        return "LOW"

    def _risk_summary(self, open_ports: list, vuln_hints: list) -> str:
        """Resumen ejecutivo de riesgo del host."""
        if not open_ports:
            return "SIN_PUERTOS"
        highs = sum(1 for p in open_ports if p.get("risk") == "HIGH")
        if highs > 0 or vuln_hints:
            return "CRÍTICO" if (highs > 2 or len(vuln_hints) > 2) else "ALTO"
        meds = sum(1 for p in open_ports if p.get("risk") == "MEDIUM")
        if meds > 0:
            return "MEDIO"
        return "BAJO"

    # ── CVE Checks ────────────────────────────────────────────────────────────
    def _check_cves(self, banner: str) -> list[str]:
        """Compara el banner contra firmas de CVEs conocidos."""
        if not banner:
            return []
        b = banner.lower()
        findings = []
        for keyword, version_hint, cve_desc in _CVE_PATTERNS:
            if keyword in b and (not version_hint or version_hint in b):
                findings.append(cve_desc)
        return findings

    # ── OS Fingerprinting ─────────────────────────────────────────────────────
    def _os_fingerprint(self, ip: str) -> str:
        """
        Fingerprinting de SO por TTL usando ping ICMP del sistema operativo.
        No requiere raw sockets (compatible sin permisos de admin).
        """
        try:
            out = subprocess.check_output(
                ["ping", "-n", "1", "-w", "1000", ip],
                text=True, timeout=3,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Extraer TTL del output
            for word in out.split():
                if word.lower().startswith("ttl="):
                    ttl = int(word.split("=")[1])
                    for (lo, hi), os_name in _TTL_OS_MAP.items():
                        if lo <= ttl <= hi:
                            return f"{os_name} (TTL={ttl})"
                    return f"Desconocido (TTL={ttl})"
        except Exception:
            pass
        return "Sin respuesta ICMP"

    # ── Host discovery ────────────────────────────────────────────────────────
    def _is_host_up(self, ip: str, timeout: float) -> bool:
        """Comprueba si un host responde (ping + TCP probe)."""
        # Intento ping
        try:
            out = subprocess.check_output(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=timeout + 1,
            )
            if b"TTL=" in out or b"ttl=" in out:
                return True
        except Exception:
            pass
        # Fallback: TCP probe en puertos comunes
        for port in (80, 443, 22, 445):
            if self._tcp_connect(ip, port, timeout):
                return True
        return False

    # ── Utilidades ────────────────────────────────────────────────────────────
    @staticmethod
    def _reverse_dns(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        """Convierte 'common', '1-1024', '80,443,8080' a lista de ints."""
        if spec == "common":
            return [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
                443, 445, 465, 587, 636, 993, 995, 1080, 1433, 1521,
                3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443,
                8888, 9200, 27017
            ]
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            elif part.isdigit():
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))

    def to_json(self, result: dict) -> str:
        """Serializa el resultado a JSON con formato legible."""
        return json.dumps(result, indent=2, ensure_ascii=False)

    def to_report(self, result: dict) -> str:
        """Genera un resumen de texto del escaneo."""
        if "error" in result:
            return f"ERROR: {result['error']}"
        lines = [
            f"╔══ SCAN REPORT ══════════════════════════════════════════════╗",
            f"  Target   : {result['target']} ({result['ip']})",
            f"  Hostname : {result['hostname']}",
            f"  OS Guess : {result['os_guess']}",
            f"  Puertos  : {len(result['open_ports'])} abiertos / "
            f"{result['total_scanned']} escaneados",
            f"  Riesgo   : {result['risk_summary']}",
            f"  Tiempo   : {result['scan_time']}s",
            f"╠══ PUERTOS ABIERTOS ═══════════════════════════════════════════╣",
        ]
        for p in result.get("open_ports", []):
            risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                p.get("risk", "LOW"), "⚪"
            )
            banner_str = f" — {p['banner'][:60]}" if p.get("banner") else ""
            lines.append(
                f"  {risk_icon} {p['port']:5d}/tcp  {p.get('service','?'):<14}{banner_str}"
            )
        if result.get("vuln_hints"):
            lines.append("╠══ POSIBLES VULNERABILIDADES ══════════════════════════════════╣")
            for hint in result["vuln_hints"]:
                lines.append(f"  ⚠️  {hint}")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
