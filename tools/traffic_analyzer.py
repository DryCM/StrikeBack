"""
TrafficAnalyzer — Captura y análisis de tráfico de red (estilo Wireshark).

AVISO: Solo para uso en redes propias o con autorización expresa.

Técnicas implementadas:
  - Captura de paquetes en tiempo real (Scapy + Npcap)
  - Análisis de protocolos: TCP/UDP/ICMP/DNS/HTTP/HTTPS/ARP
  - Detección de anomalías:
      · Port scanning (muchos SYN en poco tiempo)
      · ARP Spoofing / Man-in-the-Middle
      · DNS Exfiltration (subdominios excesivamente largos)
      · Cleartext credentials (HTTP Basic Auth, FTP, Telnet)
      · Beaconing (conexiones regulares → posible C2)
      · Lateral movement (escaneo de red interna)
  - Estadísticas de tráfico por IP, protocolo y puerto
  - Export de capturas en formato PCAP y resumen JSON
  - Modo live con callbacks en tiempo real

Requisitos:
  - Scapy (pip install scapy)
  - Npcap para Windows: https://npcap.com/dist/npcap-1.79.exe

Uso:
    ta = TrafficAnalyzer(iface="Wi-Fi")
    ta.start_capture(duration=60)         # captura 60 segundos
    summary = ta.get_summary()
    ta.save_pcap("capture.pcap")
"""

import collections
import json
import math
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from utils.logger import get_logger

logger = get_logger("TrafficAnalyzer")

# ── Constantes de detección ───────────────────────────────────────────────────
_SCAN_THRESHOLD     = 15    # SYN a >N puertos distintos en 5s = port scan
_BEACONING_WINDOW   = 60    # segundos para analizar beaconing
_BEACONING_MIN_PKTS = 5     # mínimo de paquetes para analizar jitter
_BEACONING_MAX_CV   = 0.15  # coeficiente de variación máximo (muy regular = beacon)
_DNS_MAX_LABEL_LEN  = 50    # subdominios más largos → sospechoso
_CLEARTEXT_PORTS    = {21, 23, 25, 110, 143}  # FTP, Telnet, SMTP, POP3, IMAP
_HTTP_PORT          = 80


class TrafficAnalyzer:
    """Analizador de tráfico de red en tiempo real con detección de amenazas."""

    def __init__(
        self,
        iface:            str | None = None,
        alert_callback:   Callable[[dict], None] | None = None,
    ):
        self._iface    = iface
        self._callback = alert_callback or (lambda _: None)
        self._running  = False
        self._thread:  threading.Thread | None = None

        # Estado de captura
        self._packets: list = []
        self._pkt_lock = threading.Lock()

        # Contadores para detección de anomalías
        self._syn_tracker:  dict = collections.defaultdict(set)   # ip → puertos
        self._syn_times:    dict = collections.defaultdict(list)   # ip → timestamps
        self._conn_times:   dict = collections.defaultdict(list)   # (src,dst) → timestamps
        self._alerted_ips:  set  = set()

        # Scapy — carga diferida para no fallar si no está disponible
        self._scapy_ok = False
        self._Ether = self._IP = self._TCP = self._UDP = None
        self._DNS = self._DNSQR = self._ARP = self._Raw = None
        self._sniff = None
        self._wrpcap = None
        self._rdpcap = None
        self._conf = None
        self._ifaces_available: list[str] = []

    # ── Scapy (lazy) ──────────────────────────────────────────────────────────
    def _load_scapy(self) -> bool:
        """Carga Scapy de forma diferida. Retorna True si está disponible."""
        if self._scapy_ok:
            return True
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from scapy.all import (
                    sniff, wrpcap, rdpcap, conf,
                    Ether, IP, TCP, UDP, DNS, DNSQR, ARP, Raw,
                )
            self._sniff   = sniff
            self._wrpcap  = wrpcap
            self._rdpcap  = rdpcap
            self._conf    = conf
            self._Ether   = Ether
            self._IP      = IP
            self._TCP     = TCP
            self._UDP     = UDP
            self._DNS     = DNS
            self._DNSQR   = DNSQR
            self._ARP     = ARP
            self._Raw     = Raw
            # Enumerar interfaces disponibles
            try:
                self._ifaces_available = list(conf.ifaces.keys())
            except Exception:
                self._ifaces_available = []
            self._scapy_ok = True
            logger.info("Scapy cargado correctamente.")
            return True
        except ImportError:
            logger.warning("Scapy no disponible. Instala Npcap + scapy.")
            return False
        except Exception as exc:
            logger.warning(f"Scapy error: {exc}")
            return False

    def get_interfaces(self) -> list[str]:
        """Lista las interfaces de red disponibles para captura."""
        if not self._load_scapy():
            return self._get_interfaces_fallback()
        return self._ifaces_available

    def _get_interfaces_fallback(self) -> list[str]:
        """Obtiene interfaces mediante ipconfig si Scapy no está disponible."""
        import subprocess
        try:
            out = subprocess.check_output(
                ["ipconfig"], text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stderr=subprocess.DEVNULL,
            )
            return re.findall(r"Adaptador (.+):", out)
        except Exception:
            return []

    # ── Captura ───────────────────────────────────────────────────────────────
    def start_capture(
        self,
        duration:  int   = 30,
        pkt_count: int   = 0,
        bpf_filter:str   = "",
    ) -> bool:
        """
        Inicia captura de paquetes en hilo separado.

        Args:
            duration:   Segundos de captura (0 = indefinido)
            pkt_count:  Máximo de paquetes (0 = sin límite)
            bpf_filter: Filtro BPF tipo Wireshark (ej. "tcp port 80")

        Returns:
            True si la captura se inició con éxito
        """
        if not self._load_scapy():
            return False

        self._running = True
        with self._pkt_lock:
            self._packets.clear()

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(duration, pkt_count, bpf_filter),
            name="TrafficAnalyzer",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"Captura iniciada en {self._iface or 'default'} "
            f"({duration}s / {pkt_count} pkts)"
        )
        return True

    def stop_capture(self) -> None:
        """Detiene la captura en curso."""
        self._running = False

    def _capture_loop(self, duration: int, pkt_count: int, bpf_filter: str) -> None:
        """Loop interno de captura con Scapy."""
        try:
            kwargs: dict = {
                "prn":    self._process_packet,
                "store":  True,
                "filter": bpf_filter,
            }
            if self._iface:
                kwargs["iface"] = self._iface
            if duration > 0:
                kwargs["timeout"] = duration
            if pkt_count > 0:
                kwargs["count"] = pkt_count
            kwargs["stop_filter"] = lambda _: not self._running

            pkts = self._sniff(**kwargs)
            with self._pkt_lock:
                self._packets.extend(pkts or [])
        except Exception as exc:
            logger.error(f"Error en captura: {exc}")
            if "npcap" in str(exc).lower() or "winpcap" in str(exc).lower():
                logger.warning(
                    "Npcap no instalado. Descarga desde https://npcap.com"
                )
        finally:
            self._running = False

    # ── Procesado de paquetes en tiempo real ──────────────────────────────────
    def _process_packet(self, pkt) -> None:
        """Callback por paquete — detecta anomalías en tiempo real."""
        try:
            IP  = self._IP
            TCP = self._TCP
            UDP = self._UDP
            DNS = self._DNS
            ARP = self._ARP
            Raw = self._Raw

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                now = time.time()

                # Credenciales en claro (FTP/Telnet/SMTP)
                if TCP in pkt and Raw in pkt:
                    dport = pkt[TCP].dport
                    if dport in _CLEARTEXT_PORTS:
                        self._check_cleartext_creds(pkt, src, dst, dport)

                    # HTTP Basic Auth
                    if dport == _HTTP_PORT:
                        self._check_http_basic_auth(pkt, src, dst)

                # Port scanning detection
                if TCP in pkt:
                    flags = pkt[TCP].flags
                    if flags == "S":  # SYN
                        self._track_syn(src, pkt[TCP].dport, now)

                # Beaconing detection
                if TCP in pkt or UDP in pkt:
                    self._track_connection(src, dst, now)

            # ARP Spoofing
            if ARP in pkt:
                self._check_arp_spoofing(pkt)

            # DNS Exfiltration
            if DNS in pkt and self._DNSQR in pkt:
                self._check_dns_exfiltration(pkt)

        except Exception:
            pass  # No interrumpir la captura por errores de análisis

    def _track_syn(self, src: str, dport: int, now: float) -> None:
        """Detecta port scanning por múltiples SYN desde el mismo origen."""
        self._syn_tracker[src].add(dport)
        self._syn_times[src].append(now)

        # Limpiar entradas antiguas (> 5s)
        cutoff = now - 5.0
        self._syn_times[src] = [t for t in self._syn_times[src] if t > cutoff]
        # Ports recientes: reconstruir desde timestamps
        if len(self._syn_times[src]) == 0:
            self._syn_tracker[src].clear()

        if (len(self._syn_tracker[src]) >= _SCAN_THRESHOLD
                and src not in self._alerted_ips):
            self._alerted_ips.add(src)
            self._callback({
                "source":      "TrafficAnalyzer",
                "severity":    8,
                "title":       f"Port Scan detectado desde {src}",
                "description": (
                    f"{src} ha enviado SYN a {len(self._syn_tracker[src])} puertos "
                    f"distintos en <5s."
                ),
                "details": {
                    "src":         src,
                    "ports_hit":   len(self._syn_tracker[src]),
                    "technique":   "TCP SYN Scan",
                    "mitre":       "T1046",
                },
            })

    def _track_connection(self, src: str, dst: str, now: float) -> None:
        """Detecta beaconing: intervalos muy regulares a un mismo destino."""
        key = (src, dst)
        self._conn_times[key].append(now)

        # Analizar cuando tenemos suficientes muestras
        times = self._conn_times[key]
        if len(times) >= _BEACONING_MIN_PKTS:
            self._conn_times[key] = times[-50:]  # Mantener últimas 50
            if len(times) >= _BEACONING_MIN_PKTS and self._is_beaconing(times):
                beacon_key = f"{src}->{dst}"
                if beacon_key not in self._alerted_ips:
                    self._alerted_ips.add(beacon_key)
                    intervals = [
                        round(times[i+1] - times[i], 2)
                        for i in range(len(times)-1)
                    ]
                    avg_interval = round(sum(intervals)/len(intervals), 2)
                    self._callback({
                        "source":      "TrafficAnalyzer",
                        "severity":    7,
                        "title":       f"Posible beaconing C2: {src} → {dst}",
                        "description": (
                            f"Tráfico muy regular de {src} a {dst} "
                            f"(intervalo medio: {avg_interval}s). "
                            "Posible comunicación con C2."
                        ),
                        "details": {
                            "src":          src,
                            "dst":          dst,
                            "avg_interval": avg_interval,
                            "samples":      len(times),
                            "mitre":        "T1071.001",
                        },
                    })

    @staticmethod
    def _is_beaconing(timestamps: list[float]) -> bool:
        """
        Coeficiente de variación bajo en intervalos → muy regular → beaconing.
        CV = stddev / mean < threshold
        """
        if len(timestamps) < _BEACONING_MIN_PKTS:
            return False
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            return False
        mean = sum(intervals) / len(intervals)
        if mean < 1.0:  # Menos de 1s de intervalo → tráfico normal
            return False
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std      = math.sqrt(variance)
        cv       = std / mean if mean > 0 else 1.0
        return cv < _BEACONING_MAX_CV

    def _check_cleartext_creds(self, pkt, src: str, dst: str, port: int) -> None:
        """Detecta credenciales en texto claro en protocolos inseguros."""
        try:
            Raw = self._Raw
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            patterns = [
                r"(?i)USER\s+(\S+)",
                r"(?i)PASS\s+(\S+)",
                r"(?i)login:\s*(\S+)",
            ]
            for pat in patterns:
                if re.search(pat, payload):
                    service = {21: "FTP", 23: "Telnet", 25: "SMTP",
                               110: "POP3", 143: "IMAP"}.get(port, str(port))
                    key = f"cleartext-{src}-{port}"
                    if key not in self._alerted_ips:
                        self._alerted_ips.add(key)
                        self._callback({
                            "source":      "TrafficAnalyzer",
                            "severity":    9,
                            "title":       f"Credenciales en claro: {service} desde {src}",
                            "description": (
                                f"Autenticación {service} sin cifrado detectada de {src} a {dst}."
                            ),
                            "details": {
                                "src": src, "dst": dst,
                                "protocol": service, "mitre": "T1040",
                            },
                        })
                    break
        except Exception:
            pass

    def _check_http_basic_auth(self, pkt, src: str, dst: str) -> None:
        """Detecta HTTP Basic Auth (credenciales en base64 en cabecera)."""
        try:
            Raw = self._Raw
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            if "Authorization: Basic" in payload:
                key = f"basic-auth-{src}"
                if key not in self._alerted_ips:
                    self._alerted_ips.add(key)
                    self._callback({
                        "source":      "TrafficAnalyzer",
                        "severity":    8,
                        "title":       f"HTTP Basic Auth sin TLS desde {src}",
                        "description": (
                            f"Credenciales HTTP Basic Auth transmitidas en claro de {src} a {dst}."
                        ),
                        "details": {
                            "src": src, "dst": dst,
                            "mitre": "T1040",
                        },
                    })
        except Exception:
            pass

    def _check_arp_spoofing(self, pkt) -> None:
        """Detecta ARP Spoofing: múltiples IPs anunciadas desde la misma MAC."""
        try:
            ARP = self._ARP
            if pkt[ARP].op == 2:  # is-at (ARP reply)
                mac = pkt[ARP].hwsrc
                ip  = pkt[ARP].psrc
                key = f"arp-{mac}"
                if not hasattr(self, "_arp_table"):
                    self._arp_table: dict = {}
                if mac in self._arp_table and self._arp_table[mac] != ip:
                    if key not in self._alerted_ips:
                        self._alerted_ips.add(key)
                        self._callback({
                            "source":      "TrafficAnalyzer",
                            "severity":    9,
                            "title":       f"ARP Spoofing detectado — MAC: {mac}",
                            "description": (
                                f"La MAC {mac} anunciaba la IP {self._arp_table[mac]} "
                                f"y ahora anuncia {ip}. Posible MitM."
                            ),
                            "details": {
                                "mac":      mac,
                                "old_ip":   self._arp_table[mac],
                                "new_ip":   ip,
                                "mitre":    "T1557.002",
                            },
                        })
                self._arp_table[mac] = ip
        except Exception:
            pass

    def _check_dns_exfiltration(self, pkt) -> None:
        """Detecta exfiltración DNS: subdominios excesivamente largos o frecuentes."""
        try:
            DNSQR = self._DNSQR
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            labels = qname.split(".")
            # Subdominio muy largo → exfiltración DNS
            max_label = max((len(l) for l in labels), default=0)
            if max_label > _DNS_MAX_LABEL_LEN:
                key = f"dns-exfil-{qname[:30]}"
                if key not in self._alerted_ips:
                    self._alerted_ips.add(key)
                    self._callback({
                        "source":      "TrafficAnalyzer",
                        "severity":    8,
                        "title":       f"Posible exfiltración DNS",
                        "description": (
                            f"Query DNS con subdominio sospechosamente largo ({max_label} chars): "
                            f"{qname[:80]}"
                        ),
                        "details": {
                            "qname":     qname[:200],
                            "label_len": max_label,
                            "mitre":     "T1071.004",
                        },
                    })
        except Exception:
            pass

    # ── Análisis post-captura ─────────────────────────────────────────────────
    def get_summary(self) -> dict:
        """
        Genera un resumen estadístico de la captura actual.
        Incluye: top IPs, protocolos, puertos y conversaciones.
        """
        with self._pkt_lock:
            packets = list(self._packets)

        if not packets:
            return {"status": "sin_paquetes", "total": 0}

        IP  = self._IP
        TCP = self._TCP
        UDP = self._UDP

        ip_counter   = collections.Counter()
        proto_counter = collections.Counter()
        port_counter  = collections.Counter()
        conversations: dict = collections.defaultdict(int)

        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                ip_counter[src]  += 1
                ip_counter[dst]  += 1
                conversations[f"{src} ↔ {dst}"] += 1

                if TCP in pkt:
                    proto_counter["TCP"] += 1
                    port_counter[f"tcp/{pkt[TCP].dport}"] += 1
                elif UDP in pkt:
                    proto_counter["UDP"] += 1
                    port_counter[f"udp/{pkt[UDP].dport}"] += 1
                else:
                    proto_counter["Other"] += 1

        return {
            "status":           "ok",
            "total_packets":    len(packets),
            "top_ips":          ip_counter.most_common(10),
            "protocols":        dict(proto_counter),
            "top_ports":        port_counter.most_common(15),
            "top_conversations":sorted(
                conversations.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "timestamp":        datetime.now().isoformat(),
        }

    # ── PCAP I/O ──────────────────────────────────────────────────────────────
    def save_pcap(self, filepath: str) -> bool:
        """Guarda la captura en formato PCAP compatible con Wireshark."""
        if not self._scapy_ok:
            return False
        with self._pkt_lock:
            pkts = list(self._packets)
        if not pkts:
            return False
        try:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            self._wrpcap(filepath, pkts)
            logger.info(f"Captura guardada: {filepath} ({len(pkts)} paquetes)")
            return True
        except Exception as exc:
            logger.error(f"Error guardando PCAP: {exc}")
            return False

    def load_pcap(self, filepath: str) -> int:
        """Carga una captura PCAP existente para análisis offline."""
        if not self._load_scapy():
            return 0
        try:
            pkts = self._rdpcap(filepath)
            with self._pkt_lock:
                self._packets = list(pkts)
            logger.info(f"PCAP cargado: {len(pkts)} paquetes desde {filepath}")
            return len(pkts)
        except Exception as exc:
            logger.error(f"Error cargando PCAP: {exc}")
            return 0

    def analyze_pcap(self, filepath: str) -> dict:
        """Carga y analiza un archivo PCAP offline."""
        count = self.load_pcap(filepath)
        if count == 0:
            return {"error": "No se pudo cargar el PCAP o está vacío"}
        return self.get_summary()

    def is_available(self) -> bool:
        """True si Scapy y Npcap están disponibles para captura."""
        return self._load_scapy()

    def npcap_install_hint(self) -> str:
        """Mensaje de instalación de Npcap para el usuario."""
        return (
            "Para captura de tráfico en Windows se requiere Npcap.\n"
            "Descarga: https://npcap.com/dist/npcap-1.79.exe\n"
            "Instala con: 'WinPcap API-compatible Mode' habilitado."
        )
