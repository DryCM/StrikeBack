"""
Threat Intel — consulta VirusTotal y feeds públicos de IPs maliciosas.
"""
import threading
import time
import hashlib
import os
import json
import requests
from typing import Optional, Callable
from datetime import datetime, timedelta

import config
from utils.logger import get_logger

logger = get_logger("ThreatIntel")

# Feeds públicos gratuitos de IPs maliciosas (actualizados automáticamente)
THREAT_FEEDS = [
    # Emerging Threats - IPs con actividad de ataque reciente
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    # Spamhaus DROP list
    "https://www.spamhaus.org/drop/drop.txt",
]

# Cache local para no repetir consultas VT
_vt_cache: dict = {}   # hash/ip -> resultado
_vt_cache_ttl = 3600   # 1 hora


class ThreatIntel:
    """
    Enriquece amenazas consultando:
    1. VirusTotal para hashes de procesos / IPs
    2. Feeds públicos de IPs maliciosas
    """

    def __init__(self, threat_callback: Optional[Callable] = None):
        self.threat_callback = threat_callback
        self._malicious_ips:  set  = set(config.KNOWN_MALICIOUS_IPS)
        self._malicious_nets: list = []   # rangos CIDR de feeds
        self._last_feed_update       = datetime.min
        self._feed_update_interval   = timedelta(hours=6)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def start(self):
        """Carga feeds en background."""
        t = threading.Thread(target=self._update_feeds_loop, daemon=True,
                             name="ThreatIntel")
        t.start()
        logger.info("Threat Intel iniciado.")

    # ------------------------------------------------------------------
    def is_malicious_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._malicious_ips:
                return True
            try:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                for net in self._malicious_nets:
                    if addr in net:
                        return True
            except ValueError:
                pass
        return False

    # ------------------------------------------------------------------
    def check_hash_vt(self, file_path: str) -> Optional[dict]:
        """
        Calcula el SHA-256 de un archivo y lo consulta en VirusTotal.
        Retorna: {"malicious": bool, "engines": int, "total": int, "name": str}
        """
        if not config.VIRUSTOTAL_API_KEY:
            return None

        sha256 = self._sha256(file_path)
        if not sha256:
            return None

        # Verificar cache
        now = time.time()
        cached = _vt_cache.get(sha256)
        if cached and now - cached["ts"] < _vt_cache_ttl:
            return cached["result"]

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                data  = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                result = {
                    "sha256":    sha256,
                    "malicious": stats.get("malicious", 0) > 0,
                    "engines":   stats.get("malicious", 0),
                    "total":     sum(stats.values()),
                    "name":      data["data"]["attributes"].get("meaningful_name", ""),
                }
                _vt_cache[sha256] = {"result": result, "ts": now}
                return result

            elif resp.status_code == 404:
                result = {"sha256": sha256, "malicious": False, "engines": 0,
                          "total": 0, "name": ""}
                _vt_cache[sha256] = {"result": result, "ts": now}
                return result

        except requests.RequestException as e:
            logger.debug(f"VirusTotal error: {e}")
        return None

    def check_ip_vt(self, ip: str) -> Optional[dict]:
        """Consulta una IP en VirusTotal."""
        if not config.VIRUSTOTAL_API_KEY:
            return None

        cached = _vt_cache.get(ip)
        now = time.time()
        if cached and now - cached["ts"] < _vt_cache_ttl:
            return cached["result"]

        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                data  = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                result = {
                    "ip":        ip,
                    "malicious": stats.get("malicious", 0) > 0,
                    "engines":   stats.get("malicious", 0),
                    "total":     sum(stats.values()),
                    "country":   data["data"]["attributes"].get("country", "?"),
                }
                _vt_cache[ip] = {"result": result, "ts": now}

                # Si es maliciosa, añadir a la lista dinámica
                if result["malicious"]:
                    with self._lock:
                        self._malicious_ips.add(ip)

                return result

        except requests.RequestException as e:
            logger.debug(f"VirusTotal IP error: {e}")
        return None

    # ------------------------------------------------------------------
    def _update_feeds_loop(self):
        while True:
            now = datetime.now()
            if now - self._last_feed_update >= self._feed_update_interval:
                self._download_feeds()
                self._last_feed_update = now
            time.sleep(3600)

    def _download_feeds(self):
        import ipaddress
        new_ips:  set  = set()
        new_nets: list = []
        count = 0

        for url in THREAT_FEEDS:
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code != 200:
                    continue
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    entry = line.split()[0]   # primer campo
                    try:
                        if "/" in entry:
                            net = ipaddress.ip_network(entry, strict=False)
                            new_nets.append(net)
                        else:
                            ipaddress.ip_address(entry)   # validar
                            new_ips.add(entry)
                        count += 1
                    except ValueError:
                        continue
            except Exception as e:
                logger.debug(f"Error descargando feed {url}: {e}")

        if count:
            with self._lock:
                self._malicious_ips.update(new_ips)
                self._malicious_nets = new_nets
            logger.info(f"Threat feeds actualizados: {len(new_ips)} IPs + {len(new_nets)} redes cargadas.")

    # ------------------------------------------------------------------
    @staticmethod
    def _sha256(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None
