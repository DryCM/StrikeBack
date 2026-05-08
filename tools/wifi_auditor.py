"""
WiFiAuditor — Auditoría de seguridad de redes inalámbricas.

AVISO: Solo para auditorías de redes propias o con autorización expresa.
       Escanear/atacar redes ajenas es ilegal en la mayoría de jurisdicciones.

Funcionalidades:
  - Descubrimiento de redes WiFi cercanas (SSID, BSSID, Canal, Señal, Cifrado)
  - Clasificación de seguridad: WEP (crítico) / WPA (bajo) / WPA2 / WPA3
  - Detección de redes con cifrado débil o nulo
  - Detección de redes con nombre de fábrica (SSID default: "MOVISTAR_", "JAZZTEL_"…)
  - Detección de Evil Twin / Access Points duplicados (mismo SSID, BSSID diferente)
  - Análisis de configuración del adaptador WiFi local
  - Generación de informe de seguridad con recomendaciones INCIBE

Implementación:
  - Windows: netsh wlan show networks + pywifi + WMI
  - Fallback: netsh commands si pywifi no está disponible

Uso:
    auditor = WiFiAuditor()
    networks = auditor.scan_networks()
    report   = auditor.full_audit()
"""

import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable

from utils.logger import get_logger

logger = get_logger("WiFiAuditor")

# ── Clasificación de seguridad ────────────────────────────────────────────────
_SECURITY_RATINGS = {
    "WPA3": {"score": 10, "label": "Excelente", "color": "green"},
    "WPA2": {"score": 7,  "label": "Bueno",     "color": "yellow"},
    "WPA":  {"score": 4,  "label": "Débil",      "color": "orange"},
    "WEP":  {"score": 1,  "label": "CRÍTICO",    "color": "red"},
    "OPEN": {"score": 0,  "label": "SIN CIFRADO","color": "red"},
    "UNKN": {"score": 5,  "label": "Desconocido","color": "grey"},
}

# ── SSIDs de fábrica (vulnerables a ataques por diccionario) ──────────────────
_DEFAULT_SSID_PATTERNS = [
    r"^MOVISTAR[_\-]",       # Movistar (España)
    r"^JAZZTEL[_\-]",        # Jazztel
    r"^VODAFONE[_\-]",       # Vodafone
    r"^Orange[_\-]",         # Orange
    r"^MASMOVIL[_\-]",       # MásMóvil
    r"^DIGI[_\-]",           # DIGI
    r"^TP-Link[_\-]",        # TP-Link default
    r"^ASUS[_\-]",           # ASUS router
    r"^NETGEAR[_\-]",        # Netgear
    r"^Linksys[_\-]",        # Linksys
    r"^D-Link[_\-]",         # D-Link
    r"^HOME[_\-]\d{4}",      # Genérico ISP
    r"^WiFi[_\-]\d",         # Genérico
    r"^INFINITUM",           # Telmex (México)
    r"^TELMEX",
    r"^xfinitywifi",         # Comcast (EE.UU.)
    r"^ATT\w*WiFi",
]

_SCAN_TIMEOUT = 10  # segundos para escaneo


class WiFiNetwork:
    """Representa una red WiFi detectada."""
    def __init__(self):
        self.ssid:          str  = ""
        self.bssid:         str  = ""
        self.channel:       int  = 0
        self.signal_dbm:    int  = 0
        self.auth_type:     str  = "UNKN"
        self.encryption:    str  = ""
        self.band:          str  = ""
        self.is_hidden:     bool = False

    def security_score(self) -> int:
        return _SECURITY_RATINGS.get(self.auth_type, _SECURITY_RATINGS["UNKN"])["score"]

    def is_default_ssid(self) -> bool:
        for pat in _DEFAULT_SSID_PATTERNS:
            if re.match(pat, self.ssid, re.IGNORECASE):
                return True
        return False

    def to_dict(self) -> dict:
        rating = _SECURITY_RATINGS.get(self.auth_type, _SECURITY_RATINGS["UNKN"])
        return {
            "ssid":          self.ssid or "(hidden)",
            "bssid":         self.bssid,
            "channel":       self.channel,
            "signal_dbm":    self.signal_dbm,
            "signal_pct":    self._dbm_to_percent(self.signal_dbm),
            "auth_type":     self.auth_type,
            "encryption":    self.encryption,
            "band":          self.band,
            "is_hidden":     self.is_hidden,
            "is_default_ssid": self.is_default_ssid(),
            "security_score":  rating["score"],
            "security_label":  rating["label"],
        }

    @staticmethod
    def _dbm_to_percent(dbm: int) -> int:
        """Convierte dBm a porcentaje de señal (0-100%)."""
        if dbm >= -50:  return 100
        if dbm <= -100: return 0
        return int(2 * (dbm + 100))


class WiFiAuditor:
    """Auditor de seguridad WiFi para Windows."""

    def __init__(self, alert_callback: Callable[[dict], None] | None = None):
        self._callback = alert_callback or (lambda _: None)

    # ── Escaneo de redes ──────────────────────────────────────────────────────
    def scan_networks(self) -> list[dict]:
        """
        Escanea redes WiFi cercanas usando netsh wlan.
        Retorna lista de redes con metadatos de seguridad.
        """
        networks = self._scan_netsh()
        if not networks:
            networks = self._scan_pywifi()
        return [n.to_dict() for n in networks]

    def _scan_netsh(self) -> list["WiFiNetwork"]:
        """Escanea con netsh wlan show networks mode=bssid."""
        networks = []
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                text=True, timeout=_SCAN_TIMEOUT,
                encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.warning(f"netsh wlan scan: {exc}")
            return []

        # Parsear bloques separados por "SSID N"
        blocks = re.split(r"\bSSID\s+\d+\s*:", out)
        for block in blocks[1:]:  # skip header
            net = WiFiNetwork()
            lines = block.strip().splitlines()

            if lines:
                net.ssid = lines[0].strip()

            for line in lines:
                line = line.strip()
                if re.match(r"(BSSID|BSSID\s+\d+)\s*:", line, re.I):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        net.bssid = parts[1].strip()
                elif re.match(r"Authentication", line, re.I):
                    auth_raw = line.split(":", 1)[-1].strip().upper()
                    net.auth_type = self._classify_auth(auth_raw)
                elif re.match(r"Encryption", line, re.I):
                    net.encryption = line.split(":", 1)[-1].strip()
                elif re.match(r"Signal", line, re.I):
                    pct_str = re.search(r"(\d+)%", line)
                    if pct_str:
                        pct = int(pct_str.group(1))
                        net.signal_dbm = int(pct / 2 - 100)
                elif re.match(r"Channel", line, re.I):
                    ch_m = re.search(r"(\d+)", line)
                    if ch_m:
                        net.channel = int(ch_m.group(1))
                        net.band = "5 GHz" if net.channel > 14 else "2.4 GHz"
                elif re.match(r"Radio type", line, re.I):
                    if "ax" in line.lower() or "802.11ax" in line.lower():
                        net.band = "WiFi 6 (6 GHz)"

            if net.ssid:
                networks.append(net)

        return networks

    def _scan_pywifi(self) -> list["WiFiNetwork"]:
        """Fallback con pywifi."""
        networks = []
        try:
            import pywifi
            from pywifi import const
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(2)
            results = iface.scan_results()
            for r in results:
                net = WiFiNetwork()
                net.ssid    = r.ssid
                net.bssid   = r.bssid
                net.signal_dbm = int(r.signal)
                net.auth_type  = self._pywifi_auth(r.auth)
                networks.append(net)
        except Exception as exc:
            logger.debug(f"pywifi fallback: {exc}")
        return networks

    @staticmethod
    def _classify_auth(raw: str) -> str:
        if "WPA3" in raw or "SAE" in raw:     return "WPA3"
        if "WPA2" in raw:                      return "WPA2"
        if "WPA"  in raw:                      return "WPA"
        if "WEP"  in raw:                      return "WEP"
        if "OPEN" in raw or "NONE" in raw:     return "OPEN"
        return "UNKN"

    @staticmethod
    def _pywifi_auth(auth_list: list) -> str:
        """Convierte lista de constantes pywifi a tipo de auth."""
        try:
            from pywifi import const
            for a in auth_list:
                if a == const.AUTH_ALG_OPEN:    return "OPEN"
        except Exception:
            pass
        raw = str(auth_list).upper()
        if "WPA3" in raw or "SAE" in raw: return "WPA3"
        if "WPA2" in raw:                 return "WPA2"
        if "WPA"  in raw:                 return "WPA"
        if "WEP"  in raw:                 return "WEP"
        return "UNKN"

    # ── Auditoría completa ────────────────────────────────────────────────────
    def full_audit(self) -> dict:
        """
        Ejecuta auditoría completa:
          - Escaneo de redes
          - Clasificación de riesgos
          - Detección de Evil Twin / duplicados
          - Análisis de red conectada
          - Generación de hallazgos y recomendaciones
        """
        networks_raw = self._scan_netsh() or self._scan_pywifi()
        networks     = [n.to_dict() for n in networks_raw]

        findings     = []

        # ── Redes con cifrado débil o nulo
        for n in networks:
            if n["auth_type"] == "OPEN":
                findings.append({
                    "severity": 10,
                    "type":     "RED_ABIERTA",
                    "ssid":     n["ssid"],
                    "detail":   "Red completamente abierta — tráfico interceptable.",
                    "recommendation": "No conectarse nunca sin VPN. Investigar si es legítima.",
                })
            elif n["auth_type"] == "WEP":
                findings.append({
                    "severity": 9,
                    "type":     "CIFRADO_WEP",
                    "ssid":     n["ssid"],
                    "detail":   "WEP es completamente roto (crackeable en <5 min).",
                    "recommendation": "Actualizar a WPA2/WPA3 inmediatamente.",
                })
            elif n["auth_type"] == "WPA":
                findings.append({
                    "severity": 5,
                    "type":     "CIFRADO_WPA",
                    "ssid":     n["ssid"],
                    "detail":   "WPA-TKIP tiene vulnerabilidades conocidas (TKIP MIC attack).",
                    "recommendation": "Actualizar a WPA2-AES o WPA3.",
                })

            # SSID de fábrica
            if n.get("is_default_ssid"):
                findings.append({
                    "severity": 6,
                    "type":     "SSID_DEFECTO",
                    "ssid":     n["ssid"],
                    "detail":   "SSID de fábrica detectado. La contraseña puede ser derivable.",
                    "recommendation": "Cambiar SSID y contraseña del router.",
                })

        # ── Evil Twin: mismo SSID, BSSID diferente
        ssid_bssids: dict[str, list[str]] = {}
        for n in networks:
            ssid = n["ssid"]
            bssid = n["bssid"]
            if ssid not in ("(hidden)", ""):
                ssid_bssids.setdefault(ssid, []).append(bssid)

        for ssid, bssids in ssid_bssids.items():
            unique_bssids = list(set(bssids))
            if len(unique_bssids) > 1:
                findings.append({
                    "severity": 8,
                    "type":     "EVIL_TWIN",
                    "ssid":     ssid,
                    "detail":   (
                        f"El SSID '{ssid}' aparece con {len(unique_bssids)} BSSIDs distintos. "
                        f"Posible Evil Twin / Rogue AP."
                    ),
                    "bssids":   unique_bssids,
                    "recommendation": "Verificar que solo el AP legítimo emite este SSID.",
                })

        # ── Red WiFi conectada actualmente
        connected = self._get_connected_network()

        # Emitir alertas para hallazgos críticos
        for f in findings:
            if f["severity"] >= 7:
                self._callback({
                    "source":      "WiFiAuditor",
                    "severity":    f["severity"],
                    "title":       f"[WiFi] {f['type']}: {f['ssid']}",
                    "description": f["detail"],
                    "details":     f,
                })

        return {
            "networks":          networks,
            "total_networks":    len(networks),
            "findings":          sorted(findings, key=lambda x: x["severity"], reverse=True),
            "connected_network": connected,
            "scan_timestamp":    datetime.now().isoformat(),
            "risk_level":        self._overall_risk(findings),
        }

    def _get_connected_network(self) -> dict:
        """Información de la red WiFi actualmente conectada."""
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stderr=subprocess.DEVNULL,
            )
            info = {}
            for line in out.splitlines():
                line = line.strip()
                for key, label in [
                    ("SSID", "ssid"), ("BSSID", "bssid"), ("Authentication", "auth"),
                    ("Cipher", "cipher"), ("Signal", "signal"), ("Channel", "channel"),
                    ("Radio type", "radio"),
                ]:
                    if re.match(rf"^{key}\s*:", line, re.I):
                        val = line.split(":", 1)[-1].strip()
                        if label == "ssid" and "BSSID" in line:
                            continue
                        info[label] = val
            return info
        except Exception:
            return {}

    @staticmethod
    def _overall_risk(findings: list[dict]) -> str:
        if not findings:
            return "BAJO"
        max_sev = max(f["severity"] for f in findings)
        if max_sev >= 9:   return "CRÍTICO"
        if max_sev >= 7:   return "ALTO"
        if max_sev >= 5:   return "MEDIO"
        return "BAJO"

    def get_local_adapter_info(self) -> list[dict]:
        """Información de los adaptadores WiFi locales instalados."""
        adapters = []
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stderr=subprocess.DEVNULL,
            )
            current: dict = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Name") and ":" in line:
                    if current:
                        adapters.append(current)
                    current = {"name": line.split(":", 1)[-1].strip()}
                elif current and ":" in line:
                    key, val = line.split(":", 1)
                    current[key.strip().lower().replace(" ", "_")] = val.strip()
            if current:
                adapters.append(current)
        except Exception as exc:
            logger.debug(f"get_local_adapter_info: {exc}")
        return adapters
