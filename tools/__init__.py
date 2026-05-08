"""
Paquete de herramientas de pentesting activo de StrikeBack.

AVISO LEGAL:
  Estas herramientas están diseñadas EXCLUSIVAMENTE para:
    - Auditorías de seguridad en sistemas propios
    - Pruebas con autorización expresa y por escrito del propietario
    - Entornos de laboratorio y CTF (Capture The Flag)

  El uso no autorizado contra sistemas ajenos puede constituir un delito
  tipificado en el artículo 197 bis/ter del Código Penal (España),
  el Computer Fraud and Abuse Act (EE.UU.) y legislaciones equivalentes.

  StrikeBack y sus autores no se responsabilizan del uso indebido.
"""

from tools.network_scanner   import NetworkScanner
from tools.traffic_analyzer  import TrafficAnalyzer
from tools.wifi_auditor      import WiFiAuditor
from tools.password_auditor  import PasswordAuditor
from tools.forensic_collector import ForensicCollector

__all__ = [
    "NetworkScanner",
    "TrafficAnalyzer",
    "WiFiAuditor",
    "PasswordAuditor",
    "ForensicCollector",
]
