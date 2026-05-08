# StrikeBack SOC

**StrikeBack** es una plataforma de ciberseguridad ofensiva-defensiva para Windows, diseñada para detectar, analizar y responder automáticamente a amenazas en tiempo real.

---

## Características principales

| Módulo | Descripción |
|---|---|
| **AI Intelligence v2** | Cola de prioridad, deduplicación 90s, kill chain, detección de campañas (≥3 mismo MITRE en 5min) |
| **12 Monitores** | Procesos, Red, Ficheros, Registro, Credenciales, YARA, Honeypot, EventLog, Privilegios, Inyección, AI, Auditoría |
| **AI Guard** | Sanitización de prompts, detección de inyección, validación de respuestas IA |
| **Dashboard Qt** | SOC nativo PyQt6 con columnas Sev, Fiab.%, MITRE, Kill Chain, IA, VirusTotal |
| **Dashboard Web** | Flask HTTPS en 127.0.0.1:8443 con autenticación + TOTP |
| **Auto-respuesta** | Bloqueo IPs, aislamiento procesos, snapshots VSS |
| **Pentest Tools** | Escáner red, auditor WiFi, análisis contraseñas, colector forense (RFC 3227) |
| **Crypto** | AES-256-GCM en DB, TLS self-signed, claves en Windows Credential Manager |

## Requisitos

- Windows 10/11 (64-bit)
- Python 3.11+ (o usar el EXE precompilado)
- [Groq API key](https://console.groq.com) (gratis) — para análisis IA
- [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (opcional, gratis)

## Instalación rápida

```bash
# 1. Clonar
git clone https://github.com/TU_USUARIO/StrikeBack.git
cd StrikeBack

# 2. Entorno virtual
python -m venv .venv
.venv\Scripts\activate

# 3. Dependencias
pip install -r requirements.txt

# 4. Configurar claves API (se guardan en Windows Credential Manager)
python -c "from utils.secrets_manager import store_secret; store_secret('AI_API_KEY','TU_GROQ_KEY'); store_secret('VIRUSTOTAL_API_KEY','TU_VT_KEY')"

# 5. Arrancar
python main.py
```

## Ejecutable precompilado

Descarga `StrikeBack.exe` desde [Releases](../../releases) — no requiere Python.

## Uso

- La ventana Qt se abre automáticamente al arrancar.
- El dashboard web está en `https://127.0.0.1:8443` (botón **Web** en la app).
- Las credenciales iniciales se muestran en el log al primer arranque.

## Compilar el EXE

```bash
pip install pyinstaller
pyinstaller StrikeBack.spec --noconfirm
# Resultado en dist/StrikeBack.exe
```

## Arquitectura

```
StrikeBack/
├── main.py               # Orquestador principal
├── config.py             # Configuración centralizada
├── ai/                   # Motor IA v2 (threat_analyzer, ai_guard)
├── monitors/             # 12 monitores de seguridad
├── tools/                # Herramientas pentest
├── ui/                   # Dashboard Qt nativo
├── web/                  # Dashboard Flask HTTPS
├── utils/                # Crypto, DB, alertas, logs
└── data/yara_rules/      # Reglas YARA
```

## Seguridad

- Las claves API **nunca** se almacenan en código ni en el repositorio.
- Se usan el Windows Credential Manager o variables de entorno (`STRIKEBACK_AI_API_KEY`, `STRIKEBACK_VT_API_KEY`).
- La base de datos SQLite se cifra con AES-256-GCM.

## Licencia

MIT — ver [LICENSE](LICENSE)
