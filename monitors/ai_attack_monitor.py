"""
Monitor de ataques a sistemas de IA (AI Act — Anexo IX).

Detecta en el propio PC intentos de atacar sistemas de IA instalados:
  - Envenenamiento de datos de entrenamiento (Model Poisoning · T0019)
  - Extracción / robo de modelos           (Model Inversion   · T0024)
  - Evasión de clasificadores locales      (Evasion Attack    · T0015)
  - Manipulación de configuración de IA    (Integrity Attack  · T0020)
  - Acceso no autorizado a weights/modelos (Exfiltration      · T1041)

Frameworks de referencia: ART (IBM), Foolbox (Bethge Lab), RobustBench (ETH Zürich)
"""

import os
import re
import threading
import time
from pathlib import Path
from typing import Callable, Optional
from datetime import datetime

from utils.logger import get_logger

logger = get_logger("AIAttackMonitor")

# ── Rutas donde suelen residir modelos y datos de IA en Windows ───────────────
_AI_MODEL_DIRS: list[Path] = [
    Path.home() / ".cache" / "huggingface",
    Path.home() / ".ollama" / "models",
    Path("C:/Users") / os.getenv("USERNAME", "") / "AppData" / "Local" / "ollama",
    Path("C:/ProgramData/ollama"),
    Path.home() / ".cache" / "torch",
    Path.home() / "AppData" / "Local" / "Programs" / "Ollama",
]

# ── Extensiones de archivos de modelo (weights) ───────────────────────────────
_MODEL_EXTENSIONS = {".gguf", ".bin", ".pt", ".pth", ".onnx", ".safetensors", ".pkl", ".h5"}

# ── Extensiones de datos de entrenamiento ────────────────────────────────────
_TRAINING_DATA_EXTENSIONS = {".jsonl", ".parquet", ".arrow", ".csv", ".tfrecord"}

# ── Patrones de herramientas de ataque a IA ──────────────────────────────────
# ART (art-toolbox), TextFooler, DeepFool, FGSM scripts, etc.
_AI_ATTACK_TOOL_PATTERNS: list[tuple[re.Pattern, str, int, str]] = [
    # (pattern, descripción, severidad, ATLAS/MITRE)
    (re.compile(r"art[-_]toolbox|adversarial[-_]robustness", re.I),
     "ART Toolbox detectado (framework ataques adversariales IA)", 8, "T0015"),
    (re.compile(r"textfooler|bert-attack|textbugger", re.I),
     "Herramienta de ataque NLP adversarial detectada", 8, "T0015"),
    (re.compile(r"deepfool|carlini.wagner|fgsm|pgd.attack", re.I),
     "Ataque de gradiente adversarial (Foolbox/DeepFool)", 7, "T0015"),
    (re.compile(r"model.?steal|model.?extract|knockoff", re.I),
     "Herramienta de robo/extracción de modelo detectada", 9, "T0024"),
    (re.compile(r"model.?poison|data.?poison|badnets|trojan.?nn", re.I),
     "Herramienta de envenenamiento de modelo/datos", 9, "T0019"),
    (re.compile(r"membership.?inference|privacy.?attack|mi.?attack", re.I),
     "Ataque de inferencia de membresía (privacidad)", 7, "T0024"),
    (re.compile(r"prompt.?inject|jailbreak.?llm|llm.?attack|gptfuzz", re.I),
     "Herramienta de prompt injection / jailbreak LLM", 8, "CWE-1427"),
    (re.compile(r"inversion.?attack|model.?inversion|mia.?tool", re.I),
     "Ataque de inversión de modelo (extracción de datos de entrenamiento)", 8, "T0024"),
]

# ── Cambios sospechosos en archivos de configuración de IA ───────────────────
_AI_CONFIG_PATTERNS: list[re.Pattern] = [
    re.compile(r"Modelfile", re.I),        # Ollama Modelfile
    re.compile(r"\.ollama.*config", re.I),
    re.compile(r"config\.json$", re.I),    # HuggingFace config.json
    re.compile(r"tokenizer_config", re.I),
    re.compile(r"generation_config", re.I),
]

# ── Procesos sospechosos relacionados con ataques a IA ───────────────────────
_SUSPICIOUS_AI_PROCESSES: dict[str, tuple[int, str, str]] = {
    "art":              (8, "ART Adversarial Robustness Toolbox", "T0015"),
    "textattack":       (8, "TextAttack NLP adversarial framework", "T0015"),
    "foolbox":          (7, "Foolbox gradient-based attack framework", "T0015"),
    "cleverhans":       (7, "CleverHans adversarial examples library", "T0015"),
    "robustbench":      (6, "RobustBench benchmark tool", "T0015"),
    "gptfuzz":          (9, "GPTFuzz LLM jailbreak tool", "CWE-1427"),
    "llm-attacks":      (9, "LLM-Attacks adversarial suffix tool", "CWE-1427"),
    "peezpuzz":         (8, "Prompt injection tool", "CWE-1427"),
    "mia-inference":    (8, "Membership inference attack tool", "T0024"),
    "model-steal":      (9, "Model stealing/extraction tool", "T0024"),
}


class AIAttackMonitor:
    """
    Monitor periódico (cada 30s) que detecta ataques dirigidos a sistemas
    de IA instalados en el equipo. Conforme al EU AI Act (Anexo IX).
    """

    def __init__(self, threat_callback: Callable):
        self._callback    = threat_callback
        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scan_interval = 30  # segundos
        # Snapshot de tamaños de modelos para detectar modificaciones
        self._model_snapshots: dict[str, int] = {}

    # ─────────────────────────────────────────────────────────────────────────
    def start(self):
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="AIAttackMonitor"
        )
        self._thread.start()
        logger.info("Monitor de ataques a sistemas IA iniciado.")

    def stop(self):
        self._stop_event.set()

    # ─────────────────────────────────────────────────────────────────────────
    def _run(self):
        # Primera pasada para establecer snapshot base
        self._build_model_snapshot()

        while not self._stop_event.is_set():
            try:
                self._scan_processes()
                self._scan_model_integrity()
                self._scan_ai_config_tampering()
            except Exception as e:
                logger.error(f"Error en AIAttackMonitor: {e}")

            self._stop_event.wait(timeout=self._scan_interval)

    # ─────────────────────────────────────────────────────────────────────────
    def _scan_processes(self):
        """Detecta procesos de herramientas de ataque a IA."""
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name    = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                combined = name + " " + cmdline

                for tool, (sev, desc, mitre) in _SUSPICIOUS_AI_PROCESSES.items():
                    # Coincidencia exacta de nombre de proceso (sin extensión)
                    name_no_ext = name.rsplit(".", 1)[0] if "." in name else name
                    name_match  = (name_no_ext == tool)
                    # Cmdline: solo firmas de ≥6 chars, como palabra completa (evita "art" en "start")
                    cmd_match   = (
                        len(tool) >= 6 and
                        re.search(r"(?<![a-z])" + re.escape(tool) + r"(?![a-z])", cmdline)
                    )
                    if name_match or cmd_match:
                        self._emit({
                            "source":      "AIAttackMonitor",
                            "title":       f"[{mitre}] Herramienta de ataque IA activa: {tool}",
                            "description": f"{desc} en proceso PID {proc.info.get('pid')}",
                            "severity":    sev,
                            "details": {
                                "pid":         proc.info.get("pid"),
                                "process":     name,
                                "tool":        tool,
                                "mitre":       mitre,
                                "ai_act_risk": "Alto — cumplimiento EU AI Act comprometido",
                                "cmdline":     cmdline[:200],
                            },
                        })
                        break

                # Buscar patrones de ataque en la línea de comandos
                for pattern, pdesc, psev, pmitre in _AI_ATTACK_TOOL_PATTERNS:
                    if pattern.search(combined):
                        self._emit({
                            "source":      "AIAttackMonitor",
                            "title":       f"[{pmitre}] {pdesc}",
                            "description": f"Línea de comando sospechosa en PID {proc.info.get('pid')}",
                            "severity":    psev,
                            "details": {
                                "pid":     proc.info.get("pid"),
                                "mitre":   pmitre,
                                "pattern": pattern.pattern,
                                "cmdline": cmdline[:200],
                            },
                        })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ─────────────────────────────────────────────────────────────────────────
    def _build_model_snapshot(self):
        """Registra tamaños actuales de archivos de modelo para detectar cambios."""
        for base_dir in _AI_MODEL_DIRS:
            if not base_dir.exists():
                continue
            try:
                for path in base_dir.rglob("*"):
                    if path.suffix.lower() in _MODEL_EXTENSIONS and path.is_file():
                        try:
                            self._model_snapshots[str(path)] = path.stat().st_size
                        except OSError:
                            pass
            except (PermissionError, OSError):
                continue

        logger.debug(f"[AIGuard] Snapshot de {len(self._model_snapshots)} archivos de modelo.")

    # ─────────────────────────────────────────────────────────────────────────
    def _scan_model_integrity(self):
        """
        Detecta modificaciones inesperadas en archivos de modelo (weights).
        Un cambio de tamaño indica posible envenenamiento o backdoor.
        """
        for base_dir in _AI_MODEL_DIRS:
            if not base_dir.exists():
                continue
            try:
                for path in base_dir.rglob("*"):
                    if path.suffix.lower() not in _MODEL_EXTENSIONS or not path.is_file():
                        continue
                    try:
                        current_size = path.stat().st_size
                        key          = str(path)

                        if key not in self._model_snapshots:
                            # Archivo nuevo — posible modelo descargado/inyectado
                            if current_size > 1_000_000:  # > 1 MB
                                self._emit({
                                    "source":      "AIAttackMonitor",
                                    "title":       "[T0019] Nuevo archivo de modelo detectado",
                                    "description": f"Modelo nuevo en {path.parent}: {path.name} ({current_size // 1024 // 1024} MB)",
                                    "severity":    6,
                                    "details": {
                                        "path":     key,
                                        "size_mb":  current_size // 1024 // 1024,
                                        "mitre":    "T0019",
                                        "ai_act":   "Evaluar calidad de datos (Envenenamiento)",
                                    },
                                })
                            self._model_snapshots[key] = current_size

                        elif current_size != self._model_snapshots[key]:
                            delta = current_size - self._model_snapshots[key]
                            self._emit({
                                "source":      "AIAttackMonitor",
                                "title":       "[T0019] Modificación de modelo IA detectada",
                                "description": (
                                    f"Archivo de modelo modificado: {path.name}  "
                                    f"({self._model_snapshots[key] // 1024} KB → {current_size // 1024} KB, "
                                    f"delta {delta:+d} bytes)"
                                ),
                                "severity":    9,
                                "details": {
                                    "path":          key,
                                    "size_before":   self._model_snapshots[key],
                                    "size_after":    current_size,
                                    "delta_bytes":   delta,
                                    "mitre":         "T0019",
                                    "ai_act_risk":   "CRÍTICO — Integridad del modelo comprometida",
                                    "eu_obligation": "Evaluación de calidad de datos requerida (AI Act)",
                                },
                            })
                            self._model_snapshots[key] = current_size

                    except OSError:
                        continue

            except (PermissionError, OSError):
                continue

    # ─────────────────────────────────────────────────────────────────────────
    def _scan_ai_config_tampering(self):
        """
        Detecta modificaciones recientes en archivos de configuración de modelos IA.
        Indica posible manipulación de comportamiento (integrity attack, T0020).
        """
        now = time.time()
        for base_dir in _AI_MODEL_DIRS:
            if not base_dir.exists():
                continue
            try:
                for path in base_dir.rglob("*"):
                    if not path.is_file():
                        continue
                    # ¿Coincide con un patrón de config de IA?
                    match_cfg = any(p.search(path.name) for p in _AI_CONFIG_PATTERNS)
                    if not match_cfg:
                        continue
                    try:
                        mtime = path.stat().st_mtime
                        # Modificado en los últimos 60 segundos
                        if now - mtime < 60:
                            self._emit({
                                "source":      "AIAttackMonitor",
                                "title":       "[T0020] Config de modelo IA modificada recientemente",
                                "description": f"Archivo de configuración tocado: {path}",
                                "severity":    7,
                                "details": {
                                    "path":          str(path),
                                    "modified_ago":  f"{now - mtime:.0f}s",
                                    "mitre":         "T0020",
                                    "ai_act_risk":   "Robustez técnica comprometida (Evasión)",
                                    "eu_obligation": "Robustez técnica requerida (AI Act)",
                                },
                            })
                    except OSError:
                        continue

            except (PermissionError, OSError):
                continue

    # ─────────────────────────────────────────────────────────────────────────
    def _emit(self, threat: dict):
        threat.setdefault("timestamp", datetime.now().isoformat())
        threat.setdefault("confidence", 80)
        try:
            self._callback(threat)
        except Exception as e:
            logger.error(f"[AIAttackMonitor] Error en callback: {e}")
