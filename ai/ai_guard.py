"""
AI Guard — Robustez y protección del motor de IA de StrikeBack.

Basado en los frameworks de referencia (ART/IBM, TextAttack, Foolbox, RobustBench)
y la regulación EU AI Act, este módulo implementa 5 capas de defensa:

  1. Sanitización de entrada   → evita prompt injection / misuse
  2. Detección de evasión      → obfuscación, codificaciones adversariales
  3. Validación de salida      → sanity-check del JSON de la IA
  4. Detección de envenenamiento → intentos de alterar el comportamiento del modelo
  5. Control de extracción     → limita la fuga de información interna del sistema

Referencia AI Act (Anexo IX):
  - Envenenamiento del modelo  → T0019 (ATLAS)
  - Evasión de sistemas        → T0015 (ATLAS)
  - Extracción de información  → T0024 (ATLAS)
  - Prompt injection / misuse  → CWE-1427
  - Ataques tradicionales      → CVE-based (gestionados por monitores estándar)
"""

import re
import json
import hashlib
import time
from datetime import datetime
from typing import Optional
from utils.logger import get_logger

logger = get_logger("AIGuard")

# ── Patrones de prompt injection ─────────────────────────────────────────────
# Inspirados en TextAttack adversarial NLP + OWASP LLM Top-10
_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),       "override_instructions"),
    (re.compile(r"forget\s+(all\s+)?previous\s+instructions?", re.I),       "override_instructions"),
    (re.compile(r"you\s+are\s+now\s+(?:a|an)\s+\w+", re.I),                "persona_hijack"),
    (re.compile(r"act\s+as\s+(?:if\s+you\s+are|a|an)\s+\w+", re.I),        "persona_hijack"),
    (re.compile(r"jailbreak|DAN\s+mode|developer\s+mode", re.I),            "jailbreak_attempt"),
    (re.compile(r"print\s+(your\s+)?system\s+prompt", re.I),                "prompt_extraction"),
    (re.compile(r"reveal\s+(your\s+)?(instructions?|config|api.?key)", re.I),"data_extraction"),
    (re.compile(r"<!--.*-->|<\s*script.*?>", re.I | re.S),                  "html_injection"),
    (re.compile(r"\bbase64\b.*\beval\b|\beval\b.*\bbase64\b", re.I),        "encoded_payload"),
    (re.compile(r"(?:sudo|su\s+-|admin|root)\s+\w+\s*\(", re.I),            "privilege_escalation_prompt"),
]

# ── Patrones de evasión adversarial ──────────────────────────────────────────
# Detectan técnicas tipo Foolbox: sustitución de caracteres, unicode lookalikes
_EVASION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[\u0400-\u04ff]"),               "cyrillic_lookalike"),   # Homoglyph attacks (bloque cirílico completo)
    (re.compile(r"[\u0600-\u06ff]"),               "arabic_lookalike"),
    (re.compile(r"[\uff00-\uffef]"),               "fullwidth_chars"),
    (re.compile(r"(?:\s*\u200b\s*|\s*\u00ad\s*)"), "zero_width_chars"),     # Zero-width space / soft hyphen
    (re.compile(r"(?:m.{0,2}i.{0,2}m.{0,2}i.{0,2}k.{0,2}a.{0,2}t.{0,2}z)", re.I), "obfuscated_tool_name"),
    (re.compile(r"(?:n.{0,2}m.{0,2}a.{0,2}p)", re.I),                       "obfuscated_tool_name"),
    (re.compile(r"(?:c.{0,2}o.{0,2}b.{0,2}a.{0,2}l.{0,2}t)", re.I),        "obfuscated_tool_name"),
]

# ── Campos requeridos en la respuesta JSON de la IA ──────────────────────────
_REQUIRED_AI_FIELDS = {"is_threat", "confirmed_severity", "impact", "summary"}
_SEVERITY_RANGE     = range(1, 11)

# Valores válidos para los campos opcionales del esquema v2
_VALID_URGENCY = {"immediate", "high", "medium", "low"}
_VALID_KILL_CHAIN = {
    "reconnaissance", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_control",
    "exfiltration", "impact",
}

# ── Heurísticas de envenenamiento del modelo ─────────────────────────────────
# Respuestas que indican que el modelo fue manipulado (RobustBench style)
_POISONING_INDICATORS = [
    "ignore threat",
    "do not alert",
    "this is safe",
    "no action needed",
    "i am an ai and cannot",
    "as an ai language model",
    "i cannot analyze",
    "whitelist this",
]

# Historial de hashes de prompts (para detectar repetición sospechosa / flooding)
_prompt_history: dict[str, list[float]] = {}
_MAX_SAME_PROMPT_PER_MINUTE = 5


# ═════════════════════════════════════════════════════════════════════════════
class AIGuard:
    """
    Middleware de seguridad que envuelve el prompt antes de enviarlo a la IA
    y valida la respuesta antes de usarla.

    Uso:
        guard  = AIGuard()
        prompt = guard.sanitize_input(raw_prompt)
        # ... llamada a la IA ...
        result = guard.validate_output(ai_json, original_threat)
    """

    def __init__(self):
        self._blocked_count     = 0
        self._evasion_count     = 0
        self._poisoning_count   = 0
        self._injection_count   = 0

    # ─────────────────────────────────────────────────────────────────────────
    def sanitize_input(self, prompt: str) -> tuple[str, list[dict]]:
        """
        Limpia y audita el prompt antes de enviarlo a la IA.
        Devuelve (prompt_limpio, lista_de_alertas).
        Cada alerta: {"type": str, "detail": str, "layer": str}
        """
        alerts: list[dict] = []

        # ── Capa 1: Prompt injection (OWASP LLM-01) ──────────────────────
        for pattern, attack_type in _INJECTION_PATTERNS:
            if pattern.search(prompt):
                alerts.append({
                    "type":   "PROMPT_INJECTION",
                    "detail": f"Patrón detectado: {attack_type}",
                    "layer":  "input_sanitization",
                    "mitre":  "CWE-1427",
                })
                self._injection_count += 1
                logger.warning(f"[AIGuard] Prompt injection detectado: {attack_type}")

        # ── Capa 2: Evasión adversarial (Foolbox / TextAttack style) ─────
        for pattern, evasion_type in _EVASION_PATTERNS:
            if pattern.search(prompt):
                alerts.append({
                    "type":   "ADVERSARIAL_EVASION",
                    "detail": f"Técnica de evasión: {evasion_type}",
                    "layer":  "evasion_detection",
                    "mitre":  "T0015",
                })
                self._evasion_count += 1
                logger.warning(f"[AIGuard] Evasión adversarial detectada: {evasion_type}")

        # ── Capa 3: Anti-flooding / envenenamiento por repetición ────────
        h = hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()[:16]
        now = time.time()
        history = _prompt_history.setdefault(h, [])
        history[:] = [t for t in history if now - t < 60]  # ventana 60s
        history.append(now)

        if len(history) > _MAX_SAME_PROMPT_PER_MINUTE:
            alerts.append({
                "type":   "MODEL_POISONING_ATTEMPT",
                "detail": f"Prompt idéntico enviado {len(history)}x en 60s (flooding)",
                "layer":  "poisoning_detection",
                "mitre":  "T0019",
            })
            self._poisoning_count += 1
            logger.warning(f"[AIGuard] Flooding de prompt detectado ({len(history)}x/min)")

        # ── Sanitización: eliminar caracteres zero-width y limitar largo ─
        clean = re.sub(r"[\u200b\u200c\u200d\u00ad\ufeff]", "", prompt)
        clean = clean[:4096]  # truncar para evitar context overflow

        if alerts:
            self._blocked_count += 1

        return clean, alerts

    # ─────────────────────────────────────────────────────────────────────────
    def validate_output(self, raw_json: str, original_threat: dict) -> tuple[Optional[dict], list[dict]]:
        """
        Valida y sanitiza la respuesta JSON de la IA.
        Detecta: JSON malformado, campos faltantes, valores fuera de rango,
        indicadores de envenenamiento del modelo.

        Devuelve (analysis_dict | None, lista_de_alertas).
        """
        alerts: list[dict] = []

        # ── Parse JSON ───────────────────────────────────────────────────
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            alerts.append({
                "type":   "INVALID_AI_OUTPUT",
                "detail": f"JSON inválido: {e}",
                "layer":  "output_validation",
            })
            logger.error(f"[AIGuard] JSON inválido de la IA: {e}")
            return None, alerts

        # ── Campos requeridos (RobustBench: estructura garantizada) ──────
        missing = _REQUIRED_AI_FIELDS - set(data.keys())
        if missing:
            alerts.append({
                "type":   "INCOMPLETE_AI_RESPONSE",
                "detail": f"Campos faltantes: {missing}",
                "layer":  "output_validation",
            })
            logger.warning(f"[AIGuard] Respuesta IA incompleta: faltan {missing}")

        # ── Severidad dentro de rango ─────────────────────────────────────
        sev = data.get("confirmed_severity", 0)
        if not isinstance(sev, int) or sev not in _SEVERITY_RANGE:
            alerts.append({
                "type":   "INVALID_SEVERITY",
                "detail": f"Severidad fuera de rango: {sev!r}",
                "layer":  "output_validation",
            })
            data["confirmed_severity"] = max(1, min(10, int(sev) if isinstance(sev, (int, float)) else 5))

        # ── is_threat debe ser bool ───────────────────────────────────────
        if not isinstance(data.get("is_threat"), bool):
            data["is_threat"] = bool(data.get("is_threat", False))

        # ── Validaciones de campos v2 (urgency, kill_chain_stage, actions) ──
        # urgency: normalizar a minúsculas y colapsar valores desconocidos
        urgency = str(data.get("urgency", "")).lower().strip()
        if urgency not in _VALID_URGENCY:
            # Inferir desde severidad si el campo es inválido o vacío
            sev_val = data.get("confirmed_severity", 5)
            urgency = (
                "immediate" if sev_val >= 9 else
                "high"      if sev_val >= 7 else
                "medium"    if sev_val >= 5 else
                "low"
            )
            if data.get("urgency") not in (None, ""):
                alerts.append({
                    "type":   "INVALID_URGENCY",
                    "detail": f"Valor urgency desconocido '{data.get('urgency')}' → inferido '{urgency}'",
                    "layer":  "output_validation",
                })
        data["urgency"] = urgency

        # kill_chain_stage: aceptar solo valores conocidos, convertir a null si inválido
        kcs = data.get("kill_chain_stage")
        if kcs is not None and str(kcs).lower() not in _VALID_KILL_CHAIN:
            alerts.append({
                "type":   "INVALID_KILL_CHAIN",
                "detail": f"kill_chain_stage desconocido: '{kcs}' → null",
                "layer":  "output_validation",
            })
            data["kill_chain_stage"] = None
        elif kcs is not None:
            data["kill_chain_stage"] = str(kcs).lower()

        # actions: garantizar lista de strings no vacía
        actions = data.get("actions", [])
        if not isinstance(actions, list) or not actions:
            data["actions"] = ["Revisar el evento manualmente.", "Consultar el log detallado.", "Activar respuesta si persiste."]
        else:
            data["actions"] = [str(a) for a in actions if str(a).strip()][:5]  # máx 5 acciones

        # ── Detección de envenenamiento del modelo (ART style) ───────────
        # Si la IA dice que algo grave "es seguro", podría haber sido manipulada
        summary_lower  = str(data.get("summary", "")).lower()
        impact_lower   = str(data.get("impact", "")).lower()
        combined_lower = summary_lower + " " + impact_lower

        original_sev = original_threat.get("severity", 5)
        for indicator in _POISONING_INDICATORS:
            if indicator in combined_lower:
                alerts.append({
                    "type":   "MODEL_POISONING_SUSPECTED",
                    "detail": f"Indicador sospechoso en respuesta IA: '{indicator}'",
                    "layer":  "poisoning_detection",
                    "mitre":  "T0019",
                })
                self._poisoning_count += 1
                logger.warning(f"[AIGuard] Posible envenenamiento de modelo: '{indicator}'")
                break

        # Si severidad original >= 8 y la IA dice que NO es amenaza → sospechoso
        if original_sev >= 8 and not data.get("is_threat", True):
            alerts.append({
                "type":   "SEVERITY_DOWNGRADE_SUSPECTED",
                "detail": (
                    f"Evento crítico (sev {original_sev}) marcado como no-amenaza por la IA. "
                    "Posible evasión o envenenamiento."
                ),
                "layer":  "poisoning_detection",
                "mitre":  "T0015",
            })
            self._evasion_count += 1
            logger.warning(
                f"[AIGuard] IA degradó severidad {original_sev}→ no-amenaza. Revisión manual recomendada."
            )

        # ── Extracción: detectar si la IA devolvió datos internos ────────
        internal_markers = ["system_prompt", "api_key", "AI_API_KEY", "config.py", "strikeback.db"]
        for marker in internal_markers:
            if marker.lower() in combined_lower:
                alerts.append({
                    "type":   "INFORMATION_EXTRACTION_SUSPECTED",
                    "detail": f"Posible fuga de dato interno: '{marker}' en respuesta IA",
                    "layer":  "extraction_detection",
                    "mitre":  "T0024",
                })
                logger.error(f"[AIGuard] Extracción de información detectada: '{marker}'")

        if alerts:
            data["_ai_guard_alerts"] = alerts

        return data, alerts

    # ─────────────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "blocked_total":    self._blocked_count,
            "injection_events": self._injection_count,
            "evasion_events":   self._evasion_count,
            "poisoning_events": self._poisoning_count,
        }


# Instancia global (singleton) para usar en toda la aplicación
ai_guard = AIGuard()
