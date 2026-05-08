"""
Analizador de amenazas con IA — motor v2.

Mejoras sobre v1:
  1. Cola de prioridad  — amenazas críticas se analizan primero
  2. Deduplicación      — evita re-analizar la misma clase en 90s
  3. Contexto histórico — últimas N amenazas relacionadas se incluyen en el
                          prompt (detección de kill chain y campaña)
  4. Correlación        — ≥3 eventos con la misma técnica MITRE en 5min
                          emite alerta compuesta "CAMPAÑA ACTIVA"
  5. Workers paralelos  — 2 hilos analizan en paralelo (rate-limit compartido)
  6. Backoff exponencial — reintentos inteligentes ante errores de API
  7. Heurística local   — si la API no está disponible, puntúa localmente
  8. Modelo de respaldo — si el principal falla intenta AI_MODEL_FALLBACK
"""
import heapq
import hashlib
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Optional

from openai import OpenAI, APIError, RateLimitError

import config
from utils.logger import get_logger
from ai.ai_guard import ai_guard

logger = get_logger("ThreatAnalyzer")

# ─── Ventanas de correlación ───────────────────────────────────────────────────
_CAMPAIGN_WINDOW_SECS = 300   # 5 minutos
_CAMPAIGN_MIN_EVENTS  = 3     # ≥3 eventos del mismo MITRE = campaña

# ─── Etiquetas de fase del kill chain ─────────────────────────────────────────
KILL_CHAIN_LABELS: dict[str, str] = {
    "reconnaissance":       "Reconocimiento",
    "initial_access":       "Acceso Inicial",
    "execution":            "Ejecución",
    "persistence":          "Persistencia",
    "privilege_escalation": "Escal. Privilegios",
    "defense_evasion":      "Evasión",
    "credential_access":    "Credenciales",
    "discovery":            "Descubrimiento",
    "lateral_movement":     "Mov. Lateral",
    "collection":           "Recolección",
    "command_control":      "C2",
    "exfiltration":         "Exfiltración",
    "impact":               "Impacto",
}
# Abreviaturas para la columna IA de la tabla
_KC_SHORT: dict[str, str] = {
    "reconnaissance":       "Recog.",
    "initial_access":       "Init.",
    "execution":            "Exec.",
    "persistence":          "Pers.",
    "privilege_escalation": "PrivEsc",
    "defense_evasion":      "Evasión",
    "credential_access":    "Creds.",
    "discovery":            "Descub.",
    "lateral_movement":     "Lat.Mv",
    "collection":           "Colect.",
    "command_control":      "C2",
    "exfiltration":         "Exfil.",
    "impact":               "Impacto",
}

# ─── System Prompt v2 — kill chain, correlación, campaña ──────────────────────
SYSTEM_PROMPT = """\
Eres StrikeBack v2, motor de análisis de ciberseguridad para Windows.
Recibes eventos de seguridad detectados en tiempo real con contexto de eventos \
previos recientes del mismo equipo.

Tu análisis debe:
1. Confirmar si es amenaza real o falso positivo.
2. Clasificar con MITRE ATT&CK: técnica (TXXXX) Y táctica (TAXXXX).
3. Identificar la fase del kill chain (si aplica).
4. Detectar si este evento forma parte de una campaña o ataque en curso \
   (basándote en el contexto previo).
5. Asignar severidad corregida (1-10) y urgencia de respuesta.
6. Dar 3 acciones concretas ordenadas por prioridad.

Responde SIEMPRE en este JSON exacto (sin markdown, sin texto fuera del JSON):
{
  "is_threat": true|false,
  "confirmed_severity": 1-10,
  "urgency": "immediate"|"high"|"medium"|"low",
  "mitre_technique": "TXXXX - Nombre" o null,
  "mitre_tactic": "TAXXXX - Táctica" o null,
  "kill_chain_stage": "reconnaissance"|"initial_access"|"execution"|\
"persistence"|"privilege_escalation"|"defense_evasion"|"credential_access"|\
"discovery"|"lateral_movement"|"collection"|"command_control"|\
"exfiltration"|"impact"|null,
  "related_to_previous": true|false,
  "campaign_indicator": true|false,
  "impact": "descripción del impacto en 2-3 oraciones",
  "actions": ["acción prioritaria 1", "acción 2", "acción 3"],
  "summary": "resumen en 1 línea",
  "false_positive_reason": "razón" o null
}

Si el contexto previo muestra un patrón en progreso, explícalo en impact y \
marca campaign_indicator=true.
"""


class _PriorityItem:
    """Wrapper para el heap: ordena por (-severity, monotonic_ts)."""
    __slots__ = ("priority", "ts", "threat")

    def __init__(self, threat: dict):
        self.priority = -(threat.get("severity", 5))
        self.ts       = time.monotonic()
        self.threat   = threat

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.ts < other.ts


class ThreatAnalyzer:
    """
    Motor de análisis IA v2:
    - Cola de prioridad por severidad (sev 10 primero)
    - Deduplicación con ventana de tiempo (90s default)
    - Contexto histórico para correlación de ataques (kill chain)
    - Detección automática de campañas activas
    - Workers paralelos con rate-limit compartido
    - Backoff exponencial ante errores de API
    - Heurística local si la API no está disponible
    """

    def __init__(self, result_callback: Callable):
        self.result_callback = result_callback

        # Cola de prioridad (heap + lock)
        self._heap:      list            = []
        self._heap_lock: threading.Lock  = threading.Lock()
        self._not_empty: threading.Event = threading.Event()

        self._stop_event = threading.Event()
        self._threads:   list[threading.Thread] = []

        # Rate limit compartido entre workers
        self._rl_lock           = threading.Lock()
        self._calls_this_minute = 0
        self._minute_start      = time.time()

        self._client:  Optional[OpenAI] = None
        self._enabled  = False

        # Deduplicación: md5(source|title) → timestamp
        self._dedup:      dict[str, float] = {}
        self._dedup_lock: threading.Lock   = threading.Lock()

        # Historial deslizante para contexto (últimas 50)
        self._history:      deque[dict]    = deque(maxlen=50)
        self._history_lock: threading.Lock = threading.Lock()

        # Detector de campaña: mitre → deque de timestamps
        self._campaign_tracker:   dict[str, deque] = defaultdict(lambda: deque())
        self._campaign_lock:      threading.Lock   = threading.Lock()
        self._emitted_campaigns:  set[str]         = set()

    # ------------------------------------------------------------------
    def start(self):
        if not config.AI_API_KEY or config.AI_API_KEY == "TU_API_KEY_AQUI":
            logger.warning("API key no configurada. Análisis IA desactivado.")
            return

        try:
            self._client  = OpenAI(
                api_key  = config.AI_API_KEY,
                base_url = config.AI_BASE_URL,
            )
            self._enabled = True
        except Exception as e:
            logger.error(f"Error inicializando cliente IA: {e}")
            return

        n = getattr(config, "AI_WORKER_THREADS", 2)
        for i in range(n):
            t = threading.Thread(
                target=self._run, daemon=True, name=f"AIAnalyzer-{i+1}"
            )
            t.start()
            self._threads.append(t)

        logger.info(
            f"Analizador IA v2 iniciado — {n} workers, modelo: {config.AI_MODEL}"
        )

    def stop(self):
        self._stop_event.set()
        self._not_empty.set()   # desbloquear workers dormidos

    # ------------------------------------------------------------------
    def submit(self, threat: dict):
        """Encola amenaza con prioridad. No bloqueante."""
        if not self._enabled:
            self._local_fallback(threat)
            return

        # Deduplicación
        key = hashlib.md5(
            f"{threat.get('source','')}|{(threat.get('title',''))[:80]}".encode()
        ).hexdigest()
        ttl = getattr(config, "AI_DEDUP_WINDOW_SECONDS", 90)
        now = time.time()
        with self._dedup_lock:
            if now - self._dedup.get(key, 0) < ttl:
                logger.debug(f"[AI] Dedup: '{threat.get('title','')}' omitido")
                return
            self._dedup[key] = now

        with self._heap_lock:
            heapq.heappush(self._heap, _PriorityItem(threat))
        self._not_empty.set()

    # ------------------------------------------------------------------
    def _pop(self) -> Optional[dict]:
        with self._heap_lock:
            if not self._heap:
                return None
            return heapq.heappop(self._heap).threat

    def _wait_rate_limit(self):
        """Espera slot de rate-limit de forma thread-safe."""
        while not self._stop_event.is_set():
            with self._rl_lock:
                now = time.time()
                if now - self._minute_start >= 60:
                    self._calls_this_minute = 0
                    self._minute_start      = now
                if self._calls_this_minute < config.AI_MAX_CALLS_PER_MINUTE:
                    self._calls_this_minute += 1
                    return
                wait = 61 - (now - self._minute_start)
            logger.debug(
                f"Rate limit IA ({self._calls_this_minute}/{config.AI_MAX_CALLS_PER_MINUTE}). "
                f"Esperando {wait:.0f}s"
            )
            self._stop_event.wait(timeout=max(wait, 1))

    # ------------------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():
            threat = self._pop()
            if threat is None:
                self._not_empty.wait(timeout=2)
                continue
            self._wait_rate_limit()
            if not self._stop_event.is_set():
                self._analyze(threat)

    # ------------------------------------------------------------------
    def _build_context_prompt(self, threat: dict) -> str:
        """
        Construye el prompt enriquecido con contexto histórico:
        hasta 5 amenazas previas del mismo monitor o táctica MITRE.
        """
        source = threat.get("source", "")
        t_tactic = (threat.get("ai_analysis") or {}).get("mitre_tactic", "")

        with self._history_lock:
            related = [
                t for t in self._history
                if (t.get("source") == source or
                    (t.get("ai_analysis") or {}).get("mitre_tactic") == t_tactic)
                and t is not threat
            ]
            ctx = list(related)[-5:]

        lines = [
            "=== EVENTO ACTUAL ===",
            f"Fuente      : {threat.get('source', '?')}",
            f"Título      : {threat.get('title', '?')}",
            f"Descripción : {threat.get('description', '?')}",
            f"Severidad   : {threat.get('severity', 5)}/10",
            f"Fiabilidad  : {threat.get('confidence', 0)}%",
            f"Detalles    : {json.dumps(threat.get('details', {}), ensure_ascii=False)[:400]}",
            f"Timestamp   : {threat.get('timestamp', '')}",
        ]

        if ctx:
            lines.append(f"\n=== CONTEXTO PREVIO ({len(ctx)} eventos relacionados) ===")
            for i, t in enumerate(ctx, 1):
                ai  = (t.get("ai_analysis") or {})
                kcs = _KC_SHORT.get(ai.get("kill_chain_stage", ""), "–")
                lines.append(
                    f"[{i}] {t.get('source','?')} | sev={t.get('severity','?')} | "
                    f"{t.get('title','')[:70]} | "
                    f"MITRE: {ai.get('mitre_technique') or '–'} | Fase: {kcs}"
                )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _analyze(self, threat: dict):
        raw_prompt = self._build_context_prompt(threat)

        # AIGuard: sanitizar entrada
        prompt, guard_in = ai_guard.sanitize_input(raw_prompt)
        for a in guard_in:
            logger.warning(f"[AIGuard→in] {a['type']}: {a['detail']}")

        # Intentar modelos en orden: principal → respaldo
        models = [config.AI_MODEL]
        fb = getattr(config, "AI_MODEL_FALLBACK", None)
        if fb and fb != config.AI_MODEL:
            models.append(fb)

        analysis = None
        used_model = config.AI_MODEL
        for model in models:
            analysis = self._call_api(prompt, threat, model)
            if analysis is not None:
                used_model = model
                break
            logger.warning(f"[IA] Modelo '{model}' falló, probando siguiente…")

        if analysis is None:
            analysis   = self._local_heuristic(threat)
            used_model = "heuristic_fallback"
            logger.warning(f"[IA] Heurística local para '{threat.get('title','')}'")

        threat["ai_analysis"] = analysis
        threat["ai_analyzed"] = (used_model != "heuristic_fallback")
        threat["ai_model"]    = used_model

        # Guardar en historial para contextualizar futuros análisis
        with self._history_lock:
            self._history.append(threat)

        # Correlación: detectar campaña activa
        self._check_campaign(threat, analysis)

        logger.info(
            "[IA] '%.60s' → %s sev=%s/%s fase=%s campaña=%s",
            threat.get("title", "?"),
            "AMENAZA" if analysis.get("is_threat") else "F.P.",
            analysis.get("confirmed_severity", "?"), 10,
            analysis.get("kill_chain_stage") or "–",
            "SÍ" if analysis.get("campaign_indicator") else "No",
        )

        self.result_callback(threat)

    # ------------------------------------------------------------------
    def _call_api(self, prompt: str, threat: dict, model: str) -> Optional[dict]:
        """Llama a la API con backoff exponencial (3 intentos)."""
        backoff = 2.0
        for attempt in range(3):
            try:
                resp = self._client.chat.completions.create(
                    model       = model,
                    temperature = 0.1,
                    max_tokens  = 600,
                    messages    = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                )
                raw = resp.choices[0].message.content.strip()

                # Limpiar bloques markdown si el modelo los añade
                if raw.startswith("```"):
                    lines = raw.split("\n")
                    raw   = "\n".join(lines[1:])
                    raw   = raw.rsplit("```", 1)[0].strip()
                    if raw.startswith("json"):
                        raw = raw[4:].strip()

                analysis, guard_out = ai_guard.validate_output(raw, threat)
                for a in guard_out:
                    logger.warning(f"[AIGuard→out] {a['type']}: {a['detail']}")

                if analysis is not None:
                    return analysis

            except RateLimitError:
                wait = 30 * (attempt + 1)
                logger.warning(
                    f"Rate limit API (intento {attempt+1}/3). Esperando {wait}s."
                )
                self._stop_event.wait(timeout=wait)
                with self._rl_lock:
                    self._calls_this_minute = 0
                    self._minute_start      = time.time()

            except APIError as e:
                logger.error(f"API error intento {attempt+1}/3 ({model}): {e}")
                self._stop_event.wait(timeout=backoff)
                backoff = min(backoff * 2, 30)

            except Exception as e:
                logger.error(f"Error inesperado intento {attempt+1}/3: {e}")
                self._stop_event.wait(timeout=backoff)
                backoff = min(backoff * 2, 30)

        return None

    # ------------------------------------------------------------------
    def _local_heuristic(self, threat: dict) -> dict:
        """
        Puntuación local cuando la API no está disponible.
        Reutiliza los metadatos MITRE/tactic/recommendation que los monitores
        ya inyectan en threat['details'] (p.ej. HoneypotMonitor, EventLogMonitor).
        """
        sev     = threat.get("severity", 5)
        conf    = threat.get("confidence", 70)
        details = threat.get("details") or {}

        # Si el monitor ya marcó zero_fp=True nunca clasificar como falso positivo
        zero_fp = bool(details.get("zero_fp", False))

        if not zero_fp and conf < 60:
            is_threat, urgency = False, "low"
        elif sev >= 9:
            is_threat, urgency = True, "immediate"
        elif sev >= 7:
            is_threat, urgency = True, "high"
        elif sev >= 5:
            is_threat, urgency = True, "medium"
        else:
            is_threat, urgency = sev >= 3, "low"

        # ── Extraer MITRE desde details si ya viene del monitor ──────────
        raw_mitre = details.get("mitre") or details.get("mitre_technique") or ""
        raw_tactic = details.get("tactic") or details.get("mitre_tactic") or ""

        # Normalizar técnica a formato "TXXXX - Nombre"
        mitre_technique: Optional[str] = None
        if raw_mitre:
            mitre_technique = (
                raw_mitre if raw_mitre.upper().startswith("T")
                else f"T???? - {raw_mitre}"
            )

        # Normalizar táctica
        mitre_tactic: Optional[str] = raw_tactic if raw_tactic else None

        # ── Mapear táctica → fase del kill chain ─────────────────────────
        _tactic_to_kc: dict[str, str] = {
            "reconnaissance":       "reconnaissance",
            "initial access":       "initial_access",
            "execution":            "execution",
            "persistence":          "persistence",
            "privilege escalation": "privilege_escalation",
            "defense evasion":      "defense_evasion",
            "credential access":    "credential_access",
            "discovery":            "discovery",
            "lateral movement":     "lateral_movement",
            "collection":           "collection",
            "command and control":  "command_control",
            "exfiltration":         "exfiltration",
            "impact":               "impact",
        }
        kcs: Optional[str] = None
        tactic_lower = raw_tactic.lower()
        for key, stage in _tactic_to_kc.items():
            if key in tactic_lower:
                kcs = stage
                break

        # ── Acciones: usar recommendation del monitor si existe ──────────
        recommendation = details.get("recommendation", "")
        if recommendation:
            actions = [
                recommendation,
                "Recopilar evidencias forenses (memoria y logs) antes de actuar.",
                "Aislar el proceso o equipo afectado si el riesgo lo justifica.",
            ]
        else:
            actions = [
                "Revisar manualmente este evento en el log detallado.",
                "Verificar el proceso o usuario que originó la actividad.",
                "Activar respuesta automática si el patrón persiste.",
            ]

        # ── Impacto descriptivo ──────────────────────────────────────────
        source = threat.get("source", "Monitor")
        impact = (
            f"Evento de severidad {sev}/10 detectado por {source}. "
            f"{'Confianza muy alta (zero_fp=True). ' if zero_fp else ''}"
            f"{'Técnica MITRE identificada: ' + raw_mitre + '. ' if raw_mitre else ''}"
            "Análisis heurístico local (API no disponible)."
        )

        return {
            "is_threat":           is_threat,
            "confirmed_severity":  sev,
            "urgency":             urgency,
            "mitre_technique":     mitre_technique,
            "mitre_tactic":        mitre_tactic,
            "kill_chain_stage":    kcs,
            "related_to_previous": False,
            "campaign_indicator":  False,
            "impact":              impact,
            "actions":             actions,
            "summary":             f"[Heurística] {threat.get('title','?')} — sev {sev}/10",
            "false_positive_reason": (
                None if is_threat
                else "Confianza del detector < 60%"
            ),
        }

    def _local_fallback(self, threat: dict):
        """IA desactivada por completo (sin API key). Puntúa localmente."""
        threat["ai_analysis"] = self._local_heuristic(threat)
        threat["ai_analyzed"] = False
        threat["ai_model"]    = "heuristic_local"
        self.result_callback(threat)

    # ------------------------------------------------------------------
    def _check_campaign(self, threat: dict, analysis: dict):
        """
        Detecta campaña activa: ≥CAMPAIGN_MIN_EVENTS eventos con la misma
        técnica MITRE en CAMPAIGN_WINDOW_SECS segundos → emite alerta compuesta.
        """
        mitre = analysis.get("mitre_technique") or ""
        if not mitre or not analysis.get("is_threat"):
            return

        now = time.time()
        with self._campaign_lock:
            tracker = self._campaign_tracker[mitre]
            while tracker and now - tracker[0] > _CAMPAIGN_WINDOW_SECS:
                tracker.popleft()
            tracker.append(now)
            count = len(tracker)

        if count < _CAMPAIGN_MIN_EVENTS:
            return

        # Emitir solo una vez por ventana de tiempo
        bucket = f"{mitre}|{int(now // _CAMPAIGN_WINDOW_SECS)}"
        with self._campaign_lock:
            if bucket in self._emitted_campaigns:
                return
            self._emitted_campaigns.add(bucket)

        compound_sev = min(10, (analysis.get("confirmed_severity") or 8) + 1)
        campaign_threat = {
            "source":      "AIAnalyzer",
            "title":       f"[CAMPAÑA ACTIVA] {count}x {mitre}",
            "description": (
                f"Campaña detectada: {count} eventos con técnica '{mitre}' "
                f"en {_CAMPAIGN_WINDOW_SECS // 60} minutos. "
                "Posible ataque coordinado en progreso."
            ),
            "severity":    compound_sev,
            "confidence":  95,
            "timestamp":   datetime.now().isoformat(),
            "ai_analyzed": True,
            "ai_model":    "campaign_correlator",
            "ai_analysis": {
                "is_threat":           True,
                "confirmed_severity":  compound_sev,
                "urgency":             "immediate",
                "mitre_technique":     mitre,
                "mitre_tactic":        analysis.get("mitre_tactic"),
                "kill_chain_stage":    analysis.get("kill_chain_stage"),
                "related_to_previous": True,
                "campaign_indicator":  True,
                "impact": (
                    f"Campaña activa: {count} eventos de '{mitre}' detectados en "
                    f"{_CAMPAIGN_WINDOW_SECS // 60} minutos desde el mismo equipo."
                ),
                "actions": [
                    "Aislar el equipo de la red si hay indicios de movimiento lateral.",
                    "Recopilar evidencias forenses (memoria, logs, red) antes de responder.",
                    "Activar plan de respuesta a incidentes y notificar al equipo de seguridad.",
                ],
                "summary": (
                    f"CAMPAÑA: {count}x '{mitre}' en {_CAMPAIGN_WINDOW_SECS // 60}min"
                ),
                "false_positive_reason": None,
            },
            "details": {
                "event_count": count,
                "window_secs": _CAMPAIGN_WINDOW_SECS,
                "mitre":       mitre,
                "confidence":  95,
            },
        }
        logger.critical(
            "[IA] CAMPAÑA DETECTADA: %d eventos '%s' en %d min",
            count, mitre, _CAMPAIGN_WINDOW_SECS // 60,
        )
        self.result_callback(campaign_threat)
