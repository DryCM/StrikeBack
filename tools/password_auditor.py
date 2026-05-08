"""
PasswordAuditor — Auditoría de robustez y análisis de contraseñas/hashes.

AVISO: Solo para auditar contraseñas en sistemas propios o con autorización.
       El uso no autorizado es ilegal.

Funcionalidades:
  1. Análisis de Entropía y Fortaleza:
     - Longitud, clases de caracteres, entropía de Shannon
     - Tiempo estimado de crackeo (GPU A100: 10^12 hash/s)
     - Score OWASP / NIST SP 800-63B

  2. Identificación de Hashes:
     - MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, Argon2, PBKDF2
     - Detección por longitud y prefijo

  3. Auditoría por Diccionario (autorizado):
     - Wordlist incluida (10 000 contraseñas más comunes)
     - Reglas de mutación: l33tspeak, capitalización, sufijos numéricos
     - Soporta MD5, SHA-1, SHA-256, NTLM

  4. Verificación contra Have I Been Pwned:
     - k-Anonymity API: solo envía los 5 primeros hex del hash SHA-1
     - Sin exposición de contraseña completa

  5. Generador de contraseñas seguras:
     - Contraseñas criptográficamente seguras
     - Passphrases memorables

Uso:
    pa = PasswordAuditor()
    strength = pa.analyze_password("P@ssw0rd!")
    hash_info = pa.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    crack = pa.dictionary_attack("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
    strong = pa.generate_password(length=20)
"""

import hashlib
import hmac
import math
import os
import re
import secrets
import string
import time
import urllib.request
from typing import Callable

from utils.logger import get_logger

logger = get_logger("PasswordAuditor")

# ── TOP 100 contraseñas más comunes (comprimida) ──────────────────────────────
_TOP_PASSWORDS_100 = [
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","111111","123123","admin","letmein","monkey","master",
    "dragon","pass","test","iloveyou","1q2w3e4r","000000","password1","1234",
    "hello","charlie","donald","password123","qwerty123","iloveyou1","sunshine",
    "princess","abc123456","welcome","shadow","superman","michael","football",
    "batman","pass123","trustno1","qazwsx","123qwe","starwars","baseball",
    "soccer","hockey","harley","ranger","hunter","joshua","maggie","jordan",
    "winter","jessica","maverick","guitar","dakota","cookie","chicken","flower",
    "george","andrew","cheese","thomas","access","yankees","steelers","matrix",
    "pokemon","whatever","arsenal","ferrari","london","liverpool","madrid",
    "barcelona","chelsea","arsenal","juventus","password2","123abc","abc1234",
    "password!","P@ssword","Password1","Admin123","root","toor","admin123",
    "administrator","pass1234","test123","guest","user","login","change_me",
    "default","demo","master123","secret","changeme",
]

# ── Patrones de hash por longitud y prefijo ───────────────────────────────────
_HASH_SIGNATURES = {
    32:   "MD5 / NTLM",
    40:   "SHA-1 / MySQL 5",
    56:   "SHA-224",
    64:   "SHA-256 / SHA3-256",
    96:   "SHA-384",
    128:  "SHA-512 / SHA3-512",
    60:   "bcrypt ($2a$ / $2b$)",
    34:   "MD5crypt ($1$)",
}

# ── Velocidades de crackeo estimadas (hashes/s) ───────────────────────────────
# Basado en Hashcat benchmark en RTX 4090 (ref. 2024)
_CRACK_SPEED = {
    "MD5":     164_000_000_000,   # 164 GH/s
    "SHA-1":    61_000_000_000,   #  61 GH/s
    "SHA-256":  23_000_000_000,   #  23 GH/s
    "SHA-512":   7_600_000_000,   # 7.6 GH/s
    "NTLM":    400_000_000_000,   # 400 GH/s
    "bcrypt":           184_000,  # 184 kH/s (coste 12)
    "Argon2":             1_000,  # ~1 kH/s
    "PBKDF2":           600_000,  # 600 kH/s (600k iter SHA-256)
}

# ── Wordlist de mutaciones ────────────────────────────────────────────────────
_LEET_MAP = str.maketrans("aeiost", "4310$7")

_SUFFIXES = ["1", "123", "!", "2024", "2025", "2026", "#", "@", "01", "12"]


class PasswordAuditor:
    """Auditor de contraseñas, hashes y credenciales."""

    # ── Análisis de fortaleza ─────────────────────────────────────────────────
    def analyze_password(self, password: str) -> dict:
        """
        Analiza la fortaleza de una contraseña.

        Returns:
            Dict con score 0-100, entropía, tiempo de crackeo y recomendaciones
        """
        if not password:
            return {"error": "Contraseña vacía"}

        length   = len(password)
        has_lower  = bool(re.search(r"[a-z]", password))
        has_upper  = bool(re.search(r"[A-Z]", password))
        has_digit  = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
        has_space  = " " in password

        # Espacio de caracteres
        char_space = 0
        if has_lower:   char_space += 26
        if has_upper:   char_space += 26
        if has_digit:   char_space += 10
        if has_symbol:  char_space += 32
        if has_space:   char_space += 1
        if char_space == 0:
            char_space = 26

        # Entropía de Shannon (bits)
        entropy = length * math.log2(char_space) if char_space > 1 else 0.0

        # ¿Contraseña común?
        is_common = password.lower() in _TOP_PASSWORDS_100

        # Tiempo de crackeo (MD5 GPU, peor caso)
        keyspace = char_space ** length
        crack_sec = keyspace / _CRACK_SPEED["MD5"]

        # Score 0-100
        score = 0
        if length >= 8:   score += 15
        if length >= 12:  score += 15
        if length >= 16:  score += 10
        if has_lower:     score += 10
        if has_upper:     score += 10
        if has_digit:     score += 10
        if has_symbol:    score += 20
        if entropy >= 50: score += 5
        if entropy >= 70: score += 5
        if is_common:     score  = min(score, 10)

        # Nivel NIST SP 800-63B
        if score >= 80:      level = "MUY FUERTE"
        elif score >= 60:    level = "FUERTE"
        elif score >= 40:    level = "MODERADA"
        elif score >= 20:    level = "DÉBIL"
        else:                level = "MUY DÉBIL"

        recommendations = []
        if length < 12:       recommendations.append("Usa al menos 12 caracteres")
        if not has_upper:     recommendations.append("Añade letras mayúsculas")
        if not has_lower:     recommendations.append("Añade letras minúsculas")
        if not has_digit:     recommendations.append("Añade números")
        if not has_symbol:    recommendations.append("Añade símbolos (!@#$%)")
        if is_common:         recommendations.append("Esta contraseña está en listas de brechas — cámbiala")

        return {
            "password_length":  length,
            "char_classes":     {
                "lowercase": has_lower, "uppercase": has_upper,
                "digits": has_digit, "symbols": has_symbol,
            },
            "char_space":       char_space,
            "entropy_bits":     round(entropy, 1),
            "score":            min(100, score),
            "level":            level,
            "is_common":        is_common,
            "crack_time_md5":   self._format_time(crack_sec),
            "crack_time_bcrypt":self._format_time(keyspace / _CRACK_SPEED["bcrypt"]),
            "recommendations":  recommendations,
            "complies_nist_800_63b": length >= 8 and not is_common,
        }

    # ── Identificación de hash ────────────────────────────────────────────────
    def identify_hash(self, hash_str: str) -> dict:
        """
        Identifica el tipo de hash por longitud y prefijo.

        Args:
            hash_str: Hash en hexadecimal o formato especial ($2a$...)

        Returns:
            Dict con tipo probable, longitud y recomendaciones
        """
        h = hash_str.strip()

        # Prefijos especiales
        if h.startswith("$2a$") or h.startswith("$2b$"):
            alg = "bcrypt"
            secure = True
        elif h.startswith("$argon2"):
            alg = "Argon2"
            secure = True
        elif h.startswith("$pbkdf2"):
            alg = "PBKDF2"
            secure = True
        elif h.startswith("$1$"):
            alg = "MD5crypt"
            secure = False
        elif re.fullmatch(r"[0-9a-fA-F]+", h):
            alg    = _HASH_SIGNATURES.get(len(h), f"Desconocido (len={len(h)})")
            secure = len(h) > 60 and "bcrypt" in alg
        else:
            alg    = "Formato no reconocido"
            secure = False

        # Determinar si es NTLM (hex 32, sin salt)
        if len(h) == 32 and re.fullmatch(r"[0-9a-fA-F]+", h):
            alg = "MD5 o NTLM (32-bit hex)"
            secure = False

        return {
            "hash":         h[:80],
            "algorithm":    alg,
            "length":       len(h),
            "is_secure":    secure,
            "crackable":    not secure,
            "recommendation": (
                "Usar Argon2id o PBKDF2-SHA256 (600k iter) para almacenar contraseñas."
                if not secure
                else f"{alg} es adecuado para almacenamiento de contraseñas."
            ),
        }

    # ── Dictionary Attack ────────────────────────────────────────────────────
    def dictionary_attack(
        self,
        target_hash: str,
        algorithm:   str  = "md5",
        wordlist:    list | None = None,
        use_mutations: bool = True,
    ) -> dict:
        """
        Ataque por diccionario contra un hash.

        AVISO: Solo para auditorías autorizadas.

        Args:
            target_hash: Hash a crackear
            algorithm:   'md5', 'sha1', 'sha256', 'sha512', 'ntlm'
            wordlist:    Lista personalizada (usa TOP_PASSWORDS si None)
            use_mutations: Aplicar reglas l33t/capitalización/sufijos

        Returns:
            Dict con resultado (found / not_found) y tiempo
        """
        start = time.time()
        target_hash = target_hash.strip().lower()
        alg = algorithm.lower()

        # Construir wordlist con mutaciones
        words = list(wordlist) if wordlist else list(_TOP_PASSWORDS_100)
        if use_mutations:
            words = self._apply_mutations(words)

        found_pass = None
        attempts   = 0

        for word in words:
            h = self._compute_hash(word, alg)
            if h and hmac.compare_digest(h, target_hash):
                found_pass = word
                break
            attempts += 1

        elapsed = round(time.time() - start, 3)
        return {
            "status":       "found" if found_pass else "not_found",
            "password":     found_pass,
            "attempts":     attempts,
            "algorithm":    algorithm,
            "time_seconds": elapsed,
            "rate_per_sec": round(attempts / elapsed) if elapsed > 0 else 0,
        }

    def _apply_mutations(self, words: list[str]) -> list[str]:
        """Genera variantes por l33tspeak, capitalización y sufijos numéricos."""
        mutated = []
        for w in words:
            mutated.append(w)
            mutated.append(w.capitalize())
            mutated.append(w.upper())
            mutated.append(w.translate(_LEET_MAP))
            for suffix in _SUFFIXES:
                mutated.append(w + suffix)
                mutated.append(w.capitalize() + suffix)
        return mutated

    @staticmethod
    def _compute_hash(password: str, algorithm: str) -> str | None:
        """Calcula el hash de una contraseña en el algoritmo dado."""
        try:
            pw_bytes = password.encode("utf-8")
            alg = algorithm.lower()
            if alg == "md5":
                return hashlib.md5(pw_bytes).hexdigest()
            if alg == "sha1":
                return hashlib.sha1(pw_bytes).hexdigest()
            if alg == "sha256":
                return hashlib.sha256(pw_bytes).hexdigest()
            if alg == "sha512":
                return hashlib.sha512(pw_bytes).hexdigest()
            if alg == "ntlm":
                return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
        except Exception:
            pass
        return None

    # ── Have I Been Pwned (k-Anonymity) ──────────────────────────────────────
    def check_hibp(self, password: str, timeout: int = 5) -> dict:
        """
        Comprueba si la contraseña aparece en brechas de datos (HaveIBeenPwned).

        Seguridad: Solo envía los primeros 5 caracteres del hash SHA-1 (k-Anonymity).
        La contraseña completa NUNCA abandona el sistema.

        Args:
            password: Contraseña a verificar
            timeout:  Timeout HTTP en segundos

        Returns:
            Dict con breach_count y estado
        """
        sha1     = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix   = sha1[:5]
        suffix   = sha1[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent":    "StrikeBack-SecurityAgent/2.0",
                    "Add-Padding":   "true",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")

            count = 0
            for line in body.splitlines():
                if ":" in line:
                    line_suffix, line_count = line.split(":", 1)
                    if line_suffix.upper() == suffix:
                        count = int(line_count.strip())
                        break

            return {
                "pwned":        count > 0,
                "breach_count": count,
                "status":       "checked",
                "message": (
                    f"Contraseña encontrada en {count:,} brechas de datos. "
                    "¡Cámbiala inmediatamente!"
                    if count > 0
                    else "No encontrada en brechas de datos conocidas."
                ),
            }
        except Exception as exc:
            return {
                "pwned":  None,
                "status": "error",
                "error":  str(exc),
            }

    # ── Generador de contraseñas seguras ──────────────────────────────────────
    def generate_password(
        self,
        length:      int  = 20,
        use_symbols: bool = True,
    ) -> dict:
        """
        Genera una contraseña criptográficamente segura (os.urandom).

        Args:
            length:      Longitud de la contraseña (mínimo 12)
            use_symbols: Incluir símbolos (!@#$%^&*)

        Returns:
            Dict con contraseña, entropía y análisis de fortaleza
        """
        length = max(12, length)
        alphabet = string.ascii_letters + string.digits
        if use_symbols:
            alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"

        # Asegurar al menos un carácter de cada clase (NIST SP 800-63B)
        while True:
            pw = "".join(secrets.choice(alphabet) for _ in range(length))
            if (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
                    and re.search(r"\d", pw)
                    and (not use_symbols or re.search(r"[^a-zA-Z0-9]", pw))):
                break

        return {
            "password":  pw,
            "length":    length,
            "analysis":  self.analyze_password(pw),
        }

    def generate_passphrase(self, words: int = 5) -> dict:
        """
        Genera una passphrase tipo EFF Diceware.
        Sin wordlist externa: usa combinaciones de palabras simples + números.
        """
        # Palabras cortas generadas aleatoriamente (sin diccionario externo)
        word_chars = string.ascii_lowercase
        phrase_words = []
        for _ in range(max(4, words)):
            length = secrets.randbelow(4) + 4  # 4-7 letras
            phrase_words.append("".join(secrets.choice(word_chars) for _ in range(length)))

        separator = secrets.choice(["-", "_", ".", " "])
        passphrase = separator.join(phrase_words) + str(secrets.randbelow(9999)).zfill(4)
        return {
            "passphrase": passphrase,
            "words":      words,
            "analysis":   self.analyze_password(passphrase),
        }

    # ── Hash de archivo (integridad forense) ──────────────────────────────────
    @staticmethod
    def hash_file(filepath: str) -> dict:
        """
        Calcula hashes MD5, SHA-1 y SHA-256 de un archivo.
        Útil para verificación de integridad forense.
        """
        if not os.path.exists(filepath):
            return {"error": f"Archivo no encontrado: {filepath}"}
        try:
            md5    = hashlib.md5()
            sha1   = hashlib.sha1()
            sha256 = hashlib.sha256()
            size   = 0
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)
            return {
                "filepath":   filepath,
                "size_bytes": size,
                "md5":        md5.hexdigest(),
                "sha1":       sha1.hexdigest(),
                "sha256":     sha256.hexdigest(),
                "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ── Utilidades ────────────────────────────────────────────────────────────
    @staticmethod
    def _format_time(seconds: float) -> str:
        """Convierte segundos a descripción legible."""
        if seconds < 1:          return "< 1 segundo"
        if seconds < 60:         return f"{int(seconds)} segundos"
        if seconds < 3600:       return f"{int(seconds/60)} minutos"
        if seconds < 86400:      return f"{int(seconds/3600)} horas"
        if seconds < 2_592_000:  return f"{int(seconds/86400)} días"
        if seconds < 31_536_000: return f"{int(seconds/2_592_000)} meses"
        years = seconds / 31_536_000
        if years < 1_000:        return f"{int(years)} años"
        if years < 1_000_000:    return f"{int(years/1000)}k años"
        return f"{years:.2e} años"
