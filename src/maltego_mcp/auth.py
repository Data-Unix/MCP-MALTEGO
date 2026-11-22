"""Autenticación local, derivación PBKDF2-HMAC-SHA256 y control de sesión para el panel web.

Diseño de seguridad:
- Sin dependencias externas: usa `hashlib.pbkdf2_hmac`, `hmac.compare_digest` y `secrets` de la librería estándar.
- Verificación en tiempo constante tanto de usuario como de contraseña (hash señuelo para usuarios inexistentes).
- Derivación PBKDF2 ejecutada en hilo (`asyncio.to_thread`) para no bloquear el bucle de eventos ni SSE.
- Sesiones en memoria volátil con tokens CSPRNG de 256 bits (`HttpOnly; SameSite=Strict`) y token CSRF dedicado.
- Limitador por ventana deslizante (5 fallos / 60 s -> HTTP 429 con `Retry-After`).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from maltego_mcp.config import Settings
from maltego_mcp.egress import ensure_private_file_permissions

logger = logging.getLogger("maltego_mcp.auth")

DEFAULT_ADMIN_USER = "admin"
ADMIN_ROLES: tuple[str, ...] = (
    "SUPERADMIN",
    "CTI_LEAD",
    "OSINT_ANALYST",
    "HUMINT_OPERATOR",
    "FORENSIC_PROFILER",
    "AML_INVESTIGATOR",
    "AUDITOR",
)
PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
SESSION_COOKIE_NAME = "maltego_session"
CSRF_HEADER_NAME = "x-csrf-token"
AUTH_STATE_FILE = "dashboard_auth.json"
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_ACTIVE_SESSIONS = 64
REAUTH_WINDOW_SECONDS = 300.0  # acciones que reducen la protección: contraseña confirmada hace < 5 min
MAX_TRACKED_CLIENTS = 1024

_DECOY_SALT = b"maltego-mcp-decoy-salt-v1-static"
_DECOY_DK = hashlib.pbkdf2_hmac("sha256", b"decoy-password-not-valid", _DECOY_SALT, MIN_PBKDF2_ITERATIONS, dklen=32)


def hash_password_pbkdf2(
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Genera un hash con sal `pbkdf2_sha256$<iteraciones>$<salt_hex>$<dk_hex>`."""
    iters = max(MIN_PBKDF2_ITERATIONS, int(iterations))
    raw_salt = salt if salt is not None else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, iters, dklen=32)
    return f"pbkdf2_sha256${iters}${raw_salt.hex()}${dk.hex()}"


def verify_password_pbkdf2(password: str, encoded_hash: str) -> bool:
    """Verifica una contraseña frente a un hash PBKDF2-HMAC-SHA256 en tiempo constante."""
    parts = encoded_hash.strip().split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        candidate_decoy = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _DECOY_SALT, MIN_PBKDF2_ITERATIONS, dklen=32
        )
        hmac.compare_digest(candidate_decoy, _DECOY_DK)
        return False

    try:
        iters = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_dk = bytes.fromhex(parts[3])
    except ValueError:
        candidate_decoy = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _DECOY_SALT, MIN_PBKDF2_ITERATIONS, dklen=32
        )
        hmac.compare_digest(candidate_decoy, _DECOY_DK)
        return False

    if iters < MIN_PBKDF2_ITERATIONS or len(salt) < 8 or len(expected_dk) < 16:
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(expected_dk))
    return hmac.compare_digest(candidate, expected_dk)


@dataclass(frozen=True, slots=True)
class AuthSession:
    session_id: str
    username: str
    roles: tuple[str, ...]
    csrf_token: str
    created_at: float
    expires_at: float

    def to_public_dict(self) -> dict[str, object]:
        now = time.time()
        return {
            "authenticated": True,
            "auth_required": True,
            "username": self.username,
            "roles": list(self.roles),
            "csrf_token": self.csrf_token,
            "expires_at": int(self.expires_at),
            "ttl_seconds": max(0, int(self.expires_at - now)),
            "kdf": f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} iter.)".replace(",", "."),
        }


@dataclass(frozen=True, slots=True)
class LoginResult:
    ok: bool
    status_code: int
    error: str = ""
    remaining_attempts: int = MAX_FAILED_ATTEMPTS
    retry_after: int = 0
    session: AuthSession | None = None


class DashboardAuthManager:
    """Gestor de autenticación de operador único con todos los roles y sesiones revocables."""

    def __init__(
        self,
        settings: Settings,
        *,
        max_attempts: int = MAX_FAILED_ATTEMPTS,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self.enabled: bool = bool(settings.dashboard_auth)
        self.username: str = (settings.dashboard_user or DEFAULT_ADMIN_USER).strip() or DEFAULT_ADMIN_USER
        self.roles: tuple[str, ...] = ADMIN_ROLES
        self.session_ttl: int = max(300, int(settings.dashboard_session_ttl or 28800))
        self.max_attempts: int = max(1, max_attempts)
        self.window_seconds: float = max(5.0, window_seconds)
        self._sessions: dict[str, AuthSession] = {}
        self._failures: dict[str, list[float]] = {}
        self._reauth_at: dict[str, float] = {}
        self.password_hash: str = self._resolve_password_hash(settings)
        iters = self._extract_iterations(self.password_hash)
        self._decoy_hash: str = hash_password_pbkdf2(secrets.token_urlsafe(24), iterations=iters)

    @staticmethod
    def _extract_iterations(encoded_hash: str) -> int:
        parts = encoded_hash.split("$")
        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            try:
                return max(MIN_PBKDF2_ITERATIONS, int(parts[1]))
            except ValueError:
                pass
        return PBKDF2_ITERATIONS

    def _resolve_password_hash(self, settings: Settings) -> str:
        configured = settings.dashboard_password_hash.strip()
        if configured.startswith("pbkdf2_sha256$"):
            return configured

        state_path: Path = settings.home / AUTH_STATE_FILE
        if state_path.is_file():
            try:
                data = json.loads(state_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    stored = str(data.get("password_hash") or "").strip()
                    if stored.startswith("pbkdf2_sha256$"):
                        ensure_private_file_permissions(state_path)
                        return stored
            except (OSError, ValueError):
                pass

        # Inicialización segura sin contraseña por defecto predecible cuando no hay hash en .env
        generated_hash = hash_password_pbkdf2(secrets.token_urlsafe(24), iterations=MIN_PBKDF2_ITERATIONS)
        if self.enabled:
            try:
                settings.home.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps(
                        {
                            "username": self.username,
                            "password_hash": generated_hash,
                            "note": "Define MALTEGO_MCP_DASHBOARD_PASSWORD_HASH en ~/.maltego-mcp/.env",
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                ensure_private_file_permissions(state_path)
            except OSError:
                pass
        return generated_hash

    def _prune_sessions(self, now: float) -> None:
        expired = [sid for sid, sess in self._sessions.items() if now >= sess.expires_at]
        for sid in expired:
            self._sessions.pop(sid, None)
        while len(self._sessions) >= MAX_ACTIVE_SESSIONS:
            oldest_sid = next(iter(self._sessions))
            self._sessions.pop(oldest_sid, None)

    def _prune_failures(self, client_key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        recent = [ts for ts in self._failures.get(client_key, []) if ts > cutoff]
        if recent:
            self._failures[client_key] = recent
        else:
            self._failures.pop(client_key, None)
        while len(self._failures) > MAX_TRACKED_CLIENTS:
            oldest_client = next(iter(self._failures))
            if oldest_client == client_key:
                break
            self._failures.pop(oldest_client, None)
        return recent

    def check_rate_limit(self, client_key: str) -> tuple[bool, int]:
        """Devuelve `(bloqueado, retry_after_seconds)` sin consumir intento."""
        now = time.monotonic()
        recent = self._prune_failures(client_key, now)
        if len(recent) >= self.max_attempts:
            retry_after = max(1, math.ceil(self.window_seconds - (now - recent[0])))
            return True, retry_after
        return False, 0

    def _verify_credentials_sync(self, username: str, password: str) -> bool:
        user_bytes = username.strip().encode("utf-8")
        expected_bytes = self.username.encode("utf-8")
        user_ok = hmac.compare_digest(user_bytes, expected_bytes)
        target_hash = self.password_hash if user_ok else self._decoy_hash
        pass_ok = verify_password_pbkdf2(password, target_hash)
        return bool(user_ok and pass_ok)

    async def authenticate(self, username: str, password: str, client_ip: str = "127.0.0.1") -> LoginResult:
        """Autentica al operador de forma asíncrona con limitación de intentos y tiempo constante."""
        client_key = (client_ip or "local").strip()[:80]
        blocked, retry_after = self.check_rate_limit(client_key)
        if blocked:
            return LoginResult(
                ok=False,
                status_code=429,
                error=f"Demasiados intentos fallidos. Reintenta en {retry_after} s.",
                remaining_attempts=0,
                retry_after=retry_after,
            )

        if not password or len(password) > 256 or len(username) > 128:
            # Ejecuta igualmente verificación señuelo para mantener tiempo constante
            await asyncio.to_thread(verify_password_pbkdf2, "invalid", self._decoy_hash)
            valid = False
        else:
            valid = await asyncio.to_thread(self._verify_credentials_sync, username, password)

        now_mono = time.monotonic()
        if not valid:
            recent = self._prune_failures(client_key, now_mono)
            recent.append(now_mono)
            self._failures[client_key] = recent
            remaining = max(0, self.max_attempts - len(recent))
            logger.warning(
                "Intento de acceso fallido al panel desde %s (restantes antes de bloqueo: %d)",
                client_key,
                remaining,
            )
            return LoginResult(
                ok=False,
                status_code=401,
                error="Credenciales inválidas.",
                remaining_attempts=remaining,
                retry_after=0,
            )

        self._failures.pop(client_key, None)
        now_wall = time.time()
        self._prune_sessions(now_wall)
        session = AuthSession(
            session_id=secrets.token_urlsafe(32),
            username=self.username,
            roles=self.roles,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now_wall,
            expires_at=now_wall + self.session_ttl,
        )
        self._sessions[session.session_id] = session
        logger.info("Sesión iniciada en el panel para '%s' desde %s", self.username, client_key)
        return LoginResult(ok=True, status_code=200, session=session)

    def get_valid_session(self, cookie_value: str) -> AuthSession | None:
        token = (cookie_value or "").strip()
        if not token:
            return None
        sess = self._sessions.get(token)
        if sess is None:
            return None
        if time.time() >= sess.expires_at:
            self._sessions.pop(token, None)
            return None
        return sess

    @staticmethod
    def verify_csrf(session: AuthSession, provided_token: str) -> bool:
        clean = (provided_token or "").strip()
        if not clean:
            return False
        return hmac.compare_digest(session.csrf_token, clean)

    def revoke_session(self, cookie_value: str) -> bool:
        token = (cookie_value or "").strip()
        if not token:
            return False
        self._reauth_at.pop(token, None)
        return self._sessions.pop(token, None) is not None

    def has_recent_reauth(self, session: AuthSession, max_age: float = REAUTH_WINDOW_SECONDS) -> bool:
        """¿Confirmó el operador su contraseña en esta sesión hace menos de ``max_age`` segundos?"""
        ts = self._reauth_at.get(session.session_id)
        return ts is not None and (time.monotonic() - ts) < max_age

    async def reauthenticate(self, session: AuthSession, password: str, client_ip: str = "127.0.0.1") -> LoginResult:
        """Reautenticación para acciones que reducen la protección (desconectar la VPN, cambiar de relay).
        Comparte la limitación de intentos con el login y es de tiempo constante."""
        client_key = (client_ip or "local").strip()[:80]
        blocked, retry_after = self.check_rate_limit(client_key)
        if blocked:
            return LoginResult(
                ok=False,
                status_code=429,
                error=f"Demasiados intentos fallidos. Reintenta en {retry_after} s.",
                remaining_attempts=0,
                retry_after=retry_after,
            )
        if not password or len(password) > 256:
            await asyncio.to_thread(verify_password_pbkdf2, "invalid", self._decoy_hash)
            valid = False
        else:
            valid = await asyncio.to_thread(self._verify_credentials_sync, session.username, password)
        now_mono = time.monotonic()
        if not valid:
            recent = self._prune_failures(client_key, now_mono)
            recent.append(now_mono)
            self._failures[client_key] = recent
            remaining = max(0, self.max_attempts - len(recent))
            logger.warning("Reautenticación fallida en el panel desde %s (restantes: %d)", client_key, remaining)
            return LoginResult(ok=False, status_code=401, error="Contraseña incorrecta.", remaining_attempts=remaining)
        self._failures.pop(client_key, None)
        self._reauth_at[session.session_id] = now_mono
        return LoginResult(ok=True, status_code=200, session=session)
