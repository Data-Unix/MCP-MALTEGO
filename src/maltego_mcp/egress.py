"""Punto único de salida HTTP/HTTPS y política de salida anónima (Parte B).

Control estricto de egress para Maltego MCP:
- Allowlist de hosts de proveedores autorizados con denegación por defecto.
- Lista negra de endpoints por método, host y ruta (escaneos activos, submits, etc.).
- Validación de Scope (Perímetro Intocable del caso).
- GuardedTransport con fallo cerrado (Kill-switch) y sin fugas DNS (socks5h).
- Anti DNS-rebinding sin TOCTOU (perfil direct): resolución única fuera del event loop, validación de IP pública y
  conexión a esa misma IP (PinnedDNSBackend). Con proxy (Tor/VPN) nunca se resuelve el destino en local.
- AuditLog JSONL encadenado criptográficamente por hash SHA-256 (hash incremental, sin precargar el cuerpo).
- Helper get_following() para redirecciones seguras validadas paso a paso.
- Guardia en tiempo de ejecución PEP 578 (sys.addaudithook).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sys
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpcore
import httpx

from maltego_mcp.config import Settings
from maltego_mcp.errors import EgressBlockedError, EgressKillSwitchError
from maltego_mcp.mullvad import MullvadGate, get_gate, is_mullvad_proxy_endpoint

logger = logging.getLogger("maltego_mcp.egress")

# ------------------------------------------------------------------------------------- ALLOWLIST
ALLOWED_PROVIDERS: frozenset[str] = frozenset(
    {
        # DNS pasivo / WHOIS / IP / AS / BGP / RDAP
        "dns.google",
        "cloudflare-dns.com",
        "rdap.org",
        "rdap-bootstrap.arin.net",
        "rdap.arin.net",
        "rdap.verisign.com",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
        "rdap.ripe.net",
        "rdap.db.ripe.net",
        "rdap.iana.org",
        "data.iana.org",
        "rdap.centralnic.com",
        "rdap.identitydigital.services",
        "rdap.publicinterestregistry.net",
        "rdap.nominet.uk",
        "api.mnemonic.no",
        "freeapi.robtex.com",
        "api.hackertarget.com",
        "stat.ripe.net",
        "www.peeringdb.com",
        "ip.thc.org",
        # Certificados CT
        "crt.sh",
        "api.certspotter.com",
        # Archivos y Crawlers web históricos y Boletines / Registros Oficiales
        "web.archive.org",
        "arquivo.pt",
        "index.commoncrawl.org",
        "boe.es",
        "www.boe.es",
        "openmercantil.es",
        "api.gleif.org",
        "ec.europa.eu",
        # CTI / Filtraciones / Reputación / CVEs / Contexto IP pasivo
        "otx.alienvault.com",
        "urlhaus-api.abuse.ch",
        "threatfox-api.abuse.ch",
        "mb-api.abuse.ch",
        "www.cisa.gov",
        "api.first.org",
        "api.ipapi.is",
        "api.ransomware.live",
        "ahmia.fi",
        "raw.githubusercontent.com",
        "api.github.com",
        "api.greynoise.io",
        "haveibeenpwned.com",
        "api.pwnedpasswords.com",
        "api.xposedornot.com",
        "cavalier.hudsonrock.com",
        "internetdb.shodan.io",
        "api.shodan.io",
        "search.censys.io",
        "api.censys.io",
        "api.hunter.io",
        "urlscan.io",
        "api.netlas.io",
        "leakix.net",
        "api.securitytrails.com",
        "api.chaos.projectdiscovery.io",
        "anubisdb.com",
        "www.virustotal.com",
        "virustotal.com",
        # Blockchain / Crypto forense
        "api.tatum.io",
        "mempool.space",
        # Identidades / Cuentas / Redes públicas
        "bsky.social",
        "bsky.app",
        "public.api.bsky.app",
        "api.mail.tm",
        "keybase.io",
        "gitlab.com",
        "github.com",
        "en.gravatar.com",
        "gravatar.com",
        "www.reddit.com",
        "hn.algolia.com",
        "hacker-news.firebaseio.com",
        "news.ycombinator.com",
        "lobste.rs",
        "dev.to",
        "t.me",
        # Verificación salida anónima (Parte B)
        "am.i.mullvad.net",
        "check.torproject.org",
        # Loopback / Local
        "127.0.0.1",
        "localhost",
    }
)

SPECIAL_TLDS: frozenset[str] = frozenset(
    {"onion", "local", "localhost", "test", "invalid", "example", "alt", "internal"}
)

HACKERTARGET_ALLOWED_TOOLS: frozenset[str] = frozenset({"hostsearch", "reverseiplookup"})

# (method, host, prefix)
BLACKLISTED_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # VirusTotal: bloqueado entero en modo pasivo; en modo activo jamás se permite POST ni /analyse (no intrusivo)
    ("POST", "www.virustotal.com", ""),
    ("POST", "virustotal.com", ""),
    ("*", "www.virustotal.com", "/analyse"),
    ("*", "virustotal.com", "/analyse"),
    ("*", "www.virustotal.com", ""),
    ("*", "virustotal.com", ""),
    # Shodan scan y DNS en vivo
    ("*", "api.shodan.io", "/shodan/scan"),
    ("*", "api.shodan.io", "/dns/resolve"),
    ("*", "api.shodan.io", "/dns/reverse"),
    # Censys Rescan
    ("*", "api.censys.io", "/v2/hosts/rescan"),
    ("*", "search.censys.io", "/v2/hosts/rescan"),
    # Netlas scan
    ("*", "api.netlas.io", "/api/scan"),
    # urlscan scan y live
    ("*", "urlscan.io", "/api/v1/scan"),
    ("*", "urlscan.io", "/livescan"),
    ("*", "urlscan.io", "/liveshot"),
    # OTX submit
    ("POST", "otx.alienvault.com", "/api/v1/indicators/submit"),
    # Internet Archive / Wayback / archive.today submits
    ("*", "web.archive.org", "/save"),
    ("*", "archive.today", "/submit"),
    ("*", "archive.today", "/run"),
    ("*", "archive.ph", "/submit"),
    ("*", "archive.is", "/submit"),
    # Anubis POST
    ("POST", "anubisdb.com", ""),
    # Hunter email verifier (live SMTP)
    ("*", "api.hunter.io", "/v2/email-verifier"),
    # Capturas/proxies vivos no pasivos
    ("*", "r.jina.ai", ""),
    ("*", "translate.goog", ""),
    # RIPEstat mediciones / dns en vivo
    ("*", "stat.ripe.net", "/data/dns-chain"),
    ("*", "stat.ripe.net", "/data/reverse-dns-ip"),
    ("*", "stat.ripe.net", "/data/reverse-dns-consistency"),
    ("*", "stat.ripe.net", "/data/zonemaster"),
)


# ------------------------------------------------------------------------------------- SCOPE
@dataclass(slots=True)
class Scope:
    """Perímetro Intocable del caso (objetivos protegidos que jamás se contactan directamente)."""

    case_id: str
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)

    def is_untouchable(self, host_or_ip: str) -> bool:
        norm = host_or_ip.strip().lower().rstrip(".")
        if not norm:
            return False
        if norm in self.domains:
            return True
        for d in self.domains:
            if norm.endswith("." + d):
                return True
        if norm in self.ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(norm)
            for net in self.networks:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
        return False


# ------------------------------------------------------------------------------------- ANTI-REBINDING (IP fijada)
def _norm_host(host: str) -> str:
    return host.strip().lower().rstrip(".").strip("[]")


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """IP enrutable en Internet: excluye privadas, loopback, link-local, reservadas, CGNAT, multicast..."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def resolve_and_validate(host: str, port: int, *, allow_private: bool = False) -> str:
    """Resuelve ``host`` UNA sola vez (en el executor, sin bloquear el event loop) y devuelve la IP a la que conectar.

    Todas las IPs devueltas deben ser públicas (anti DNS-rebinding), salvo loopback para ``localhost`` o hosts de
    confianza declarados en configuración (``allow_private``). Como se conecta exactamente a la IP devuelta, no hay
    una segunda resolución que un atacante pueda alterar (sin TOCTOU).
    """
    norm = _norm_host(host)
    try:
        literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(norm)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_loopback or allow_private or _is_public_ip(literal):
            return str(literal)
        raise EgressBlockedError(f"Petición bloqueada (REBIND_BLOCKED): IP no pública {literal}")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(norm, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EgressBlockedError(
            f"Petición bloqueada (DNS_FAIL): no se pudo resolver '{norm}' ({exc.__class__.__name__})"
        ) from None
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            ips.append(ipaddress.ip_address(raw))
        except ValueError:
            raise EgressBlockedError(f"Petición bloqueada (INVALID_IP): '{norm}' devolvió '{raw}'") from None
    if not ips:
        raise EgressBlockedError(f"Petición bloqueada (DNS_FAIL): '{norm}' no devolvió direcciones")
    for ip in ips:
        ok = ip.is_loopback if norm == "localhost" else (allow_private or _is_public_ip(ip))
        if not ok:
            raise EgressBlockedError(f"Petición bloqueada (REBIND_BLOCKED): '{norm}' resuelve a IP no pública {ip}")
    return str(next((ip for ip in ips if ip.version == 4), ips[0]))


class PinnedDNSBackend(httpcore.AsyncNetworkBackend):
    """Backend de red de httpcore que valida y FIJA la IP de cada conexión TCP directa.

    Solo se instala en el perfil ``direct``. Con proxy (Tor/VPN, ``socks5h``) el destino lo resuelve el proxy y no
    debe resolverse en local: hacerlo filtraría por DNS, fuera del túnel, qué proveedores se consultan.
    El TLS sigue verificándose contra el hostname original (SNI y certificado), no contra la IP.
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend, trusted_hosts: Iterable[str] = ()) -> None:
        self._inner = inner
        self._trusted = frozenset(n for n in (_norm_host(h) for h in trusted_hosts if h) if n)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        ip = await resolve_and_validate(host, port, allow_private=_norm_host(host) in self._trusted)
        return await self._inner.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[Any] | None = None
    ) -> httpcore.AsyncNetworkStream:
        raise EgressBlockedError("Petición bloqueada (UNIX_SOCKET_BLOCKED): el egreso no admite sockets UNIX")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _pin_dns(transport: httpx.AsyncHTTPTransport, trusted_hosts: Iterable[str]) -> bool:
    """Instala PinnedDNSBackend en el pool de httpx. Devuelve False si la estructura interna de httpx cambió
    (lo detecta tests/test_egress.py antes de que llegue a producción)."""
    pool = getattr(transport, "_pool", None)
    inner = getattr(pool, "_network_backend", None)
    if pool is None or not isinstance(inner, httpcore.AsyncNetworkBackend):
        logger.warning("No se pudo fijar la IP en el pool de httpx: anti-rebinding no disponible en este cliente.")
        return False
    pool._network_backend = PinnedDNSBackend(inner, trusted_hosts)
    return True


# ------------------------------------------------------------------------------------- POLICY
class EgressPolicy:
    """Política de control de salida pasiva."""

    def __init__(
        self,
        allowed_hosts: frozenset[str] = ALLOWED_PROVIDERS,
        extra_allowed_hosts: set[str] | None = None,
        allow_active: bool | None = None,
    ) -> None:
        self.allowed_hosts = allowed_hosts if extra_allowed_hosts is None else (allowed_hosts | extra_allowed_hosts)
        if allow_active is None:
            self.allow_active = (
                os.environ.get("MALTEGO_MCP_ALLOW_ACTIVE", "").strip() in ("1", "true", "yes")
                or os.environ.get("MALTEGO_MCP_MODE", "").strip().lower() == "active"
            )
        else:
            self.allow_active = allow_active

    def validate_request(
        self,
        method: str,
        url: httpx.URL | str,
        scope: Scope | None = None,
    ) -> tuple[bool, str]:
        parsed = httpx.URL(url)
        host = (parsed.host or "").lower().rstrip(".")
        scheme = (parsed.scheme or "").lower()
        method_up = method.upper().strip()

        # 1. Esquema permitido
        if scheme not in ("https", "http"):
            return False, f"SCHEME_NOT_ALLOWED: esquema '{scheme}' no soportado (solo https)"
        if scheme == "http" and host not in ("127.0.0.1", "localhost"):
            return False, f"INSECURE_HTTP_BLOCKED: solo se permite https hacia proveedores remotos ({host})"

        # 2. TLD especial
        parts = host.split(".")
        if len(parts) > 1 and parts[-1] in SPECIAL_TLDS and host not in ("localhost", "127.0.0.1"):
            return False, f"SPECIAL_TLD_BLOCKED: TLD de uso especial '{parts[-1]}' bloqueado en egress ({host})"

        # 3. IP literal externa (solo loopback permitido)
        try:
            ip_obj = ipaddress.ip_address(host)
            if not ip_obj.is_loopback:
                return (
                    False,
                    f"LITERAL_IP_BLOCKED: IPs literales directas bloqueadas ({host}); use el nombre del proveedor",
                )
        except ValueError:
            pass

        # 4. Perímetro intocable del caso
        if scope and scope.is_untouchable(host):
            return (
                False,
                f"PERIMETER_UNTOUCHABLE: '{host}' forma parte del Perímetro Intocable del caso {scope.case_id}",
            )

        # 5. Lista negra de endpoints y proveedores
        path = parsed.path
        for b_method, b_host, b_pattern in BLACKLISTED_PATTERNS:
            if (
                b_host in ("virustotal.com", "www.virustotal.com")
                and self.allow_active
                and b_method == "*"
                and not b_pattern
            ):
                continue
            if (b_method == "*" or b_method == method_up) and (b_host == host or not b_host):
                if b_pattern and b_pattern in path:
                    return (
                        False,
                        f"ENDPOINT_BLACKLISTED: endpoint '{path}' en '{host}' bloqueado por la lista negra pasiva",
                    )
                if not b_pattern:
                    return False, f"HOST_BLACKLISTED: proveedor '{host}' bloqueado por completo en modo pasivo"

        # 6. Allowlist de proveedores pasivos
        if host not in self.allowed_hosts:
            return False, f"HOST_NOT_ALLOWED: host '{host}' no autorizado en la allowlist pasiva de proveedores"

        # 7. Reglas específicas por proveedor (ej. HackerTarget)
        if host == "api.hackertarget.com":
            if method_up != "GET":
                return False, "HACKERTARGET_METHOD_BLOCKED: solo se permite GET en HackerTarget"
            query_str = (parsed.query or b"").decode("utf-8", "ignore")
            params = urllib.parse.parse_qs(query_str)
            tool_candidates = [p.lower().strip() for p in path.strip("/").split("/") if p]
            tool_candidates.extend(t.lower().strip() for t in params.get("tool", []))
            for tool_name in tool_candidates:
                if tool_name not in HACKERTARGET_ALLOWED_TOOLS:
                    return (
                        False,
                        f"HACKERTARGET_TOOL_BLOCKED: herramienta '{tool_name}' no permitida "
                        "(solo hostsearch/reverseiplookup)",
                    )

        # La política NO resuelve DNS: es síncrona y no conoce el perfil. El anti-rebinding se aplica al conectar
        # (PinnedDNSBackend, solo perfil direct), con una única resolución y la IP fijada.
        return True, "ALLOWED"


# ------------------------------------------------------------------------------------- AUDIT LOG & REDACTION
_SECRET_QUERY_SUBSTRINGS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "pass",
    "pwd",
    "auth",
    "sig",
    "cookie",
    "session",
    "jwt",
    "bearer",
    "cred",
)
_URL_IN_TEXT_RE = re.compile(r"(?:https?|socks5h?|socks4a?|wss?)://[^\s'\"<>)\]]+", re.IGNORECASE)
_SENSITIVE_ENV_TOKENS: tuple[str, ...] = ("KEY", "TOKEN", "SECRET", "PASSWORD", "COOKIE", "AUTH", "HASH")
_SENSITIVE_REDIRECT_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "x-apikey",
        "x-otx-api-key",
        "api-key",
        "apikey",
        "auth-key",
        "hibp-api-key",
        "key",
        "x-key",
        "private-token",
        "x-inbox-token",
    }
)


def ensure_private_file_permissions(path: Path) -> None:
    """Restringe permisos del fichero a 0o600 cuando el sistema operativo lo soporta."""
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, 0o600)


def mask_url_secrets(url: str | httpx.URL) -> str:
    """Enmascara credenciales userinfo (user:pass@host) y parámetros sensibles en query strings."""
    raw = str(url).strip()
    if not raw:
        return ""
    try:
        split = urllib.parse.urlsplit(raw)
    except ValueError:
        return "[URL_REDACTED]"

    netloc = split.netloc
    if "@" in netloc:
        host_part = netloc.rsplit("@", 1)[1]
        netloc = f"***:***@{host_part}"

    new_query = split.query
    if split.query:
        params = urllib.parse.parse_qsl(split.query, keep_blank_values=True)
        masked: list[tuple[str, str]] = []
        for k, v in params:
            k_lower = k.lower()
            if any(sub in k_lower for sub in _SECRET_QUERY_SUBSTRINGS):
                masked.append((k, "***"))
            else:
                masked.append((k, v))
        new_query = urllib.parse.urlencode(masked, safe="*")

    return urllib.parse.urlunsplit((split.scheme, netloc, split.path, new_query, split.fragment))


def redact_secrets(text: str, env: Mapping[str, str] | None = None) -> str:
    """Sanitiza URLs con credenciales/keys y purga cualquier valor secreto configurado en `env`."""
    if not text:
        return ""
    cleaned = _URL_IN_TEXT_RE.sub(lambda m: mask_url_secrets(m.group(0)), str(text))
    source_env = env if env is not None else os.environ
    for k, v in source_env.items():
        if not v:
            continue
        k_up = k.upper()
        if not any(tok in k_up for tok in _SENSITIVE_ENV_TOKENS):
            continue
        secret_val = v.strip()
        if len(secret_val) < 6:
            continue
        if secret_val in cleaned:
            cleaned = cleaned.replace(secret_val, "[REDACTED]")
        quoted = urllib.parse.quote(secret_val, safe="")
        if len(quoted) >= 6 and quoted in cleaned:
            cleaned = cleaned.replace(quoted, "[REDACTED]")
    return cleaned


class AuditLog:
    """Registro JSONL encadenado por hash SHA-256 para auditoría de tráfico saliente."""

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path
        self._lock = asyncio.Lock()
        self._last_hash = "0" * 64
        self._seq = 0
        if self.log_path and self.log_path.is_file():
            self._init_from_file()

    def _init_from_file(self) -> None:
        assert self.log_path is not None
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self._seq = entry.get("seq", self._seq)
                        self._last_hash = entry.get("record_hash", self._last_hash)
        except Exception as e:
            logger.warning("No se pudo leer log de auditoría existente: %s", e)

    async def record(
        self,
        case_id: str,
        decision: str,
        reason: str,
        method: str,
        url: str | httpx.URL,
        status_code: int | None = None,
        response_sha256: str = "",
        egress_profile: str = "direct",
    ) -> dict[str, Any]:
        async with self._lock:
            self._seq += 1
            now_utc = datetime.datetime.now(datetime.UTC).isoformat()
            parsed = httpx.URL(url)
            host = parsed.host or ""
            path = parsed.path or "/"
            url_masked = mask_url_secrets(url)
            safe_reason = redact_secrets(reason)

            entry_data = {
                "seq": self._seq,
                "prev_hash": self._last_hash,
                "timestamp_utc": now_utc,
                "case_id": case_id,
                "decision": decision,
                "reason": safe_reason,
                "method": method.upper(),
                "url_masked": url_masked,
                "host": host,
                "path": path,
                "status_code": status_code,
                "response_sha256": response_sha256,
                "egress_profile": egress_profile,
            }
            # Criptografía: hash del registro serializado canónicamente
            canonical_json = json.dumps(entry_data, sort_keys=True)
            record_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            entry_data["record_hash"] = record_hash
            self._last_hash = record_hash

            if self.log_path:
                try:
                    await asyncio.to_thread(self._append_entry, self.log_path, entry_data)
                except OSError as e:
                    logger.warning("Fallo escribiendo en AuditLog (%s): %s", self.log_path, e)

            return entry_data

    @staticmethod
    def _append_entry(log_path: Path, entry_data: dict[str, Any]) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_data) + "\n")
        ensure_private_file_permissions(log_path)

    @classmethod
    def verify_file(cls, path: Path) -> tuple[bool, str]:
        """Comprueba la integridad de la cadena de hashes de un AuditLog."""
        if not path.is_file():
            return False, f"El fichero no existe: {path}"
        last_hash = "0" * 64
        expected_seq = 1
        with open(path, encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                actual_hash = entry.pop("record_hash", "")
                if entry.get("seq") != expected_seq:
                    return (
                        False,
                        f"Secuencia rota en línea {idx}: esperado {expected_seq}, obtenido {entry.get('seq')}",
                    )
                if entry.get("prev_hash") != last_hash:
                    return (
                        False,
                        f"Hash previo roto en línea {idx}: esperado {last_hash}, obtenido {entry.get('prev_hash')}",
                    )
                canonical = json.dumps(entry, sort_keys=True)
                computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if computed != actual_hash:
                    return False, f"Firma inválida en línea {idx}: calculado {computed}, registrado {actual_hash}"
                last_hash = actual_hash
                expected_seq += 1
        return True, f"Cadena íntegra con {expected_seq - 1} registros verificados."


# ------------------------------------------------------------------------------------- GUARDED TRANSPORT
class _AuditedStream(httpx.AsyncByteStream):
    """Cuerpo de respuesta con SHA-256 incremental y registro de auditoría al cerrarse.

    Si el consumidor no lee el cuerpo entero (p. ej. aborta por un tope de tamaño) el hash queda vacío: nunca se
    registra un hash de un contenido que no se ha visto completo.
    """

    def __init__(self, inner: httpx.AsyncByteStream, on_close: Callable[[str], Awaitable[None]]) -> None:
        self._inner = inner
        self._on_close = on_close
        self._sha = hashlib.sha256()
        self._complete = False
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._inner:
            self._sha.update(chunk)
            yield chunk
        self._complete = True

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._inner.aclose()
        finally:
            await self._on_close(self._sha.hexdigest() if self._complete else "")


def _is_loopback_host(host: str) -> bool:
    h = _norm_host(host)
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


class _LoopbackRouter(httpx.AsyncBaseTransport):
    """Con el Anillo Mullvad: loopback (TRX local, Tor local) va directo y no sale de la máquina; el resto, por el
    proxy SOCKS interno del túnel."""

    def __init__(self, proxied: httpx.AsyncBaseTransport, local: httpx.AsyncBaseTransport) -> None:
        self.proxied = proxied
        self.local = local

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = self.local if _is_loopback_host(request.url.host) else self.proxied
        return await target.handle_async_request(request)

    async def aclose(self) -> None:
        await self.proxied.aclose()
        await self.local.aclose()


class GuardedTransport(httpx.AsyncBaseTransport):
    """Transporte httpx que valida cada salto contra EgressPolicy, Scope, compuerta Mullvad y Kill-Switch."""

    def __init__(
        self,
        underlying: httpx.AsyncBaseTransport,
        policy: EgressPolicy,
        audit_log: AuditLog | None = None,
        scope: Scope | None = None,
        profile: str = "direct",
        gate: MullvadGate | None = None,
        misconfigured: str = "",
    ) -> None:
        self._underlying = underlying
        self.policy = policy
        self.audit_log = audit_log
        self.scope = scope
        self.profile = profile
        self.gate = gate
        self.misconfigured = misconfigured

    async def _block(self, cid: str, request: httpx.Request, reason: str, profile: str) -> None:
        if self.audit_log:
            await self.audit_log.record(
                case_id=cid,
                decision="blocked",
                reason=reason,
                method=request.method,
                url=str(request.url),
                status_code=None,
                response_sha256="",
                egress_profile=profile,
            )

    async def aclose(self) -> None:
        await self._underlying.aclose()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        cid = self.scope.case_id if self.scope else "default"
        if self.misconfigured:
            await self._block(cid, request, f"KILL_SWITCH: {self.misconfigured}", self.profile)
            raise EgressKillSwitchError(f"Salida bloqueada: {self.misconfigured}")
        ok, reason = self.policy.validate_request(request.method, request.url, scope=self.scope)
        if not ok:
            masked_req_url = mask_url_secrets(request.url)
            if self.audit_log:
                await self.audit_log.record(
                    case_id=cid,
                    decision="blocked",
                    reason=reason,
                    method=request.method,
                    url=str(request.url),
                    status_code=None,
                    response_sha256="",
                    egress_profile=self.profile,
                )
            raise EgressBlockedError(f"Petición bloqueada ({reason}): {request.method} {masked_req_url}")

        # Anillo 2: compuerta fail-closed. Loopback no sale de la máquina y no necesita atestación.
        audit_profile = self.profile
        if self.gate is not None and not _is_loopback_host(request.url.host):
            try:
                att = await self.gate.ensure()
            except EgressKillSwitchError as exc:
                await self._block(cid, request, f"MULLVAD_GATE: {exc}", self.profile)
                raise
            audit_profile = f"{self.profile}:{att.exit_hostname}"  # auditoría veraz: relay de salida atestado

        try:
            response = await self._underlying.handle_async_request(request)
        except EgressBlockedError as exc:  # anti-rebinding al conectar (PinnedDNSBackend)
            await self._block(cid, request, str(exc), audit_profile)
            raise
        except (httpx.ProxyError, httpx.ConnectError, OSError) as exc:
            if self.profile in ("tor", "vpn", "mullvad"):
                if self.gate is not None:
                    self.gate.invalidate()  # el túnel falló: la próxima petición vuelve a atestar
                await self._block(
                    cid,
                    request,
                    f"KILL_SWITCH: fallo en túnel {self.profile} ({exc.__class__.__name__})",
                    audit_profile,
                )
                raise EgressKillSwitchError(
                    f"Fallo en túnel de salida {self.profile.upper()} ({request.url.host}): "
                    f"kill-switch activado, petición abortada para evitar exposición directa."
                ) from None
            raise

        audit_log = self.audit_log
        if audit_log is None:
            return response
        status = response.status_code
        profile = audit_profile

        async def _record(digest: str) -> None:
            await audit_log.record(
                case_id=cid,
                decision="allowed",
                reason="ALLOWED",
                method=request.method,
                url=str(request.url),
                status_code=status,
                response_sha256=digest,
                egress_profile=profile,
            )

        if not isinstance(response.stream, httpx.AsyncByteStream):  # pragma: no cover - transportes síncronos
            await _record("")
            return response
        # El cuerpo NO se precarga: se calcula el hash a medida que el consumidor lee (respeta los topes de tamaño
        # por streaming, p. ej. los 5 MB de transforms/client.py) y la auditoría se registra al cerrar la respuesta.
        return httpx.Response(
            status_code=status,
            headers=response.headers,
            stream=_AuditedStream(response.stream, _record),
            extensions=response.extensions,
            request=request,
        )


# ------------------------------------------------------------------------------------- SOCKS AUTH INJECTION
def inject_socks_auth(proxy_url: str, username: str, password: str = "tor_mcp") -> str:
    """Inyecta credenciales en una URL SOCKS5h para aislar circuitos Tor (IsolateSOCKSAuth)."""
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = parsed.scheme or "socks5h"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 9050
    user_enc = urllib.parse.quote(username)
    pass_enc = urllib.parse.quote(password)
    return f"{scheme}://{user_enc}:{pass_enc}@{host}:{port}"


# ------------------------------------------------------------------------------------- FACTORY CLIENT
DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"


def get_user_agent(env: dict[str, str] | None = None) -> str:
    """User-Agent neutro configurado o Firefox 128 neutral por defecto."""
    e = os.environ if env is None else env
    custom = e.get("MALTEGO_MCP_USER_AGENT", "").strip()
    if custom:
        return custom
    return DEFAULT_USER_AGENT


def create_mullvad_probe_client(
    socks_url: str,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Cliente de atestación del Anillo 2: SOLO por el proxy SOCKS interno de Mullvad (no existe fuera del túnel,
    así que nunca puede salir directo), sin redirecciones ni variables de entorno de proxy. Lo usa ``mullvad.py``
    para am.i.mullvad.net y la lista viva de relays; no pasa por la compuerta (es quien la abre)."""
    parsed = urllib.parse.urlsplit(socks_url)
    if transport is None and not is_mullvad_proxy_endpoint(parsed.hostname or "", parsed.port or 0):
        raise EgressKillSwitchError("El cliente de atestación solo puede usar el proxy interno de Mullvad.")
    if transport is not None:
        return httpx.AsyncClient(transport=transport, timeout=timeout, trust_env=False, follow_redirects=False)
    return httpx.AsyncClient(
        proxy=socks_url,
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        headers={"User-Agent": get_user_agent()},
    )


def _mullvad_proxy_for(s: Settings, provider: str) -> str:
    """Proxy SOCKS del Anillo 2. Con aislamiento por proveedor (M5) cada proveedor sale por un relay PROPIO fijo
    (determinista), a través de su SOCKS interno (10.124.x.x, solo alcanzable dentro del túnel)."""
    base = s.mullvad_socks or "socks5h://10.64.0.1:1080"
    if s.mullvad_isolation != "per_provider" or not provider:
        return base
    relays = [r for r in get_gate(s.home, base, s.mullvad_attest_ttl).registry.all() if r.socks_name]
    if not relays:
        return base
    idx = int.from_bytes(hashlib.sha256(provider.encode("utf-8")).digest()[:4], "big") % len(relays)
    return f"socks5h://{relays[idx].socks_name}:1080"


def create_egress_client(
    settings: Settings | None = None,
    scope: Scope | None = None,
    audit_log: AuditLog | None = None,
    timeout: float = 20.0,
    transport: httpx.AsyncBaseTransport | None = None,
    headers: dict[str, str] | None = None,
    provider: str = "",
    extra_allowed_hosts: set[str] | None = None,
    allow_active: bool | None = None,
) -> httpx.AsyncClient:
    """Factoría central única para todos los clientes HTTP salientes del MCP."""
    s = settings or Settings.from_env()
    profile = s.egress.lower() if hasattr(s, "egress") else "direct"
    proxy_url = ""
    misconfigured = ""

    # Mapeo por proveedor
    if s.egress_per_provider and provider:
        mapping = dict(p.split("=", 1) for p in s.egress_per_provider.split(",") if "=" in p)
        if provider in mapping:
            profile = mapping[provider].strip().lower()

    if s.require_mullvad and profile not in ("mullvad", "tor"):
        profile = "mullvad"  # nunca se rebaja el Anillo 2 (defensa en profundidad además de config.py)

    if profile == "vpn":
        if s.egress_proxy:
            proxy_url = s.egress_proxy
        else:
            # T1: antes caía a salida directa en silencio (fail-open). Ahora bloquea.
            misconfigured = "perfil 'vpn' sin MALTEGO_MCP_EGRESS_PROXY (se bloquea en vez de salir directo)"
    elif profile == "mullvad":
        proxy_url = _mullvad_proxy_for(s, provider)
    elif profile == "tor":
        base_tor = s.tor_socks or "socks5h://127.0.0.1:9050"
        rot = s.tor_rotation.lower()
        if rot == "per_provider" and provider:
            proxy_url = inject_socks_auth(base_tor, f"prov_{provider}", "tor_mcp")
        elif rot == "per_request":
            proxy_url = inject_socks_auth(base_tor, f"req_{secrets.token_hex(4)}", "tor_mcp")
        else:
            proxy_url = base_tor

    # Hosts declarados en configuración (servidores TRX propios, proxy) -> allowlist dinámica del guardián PEP 578.
    trusted = set(extra_allowed_hosts or ())
    if trusted:
        register_egress_hosts(trusted)
    if proxy_url:
        proxy_host = urllib.parse.urlsplit(proxy_url).hostname
        if proxy_host:
            register_egress_hosts([proxy_host])

    base_transport = transport
    if base_transport is None:
        if proxy_url and profile == "mullvad":
            local = httpx.AsyncHTTPTransport()
            _pin_dns(local, trusted)
            base_transport = _LoopbackRouter(httpx.AsyncHTTPTransport(proxy=proxy_url), local)
        elif proxy_url:
            # Con proxy (Tor/VPN) el destino lo resuelve el proxy: nada de resolución local (sin fugas DNS).
            base_transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        else:
            direct = httpx.AsyncHTTPTransport()
            _pin_dns(direct, trusted)  # anti-rebinding: resolución única + IP fijada
            base_transport = direct

    active_flag = allow_active if allow_active is not None else (s.mode == "active")
    policy = EgressPolicy(extra_allowed_hosts=extra_allowed_hosts, allow_active=active_flag)
    gate = (
        get_gate(s.home, s.mullvad_socks, s.mullvad_attest_ttl, remote_check=s.mullvad_remote_check)
        if s.require_mullvad or profile == "mullvad"
        else None
    )
    guarded = GuardedTransport(
        underlying=base_transport,
        policy=policy,
        audit_log=audit_log,
        scope=scope,
        profile=profile,
        gate=gate,
        misconfigured=misconfigured,
    )

    req_headers = {"User-Agent": get_user_agent()}
    if headers:
        req_headers.update(headers)

    return httpx.AsyncClient(
        transport=guarded,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers=req_headers,
    )


# ------------------------------------------------------------------------------------- GET FOLLOWING
async def get_following(
    client: httpx.AsyncClient,
    url: str,
    max_redirects: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    """Ejecuta una petición GET siguiendo redirecciones manualmente con validación por salto."""
    current_url = url
    visited: set[str] = {current_url}
    call_kwargs = dict(kwargs)

    for hop in range(max_redirects + 1):
        if hop > 0:
            call_kwargs.pop("params", None)
        resp = await client.get(current_url, **call_kwargs)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            if not loc:
                return resp
            next_url = urllib.parse.urljoin(current_url, loc)
            if next_url in visited:
                raise EgressBlockedError(f"Bucle de redirección detectado: {mask_url_secrets(next_url)}")
            cur_host = (urllib.parse.urlsplit(current_url).hostname or "").lower()
            nxt_host = (urllib.parse.urlsplit(next_url).hostname or "").lower()
            if nxt_host != cur_host:
                call_kwargs.pop("auth", None)
                raw_hdrs = call_kwargs.get("headers")
                if isinstance(raw_hdrs, Mapping):
                    call_kwargs["headers"] = {
                        hk: hv for hk, hv in raw_hdrs.items() if hk.lower() not in _SENSITIVE_REDIRECT_HEADERS
                    }
            visited.add(next_url)
            current_url = next_url
            continue
        return resp
    raise EgressBlockedError(
        f"Excedido el límite máximo de redirecciones ({max_redirects}) hacia {mask_url_secrets(current_url)}"
    )


# ------------------------------------------------------------------------------------- TUNNEL HEALTH
async def check_egress_tunnel(
    profile: str,
    proxy_url: str = "",
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Verifica la conectividad real del túnel de salida anónima (Parte B)."""
    prof = profile.lower().strip()
    if prof == "direct":
        return {"ok": True, "profile": "direct", "message": "Salida directa sin proxy"}

    if prof == "mullvad":
        # Atestación doble del Anillo 2 (daemon + am.i por el proxy interno del túnel), sin cachés.
        att = await get_gate().attest(force=True)
        return {"ok": att.ok, "profile": prof, "code": att.code, "reason": att.reason, "exit": att.exit_hostname}
    if prof == "vpn":
        target, field_name = "https://am.i.mullvad.net/json", "mullvad_exit_ip"
    elif prof == "tor":
        target, field_name = "https://check.torproject.org/api/ip", "IsTor"
    else:
        return {"ok": False, "profile": prof, "error": f"Perfil de salida desconocido: {prof}"}
    if not proxy_url and client is None:
        # T2: antes se comprobaba con el cliente por defecto (salida directa) y se daba por bueno cualquier 200.
        return {
            "ok": False,
            "profile": prof,
            "error": f"Perfil '{prof}' sin proxy configurado: no hay túnel que verificar",
        }

    cl = client or httpx.AsyncClient(proxy=proxy_url, timeout=10.0, trust_env=False, follow_redirects=False)
    try:
        async with cl:
            resp = await cl.get(target)
            if resp.status_code != 200:
                return {"ok": False, "profile": prof, "status_code": resp.status_code}
            data = resp.json()
            verified = isinstance(data, dict) and data.get(field_name) is True
            return {"ok": verified, "profile": prof, "verified_field": field_name}
    except Exception as exc:
        return {"ok": False, "profile": prof, "error": redact_secrets(str(exc))}


# ------------------------------------------------------------------------------------- TOR NEWNYM
def rotate_tor_circuit_newnym(
    control_host: str = "127.0.0.1",
    control_port: int = 9051,
    password: str = "",
    timeout: float = 5.0,
) -> tuple[bool, str]:
    """Solicita un nuevo circuito a Tor enviando SIGNAL NEWNYM por el puerto de control TCP."""
    try:
        with socket.create_connection((control_host, control_port), timeout=timeout) as s:
            f = s.makefile("rw", encoding="utf-8")
            # 1. Autenticación
            if password:
                f.write(f'AUTHENTICATE "{password}"\r\n')
            else:
                f.write("AUTHENTICATE\r\n")
            f.flush()
            auth_resp = f.readline().strip()
            if not auth_resp.startswith("250"):
                return False, f"Autenticación en puerto de control Tor rechazada: {auth_resp}"

            # 2. Señal NEWNYM
            f.write("SIGNAL NEWNYM\r\n")
            f.flush()
            sig_resp = f.readline().strip()
            if not sig_resp.startswith("250"):
                return False, f"Fallo al enviar SIGNAL NEWNYM a Tor: {sig_resp}"
            return True, "Circuito Tor rotado con éxito (SIGNAL NEWNYM aceptado)."
    except OSError as exc:
        return False, f"Puerto de control Tor inaccesible ({control_host}:{control_port}): {exc}"


# ------------------------------------------------------------------------------------- PEP 578 GUARD
_PEP578_INSTALLED = False
_PEP578_STRICT = False
# Hosts de confianza declarados en configuración (servidores TRX propios, endpoint Gremlin, proxy de salida).
_RUNTIME_DNS_ALLOWED: set[str] = set()
# IPs con conexión directa autorizada en modo estricto (endpoint Gremlin: depende del Anillo 1, ver docs/USO.md).
_RUNTIME_CONNECT_ALLOWED: set[str] = set()


def register_direct_endpoint(host: str, port: int = 443) -> None:
    """Autoriza la conexión directa (modo estricto) a un endpoint propio declarado en configuración, p. ej. Gremlin.
    Resuelve el host una vez (la consulta DNS va por el túnel con el Anillo 1) y registra sus IPs."""
    register_egress_hosts([host])
    with contextlib.suppress(OSError):
        for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
            _RUNTIME_CONNECT_ALLOWED.add(str(info[4][0]).split("%", 1)[0])


def connect_allowed(addr: object) -> bool:
    """Decisión del guardián estricto para ``socket.connect``: loopback, proxies SOCKS internos de Mullvad y
    endpoints directos registrados. Todo lo demás saldría por fuera del proxy del Anillo 2."""
    if not isinstance(addr, tuple) or len(addr) < 2:
        return True  # AF_UNIX y similares: locales
    host, port = str(addr[0]).split("%", 1)[0], addr[1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified:
        return True
    if isinstance(port, int) and is_mullvad_proxy_endpoint(str(ip), port):
        return True
    return str(ip) in _RUNTIME_CONNECT_ALLOWED


def register_egress_hosts(hosts: Iterable[str]) -> None:
    """Añade hosts declarados en configuración a la allowlist dinámica del guardián PEP 578."""
    _RUNTIME_DNS_ALLOWED.update(n for n in (_norm_host(h) for h in hosts if h) if n)


def dns_lookup_allowed(host: object, allowed_hosts: frozenset[str] = ALLOWED_PROVIDERS) -> bool:
    """Decisión del guardián para una resolución DNS.

    Se permite: literales IP (no generan consulta DNS; los usa la conexión con IP fijada), ``localhost``, vacío
    (``bind``), proveedores de la allowlist y hosts registrados con ``register_egress_hosts``.
    """
    text = host.decode("utf-8", "ignore") if isinstance(host, bytes) else ("" if host is None else str(host))
    norm = _norm_host(text).split("%", 1)[0]
    if not norm or norm == "localhost":
        return True
    try:
        ipaddress.ip_address(norm)
        return True
    except ValueError:
        pass
    return norm in allowed_hosts or norm in _RUNTIME_DNS_ALLOWED


def install_egress_audit_hook(
    allowed_hosts: frozenset[str] = ALLOWED_PROVIDERS,
    enabled: bool = True,
    strict_connect: bool = False,
) -> None:
    """Instala la guardia PEP 578 (sys.addaudithook). Es global e irreversible en el proceso: se instala solo desde
    el punto de entrada (`server.main`), nunca al construir el servidor (tests, embebidos).
    Desactivable con MALTEGO_MCP_DISABLE_PEP578=1."""
    global _PEP578_INSTALLED, _PEP578_STRICT
    if not enabled or _PEP578_INSTALLED:
        return
    if os.environ.get("MALTEGO_MCP_DISABLE_PEP578", "").strip() in ("1", "true", "yes"):
        return

    def audit_hook(event: str, args: tuple[Any, ...]) -> None:
        if event in ("socket.getaddrinfo", "socket.gethostbyname"):
            if args and not dns_lookup_allowed(args[0], allowed_hosts):
                raise PermissionError(f"PEP 578 Egress Guard: resolución DNS no autorizada hacia '{args[0]!s}'")
        elif event == "socket.connect" and args and len(args) >= 2:
            sock, addr = args[0], args[1]
            if strict_connect and not connect_allowed(addr):
                raise PermissionError(
                    f"PEP 578 Egress Guard (Anillo Mullvad): conexión directa no autorizada hacia {addr!r}"
                )
            if (
                isinstance(sock, socket.socket)
                and sock.type == socket.SOCK_DGRAM
                and isinstance(addr, tuple)
                and len(addr) >= 2
                and addr[1] == 53
            ):
                raise PermissionError("PEP 578 Egress Guard: tráfico directo UDP/53 (DNS) bloqueado")

    sys.addaudithook(audit_hook)
    _PEP578_INSTALLED = True
    _PEP578_STRICT = strict_connect


def is_egress_audit_hook_installed() -> bool:
    """Indica si el hook de auditoría PEP 578 está activo en el proceso."""
    return _PEP578_INSTALLED
