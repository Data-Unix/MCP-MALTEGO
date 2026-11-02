"""Gestor de cuentas de redes sociales, sesiones y *Sock Puppets* (`~/.maltego-mcp/accounts.toml` + `.env`).

Reglas OPSEC y de seguridad:
- Las credenciales (tokens, cookies, claves) NUNCA entran en el grafo, ni en `.mtgx`, ni en logs.
- Soporta múltiples cuentas por plataforma con rotación *round-robin* y *cooldown* automático ante HTTP 429/403.
- Incluye un generador local (offline) de identidades operativas (*Sock Puppet Persona Kit*) para investigaciones
  en redes sociales, foros técnicos y entornos `.onion` descubiertos en el grafo.
"""

from __future__ import annotations

import hashlib
import os
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ACCOUNTS_FILE = "accounts.toml"

PLATFORM_ENV_VARS: dict[str, tuple[str, ...]] = {
    "github": ("GITHUB_TOKEN",),
    "gitlab": ("GITLAB_TOKEN",),
    "reddit": ("REDDIT_TOKEN", "REDDIT_SESSION", "REDDIT_SESSION_COOKIE"),
    "telegram": ("TELEGRAM_BOT_TOKEN",),
    "discord": ("DISCORD_BOT_TOKEN",),
    "mastodon": ("MASTODON_TOKEN",),
    "bluesky": ("BLUESKY_TOKEN",),
    "intelx": ("INTELX_API_KEY",),
    "tor": ("TOR_SOCKS_PROXY",),
    "onion": ("TOR_SOCKS_PROXY",),
}

ROLE_TEMPLATES: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "cyber_researcher": (
        "Alex Vance",
        "Independent security researcher focusing on malware analysis, reverse engineering & threat telemetry.",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("reverse-engineering", "threat-intel", "yara", "linux", "rust"),
    ),
    "security_researcher": (
        "Alex Vance",
        "Independent security researcher focusing on malware analysis, reverse engineering & threat telemetry.",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("reverse-engineering", "threat-intel", "yara", "linux", "rust"),
    ),
    "threat_intel_collector": (
        "Erik Lindqvist",
        "Cyber threat intelligence specialist tracking ransomware groups, infostealers and access brokers.",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("cti", "ransomware", "infostealers", "darkweb", "malware"),
    ),
    "underground_auditor": (
        "Marco Rossi",
        "Infosec contractor & red-team operator. Auditing network perimeters, dump integrity and OPSEC.",
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("opsec", "tor", "monero", "pgp", "netsec"),
    ),
    "devops_freelancer": (
        "Liam Cooper",
        "Cloud infrastructure consultant & SRE. Kubernetes, Terraform, CI/CD pipelines and Linux hardening.",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
        ("kubernetes", "terraform", "golang", "docker", "devops"),
    ),
    "crypto_analyst": (
        "Sora Tanaka",
        "On-chain liquidity tracker, DeFi auditor and privacy protocol enthusiast.",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("bitcoin", "monero", "defi", "zkp", "onchain"),
    ),
    "osint_journalist": (
        "Clara Dupont",
        "Digital investigations & open-source research. Tracking corporate registries and public records.",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("osint", "journalism", "archives", "foia", "data"),
    ),
    "journalist": (
        "Clara Dupont",
        "Digital investigations & open-source research. Tracking corporate registries and public records.",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ("osint", "journalism", "archives", "foia", "data"),
    ),
}

REGION_TIMEZONES: dict[str, tuple[str, str]] = {
    "eu-west": ("UTC+1", "Europe/Madrid"),
    "eu": ("UTC+1", "Europe/Berlin"),
    "us-east": ("UTC-5", "America/New_York"),
    "us": ("UTC-5", "America/New_York"),
    "latam": ("UTC-3", "America/Buenos_Aires"),
    "ee-utc3": ("UTC+3", "Europe/Helsinki"),
    "ee": ("UTC+3", "Europe/Tallinn"),
    "apac": ("UTC+9", "Asia/Tokyo"),
}


@dataclass(slots=True)
class SocialAccount:
    id: str
    platform: str
    handle: str = ""
    username: str = ""
    token: str = ""
    cookie: str = ""
    token_env: str = ""
    user_agent: str = ""
    proxy: str = ""
    target_site: str = ""
    site: str = ""
    rate_limit_rpm: int = 30
    enabled: bool = True
    cooldown_until: float = 0.0

    def __post_init__(self) -> None:
        if not self.handle and self.username:
            self.handle = self.username
        elif not self.username and self.handle:
            self.username = self.handle
        if not self.target_site and self.site:
            self.target_site = self.site
        elif not self.site and self.target_site:
            self.site = self.target_site

    def is_ready(self, env: dict[str, str] | None = None) -> bool:
        if not self.enabled:
            return False
        if self.cooldown_until > time.time():
            return False
        if self.token or self.cookie:
            return True
        if self.token_env:
            e = os.environ if env is None else env
            return bool(e.get(self.token_env, "").strip())
        return True

    def secret_status(self, env: dict[str, str] | None = None) -> str:
        if not self.enabled:
            return "deshabilitada"
        if self.token:
            prefix = self.token[:3] if len(self.token) >= 6 else "***"
            return f"configurada ({prefix}****)"
        if self.cookie:
            return "cookie configurada (****)"
        if not self.token_env:
            return "perfil pasivo (sin token)"
        e = os.environ if env is None else env
        val = e.get(self.token_env, "").strip()
        if not val:
            return f"falta {self.token_env}"
        prefix = val[:3] if len(val) >= 6 else ""
        return f"configurada ({prefix}****)"

    def headers(self, env: dict[str, str] | None = None, default_ua: str = "") -> dict[str, str]:
        hdrs: dict[str, str] = {}
        if self.user_agent:
            hdrs["User-Agent"] = self.user_agent
        elif default_ua:
            hdrs["User-Agent"] = default_ua

        if self.cookie:
            hdrs["Cookie"] = self.cookie

        e = os.environ if env is None else env
        token = self.token or (e.get(self.token_env, "").strip() if self.token_env else "")
        if not token:
            return hdrs

        plat = self.platform.lower()
        if plat == "github":
            hdrs["Authorization"] = f"Bearer {token}"
            hdrs["Accept"] = "application/vnd.github+json"
        elif plat == "gitlab":
            hdrs["PRIVATE-TOKEN"] = token
        elif plat in ("reddit", "mastodon", "bluesky", "discord"):
            hdrs["Authorization"] = token if " " in token else f"Bearer {token}"
        elif plat == "intelx":
            hdrs["x-key"] = token
        else:
            hdrs["Authorization"] = f"Bearer {token}"
        return hdrs

    def to_public_dict(self, env: dict[str, str] | None = None) -> dict[str, object]:
        ready = self.is_ready(env)
        status = self.secret_status(env)
        uname = self.username or self.handle
        st = self.target_site or self.site
        return {
            "id": self.id,
            "platform": self.platform,
            "username": uname,
            "handle": uname,
            "site": st,
            "target_site": st,
            "status": status,
            "secret_preview": status,
            "ready": ready,
            "available": ready,
            "proxy_configured": bool(self.proxy),
            "rate_limit_rpm": self.rate_limit_rpm,
        }


@dataclass(frozen=True, slots=True)
class SockPuppetPersona:
    persona_id: str
    handle: str
    display_name: str
    alt_handles: list[str]
    role: str
    region: str
    timezone: str
    target_site: str
    bio: str
    user_agent: str
    burner_email_hint: str
    pgp_key_id_hint: str
    totp_secret_base32: str
    opsec_checklist: list[str]
    interests: list[str]
    proxy_recommendation: str
    opsec_rules: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "persona_id": self.persona_id,
            "handle": self.handle,
            "display_name": self.display_name,
            "alt_handles": self.alt_handles,
            "role": self.role,
            "region": self.region,
            "timezone": self.timezone,
            "target_site": self.target_site,
            "bio": self.bio,
            "user_agent": self.user_agent,
            "burner_email_hint": self.burner_email_hint,
            "pgp_key_id_hint": self.pgp_key_id_hint,
            "totp_secret_base32": self.totp_secret_base32,
            "opsec_checklist": self.opsec_checklist,
            "interests": self.interests,
            "proxy_recommendation": self.proxy_recommendation,
            "opsec_rules": self.opsec_rules,
        }


@dataclass(slots=True)
class AccountPool:
    accounts: list[SocialAccount] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    _cursor: dict[str, int] = field(default_factory=dict)

    def acquire(self, platform: str, site: str = "") -> SocialAccount | None:
        """Selecciona una cuenta disponible mediante round-robin con filtrado opcional de sitio."""
        plat = platform.strip().lower()
        target = site.strip().lower()
        candidates: list[SocialAccount] = []
        for a in self.accounts:
            if a.platform.lower() != plat or not a.is_ready(self.env):
                continue
            if target:
                acc_site = (a.target_site or a.site).lower()
                if acc_site and acc_site != target and target not in acc_site and acc_site not in target:
                    continue
            candidates.append(a)
        if not candidates:
            # Reintento sin filtro estricto de sitio si no hay específica
            candidates = [a for a in self.accounts if a.platform.lower() == plat and a.is_ready(self.env)]
        if not candidates:
            return None
        idx = self._cursor.get(plat, 0) % len(candidates)
        self._cursor[plat] = idx + 1
        return candidates[idx]

    def select(self, platform: str, env: dict[str, str] | None = None) -> SocialAccount | None:
        if env is not None:
            self.env = env
        return self.acquire(platform)

    def auth_headers(self, account: SocialAccount | None, default_ua: str = "") -> dict[str, str]:
        if account is None:
            return {}
        return account.headers(self.env, default_ua)

    def mark_rate_limited(self, account_or_id: SocialAccount | str, cooldown_seconds: float = 600.0) -> None:
        aid = account_or_id.id if isinstance(account_or_id, SocialAccount) else str(account_or_id)
        until = time.time() + max(5.0, cooldown_seconds)
        for acc in self.accounts:
            if acc.id == aid or acc.handle == aid or acc.username == aid:
                acc.cooldown_until = until

    def summary(self, env: dict[str, str] | None = None) -> list[dict[str, object]]:
        e = self.env if env is None else env
        return [a.to_public_dict(e) for a in self.accounts]


def ensure_accounts_template(home: Path) -> Path:
    """Crea una plantilla comentada `~/.maltego-mcp/accounts.toml` si no existe."""
    home.mkdir(parents=True, exist_ok=True)
    path = home / ACCOUNTS_FILE
    if path.is_file():
        return path
    template = (
        "# Bóveda local de cuentas y Sock Puppets para MCP Maltego (~/.maltego-mcp/accounts.toml)\n"
        "# Los secretos reales (tokens/cookies) se guardan en ~/.maltego-mcp/.env y se referencian con token_env.\n\n"
        "# [[accounts]]\n"
        '# id = "sp-github-01"\n'
        '# platform = "github"\n'
        '# username = "sec_researcher_01"\n'
        '# token_env = "GITHUB_TOKEN"\n'
        "# rate_limit_rpm = 30\n"
        "# enabled = true\n"
    )
    path.write_text(template, encoding="utf-8")
    return path


def load_account_pool(home: Path, env: dict[str, str] | None = None) -> AccountPool:
    """Carga las cuentas de `~/.maltego-mcp/accounts.toml` más las variables de entorno configuradas en `.env`."""
    active_env = dict(os.environ if env is None else env)
    path = home / ACCOUNTS_FILE
    accounts: list[SocialAccount] = []
    seen_envs: set[str] = set()

    if path.is_file():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for item in data.get("accounts", []):
                if not isinstance(item, dict):
                    continue
                acc_id = str(item.get("id") or item.get("username") or item.get("handle") or "sp").strip()[:80]
                plat = str(item.get("platform") or "generic").strip().lower()[:40]
                tenv = str(item.get("token_env") or "").strip()[:80]
                handle_val = str(item.get("handle") or item.get("username") or "").strip()[:80]
                token_val = str(item.get("token") or "").strip()
                cookie_val = str(item.get("cookie") or "").strip()
                target_site = str(item.get("target_site") or item.get("site") or "").strip()[:200]
                if tenv:
                    seen_envs.add(tenv)
                accounts.append(
                    SocialAccount(
                        id=acc_id,
                        platform=plat,
                        handle=handle_val,
                        username=handle_val,
                        token=token_val,
                        cookie=cookie_val,
                        token_env=tenv,
                        user_agent=str(item.get("user_agent") or "").strip()[:240],
                        proxy=str(item.get("proxy") or "").strip()[:200],
                        target_site=target_site,
                        site=target_site,
                        rate_limit_rpm=max(1, min(600, int(item.get("rate_limit_rpm", 30) or 30))),
                        enabled=bool(item.get("enabled", True)),
                    )
                )
        except (OSError, tomllib.TOMLDecodeError, ValueError):
            pass

    for plat, env_keys in PLATFORM_ENV_VARS.items():
        for ek in env_keys:
            if ek not in seen_envs and active_env.get(ek, "").strip():
                accounts.append(
                    SocialAccount(
                        id=f"env-{plat}-{ek.lower()}",
                        platform=plat,
                        handle=f"env:{ek}",
                        username=f"env:{ek}",
                        token_env=ek,
                        enabled=True,
                    )
                )
                seen_envs.add(ek)

    return AccountPool(accounts=accounts, env=active_env)


def generate_sockpuppet_persona(
    role: str = "cyber_researcher",
    region: str = "eu-west",
    target_site: str = "",
    seed: str = "",
) -> SockPuppetPersona:
    """Genera localmente (offline) un kit de identidad operativa (*Sock Puppet*) coherente y aislado."""
    norm_role = role.strip().lower()
    if norm_role not in ROLE_TEMPLATES:
        norm_role = "cyber_researcher"
    norm_region = region.strip().lower()
    if norm_region not in REGION_TIMEZONES:
        norm_region = "eu-west"

    disp_name, bio_tpl, ua, interests = ROLE_TEMPLATES[norm_role]
    tz_offset, tz_name = REGION_TIMEZONES[norm_region]
    raw_seed = f"{norm_role}:{norm_region}:{target_site.strip().lower()}:{seed.strip()}"
    digest = hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()

    prefixes = ("null", "cipher", "vectr", "kestrel", "hex", "drift", "node", "lynx")
    nouns = ("trace", "pulse", "grid", "forge", "stack", "orbit", "shift", "warden")
    p_idx = int(digest[:4], 16) % len(prefixes)
    n_idx = int(digest[4:8], 16) % len(nouns)
    num_tag = int(digest[8:12], 16) % 900 + 100

    primary_handle = f"{prefixes[p_idx]}_{nouns[n_idx]}{num_tag}"
    alt_handles = [
        f"{prefixes[(p_idx + 1) % len(prefixes)]}{nouns[n_idx]}_{num_tag % 99:02d}",
        f"{nouns[(n_idx + 2) % len(nouns)]}.{prefixes[p_idx]}",
    ]
    is_onion = ".onion" in target_site.lower()
    proxy_rec = "socks5://127.0.0.1:9050" if is_onion else " residencial/VPN dedicado a la región " + norm_region

    # Generación determinista de TOTP secreto Base32 de 32 chars
    b32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    totp_secret = "".join(b32_chars[int(digest[i : i + 2], 16) % len(b32_chars)] for i in range(0, 64, 2))[:32]
    pgp_id = f"0x{digest[:16].upper()}"
    burner_email = f"{primary_handle}@duck.com" if not is_onion else f"{primary_handle}@dnmx.org"

    opsec_rules = [
        f"Mantener actividad estrictamente dentro del huso {tz_offset} ({tz_name}).",
        "No reutilizar este handle ni su clave PGP en ningún otro caso ni cuenta personal.",
        f"Fijar siempre el User-Agent asignado y salir por {proxy_rec}.",
        "Operar en modo estrictamente pasivo (lectura/observación); nunca interactuar con mercados ilícitos.",
    ]
    if is_onion:
        opsec_rules.append(
            "Para foros/mercados .onion: desactivar JavaScript en Tor Browser al registrar manualmente el avatar."
        )

    opsec_checklist = [
        f"Verificar salida por proxy dedicado ({proxy_rec})",
        f"Configurar cliente con User-Agent: {ua[:60]}...",
        f"Importar semilla TOTP 2FA offline en KeepassXC ({totp_secret[:6]}...)",
        f"Generar par de claves PGP offline asignado a {burner_email}",
        "Nunca cruzar números de teléfono reales ni métodos de pago de clearnet",
    ]

    return SockPuppetPersona(
        persona_id=f"sp-{digest[:10]}",
        handle=primary_handle,
        display_name=disp_name,
        alt_handles=alt_handles,
        role=norm_role,
        region=norm_region,
        timezone=f"{tz_offset} ({tz_name})",
        target_site=target_site.strip() or "general",
        bio=bio_tpl.strip(),
        user_agent=ua.strip(),
        burner_email_hint=burner_email,
        pgp_key_id_hint=pgp_id,
        totp_secret_base32=totp_secret,
        opsec_checklist=opsec_checklist,
        interests=list(interests),
        proxy_recommendation=proxy_rec.strip(),
        opsec_rules=opsec_rules,
    )


def save_persona_to_accounts_toml(home: Path, persona: SockPuppetPersona, platform: str = "onion_forum") -> Path:
    """Registra el perfil *Sock Puppet* generado en `~/.maltego-mcp/accounts.toml` (sin secretos)."""
    path = ensure_accounts_template(home)
    existing = path.read_text(encoding="utf-8")
    if f'id = "{persona.persona_id}"' in existing:
        return path
    proxy_val = "socks5://127.0.0.1:9050" if ".onion" in persona.target_site.lower() else ""
    block = (
        f"\n[[accounts]]\n"
        f'id = "{persona.persona_id}"\n'
        f'platform = "{platform.strip().lower()[:40]}"\n'
        f'username = "{persona.handle}"\n'
        f'handle = "{persona.handle}"\n'
        f'target_site = "{persona.target_site.replace(chr(34), "")[:180]}"\n'
        f'user_agent = "{persona.user_agent.replace(chr(34), "")}"\n'
        f'proxy = "{proxy_val}"\n'
        f"rate_limit_rpm = 15\n"
        f"enabled = true\n"
    )
    path.write_text(existing.rstrip() + "\n" + block, encoding="utf-8")
    return path
