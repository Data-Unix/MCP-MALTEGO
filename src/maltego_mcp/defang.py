"""Módulo de neutralización (defang) y securización de indicadores OSINT.

Convierte URLs, dominios, direcciones IP y correos en representaciones inertes
(ej. hxxps[://]sub[.]dominio[.]tld, user[@]example[.]com, 1[.]2[.]3[.]4)
para evitar navegación accidental, prefetching por DNS o ejecución inadvertida.
"""

from __future__ import annotations

import re

# Protocolos
_INLINE_URL_RE = re.compile(r"\b(https?|ftp|sftp)://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang(value: object) -> str:
    """Neutraliza un indicador OSINT o URL (ej. hxxps[://]domain[.]com)."""
    raw = str(value or "").strip()
    if not raw:
        return ""

    s = raw
    # Reemplazo de esquemas
    s = re.sub(r"^https://", "hxxps[://]", s, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp[://]", s, flags=re.IGNORECASE)
    s = re.sub(r"^ftp://", "fxp[://]", s, flags=re.IGNORECASE)
    s = re.sub(r"^sftp://", "sfxp[://]", s, flags=re.IGNORECASE)

    # Reemplazo de puntos
    s = s.replace(".", "[.]")

    # Reemplazo de arroba en correos
    if "@" in s and not s.startswith("hxxp"):
        s = s.replace("@", "[@]")

    return s


def defang_text(text: str) -> str:
    """Escanea y neutraliza todas las URLs, IPs y correos dentro de un bloque de texto."""
    if not text:
        return ""

    def _replace_url(match: re.Match[str]) -> str:
        url = match.group(0)
        return defang(url)

    def _replace_email(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    # 1. Neutralizar URLs
    res = _INLINE_URL_RE.sub(_replace_url, text)
    # 2. Neutralizar correos
    res = _EMAIL_RE.sub(_replace_email, res)
    return res


def refang(value: object) -> str:
    """Restaura un indicador neutralizado a su forma original (uso interno/tests)."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    s = raw
    s = re.sub(r"^hxxps\[://\]", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp\[://\]", "http://", s, flags=re.IGNORECASE)
    s = re.sub(r"^fxp\[://\]", "ftp://", s, flags=re.IGNORECASE)
    s = re.sub(r"^sfxp\[://\]", "sftp://", s, flags=re.IGNORECASE)
    s = s.replace("[.]", ".")
    s = s.replace("[@]", "@")
    return s
