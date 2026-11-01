"""Enrutador semántico e índice local SQLite de filtraciones (Dark Web & Breach Leaks).

- Base de datos local embebida con `sqlite3` estándar en `<MALTEGO_MCP_HOME>/breaches.sqlite`.
- Indexa automáticamente ficheros `.csv`, `.tsv`, `.jsonl` o `.txt` depositados en `<MALTEGO_MCP_HOME>/breaches/`
  o mediante `maltegoctl index-breaches <fichero>`.
- Consultas 100 % parametrizadas (sin concatenación SQL) y límites de tamaño para proteger memoria/disco.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from maltego_mcp.domain.detect import resolve_type_for_value
from maltego_mcp.errors import InvalidInput

BREACH_DB_NAME = "breaches.sqlite"
BREACH_DIR_NAME = "breaches"
MAX_BREACH_FILE_BYTES = 50 * 1024 * 1024
MAX_BREACH_ROWS = 200_000
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS breach_sources (
    file_name TEXT PRIMARY KEY,
    mtime_ns INTEGER NOT NULL,
    row_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS breach_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL DEFAULT '',
    alias TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    breach_name TEXT NOT NULL DEFAULT 'LocalBreach',
    breach_date TEXT NOT NULL DEFAULT '',
    source_file TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_breach_email ON breach_records(email);
CREATE INDEX IF NOT EXISTS idx_breach_alias ON breach_records(alias);
CREATE INDEX IF NOT EXISTS idx_breach_domain ON breach_records(domain);
CREATE INDEX IF NOT EXISTS idx_breach_phone ON breach_records(phone);
CREATE INDEX IF NOT EXISTS idx_breach_hash ON breach_records(password_hash);
"""


@dataclass(frozen=True, slots=True)
class BreachHit:
    breach_name: str
    breach_date: str = ""
    email: str = ""
    alias: str = ""
    domain: str = ""
    phone: str = ""
    password_hash: str = ""
    source: str = "local_sqlite"
    exposure_count: int = 1


def classify_breach_indicator(entity_type: str, value: str) -> tuple[str, str]:
    """Clasifica semánticamente el indicador en ('email'|'hash'|'phone'|'domain'|'alias', valor_normalizado)."""
    text = value.strip()
    mtype = entity_type.strip().lower()
    if _HEX_HASH_RE.match(text):
        return "hash", text.lower()
    if "@" in text and "." in text.split("@")[-1]:
        return "email", text.lower()
    if mtype == "maltego.phonenumber" or (text.startswith("+") and sum(c.isdigit() for c in text) >= 6):
        digits = "+" + "".join(c for c in text if c.isdigit())
        return "phone", digits
    if not mtype or mtype in ("auto", "maltego.phrase"):
        detected = resolve_type_for_value("auto", text).maltego_type.lower()
        if detected != "maltego.phrase":
            mtype = detected
    if mtype == "maltego.emailaddress":
        return "email", text.lower()
    if mtype == "maltego.hash":
        return "hash", text.lower()
    if mtype in ("maltego.domain", "maltego.dnsname", "maltego.website"):
        return "domain", text.lower().rstrip(".")
    return "alias", text.lstrip("@").lower()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.executescript(SCHEMA_SQL)
    return conn


def _norm_row(raw: dict[str, str], default_source: str) -> tuple[str, str, str, str, str, str, str, str] | None:
    email = (raw.get("email") or raw.get("mail") or "").strip().lower()
    alias = (raw.get("alias") or raw.get("username") or raw.get("user") or "").strip().lstrip("@").lower()
    domain = (raw.get("domain") or "").strip().lower().rstrip(".")
    if not domain and "@" in email:
        domain = email.rpartition("@")[2]
    if not alias and "@" in email:
        alias = email.rpartition("@")[0].split("+", 1)[0]
    phone_raw = (raw.get("phone") or raw.get("phonenumber") or "").strip()
    phone = ("+" + "".join(c for c in phone_raw if c.isdigit())) if phone_raw else ""
    phash = (raw.get("hash") or raw.get("password_hash") or raw.get("sha1") or "").strip().lower()
    bname = (raw.get("breach") or raw.get("breach_name") or raw.get("source") or default_source).strip()[:120]
    bdate = (raw.get("date") or raw.get("breach_date") or "").strip()[:40]
    if not any((email, alias, domain, phone, phash)):
        return None
    return (
        email[:254],
        alias[:120],
        domain[:253],
        phone[:30],
        phash[:128],
        bname or default_source,
        bdate,
        default_source,
    )


def index_breach_file(db_path: Path, file_path: Path) -> int:
    """Indexa un fichero (.csv, .tsv, .jsonl, .txt) en la base SQLite de filtraciones."""
    if not file_path.is_file():
        raise InvalidInput(f"No existe el fichero '{file_path}'.")
    size = file_path.stat().st_size
    if size > MAX_BREACH_FILE_BYTES:
        raise InvalidInput(f"El fichero '{file_path.name}' supera el límite de 50 MB.")
    text = file_path.read_text(encoding="utf-8-sig", errors="replace")
    suffix = file_path.suffix.lower()
    default_name = file_path.stem[:80] or "LocalBreach"
    rows: list[tuple[str, str, str, str, str, str, str, str]] = []

    if suffix == ".jsonl":
        for line in text.splitlines()[:MAX_BREACH_ROWS]:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                norm = _norm_row({str(k).lower(): str(v) for k, v in obj.items() if v is not None}, default_name)
                if norm:
                    rows.append(norm)
    elif suffix in (".csv", ".tsv"):
        delim = "\t" if suffix == ".tsv" else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        for i, r in enumerate(reader):
            if i >= MAX_BREACH_ROWS:
                break
            norm = _norm_row({(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}, default_name)
            if norm:
                rows.append(norm)
    elif suffix == ".txt":
        for line in text.splitlines()[:MAX_BREACH_ROWS]:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in re.split(r"[:;,|\t]", line) if p.strip()]
            raw: dict[str, str] = {"breach_name": default_name}
            for p in parts:
                kind, cleaned = classify_breach_indicator("auto", p)
                raw.setdefault(kind if kind != "hash" else "password_hash", cleaned)
            norm = _norm_row(raw, default_name)
            if norm:
                rows.append(norm)
    else:
        raise InvalidInput("Formato no soportado para index-breaches: usa .csv, .tsv, .jsonl o .txt.")

    mtime_ns = file_path.stat().st_mtime_ns
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM breach_records WHERE source_file = ?", (default_name,))
        if rows:
            conn.executemany(
                "INSERT INTO breach_records "
                "(email, alias, domain, phone, password_hash, breach_name, breach_date, source_file) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        conn.execute(
            "INSERT OR REPLACE INTO breach_sources (file_name, mtime_ns, row_count) VALUES (?, ?, ?)",
            (file_path.name, mtime_ns, len(rows)),
        )
    return len(rows)


def sync_breach_dir(home: Path) -> int:
    """Indexa automáticamente los ficheros nuevos o modificados en `<home>/breaches/`."""
    breach_dir = home / BREACH_DIR_NAME
    if not breach_dir.is_dir():
        return 0
    db_path = home / BREACH_DB_NAME
    total_added = 0
    with _connect(db_path) as conn:
        known = {
            str(r[0]): int(r[1]) for r in conn.execute("SELECT file_name, mtime_ns FROM breach_sources").fetchall()
        }
    for f in sorted(breach_dir.iterdir()):
        if not f.is_file() or f.suffix.lower() not in (".csv", ".tsv", ".jsonl", ".txt"):
            continue
        try:
            if known.get(f.name) == f.stat().st_mtime_ns:
                continue
            total_added += index_breach_file(db_path, f)
        except (OSError, InvalidInput):
            continue
    return total_added


def query_local_breaches(home: Path, kind: str, normalized_value: str, limit: int = 25) -> list[BreachHit]:
    """Consulta el índice SQLite local por tipo semántico."""
    if home.suffix.lower() == ".sqlite" or home.is_file():
        db_path = home
    else:
        sync_breach_dir(home)
        db_path = home / BREACH_DB_NAME
    if not db_path.is_file():
        return []
    col_map = {
        "email": "email",
        "alias": "alias",
        "domain": "domain",
        "phone": "phone",
        "hash": "password_hash",
    }
    col = col_map.get(kind, "alias")
    query = (
        f"SELECT breach_name, breach_date, email, alias, domain, phone, password_hash, source_file "
        f"FROM breach_records WHERE {col} = ? LIMIT ?"
    )
    with _connect(db_path) as conn:
        rows = conn.execute(query, (normalized_value, max(1, min(limit, 256)))).fetchall()
    return [
        BreachHit(
            breach_name=str(r[0] or "LocalBreach"),
            breach_date=str(r[1] or ""),
            email=str(r[2] or ""),
            alias=str(r[3] or ""),
            domain=str(r[4] or ""),
            phone=str(r[5] or ""),
            password_hash=str(r[6] or ""),
            source=f"local_sqlite:{r[7]}" if r[7] else "local_sqlite",
        )
        for r in rows
    ]
