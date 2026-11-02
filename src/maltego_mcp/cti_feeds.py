"""Sincronizador e índice SQLite de fuentes CTI activas (`fastfire/deepdarkCTI`).

- Descarga y parsea las tablas Markdown de `https://github.com/fastfire/deepdarkCTI`.
- Conserva ESTRICTAMENTE las fuentes cuyo estado es `ONLINE` o `VALID`.
- Cuando se sincroniza una lista (`sync_deepdark_cti`), añade automáticamente las nuevas entradas activas y
  elimina/actualiza aquellas que hayan pasado a `OFFLINE`, `EXPIRED`, `SEIZED` o `DOWN`.
- Incluye una semilla inicial verificada para funcionar también sin red o antes de la primera sincronización.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

CTI_DB_NAME = "cti_feeds.sqlite"
DEEPDARK_RAW_BASE = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"
DEFAULT_SYNC_TTL_S = 24 * 3600

DEEPDARK_FEEDS: tuple[tuple[str, str], ...] = (
    ("ransomware_gang.md", "ransomware_gang"),
    ("markets.md", "market"),
    ("forum.md", "forum"),
    ("search_engines.md", "search_engine"),
    ("telegram_threat_actors.md", "telegram_threat_actor"),
    ("telegram_infostealer.md", "telegram_infostealer"),
    ("telegram_ransomware.md", "telegram_ransomware"),
    ("discord.md", "discord"),
    ("maas.md", "maas"),
    ("exploits.md", "exploit"),
)

ACTIVE_STATUSES = {"ONLINE", "VALID"}
INACTIVE_STATUSES = {"OFFLINE", "EXPIRED", "DEAD", "DOWN", "SEIZED", "CLOSED", "INACTIVE"}

_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^\s)]+)\)")
_URL_RE = re.compile(r"https?://[^\s|)<>\"]+")
_ONION_RE = re.compile(r"\b([a-z2-7]{16,56}\.onion)\b", re.IGNORECASE)
_TG_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z0-9_]{4,64})", re.IGNORECASE)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cti_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_file TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    onion_domain TEXT NOT NULL DEFAULT '',
    telegram_handle TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ONLINE',
    description TEXT NOT NULL DEFAULT '',
    updated_ts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cti_category ON cti_sources(category);
CREATE INDEX IF NOT EXISTS idx_cti_onion ON cti_sources(onion_domain);
CREATE INDEX IF NOT EXISTS idx_cti_tg ON cti_sources(telegram_handle);
CREATE INDEX IF NOT EXISTS idx_cti_name ON cti_sources(name);

CREATE TABLE IF NOT EXISTS cti_sync_meta (
    feed_file TEXT PRIMARY KEY,
    etag TEXT NOT NULL DEFAULT '',
    last_sync_ts INTEGER NOT NULL DEFAULT 0,
    active_count INTEGER NOT NULL DEFAULT 0,
    purged_offline INTEGER NOT NULL DEFAULT 0
);
"""

# Semilla inicial de fuentes ONLINE de deepdarkCTI para disponibilidad inmediata sin red
SEED_ENTRIES: tuple[tuple[str, str, str, str, str, str, str, str], ...] = (
    (
        "search_engines.md",
        "search_engine",
        "Ahmia",
        "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "",
        "ONLINE",
        "Clearnet & Onion search engine for Tor hidden services (ahmia.fi)",
    ),
    (
        "search_engines.md",
        "search_engine",
        "Torch",
        "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion",
        "xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion",
        "",
        "ONLINE",
        "Tor dark web search engine",
    ),
    (
        "forum.md",
        "forum",
        "Dread",
        "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion",
        "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion",
        "",
        "ONLINE",
        "Reddit-like darknet discussion forum and market review aggregator",
    ),
    (
        "forum.md",
        "forum",
        "XSS Forum",
        "https://xss.is",
        "expyuzz4wqqyqhjn.onion",
        "",
        "ONLINE",
        "Russian-speaking cybercrime and exploit forum",
    ),
    (
        "forum.md",
        "forum",
        "Exploit.in",
        "https://exploit.in",
        "",
        "",
        "ONLINE",
        "High-tier threat actor and zero-day forum",
    ),
    (
        "ransomware_gang.md",
        "ransomware_gang",
        "Akira",
        "http://akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion",
        "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion",
        "",
        "ONLINE",
        "Akira ransomware group leak site and negotiation portal",
    ),
    (
        "ransomware_gang.md",
        "ransomware_gang",
        "Play",
        "http://mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd.onion",
        "mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd.onion",
        "",
        "ONLINE",
        "Play (PlayCrypt) ransomware group data leak site",
    ),
    (
        "ransomware_gang.md",
        "ransomware_gang",
        "RansomHub",
        "http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",
        "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",
        "",
        "ONLINE",
        "RansomHub RaaS extortion blog",
    ),
    (
        "ransomware_gang.md",
        "ransomware_gang",
        "Cl0p",
        "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion",
        "santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion",
        "",
        "ONLINE",
        "Cl0p leak site (CLExploit)",
    ),
    (
        "markets.md",
        "market",
        "Russian Market",
        "https://russianmarket.to",
        "",
        "",
        "ONLINE",
        "Infostealer logs, RDP and credentials marketplace",
    ),
    (
        "telegram_infostealer.md",
        "telegram_infostealer",
        "RedLine & Lumma Stealer Cloud Logs",
        "https://t.me/s/stealerlogs_cti",
        "",
        "stealerlogs_cti",
        "ONLINE",
        "Infostealer logs feed tracked in deepdarkCTI",
    ),
)


@dataclass(frozen=True, slots=True)
class CTISourceRecord:
    category: str
    name: str
    url: str
    onion_domain: str
    telegram_handle: str
    status: str
    description: str
    feed_file: str

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "name": self.name,
            "url": self.url,
            "onion_domain": self.onion_domain,
            "telegram_handle": self.telegram_handle,
            "status": self.status,
            "description": self.description,
            "feed_file": self.feed_file,
        }


@dataclass(frozen=True, slots=True)
class CTISyncSummary:
    files_checked: int
    files_updated: int
    active_sources: int
    purged_offline: int
    db_path: str = ""

    def __getitem__(self, item: str) -> Any:
        if item == "updated":
            return bool(self.files_updated > 0 or self.files_checked > 0)
        if item == "active_rows":
            return self.active_sources
        if item == "purged_rows":
            return self.purged_offline
        if item == "db_path":
            return self.db_path
        return getattr(self, item)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_checked": self.files_checked,
            "files_updated": self.files_updated,
            "active_sources": self.active_sources,
            "purged_offline": self.purged_offline,
            "db_path": self.db_path,
            "updated": bool(self.files_updated > 0 or self.files_checked > 0),
        }


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.executescript(SCHEMA_SQL)
    return conn


def ensure_seed_cti_db(home: Path) -> Path:
    """Inicializa `cti_feeds.sqlite` con la semilla verificada si aún está vacía."""
    db_path = home if home.suffix.lower() == ".sqlite" else (home / CTI_DB_NAME)
    now_ts = int(time.time())
    with _connect(db_path) as conn:
        count = int(conn.execute("SELECT COUNT(*) FROM cti_sources").fetchone()[0])
        if count == 0:
            conn.executemany(
                "INSERT INTO cti_sources "
                "(feed_file, category, name, url, onion_domain, telegram_handle, status, description, updated_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(*row, now_ts) for row in SEED_ENTRIES],
            )
    return db_path


def parse_deepdark_markdown(feed_file: str, category: str, markdown_text: str) -> list[CTISourceRecord]:
    """Parsea una tabla Markdown de `fastfire/deepdarkCTI`.

    Devuelve exclusivamente las entradas activas (`ONLINE` o `VALID`).
    """
    active: list[CTISourceRecord] = []
    seen_keys: set[tuple[str, str]] = set()

    for raw_line in markdown_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|") or line.count("|") < 3:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or all(not c or set(c) <= {"-", ":", " "} for c in cells):
            continue
        first_lower = cells[0].lower()
        if first_lower in ("name", "link", "url", "channel", "forum", "market", "search engine", "group", "title"):
            continue

        upper_cells = [c.upper().strip("*_ ") for c in cells]
        status = ""
        status_idx = -1
        for idx, uc in enumerate(upper_cells):
            if uc in ACTIVE_STATUSES:
                status = uc
                status_idx = idx
                break
            if uc in INACTIVE_STATUSES or any(tok in uc.split() for tok in INACTIVE_STATUSES):
                status = "OFFLINE"
                status_idx = idx
                break

        if status in ("OFFLINE", "") or status not in ACTIVE_STATUSES:
            continue

        row_joined = " | ".join(cells)
        md_match = _MD_LINK_RE.search(row_joined)
        url_match = _URL_RE.search(row_joined)
        url = ""
        name = ""
        if md_match:
            name = md_match.group(1).strip()
            url = md_match.group(2).strip()
        elif url_match:
            url = url_match.group(0).strip()

        if not name:
            for idx, c in enumerate(cells):
                if idx == status_idx or not c:
                    continue
                cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", c).strip()
                if cleaned and not cleaned.startswith("http") and cleaned.upper() not in ACTIVE_STATUSES:
                    name = cleaned[:120]
                    break
        if not name and url:
            host = urlsplit(url).hostname or url
            name = host[:120]
        if not name:
            continue

        onion_match = _ONION_RE.search(row_joined)
        onion = onion_match.group(1).lower() if onion_match else ""
        if not url and onion:
            url = f"http://{onion}"

        tg_match = _TG_RE.search(row_joined)
        tg_handle = tg_match.group(1).lower() if tg_match else ""

        desc_parts = [
            re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", c).strip()
            for idx, c in enumerate(cells)
            if idx != status_idx and c.strip() and c.strip() != name and c.strip() != url
        ]
        description = " — ".join(p for p in desc_parts if p and p.upper() not in ACTIVE_STATUSES)[:300]

        dedup_key = (name.lower(), (url or onion or tg_handle).lower())
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        active.append(
            CTISourceRecord(
                category=category,
                name=name[:120],
                url=url[:400],
                onion_domain=onion[:120],
                telegram_handle=tg_handle[:80],
                status=status,
                description=description,
                feed_file=feed_file,
            )
        )
    return active


def apply_feed_snapshot(
    db_path: Path,
    feed_file: str,
    category: str,
    content: str | list[CTISourceRecord],
    etag: str = "",
) -> tuple[int, int]:
    """Reemplaza el listado de `feed_file` en SQLite (añade ONLINE y purga las que pasaron a OFFLINE)."""
    active = content if isinstance(content, list) else parse_deepdark_markdown(feed_file, category, content)

    now_ts = int(time.time())
    with _connect(db_path) as conn:
        prev_count = int(
            conn.execute("SELECT COUNT(*) FROM cti_sources WHERE feed_file = ?", (feed_file,)).fetchone()[0]
        )
        conn.execute("DELETE FROM cti_sources WHERE feed_file = ?", (feed_file,))
        if active:
            conn.executemany(
                "INSERT INTO cti_sources "
                "(feed_file, category, name, url, onion_domain, telegram_handle, status, description, updated_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        r.feed_file,
                        r.category,
                        r.name,
                        r.url,
                        r.onion_domain,
                        r.telegram_handle,
                        r.status,
                        r.description,
                        now_ts,
                    )
                    for r in active
                ],
            )
        purged = max(0, prev_count)
        conn.execute(
            "INSERT OR REPLACE INTO cti_sync_meta "
            "(feed_file, etag, last_sync_ts, active_count, purged_offline) VALUES (?, ?, ?, ?, ?)",
            (feed_file, etag, now_ts, len(active), purged),
        )
    return len(active), purged


async def sync_deepdark_cti(
    home: Path,
    http: httpx.AsyncClient,
    force: bool = False,
    ttl_seconds: int = DEFAULT_SYNC_TTL_S,
    max_age_seconds: int | None = None,
) -> CTISyncSummary:
    """Sincroniza las listas de `fastfire/deepdarkCTI` con soporte ETag y purga automática de fuentes OFFLINE."""
    if max_age_seconds is not None:
        ttl_seconds = max_age_seconds
    db_path = ensure_seed_cti_db(home)
    now_ts = int(time.time())
    with _connect(db_path) as conn:
        meta = {
            str(r[0]): (str(r[1]), int(r[2]), int(r[3]), int(r[4]))
            for r in conn.execute(
                "SELECT feed_file, etag, last_sync_ts, active_count, purged_offline FROM cti_sync_meta"
            ).fetchall()
        }

    files_checked = 0
    files_updated = 0
    for feed_file, category in DEEPDARK_FEEDS:
        etag, last_ts, _, _ = meta.get(feed_file, ("", 0, 0, 0))
        if not force and last_ts > 0 and (now_ts - last_ts) < ttl_seconds:
            continue
        files_checked += 1
        headers: dict[str, str] = {}
        if etag and not force:
            headers["If-None-Match"] = etag
        try:
            resp = await http.get(f"{DEEPDARK_RAW_BASE}/{feed_file}", headers=headers)
        except httpx.HTTPError:
            continue
        if resp.status_code == 304:
            with _connect(db_path) as conn:
                conn.execute("UPDATE cti_sync_meta SET last_sync_ts = ? WHERE feed_file = ?", (now_ts, feed_file))
            continue
        if resp.status_code != 200 or not resp.text.strip():
            continue
        new_etag = resp.headers.get("etag", "")
        active_cnt, _ = apply_feed_snapshot(db_path, feed_file, category, resp.text, new_etag)
        if active_cnt > 0:
            files_updated += 1

    with _connect(db_path) as conn:
        total_active = int(conn.execute("SELECT COUNT(*) FROM cti_sources").fetchone()[0])
        total_purged = int(conn.execute("SELECT COALESCE(SUM(purged_offline), 0) FROM cti_sync_meta").fetchone()[0])
    return CTISyncSummary(
        files_checked=files_checked,
        files_updated=files_updated,
        active_sources=total_active,
        purged_offline=total_purged,
        db_path=str(db_path),
    )


def search_cti_feeds(
    home: Path,
    query: str,
    category: str = "",
    limit: int = 25,
    active_only: bool = True,
) -> list[CTISourceRecord]:
    """Busca en las fuentes CTI activas (`ONLINE` / `VALID`) por nombre, dominio, `.onion`, canal o descripción."""
    db_path = ensure_seed_cti_db(home)
    q = query.strip().lower()
    if q.startswith(("http://", "https://")):
        parsed = urlsplit(q)
        q = (parsed.hostname or q).lower()
    q = q.lstrip("@")
    like = f"%{q}%"
    cat = category.strip().lower()
    cap = max(1, min(limit, 100))
    status_clause = "status IN ('ONLINE', 'VALID')" if active_only else "1=1"

    with _connect(db_path) as conn:
        if cat:
            rows = conn.execute(
                "SELECT category, name, url, onion_domain, telegram_handle, status, description, feed_file "
                "FROM cti_sources "
                f"WHERE {status_clause} AND category = ? "
                "AND (LOWER(name) LIKE ? OR LOWER(url) LIKE ? OR LOWER(onion_domain) LIKE ? "
                "OR LOWER(telegram_handle) LIKE ? OR LOWER(description) LIKE ?) "
                "LIMIT ?",
                (cat, like, like, like, like, like, cap),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT category, name, url, onion_domain, telegram_handle, status, description, feed_file "
                "FROM cti_sources "
                f"WHERE {status_clause} "
                "AND (LOWER(name) LIKE ? OR LOWER(url) LIKE ? OR LOWER(onion_domain) LIKE ? "
                "OR LOWER(telegram_handle) LIKE ? OR LOWER(description) LIKE ?) "
                "LIMIT ?",
                (like, like, like, like, like, cap),
            ).fetchall()

    return [
        CTISourceRecord(
            category=str(r[0]),
            name=str(r[1]),
            url=str(r[2]),
            onion_domain=str(r[3]),
            telegram_handle=str(r[4]),
            status=str(r[5]),
            description=str(r[6]),
            feed_file=str(r[7]),
        )
        for r in rows
    ]
