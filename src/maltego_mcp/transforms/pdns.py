"""Módulo de DNS pasivo (pDNS), fuentes históricas de archivo y extracción segura de metadatos (F4).

Sustituye la resolución activa (DoH/DNS en vivo) por consultas históricas en agregadores
pasivos (Mnemonic, Robtex, OTX, InternetDB, THC, HackerTarget reverseiplookup), incorpora
búsqueda en archivos históricos (Wayback CDX, arquivo.pt), extracción de metadatos de documentos
sin ejecución (defusedxml / Info PDF) y heurística de detección de dominios canario.
"""

from __future__ import annotations

import datetime
import io
import math
import re
import urllib.parse
import zipfile
from typing import Any

import defusedxml.minidom
import httpx

from maltego_mcp.errors import EgressBlockedError, EgressKillSwitchError

# Independence clusters según diseño F4 / §4.1
CLUSTER_MNEMONIC = "pdns_sensor_mnemonic"
CLUSTER_ROBTEX = "pdns_aggregator_robtex"
CLUSTER_OTX = "cti_alienvault_otx"
CLUSTER_INTERNETDB = "scanner_shodan_internetdb"
CLUSTER_THC = "osint_thc"
CLUSTER_HACKERTARGET = "osint_hackertarget_reverse"
CLUSTER_CRTSH = "ct_crtsh"
CLUSTER_WAYBACK = "archive_wayback_cdx"
CLUSTER_ARQUIVO = "archive_arquivo_cdx"

CANARY_SUBDOMAIN_MAX_LEN = 30
ENTROPY_THRESHOLD = 3.8


def shannon_entropy(data: str) -> float:
    """Calcula la entropía de Shannon de una cadena."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def is_possible_canary(subdomain: str) -> bool:
    """Heurística F4.4: detecta posibles subdominios canario / token trampa (avisa, no bloquea).

    Criterios: etiqueta con entropía alta (>3.8), o aspecto de base32, o >30 caracteres.
    """
    clean = subdomain.strip().lower()
    first_label = clean.split(".")[0] if "." in clean else clean
    if len(first_label) > CANARY_SUBDOMAIN_MAX_LEN:
        return True
    if shannon_entropy(first_label) >= ENTROPY_THRESHOLD and len(first_label) >= 16:
        return True
    # Aspecto de base32 puro (alfabeto RFC 4648 sin relleno)
    return bool(len(first_label) >= 20 and re.fullmatch(r"[a-z2-7]+", first_label))


def normalize_iso_utc(ts: Any) -> str:
    """Convierte timestamps heterogéneos (ms unix, s unix o cadenas ISO) a formato ISO 8601 UTC."""
    if not ts:
        return ""
    if isinstance(ts, (int, float)):
        # Si es milisegundos (>10 dígitos)
        val = float(ts)
        if val > 1e11:
            val /= 1000.0
        try:
            dt = datetime.datetime.fromtimestamp(val, tz=datetime.UTC)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            return ""
    s = str(ts).strip()
    if s.isdigit():
        return normalize_iso_utc(int(s))
    # Tratamiento de fecha textual
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        return dt.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return s[:25]


# ------------------------------------------------------------------------------------- pDNS: Mnemonic
async def fetch_mnemonic_pdns(client: httpx.AsyncClient, query: str, rrtype: str = "") -> list[dict[str, Any]]:
    """Consulta Mnemonic pDNS v3 (10 req/min, 1000/día, pasivo, sin clave)."""
    from maltego_mcp.egress import get_following

    clean_q = query.strip().rstrip(".")
    url = f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(clean_q)}"
    params: dict[str, str] = {}
    if rrtype:
        params["rrtype"] = rrtype.lower()
    try:
        resp = await get_following(client, url, params=params, timeout=12.0)
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            return []
        data = resp.json()
        raw_items = data.get("data") if isinstance(data, dict) else []
        results: list[dict[str, Any]] = []
        for it in raw_items or []:
            ans = str(it.get("answer") or it.get("rrdata") or "").strip()
            if not ans:
                continue
            first = normalize_iso_utc(it.get("firstSeenTimestamp") or it.get("first_seen"))
            last = normalize_iso_utc(it.get("lastSeenTimestamp") or it.get("last_seen"))
            results.append(
                {
                    "query": clean_q,
                    "answer": ans,
                    "rrtype": str(it.get("rrtype") or "").upper(),
                    "first_seen": first,
                    "last_seen": last,
                    "count": it.get("count", 1),
                    "source": "mnemonic",
                    "independence_cluster": CLUSTER_MNEMONIC,
                }
            )
        return results
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


# ------------------------------------------------------------------------------------- pDNS: Robtex
async def fetch_robtex_pdns(client: httpx.AsyncClient, target: str, reverse: bool = False) -> list[dict[str, Any]]:
    """Consulta Robtex Free API pDNS forward/reverse (10 req/h, pasivo)."""
    from maltego_mcp.egress import get_following

    clean_t = target.strip().rstrip(".")
    mode = "reverse" if reverse else "forward"
    url = f"https://freeapi.robtex.com/pdns/{mode}/{urllib.parse.quote(clean_t)}"
    try:
        resp = await get_following(client, url, timeout=12.0)
        if resp.status_code in (404, 429) or resp.status_code >= 400:
            return []
        lines = resp.text.strip().splitlines()
        results: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                import json

                it = json.loads(line)
            except Exception:
                continue
            ans = str(it.get("rrdata") or "").strip()
            if not ans:
                continue
            first = normalize_iso_utc(it.get("time_first"))
            last = normalize_iso_utc(it.get("time_last"))
            results.append(
                {
                    "query": clean_t,
                    "answer": ans,
                    "rrtype": str(it.get("rrtype") or "").upper(),
                    "first_seen": first,
                    "last_seen": last,
                    "source": "robtex",
                    "independence_cluster": CLUSTER_ROBTEX,
                }
            )
        return results
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


# ------------------------------------------------------------------------------------- pDNS: OTX
async def fetch_otx_pdns(client: httpx.AsyncClient, domain: str, api_key: str) -> list[dict[str, Any]]:
    """Consulta AlienVault OTX Passive DNS para un dominio si hay API key configurada."""
    from maltego_mcp.egress import get_following

    clean_d = domain.strip().rstrip(".")
    if not api_key:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(clean_d)}/passive_dns"
    try:
        resp = await get_following(client, url, headers={"X-OTX-API-KEY": api_key}, timeout=15.0)
        if resp.status_code != 200:
            return []
        data = resp.json()
        passive_records = data.get("passive_dns") or []
        results: list[dict[str, Any]] = []
        for it in passive_records:
            ans = str(it.get("address") or it.get("hostname") or "").strip()
            if not ans:
                continue
            first = normalize_iso_utc(it.get("first"))
            last = normalize_iso_utc(it.get("last"))
            results.append(
                {
                    "query": clean_d,
                    "answer": ans,
                    "rrtype": str(it.get("record_type") or "").upper(),
                    "first_seen": first,
                    "last_seen": last,
                    "source": "otx",
                    "independence_cluster": CLUSTER_OTX,
                }
            )
        return results
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


# ------------------------------------------------------------------------------------- PTR Pasivo
async def fetch_passive_ptr(client: httpx.AsyncClient, ip: str) -> list[dict[str, Any]]:
    """Consulta hostnames de IP usando exclusivamente agregadores pasivos sin generar PTR activo."""
    from maltego_mcp.egress import get_following

    clean_ip = ip.strip()
    hostnames: dict[str, dict[str, str]] = {}

    # 1. Shodan InternetDB (hostnames conocidos)
    try:
        resp = await get_following(client, f"https://internetdb.shodan.io/{clean_ip}", timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            for h in data.get("hostnames") or []:
                norm_h = h.strip().lower().rstrip(".")
                if norm_h and norm_h not in hostnames:
                    hostnames[norm_h] = {
                        "source": "internetdb",
                        "cluster": CLUSTER_INTERNETDB,
                        "first_seen": "",
                        "last_seen": "",
                    }
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        pass

    # 2. Robtex reverse pDNS
    try:
        robtex_res = await fetch_robtex_pdns(client, clean_ip, reverse=True)
        for r in robtex_res:
            norm_h = r["answer"].lower().rstrip(".")
            if norm_h:
                hostnames[norm_h] = {
                    "source": "robtex",
                    "cluster": CLUSTER_ROBTEX,
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        pass

    # 3. ip.thc.org
    try:
        resp_thc = await get_following(client, f"https://ip.thc.org/{clean_ip}", timeout=8.0)
        if resp_thc.status_code == 200:
            for line in resp_thc.text.splitlines():
                line = line.strip().lower().rstrip(".")
                if "." in line and " " not in line and not line.startswith("<") and line not in hostnames:
                    hostnames[line] = {
                        "source": "thc",
                        "cluster": CLUSTER_THC,
                        "first_seen": "",
                        "last_seen": "",
                    }
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        pass

    # 4. HackerTarget reverseiplookup (único endpoint pasivo autorizado de HT para PTR)
    try:
        resp_ht = await get_following(
            client, f"https://api.hackertarget.com/reverseiplookup/?q={clean_ip}", timeout=8.0
        )
        if resp_ht.status_code == 200 and "error" not in resp_ht.text.lower():
            for line in resp_ht.text.splitlines()[:50]:
                line = line.strip().lower().rstrip(".")
                if "," in line:
                    line = line.split(",")[0].strip()
                if "." in line and " " not in line and line not in hostnames:
                    hostnames[line] = {
                        "source": "hackertarget",
                        "cluster": CLUSTER_HACKERTARGET,
                        "first_seen": "",
                        "last_seen": "",
                    }
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        pass

    return [
        {
            "hostname": h,
            "source": meta["source"],
            "independence_cluster": meta["cluster"],
            "first_seen": meta["first_seen"],
            "last_seen": meta["last_seen"],
        }
        for h, meta in sorted(hostnames.items())
    ]


# ------------------------------------------------------------------------------------- Archivos: CDX
async def fetch_wayback_cdx(client: httpx.AsyncClient, domain: str, limit: int = 100) -> list[dict[str, str]]:
    """Búsqueda en Wayback Machine CDX (sólo texto, solo metadatos de URL, sin abrir el sitio)."""
    from maltego_mcp.egress import get_following

    clean_d = domain.strip().rstrip(".")
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": clean_d,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "collapse": "urlkey",
        "limit": str(min(limit, 500)),
    }
    try:
        resp = await get_following(client, url, params=params, timeout=15.0)
        if resp.status_code != 200:
            return []
        rows = resp.json()
        if not rows or len(rows) < 2:
            return []
        headers = [h.lower() for h in rows[0]]
        out: list[dict[str, str]] = []
        for r in rows[1:]:
            item = dict(zip(headers, [str(c) for c in r], strict=False))
            orig = item.get("original", "")
            ts = normalize_iso_utc(item.get("timestamp", ""))
            mime = item.get("mimetype", "")
            if orig:
                out.append(
                    {
                        "url": orig,
                        "timestamp": ts,
                        "mimetype": mime,
                        "statuscode": item.get("statuscode", ""),
                        "digest": item.get("digest", ""),
                        "source": "wayback_cdx",
                        "independence_cluster": CLUSTER_WAYBACK,
                    }
                )
        return out
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


async def fetch_arquivo_cdx(client: httpx.AsyncClient, domain: str, limit: int = 100) -> list[dict[str, str]]:
    """Búsqueda en arquivo.pt CDX histórico para rastreo lateral pasivo."""
    from maltego_mcp.egress import get_following

    clean_d = domain.strip().rstrip(".")
    url = "https://arquivo.pt/wayback/cdx"
    params = {
        "url": clean_d,
        "matchType": "domain",
        "output": "json",
        "limit": str(min(limit, 200)),
    }
    try:
        resp = await get_following(client, url, params=params, timeout=15.0)
        if resp.status_code != 200:
            return []
        lines = resp.text.strip().splitlines()
        out: list[dict[str, str]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                import json

                it = json.loads(line)
            except Exception:
                continue
            orig = it.get("original") or it.get("url") or ""
            if orig:
                out.append(
                    {
                        "url": orig,
                        "timestamp": normalize_iso_utc(it.get("timestamp")),
                        "mimetype": it.get("mimetype", ""),
                        "source": "arquivo_cdx",
                        "independence_cluster": CLUSTER_ARQUIVO,
                    }
                )
        return out
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


# ------------------------------------------------------------------------------------- CT: Organización
async def fetch_crtsh_by_org(client: httpx.AsyncClient, organization: str, limit: int = 50) -> list[dict[str, str]]:
    """Consulta Certificate Transparency por Organización (crt.sh?O=...) sin tocar al objetivo."""
    from maltego_mcp.egress import get_following

    clean_org = organization.strip()
    if not clean_org or len(clean_org) < 2:
        return []
    url = f"https://crt.sh/?O={urllib.parse.quote(clean_org)}&output=json"
    try:
        resp = await get_following(client, url, timeout=25.0)
        if resp.status_code != 200:
            return []
        items = resp.json()
        if not isinstance(items, list):
            return []
        seen: set[str] = set()
        out: list[dict[str, str]] = []
        for it in items:
            names = str(it.get("name_value") or it.get("common_name") or "")
            not_before = normalize_iso_utc(it.get("not_before"))
            for n in names.splitlines():
                n_clean = n.strip().lower().lstrip("*.")
                if n_clean and "." in n_clean and n_clean not in seen:
                    seen.add(n_clean)
                    out.append(
                        {
                            "domain": n_clean,
                            "not_before": not_before,
                            "issuer": str(it.get("issuer_name") or ""),
                            "source": "crtsh_org",
                            "independence_cluster": CLUSTER_CRTSH,
                            "possible_canary": "true" if is_possible_canary(n_clean) else "false",
                        }
                    )
            if len(out) >= limit:
                break
        return out
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


# ------------------------------------------------------------------------------------- Metadatos Seguros
MAX_OOXML_MEMBER_BYTES = 5 * 1024 * 1024  # 5 MB tope anti zip-bomb


def _safe_read_zip_member(
    zf: zipfile.ZipFile, member_name: str, max_bytes: int = MAX_OOXML_MEMBER_BYTES
) -> bytes | None:
    """Lee un miembro de archivo ZIP con doble verificación de tamaño (declarado y real) para mitigar zip-bombs."""
    try:
        info = zf.getinfo(member_name)
    except KeyError:
        return None
    if info.file_size > max_bytes:
        return None
    with zf.open(info) as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        return None
    return data


def extract_doc_metadata(file_bytes: bytes, filename: str) -> dict[str, str]:
    """Extrae metadatos de documentos de forma pasiva y segura (sin renderizar ni ejecutar macros).

    Soporta OOXML (.docx, .xlsx, .pptx) y ODF (.odt) con defusedxml + zipfile, y diccionario /Info en PDF.
    """
    fn = filename.lower()
    meta: dict[str, str] = {
        "title": "",
        "creator": "",
        "last_modified_by": "",
        "created": "",
        "modified": "",
        "software": "",
        "company": "",
    }
    # 1. Archivos empaquetados OOXML / ODF (ZIP)
    if fn.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                # docProps/core.xml en OOXML o meta.xml en ODF
                target_xml = ""
                for name in zf.namelist():
                    if name.lower() in ("docprops/core.xml", "meta.xml"):
                        target_xml = name
                        break
                if target_xml:
                    raw_core = _safe_read_zip_member(zf, target_xml)
                    if raw_core is not None:
                        xml_content = raw_core.decode("utf-8", errors="ignore")
                        dom = defusedxml.minidom.parseString(xml_content)

                        def _tag_text(tag: str) -> str:
                            elems = dom.getElementsByTagName(tag)
                            if elems and elems[0].firstChild:
                                return str(elems[0].firstChild.nodeValue or "").strip()
                            return ""

                        meta["title"] = _tag_text("dc:title") or _tag_text("title")
                        meta["creator"] = _tag_text("dc:creator") or _tag_text("creator")
                        meta["last_modified_by"] = _tag_text("cp:lastModifiedBy")
                        meta["created"] = normalize_iso_utc(_tag_text("dcterms:created") or _tag_text("creation-date"))
                        meta["modified"] = normalize_iso_utc(_tag_text("dcterms:modified") or _tag_text("date"))

                # docProps/app.xml para Company y Application
                app_target = next((n for n in zf.namelist() if n.lower() == "docprops/app.xml"), None)
                if app_target:
                    raw_app = _safe_read_zip_member(zf, app_target)
                    if raw_app is not None:
                        app_xml = raw_app.decode("utf-8", errors="ignore")
                        dom_app = defusedxml.minidom.parseString(app_xml)
                        for el in dom_app.getElementsByTagName("Company"):
                            if el.firstChild:
                                meta["company"] = str(el.firstChild.nodeValue or "").strip()
                        for el in dom_app.getElementsByTagName("Application"):
                            if el.firstChild:
                                meta["software"] = str(el.firstChild.nodeValue or "").strip()
        except Exception:
            pass
        return {k: v for k, v in meta.items() if v}

    # 2. Documentos PDF (búsqueda segura de /Info y XMP básico sin ejecución)
    if fn.endswith(".pdf"):
        try:
            # Buscar diccionario /Info en los bytes iniciales y finales (256 KB)
            sample = file_bytes[:131072] + file_bytes[-131072:]
            text_sample = sample.decode("latin1", errors="ignore")

            def _find_pdf_prop(key: str) -> str:
                m = re.search(rf"/{key}\s*\(([^)]+)\)", text_sample)
                if m:
                    return m.group(1).strip()
                return ""

            meta["title"] = _find_pdf_prop("Title")
            author = _find_pdf_prop("Author")
            creator = _find_pdf_prop("Creator")
            producer = _find_pdf_prop("Producer")
            meta["creator"] = author or (creator if not producer else "")
            meta["software"] = producer or creator
            created_raw = _find_pdf_prop("CreationDate")
            if created_raw and created_raw.startswith("D:"):
                meta["created"] = normalize_iso_utc(created_raw[2:16])
            mod_raw = _find_pdf_prop("ModDate")
            if mod_raw and mod_raw.startswith("D:"):
                meta["modified"] = normalize_iso_utc(mod_raw[2:16])
        except Exception:
            pass
        return {k: v for k, v in meta.items() if v}

    return {}


_SPANISH_CIF_RE = re.compile(r"\b([A-HJ-NP-SUVW])[-\s]?(\d{7}[0-9A-J])\b")
_SPANISH_COMPANY_RE = re.compile(
    r"\b([A-ZÁÉÍÓÚÑ][A-Za-záéíóúñÁÉÍÓÚÑ0-9\s,\.&-]{2,55}?\s+(?:S\.L\.U\.|S\.L\.|S\.A\.U\.|S\.A\.))"
)
_ARCHIVE_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,190}\.[a-zA-Z]{2,12}")
_SPANISH_PHONE_RE = re.compile(r"(?:\+34[\s.-]?)?\b([6789]\d{2}[\s.-]?\d{2,3}[\s.-]?\d{2,3}(?:[\s.-]?\d{2})?)\b")
_ARCHIVE_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PRIORITY_ARCHIVE_PATHS = (
    "aviso-legal",
    "legal",
    "privacidad",
    "privacy",
    "contacto",
    "contact",
    "quienes-somos",
    "about",
    "terminos",
    "condiciones",
)


def extract_archived_html_entities(html_text: str) -> dict[str, list[str]]:
    """Extrae determinísticamente CIF/NIF, razones sociales, correos, teléfonos y título desde HTML archivado."""
    sample = html_text[:250_000]
    cifs: list[str] = []
    seen_cifs: set[str] = set()
    for letter, digits in _SPANISH_CIF_RE.findall(sample):
        norm_cif = f"{letter.upper()}{digits.upper()}"
        if norm_cif not in seen_cifs:
            seen_cifs.add(norm_cif)
            cifs.append(norm_cif)

    companies: list[str] = []
    seen_comp: set[str] = set()
    for raw_c in _SPANISH_COMPANY_RE.findall(sample):
        clean_c = " ".join(raw_c.split()).strip(" ,-")
        if 5 <= len(clean_c) <= 70 and clean_c.lower() not in seen_comp and "<" not in clean_c and ">" not in clean_c:
            seen_comp.add(clean_c.lower())
            companies.append(clean_c)

    emails: list[str] = []
    seen_em: set[str] = set()
    for raw_e in _ARCHIVE_EMAIL_RE.findall(sample):
        em = raw_e.lower().strip(".")
        if any(em.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff")):
            continue
        if em not in seen_em:
            seen_em.add(em)
            emails.append(em)

    phones: list[str] = []
    seen_ph: set[str] = set()
    for raw_p in _SPANISH_PHONE_RE.findall(sample):
        digits_only = re.sub(r"\D", "", raw_p)
        if len(digits_only) == 9 and digits_only[0] in "6789" and digits_only not in seen_ph:
            # Evitar confundir CIFs o timestamps con teléfonos si no hay separadores o contexto
            seen_ph.add(digits_only)
            phones.append(f"+34 {digits_only[:3]} {digits_only[3:6]} {digits_only[6:]}")

    titles: list[str] = []
    m_title = _ARCHIVE_TITLE_RE.search(sample)
    if m_title:
        clean_t = " ".join(m_title.group(1).split())[:140]
        if clean_t:
            titles.append(clean_t)

    return {
        "cifs": cifs[:10],
        "companies": companies[:10],
        "emails": emails[:20],
        "phones": phones[:15],
        "titles": titles[:3],
    }


async def fetch_wayback_snapshot_entities(
    client: httpx.AsyncClient, target: str, max_snapshots: int = 3
) -> dict[str, Any]:
    """Recupera instantáneas HTML desde web.archive.org (100 % pasivo, sin tocar el objetivo) y extrae entidades."""
    from maltego_mcp.egress import get_following

    clean_t = target.strip().rstrip(".")
    domain = urllib.parse.urlsplit(clean_t).hostname or clean_t.split("/")[0]
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": ["statuscode:200", "mimetype:text/html"],
        "collapse": "urlkey",
        "limit": "80",
    }
    candidates: list[tuple[int, str, str]] = []
    try:
        resp = await get_following(client, cdx_url, params=params, timeout=15.0)
        if resp.status_code == 200:
            rows = resp.json()
            if isinstance(rows, list) and len(rows) >= 2:
                headers = [str(h).lower() for h in rows[0]]
                for r in rows[1:]:
                    item = dict(zip(headers, [str(c) for c in r], strict=False))
                    orig = item.get("original", "")
                    raw_ts = item.get("timestamp", "")
                    if not orig or not raw_ts or not raw_ts.isdigit():
                        continue
                    low_orig = orig.lower()
                    if any(low_orig.endswith(ext) for ext in (".css", ".js", ".xml", ".json", ".ico", ".rss")):
                        continue
                    path = urllib.parse.urlsplit(orig).path.strip("/").lower()
                    score = 0
                    if not path:
                        score = 100
                    elif any(k in path for k in _PRIORITY_ARCHIVE_PATHS):
                        score = 95
                    elif path.count("/") == 0:
                        score = 60
                    else:
                        score = 20
                    candidates.append((score, raw_ts, orig))
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        pass

    candidates.sort(key=lambda x: (-x[0], -int(x[1])))
    selected = candidates[: max(1, min(max_snapshots, 4))]

    agg: dict[str, list[str]] = {"cifs": [], "companies": [], "emails": [], "phones": [], "titles": []}
    snapshots_fetched: list[dict[str, str]] = []

    for _, raw_ts, orig in selected:
        snap_url = f"https://web.archive.org/web/{raw_ts}id_/{orig}"
        try:
            snap_resp = await get_following(client, snap_url, timeout=15.0)
            if snap_resp.status_code != 200:
                continue
            ext = extract_archived_html_entities(snap_resp.text)
            snapshots_fetched.append({"timestamp": normalize_iso_utc(raw_ts), "url": orig, "archive_url": snap_url})
            for k in agg:
                for val in ext.get(k, []):
                    if val not in agg[k]:
                        agg[k].append(val)
        except (EgressBlockedError, EgressKillSwitchError):
            raise
        except Exception:
            continue

    return {
        "domain": domain,
        "snapshots": snapshots_fetched,
        "entities": agg,
        "independence_cluster": CLUSTER_WAYBACK,
    }


CLUSTER_BOE = "gov_boe_borme"
CLUSTER_COMMONCRAWL = "archive_commoncrawl_cdx"
CLUSTER_ANUBIS = "osint_anubis_subdomains"
CLUSTER_OPENMERCANTIL = "gov_borme_openmercantil"
CLUSTER_GLEIF = "gov_gleif_lei"
CLUSTER_VIES = "gov_eu_vies"
CLUSTER_IPAPI_IS = "ip_context_ipapi_is"
CLUSTER_EPSS = "vuln_first_epss"
CLUSTER_THREATFOX = "cti_abusech_threatfox"

_DEFAULT_CC_INDEX_URL = "https://index.commoncrawl.org/CC-MAIN-2026-43-index"
_CORP_SUFFIX_RE = re.compile(
    r"\b(?:S\.?L\.?U\.?|S\.?L\.?L\.?|S\.?L\.?|S\.?A\.?U\.?|S\.?A\.?|SOCIEDAD\s+LIMITADA|SOCIEDAD\s+ANONIMA)\b\.?",
    re.IGNORECASE,
)
_EU_VAT_RE = re.compile(
    r"^(?:(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[-\s]?)?"
    r"([A-Z0-9]{7,12})$",
    re.IGNORECASE,
)


async def fetch_anubis_subdomains(client: httpx.AsyncClient, domain: str, limit: int = 100) -> list[dict[str, str]]:
    """Consulta pasiva de subdominios en AnubisDB (https://anubisdb.com/anubis/subdomains/{domain})."""
    from maltego_mcp.egress import get_following

    clean_d = domain.strip().lower().rstrip(".")
    if not clean_d or "." not in clean_d:
        return []
    url = f"https://anubisdb.com/anubis/subdomains/{urllib.parse.quote(clean_d)}"
    try:
        resp = await get_following(client, url, timeout=10.0)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not isinstance(data, list):
            return []
        seen: set[str] = set()
        out: list[dict[str, str]] = []
        for raw in data:
            sub = str(raw or "").strip().lower().lstrip("*.").rstrip(".")
            if not sub or sub == clean_d or not sub.endswith("." + clean_d):
                continue
            if sub not in seen:
                seen.add(sub)
                out.append(
                    {
                        "subdomain": sub,
                        "source": "anubisdb",
                        "independence_cluster": CLUSTER_ANUBIS,
                        "possible_canary": "true" if is_possible_canary(sub) else "false",
                    }
                )
            if len(out) >= limit:
                break
        return out
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


async def fetch_commoncrawl_cdx(client: httpx.AsyncClient, domain: str, limit: int = 100) -> list[dict[str, str]]:
    """Consulta el índice CDX de Common Crawl usando prefijo SURT directo (evita timeouts de comodín inicial)."""
    import json as _json

    from maltego_mcp.egress import get_following

    clean_d = domain.strip().lower().rstrip(".")
    if not clean_d or "." not in clean_d:
        return []
    params = {
        "url": f"{clean_d}/*",
        "output": "json",
        "limit": str(min(max(limit, 1), 200)),
    }
    try:
        resp = await get_following(client, _DEFAULT_CC_INDEX_URL, params=params, timeout=12.0)
        if resp.status_code != 200:
            return []
        out: list[dict[str, str]] = []
        seen: set[str] = set()
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                it = _json.loads(line)
            except Exception:
                continue
            orig = str(it.get("url") or it.get("original") or "").strip()
            if not orig or orig in seen:
                continue
            seen.add(orig)
            out.append(
                {
                    "url": orig,
                    "timestamp": normalize_iso_utc(it.get("timestamp", "")),
                    "mimetype": str(it.get("mime") or it.get("mime-detected") or ""),
                    "statuscode": str(it.get("status") or ""),
                    "digest": str(it.get("digest") or ""),
                    "source": "commoncrawl_cdx",
                    "independence_cluster": CLUSTER_COMMONCRAWL,
                }
            )
            if len(out) >= limit:
                break
        return out
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []


async def fetch_vies_vat(client: httpx.AsyncClient, vat_raw: str) -> dict[str, str] | None:
    """Valida pasivamente un NIF/CIF/VAT intracomunitario en el censo europeo VIES (REST API oficial)."""
    from maltego_mcp.egress import get_following

    clean = re.sub(r"[^A-Za-z0-9]", "", vat_raw.strip().upper())
    if clean.startswith("CIF") or clean.startswith("NIF") or clean.startswith("VAT"):
        clean = clean[3:]
    m = _EU_VAT_RE.match(clean)
    if not m:
        return None
    country = (m.group(1) or "").upper()
    vat_num = m.group(2).upper()
    if not country:
        # Si coincide con estructura de CIF/NIF español, asumir ES por defecto
        if _SPANISH_CIF_RE.fullmatch(vat_num) or re.fullmatch(r"\d{8}[A-Z]", vat_num):
            country = "ES"
        else:
            return None
    url = (
        f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/"
        f"{urllib.parse.quote(country)}/vat/{urllib.parse.quote(vat_num)}"
    )
    try:
        resp = await get_following(client, url, timeout=10.0)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not isinstance(data, dict):
            return None
        is_valid = bool(data.get("isValid"))
        user_error = str(data.get("userError") or "")
        if not is_valid and user_error not in ("VALID",):
            return None
        name = str(data.get("name") or "").strip()
        if name in ("---", "-", "none", "null"):
            name = ""
        address = " ".join(str(data.get("address") or "").split()).strip()
        if address in ("---", "-", "none", "null"):
            address = ""
        return {
            "country": country,
            "vat_number": vat_num,
            "full_vat": f"{country}{vat_num}",
            "is_valid": "true" if is_valid else "false",
            "name": name,
            "address": address,
            "request_date": normalize_iso_utc(data.get("requestDate", "")),
            "source": "eu_vies",
            "independence_cluster": CLUSTER_VIES,
        }
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return None


async def fetch_openmercantil_records(
    client: httpx.AsyncClient,
    query: str,
    *,
    is_person: bool = False,
    limit: int = 15,
) -> list[dict[str, str]]:
    """Consulta pasiva a OpenMercantil (BORME estructurado, CIF, domicilio, cargos vigentes/históricos y actos)."""
    from maltego_mcp.egress import get_following

    raw_q = " ".join(query.strip().split())
    if not raw_q or len(raw_q) < 2:
        return []

    records: list[dict[str, str]] = []
    seen_keys: set[str] = set()

    def _add(rec: dict[str, str]) -> None:
        key = f"{rec.get('kind')}:{rec.get('value', '').lower()}"
        if rec.get("value") and key not in seen_keys and len(records) < limit:
            seen_keys.add(key)
            records.append(rec)

    # Modo 1: Búsqueda e hidratación de Persona Física (administrador / apoderado -> empresas vinculadas)
    if is_person:
        if len(raw_q) < 3:
            return []
        try:
            resp = await get_following(
                client,
                "https://openmercantil.es/api/v1/person/search",
                params={"q": raw_q, "limit": "5"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                pdata = resp.json()
                items = pdata.get("items") if isinstance(pdata, dict) else []
                for p_item in (items or [])[:3]:
                    p_slug = str(p_item.get("slug") or "").strip()
                    if not p_slug:
                        continue
                    det_resp = await get_following(
                        client,
                        f"https://openmercantil.es/api/v1/person/{urllib.parse.quote(p_slug)}",
                        timeout=10.0,
                    )
                    if det_resp.status_code != 200:
                        continue
                    det = det_resp.json()
                    if not isinstance(det, dict):
                        continue
                    p_name = str(det.get("name") or p_item.get("name") or raw_q).strip()
                    positions = list(det.get("active_positions") or []) + list(det.get("inactive_positions") or [])
                    for pos in positions:
                        comp_name = str(pos.get("company_name") or pos.get("company") or "").strip()
                        cif = str(pos.get("cif") or "").strip()
                        role = str(pos.get("role") or "CARGO").strip()
                        since = normalize_iso_utc(pos.get("since") or det.get("first_seen") or "")
                        until = normalize_iso_utc(pos.get("until") or det.get("last_seen") or "")
                        if comp_name:
                            _add(
                                {
                                    "kind": "borme_company",
                                    "value": comp_name,
                                    "cif": cif,
                                    "role": role,
                                    "person_name": p_name,
                                    "first_seen": since,
                                    "last_seen": until or since,
                                    "timestamp": until or since,
                                    "title": f"[BORME Cargo] {p_name} -> {role} en {comp_name}",
                                    "url": f"https://openmercantil.es/persona/{p_slug}",
                                    "source": "openmercantil",
                                    "independence_cluster": CLUSTER_OPENMERCANTIL,
                                }
                            )
                        if cif:
                            _add(
                                {
                                    "kind": "borme_cif",
                                    "value": cif,
                                    "company_name": comp_name,
                                    "timestamp": until or since,
                                    "title": f"[CIF] {cif} ({comp_name})",
                                    "url": f"https://openmercantil.es/persona/{p_slug}",
                                    "source": "openmercantil",
                                    "independence_cluster": CLUSTER_OPENMERCANTIL,
                                }
                            )
        except (EgressBlockedError, EgressKillSwitchError):
            raise
        except Exception:
            pass
        return records

    # Modo 2: Búsqueda de Empresa o CIF (con fallback sin sufijo societario / token distintivo)
    clean_co = _CORP_SUFFIX_RE.sub("", raw_q).strip(" ,.-")
    if clean_co.upper().startswith("[CIF]"):
        clean_co = clean_co[5:].strip()
    queries_to_try = [clean_co or raw_q]
    tokens = [t for t in re.split(r"[\s,.-]+", clean_co) if len(t) >= 4]
    if len(tokens) > 1:
        longest_tok = max(tokens, key=len)
        if longest_tok.lower() != clean_co.lower():
            queries_to_try.append(longest_tok)

    matched_items: list[dict[str, Any]] = []
    for q_candidate in queries_to_try:
        try:
            resp = await get_following(
                client,
                "https://openmercantil.es/api/v1/search",
                params={"q": q_candidate, "limit": "5"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                sdata = resp.json()
                raw_items = sdata.get("items") if isinstance(sdata, dict) else []
                if raw_items:
                    matched_items = list(raw_items)
                    break
        except (EgressBlockedError, EgressKillSwitchError):
            raise
        except Exception:
            continue

    for item in matched_items[:3]:
        slug = str(item.get("slug") or "").strip()
        co_name = str(item.get("name") or "").strip()
        cif = str(item.get("cif") or "").strip()
        province = str(item.get("province") or "").strip()
        first_seen = normalize_iso_utc(item.get("first_seen") or "")
        last_seen = normalize_iso_utc(item.get("last_seen") or "")

        if co_name:
            _add(
                {
                    "kind": "borme_company",
                    "value": co_name,
                    "cif": cif,
                    "province": province,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "timestamp": last_seen or first_seen,
                    "title": f"[BORME Sociedad] {co_name}" + (f" (CIF: {cif})" if cif else ""),
                    "url": f"https://openmercantil.es/empresa/{slug}" if slug else "https://openmercantil.es",
                    "source": "openmercantil",
                    "independence_cluster": CLUSTER_OPENMERCANTIL,
                }
            )
        if cif:
            _add(
                {
                    "kind": "borme_cif",
                    "value": cif,
                    "company_name": co_name,
                    "timestamp": last_seen or first_seen,
                    "title": f"[CIF] {cif} — {co_name}",
                    "url": f"https://openmercantil.es/empresa/{slug}" if slug else "https://openmercantil.es",
                    "source": "openmercantil",
                    "independence_cluster": CLUSTER_OPENMERCANTIL,
                }
            )

        if not slug:
            continue

        # Hidratación de ficha completa de la empresa (/api/v1/company/{slug})
        try:
            c_resp = await get_following(
                client,
                f"https://openmercantil.es/api/v1/company/{urllib.parse.quote(slug)}",
                timeout=10.0,
            )
            if c_resp.status_code != 200:
                continue
            c_data = c_resp.json()
            if not isinstance(c_data, dict):
                continue
            comp_obj = c_data.get("company") or {}
            address = str(comp_obj.get("address") or "").strip()
            website = str(comp_obj.get("website") or "").strip()
            status = str(comp_obj.get("status") or "").strip()
            if address:
                _add(
                    {
                        "kind": "borme_address",
                        "value": address,
                        "company_name": co_name,
                        "timestamp": last_seen or first_seen,
                        "title": f"[Domicilio Social] {address}",
                        "url": f"https://openmercantil.es/empresa/{slug}",
                        "source": "openmercantil",
                        "independence_cluster": CLUSTER_OPENMERCANTIL,
                    }
                )
            if website and "." in website:
                _add(
                    {
                        "kind": "borme_website",
                        "value": website,
                        "company_name": co_name,
                        "timestamp": last_seen or first_seen,
                        "title": f"[Web BORME] {website}",
                        "url": f"https://openmercantil.es/empresa/{slug}",
                        "source": "openmercantil",
                        "independence_cluster": CLUSTER_OPENMERCANTIL,
                    }
                )
            officers_obj = c_data.get("officers") or {}
            all_officers = [(o, "current") for o in (officers_obj.get("current") or []) if isinstance(o, dict)] + [
                (o, "historical") for o in (officers_obj.get("historical") or []) if isinstance(o, dict)
            ]
            for off, off_status in all_officers[:8]:
                o_name = str(off.get("name") or "").strip()
                o_role = str(off.get("role") or "CARGO").strip()
                o_since = normalize_iso_utc(off.get("since") or off.get("date_from") or first_seen)
                if o_name:
                    _add(
                        {
                            "kind": "borme_officer",
                            "value": o_name,
                            "role": o_role,
                            "officer_status": off_status,
                            "company_name": co_name,
                            "cif": cif,
                            "timestamp": o_since or last_seen,
                            "title": f"[Cargo BORME {off_status}] {o_name} ({o_role} en {co_name})",
                            "url": f"https://openmercantil.es/empresa/{slug}",
                            "source": "openmercantil",
                            "independence_cluster": CLUSTER_OPENMERCANTIL,
                        }
                    )
            for ev in (c_data.get("events") or [])[:4]:
                if not isinstance(ev, dict):
                    continue
                ev_type = str(ev.get("type") or "Acto").strip()
                ev_date = normalize_iso_utc(ev.get("date") or "")
                ev_details = " ".join(str(ev.get("details") or ev.get("description") or "").split())[:180]
                if ev_details:
                    _add(
                        {
                            "kind": "borme_act",
                            "value": f"[BORME {ev_date[:10] or status} · {ev_type}] {ev_details}",
                            "company_name": co_name,
                            "timestamp": ev_date or last_seen,
                            "title": f"[BORME {ev_type}] {co_name}",
                            "url": f"https://openmercantil.es/empresa/{slug}",
                            "source": "openmercantil",
                            "independence_cluster": CLUSTER_OPENMERCANTIL,
                        }
                    )
        except (EgressBlockedError, EgressKillSwitchError):
            raise
        except Exception:
            continue

    return records


async def fetch_gleif_corporate(client: httpx.AsyncClient, query: str, limit: int = 10) -> list[dict[str, str]]:
    """Consulta pasiva al registro corporativo global GLEIF (LEI, NIF registral, sede y sociedades matrices)."""
    from maltego_mcp.egress import get_following

    clean_q = " ".join(query.strip().split())
    if not clean_q or len(clean_q) < 2:
        return []
    search_term = _CORP_SUFFIX_RE.sub("", clean_q).strip(" ,.-") or clean_q
    url = "https://api.gleif.org/api/v1/lei-records"
    params = {"filter[entity.legalName]": search_term, "page[size]": str(min(max(limit, 1), 5))}
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    def _add(item: dict[str, str]) -> None:
        k = f"{item.get('kind')}:{item.get('value', '').lower()}"
        if item.get("value") and k not in seen and len(out) < limit:
            seen.add(k)
            out.append(item)

    try:
        resp = await get_following(client, url, params=params, timeout=12.0)
        if resp.status_code != 200:
            return []
        payload = resp.json()
        rows = payload.get("data") if isinstance(payload, dict) else []
        for rec in (rows or [])[:3]:
            if not isinstance(rec, dict):
                continue
            lei = str(rec.get("id") or "").strip()
            attrs = rec.get("attributes") or {}
            ent = attrs.get("entity") or {}
            reg = attrs.get("registration") or {}
            legal_name = str((ent.get("legalName") or {}).get("name") or "").strip()
            reg_as = str(ent.get("registeredAs") or "").strip()
            jurisdiction = str(ent.get("jurisdiction") or "").strip()
            status = str(ent.get("status") or "").strip()
            last_update = normalize_iso_utc(reg.get("lastUpdateDate") or reg.get("initialRegistrationDate") or "")
            legal_addr = ent.get("legalAddress") or {}
            addr_lines = [str(x).strip() for x in (legal_addr.get("addressLines") or []) if x]
            city = str(legal_addr.get("city") or "").strip()
            country = str(legal_addr.get("country") or jurisdiction).strip()
            full_addr = ", ".join([*addr_lines, city, country]).strip(", ")

            if legal_name:
                _add(
                    {
                        "kind": "gleif_company",
                        "value": legal_name,
                        "lei": lei,
                        "registered_as": reg_as,
                        "jurisdiction": jurisdiction,
                        "status": status,
                        "timestamp": last_update,
                        "source": "gleif",
                        "independence_cluster": CLUSTER_GLEIF,
                    }
                )
            if lei:
                _add(
                    {
                        "kind": "gleif_lei",
                        "value": f"[LEI] {lei}" + (f" (Reg: {reg_as})" if reg_as else ""),
                        "lei": lei,
                        "registered_as": reg_as,
                        "company_name": legal_name,
                        "timestamp": last_update,
                        "source": "gleif",
                        "independence_cluster": CLUSTER_GLEIF,
                    }
                )
            if full_addr:
                _add(
                    {
                        "kind": "gleif_location",
                        "value": full_addr,
                        "company_name": legal_name,
                        "country": country,
                        "timestamp": last_update,
                        "source": "gleif",
                        "independence_cluster": CLUSTER_GLEIF,
                    }
                )

            # Consulta de sociedad matriz directa o última si está declarada
            rels = rec.get("relationships") or {}
            for rel_key, rel_label in (("direct-parent", "direct_parent"), ("ultimate-parent", "ultimate_parent")):
                links_obj = (rels.get(rel_key) or {}).get("links") or {}
                rel_link = links_obj.get("lei-record") or links_obj.get("related")
                if not rel_link or not isinstance(rel_link, str):
                    continue
                try:
                    p_resp = await get_following(client, rel_link, timeout=8.0)
                    if p_resp.status_code == 200:
                        p_data = (p_resp.json() or {}).get("data") or {}
                        p_ent = (p_data.get("attributes") or {}).get("entity") or {}
                        p_name = str((p_ent.get("legalName") or {}).get("name") or "").strip()
                        p_lei = str(p_data.get("id") or "").strip()
                        p_jur = str(p_ent.get("jurisdiction") or "").strip()
                        if p_name and p_name.lower() != legal_name.lower():
                            _add(
                                {
                                    "kind": "gleif_parent",
                                    "value": p_name,
                                    "lei": p_lei,
                                    "jurisdiction": p_jur,
                                    "relation": rel_label,
                                    "timestamp": last_update,
                                    "source": "gleif",
                                    "independence_cluster": CLUSTER_GLEIF,
                                }
                            )
                except (EgressBlockedError, EgressKillSwitchError):
                    raise
                except Exception:
                    continue
    except (EgressBlockedError, EgressKillSwitchError):
        raise
    except Exception:
        return []
    return out


async def fetch_boe_borme_records(
    client: httpx.AsyncClient,
    query: str,
    limit: int = 15,
    *,
    is_person: bool = False,
) -> list[dict[str, str]]:
    """Consulta pasiva unificada de BORME (OpenMercantil), censo VIES, BOE histórico y certificados CT por Org."""
    from maltego_mcp.egress import get_following

    clean_q = " ".join(query.strip().split())
    if not clean_q or len(clean_q) < 2:
        return []

    records: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    # 0. OpenMercantil (BORME estructurado: sociedades, CIF, domicilio, cargos y actos registrales)
    om_records = await fetch_openmercantil_records(client, clean_q, is_person=is_person, limit=limit)
    for r in om_records:
        records.append(r)

    # 0b. Si la consulta es o contiene un NIF/CIF/VAT intracomunitario (o si OpenMercantil descubrió el CIF),
    # validar pasivamente en el censo europeo EU VIES.
    discovered_cif = next((r.get("cif", "") for r in om_records if r.get("cif")), "")
    vies_info = await fetch_vies_vat(client, clean_q)
    if not vies_info and discovered_cif:
        vies_info = await fetch_vies_vat(client, discovered_cif)
    if vies_info:
        v_name = vies_info.get("name", "")
        v_addr = vies_info.get("address", "")
        v_vat = vies_info.get("full_vat", "")
        records.append(
            {
                "kind": "vies_vat",
                "value": f"[VIES VALIDADO] {v_vat}" + (f" — {v_name}" if v_name else ""),
                "title": f"[VIES UE] {v_vat} válido en censo intracomunitario",
                "timestamp": vies_info.get("request_date", ""),
                "url": "https://ec.europa.eu/taxation_customs/vies/",
                "source": "eu_vies",
                "independence_cluster": CLUSTER_VIES,
            }
        )
        if v_name:
            records.append(
                {
                    "kind": "borme_company",
                    "value": v_name,
                    "cif": v_vat,
                    "timestamp": vies_info.get("request_date", ""),
                    "title": f"[Razón Social VIES] {v_name}",
                    "url": "https://ec.europa.eu/taxation_customs/vies/",
                    "source": "eu_vies",
                    "independence_cluster": CLUSTER_VIES,
                }
            )
        if v_addr:
            records.append(
                {
                    "kind": "borme_address",
                    "value": v_addr,
                    "company_name": v_name,
                    "timestamp": vies_info.get("request_date", ""),
                    "title": f"[Domicilio VIES] {v_addr}",
                    "url": "https://ec.europa.eu/taxation_customs/vies/",
                    "source": "eu_vies",
                    "independence_cluster": CLUSTER_VIES,
                }
            )

    # 1. Consulta en índice de certificados CT por organización (si no es persona física)
    if not is_person:
        certs = await fetch_crtsh_by_org(client, clean_q, limit=min(limit, 10))
        for c in certs:
            dom = c.get("domain", "")
            if dom and dom not in seen_urls:
                seen_urls.add(dom)
                records.append(
                    {
                        "kind": "cert_org",
                        "value": dom,
                        "title": f"[CT Org] Certificado emitido para '{clean_q}': {dom}",
                        "timestamp": c.get("not_before", ""),
                        "url": f"https://crt.sh/?O={urllib.parse.quote(clean_q)}",
                        "source": "crtsh_org",
                        "independence_cluster": CLUSTER_CRTSH,
                    }
                )

    # 2. Comprobación pasiva de boletines BORME/BOE archivados en Wayback CDX
    slug = re.sub(r"[^a-z0-9]+", "-", clean_q.lower()).strip("-")
    if slug:
        try:
            resp = await get_following(
                client,
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"boe.es/*{slug}*",
                    "output": "json",
                    "fl": "timestamp,original,statuscode",
                    "collapse": "urlkey",
                    "limit": str(min(limit, 15)),
                },
                timeout=12.0,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if isinstance(rows, list) and len(rows) >= 2:
                    headers = [str(h).lower() for h in rows[0]]
                    for r in rows[1:]:
                        item = dict(zip(headers, [str(c) for c in r], strict=False))
                        orig = item.get("original", "")
                        if orig and orig not in seen_urls:
                            seen_urls.add(orig)
                            records.append(
                                {
                                    "kind": "boe_url",
                                    "value": orig,
                                    "title": f"[BOE/BORME] Publicación indexada para '{clean_q}'",
                                    "timestamp": normalize_iso_utc(item.get("timestamp", "")),
                                    "url": orig,
                                    "source": "boe_wayback",
                                    "independence_cluster": CLUSTER_BOE,
                                }
                            )
        except (EgressBlockedError, EgressKillSwitchError):
            raise
        except Exception:
            pass
    return records[:limit]
