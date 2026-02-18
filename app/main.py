from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, quote_plus
from datetime import datetime, timezone
import uuid
import asyncio
import re
import json
import io
import os
import xml.etree.ElementTree as ET

import httpx
from bs4 import BeautifulSoup
import tldextract

from PIL import Image, ImageDraw, ImageFont
import imagehash
import piexif

# DB
import sqlite3
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:
    psycopg2 = None
    RealDictCursor = None


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(title="VeriScan V1 Demo (Hosted)")
APP_VERSION = "veriscan-corroboration-v7_2-bing-rss-links-2026-02-18"

UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Caches
DOMAIN_AGE_CACHE: dict[str, dict] = {}
CORRO_CACHE: dict[str, dict] = {}

# Env
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = str((BASE_DIR / "veriscan.db").resolve())
POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")


TRUSTED_DOMAINS = {
    "reuters.com",
    "apnews.com",
    "bbc.com",
    "bbc.co.uk",
    "npr.org",
    "nytimes.com",
    "washingtonpost.com",
    "theguardian.com",
    "cnn.com",
    "wsj.com",
    "bloomberg.com",
    "cnbc.com",
    "abcnews.go.com",
    "nbcnews.com",
    "usatoday.com",
    "forbes.com",
    "time.com",
    "economist.com",
    "aljazeera.com",
    "propublica.org",
    "pbs.org",
    "axios.com",
    "politico.com",
    "who.int",
    "cdc.gov",
    "fda.gov",
    "nih.gov",
}


# -------------------------
# Database
# -------------------------

def _pg_connect():
    if not psycopg2:
        raise RuntimeError("psycopg2 not installed. Add psycopg2-binary to requirements.txt")
    dsn = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(dsn)


def _sqlite_connect():
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    if POSTGRES:
        conn = _pg_connect()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    report_json TEXT,
                    error_text TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """)
            conn.commit()
        finally:
            conn.close()
    else:
        conn = _sqlite_connect()
        try:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                report_json TEXT,
                error_text TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)
            conn.commit()
        finally:
            conn.close()


def db_upsert_scan(scan_id: str, status: str, report: dict | None = None, error: str | None = None):
    report_json = json.dumps(report) if report is not None else None

    if POSTGRES:
        conn = _pg_connect()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                INSERT INTO scans (scan_id, status, report_json, error_text, created_at, updated_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (scan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    report_json = EXCLUDED.report_json,
                    error_text = EXCLUDED.error_text,
                    updated_at = NOW();
                """, (scan_id, status, report_json, error))
            conn.commit()
        finally:
            conn.close()
    else:
        now = datetime.now(timezone.utc).isoformat()
        conn = _sqlite_connect()
        try:
            conn.execute("""
            INSERT INTO scans (scan_id, status, report_json, error_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status=excluded.status,
                report_json=excluded.report_json,
                error_text=excluded.error_text,
                updated_at=excluded.updated_at;
            """, (scan_id, status, report_json, error, now, now))
            conn.commit()
        finally:
            conn.close()


def db_get_scan(scan_id: str) -> dict | None:
    if POSTGRES:
        conn = _pg_connect()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT scan_id, status, report_json, error_text FROM scans WHERE scan_id = %s;", (scan_id,))
                row = cur.fetchone()
                if not row:
                    return None
                report = json.loads(row["report_json"]) if row.get("report_json") else None
                return {
                    "scan_id": row["scan_id"],
                    "status": row["status"],
                    "report": report,
                    "error": row.get("error_text"),
                }
        finally:
            conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.execute("SELECT scan_id, status, report_json, error_text FROM scans WHERE scan_id = ?;", (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            report = json.loads(row["report_json"]) if row["report_json"] else None
            return {
                "scan_id": row["scan_id"],
                "status": row["status"],
                "report": report,
                "error": row["error_text"],
            }
        finally:
            conn.close()


@app.on_event("startup")
def _startup():
    db_init()


# -------------------------
# Helpers
# -------------------------

def is_url_safe(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if host in ("localhost",) or host.endswith(".local"):
        return False
    return True


def clamp(x: int) -> int:
    return max(0, min(100, x))


def band_label(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Limited"
    if score >= 20:
        return "Weak"
    return "Uncertain"


def normalize_domain(d: str) -> str:
    return (d or "").lower().strip().lstrip(".")


def parse_domain(url: str) -> str | None:
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _parse_rdap_created(events: list[dict]) -> datetime | None:
    for e in events or []:
        action = (e.get("eventAction") or "").lower()
        if action in ("registration", "created"):
            dt = e.get("eventDate")
            if not dt:
                continue
            try:
                if dt.endswith("Z"):
                    dt = dt[:-1] + "+00:00"
                return datetime.fromisoformat(dt)
            except Exception:
                continue
    return None


async def rdap_domain_age_days(domain: str) -> int | None:
    cached = DOMAIN_AGE_CACHE.get(domain)
    if cached:
        fetched_at: datetime = cached.get("fetched_at")
        if fetched_at and (datetime.now(timezone.utc) - fetched_at).days < 30:
            return cached.get("age_days")

    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, headers={"User-Agent": "VeriScan/0.1"}) as client:
            r = await client.get(url)
            if r.status_code != 200:
                DOMAIN_AGE_CACHE[domain] = {"age_days": None, "fetched_at": datetime.now(timezone.utc)}
                return None
            data = r.json()
    except Exception:
        DOMAIN_AGE_CACHE[domain] = {"age_days": None, "fetched_at": datetime.now(timezone.utc)}
        return None

    created = _parse_rdap_created(data.get("events", []))
    if not created:
        DOMAIN_AGE_CACHE[domain] = {"age_days": None, "fetched_at": datetime.now(timezone.utc)}
        return None

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age_days = max((datetime.now(timezone.utc) - created).days, 0)
    DOMAIN_AGE_CACHE[domain] = {"age_days": age_days, "fetched_at": datetime.now(timezone.utc)}
    return age_days


def strip_publisher_terms(title: str, domain: str | None) -> str:
    t = (title or "").strip()
    if not t:
        return ""
    t = re.sub(r"\s*[:\|\-]\s*[A-Za-z0-9\.]{2,}\s*$", "", t).strip()
    base = (domain or "").split(".")[0].lower().strip()
    if base:
        t = re.sub(rf"\b{re.escape(base)}\b", "", t, flags=re.IGNORECASE).strip()
    t = re.sub(r"\b(npr|reuters|ap|bbc|cnn)\b", "", t, flags=re.IGNORECASE).strip()
    t = re.sub(r"\s+", " ", t).strip()
    return t


def extract_entityish_terms(title: str) -> list[str]:
    if not title:
        return []
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9\-’']+", title)
    stop_caps = {
        "The","A","An","And","Or","But","To","Of","In","On","For","With","From","By","At",
        "This","That","These","Those","It","Its","As","Is","Are","Was","Were","Be","Been",
        "Breaking","Live","Update","Opinion","Analysis","Longtime"
    }
    picks = []
    for t in tokens:
        if t in stop_caps:
            continue
        if (t.isupper() and len(t) >= 2) or (t[0].isupper() and len(t) >= 3):
            picks.append(t)

    seen = set()
    out = []
    for p in picks:
        pl = p.lower()
        if pl not in seen:
            seen.add(pl)
            out.append(p)
    return out[:6]


def build_claim_query(title: str, domain: str | None) -> str:
    clean = strip_publisher_terms(title, domain)
    if not clean:
        return ""
    clean = re.sub(r"\b(rev|reverend|mr|mrs|ms|dr)\.?\b", "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"\s+", " ", clean).strip()
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9\-’']+|\d+", clean)

    action_words = {
        "dies","dead","killed","killing","murder","arrested","charged","sentenced",
        "wins","won","loses","lost","lawsuit","sued","sues","indicted","resigns","steps",
        "announces","launches","files","bans","ban","approves","rejects","fires","fired",
        "hospitalized","missing","found","confirms","denies"
    }
    stop = {
        "the","a","an","and","or","but","to","of","in","on","for","with","from","by","at",
        "this","that","these","those","it","its","as","is","are","was","were","be","been",
        "longtime","latest","update","live","exclusive","report","reports","analysis","opinion",
        "leader","leaders","civil","rights"
    }

    entities = extract_entityish_terms(clean)
    ent_part = [e.lower() for e in entities[:2]]

    action_part = []
    for t in tokens:
        tl = t.lower()
        if tl in action_words:
            action_part = [tl]
            break

    nums = [t for t in tokens if t.isdigit()]
    num_part = nums[:2]

    extras = []
    for t in tokens:
        tl = t.lower()
        if tl in stop:
            continue
        if tl in ent_part:
            continue
        if tl in action_part:
            continue
        if t.isdigit():
            continue
        if len(tl) >= 5:
            extras.append(tl)
        if len(extras) >= 3:
            break

    parts = []
    parts += ent_part
    parts += action_part
    parts += num_part
    parts += extras

    seen = set()
    out = []
    for p in parts:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)

    return " ".join(out[:8]).strip()


def build_corroboration_queries(title: str, domain: str | None) -> list[str]:
    q1 = build_claim_query(title, domain)
    clean_title = strip_publisher_terms(title, domain)
    ents = extract_entityish_terms(clean_title)
    q2 = " ".join([e.lower() for e in ents[:4]]) if ents else ""
    base_dom = (domain or "").split(".")[0].lower().strip()
    q3 = f"{base_dom} {q1}".strip() if base_dom and q1 else ""

    qs = []
    seen = set()
    for q in [q1, q2, q3]:
        q = (q or "").strip()
        if not q:
            continue
        if q in seen:
            continue
        seen.add(q)
        qs.append(q)
    return qs


# -------------------------
# Corroboration: Bing News RSS with Evidence Links — V7.2
# -------------------------

def _unwrap_bing_news_link(u: str) -> str:
    if not u:
        return ""
    try:
        p = urlparse(u)
    except Exception:
        return u
    host = (p.hostname or "").lower()
    if "bing.com" not in host:
        return u
    qs = parse_qs(p.query)
    for key in ("url", "u", "r", "RU"):
        if key in qs and qs[key]:
            return unquote(qs[key][0]).strip()
    return u


async def _resolve_final_url(u: str) -> str:
    if not u:
        return ""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as client:
            try:
                r = await client.head(u)
                if r.status_code < 400:
                    return str(r.url)
            except Exception:
                pass
            r = await client.get(u)
            if r.status_code < 400:
                return str(r.url)
    except Exception:
        return u
    return u


def _parse_rss_items(xml_text: str) -> list[dict]:
    """
    Returns list of items: {title, link}
    """
    out = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out

    # Iterate items, ignore namespaces by checking tag suffix
    for item in root.iter():
        if not item.tag.lower().endswith("item"):
            continue
        title = ""
        link = ""
        for child in list(item):
            tag = child.tag.lower()
            if tag.endswith("title") and child.text and not title:
                title = child.text.strip()
            if tag.endswith("link") and child.text and not link:
                link = child.text.strip()
        if link:
            out.append({"title": title[:220], "link": link})
    return out


def _is_trusted_domain(dom: str) -> str | None:
    """
    Returns the trusted domain matched (from TRUSTED_DOMAINS) or None.
    """
    d = normalize_domain(dom)
    for td in TRUSTED_DOMAINS:
        tdn = normalize_domain(td)
        if d == tdn or d.endswith("." + tdn):
            return td
    return None


async def bing_rss_corroboration_with_links(claim_query: str, exclude_domain: str | None) -> dict:
    exclude = normalize_domain(exclude_domain or "")
    q = quote_plus(claim_query)
    rss_url = f"https://www.bing.com/news/search?q={q}&format=rss"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
        "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
            r = await client.get(rss_url)
            if r.status_code != 200:
                return {"ok": False, "status_code": r.status_code, "rss_url": rss_url}
            xml_text = r.text
    except Exception as e:
        return {"ok": False, "status_code": None, "error": str(e), "rss_url": rss_url}

    items = _parse_rss_items(xml_text)

    # Unwrap links; resolve bing.com redirects (cap)
    unwrapped = []
    for it in items:
        u = _unwrap_bing_news_link(it["link"])
        unwrapped.append({"title": it.get("title", ""), "link": u})

    # resolve remaining bing.com links
    N_RESOLVE = 12
    resolved_count = 0
    for it in unwrapped:
        dom = normalize_domain(parse_domain(it["link"]) or "")
        if (dom == "bing.com" or dom.endswith(".bing.com")) and resolved_count < N_RESOLVE:
            it["link"] = await _resolve_final_url(it["link"])
            resolved_count += 1

    # Build evidence lists
    all_outlet_domains = []
    evidence = []
    trusted_domains_found = set()

    seen_links = set()
    for it in unwrapped:
        link = (it.get("link") or "").strip()
        if not link or link in seen_links:
            continue
        seen_links.add(link)

        dom = normalize_domain(parse_domain(link) or "")
        if not dom:
            continue
        if exclude and (dom == exclude or dom.endswith("." + exclude)):
            continue

        all_outlet_domains.append(dom)

        trusted_match = _is_trusted_domain(dom)
        if trusted_match:
            trusted_domains_found.add(trusted_match)

        evidence.append({
            "title": (it.get("title") or "").strip()[:220],
            "domain": dom,
            "url": link,
            "trusted": bool(trusted_match),
        })

    # unique outlets
    seen = set()
    uniq_outlets = []
    for d in all_outlet_domains:
        if d not in seen:
            seen.add(d)
            uniq_outlets.append(d)

    # Sort evidence: trusted first, then by domain, then title length
    evidence_sorted = sorted(
        evidence,
        key=lambda x: (0 if x["trusted"] else 1, x["domain"], -len(x.get("title") or "")),
    )

    # Keep a reasonable amount
    TOP_EVIDENCE = 8
    evidence_sorted = evidence_sorted[:TOP_EVIDENCE]

    return {
        "ok": True,
        "status_code": 200,
        "rss_url": rss_url,
        "resolved_count": resolved_count,
        "all_outlets_hits": len(uniq_outlets),
        "all_outlets_domains": uniq_outlets,
        "trusted_hits": len(trusted_domains_found),
        "trusted_domains": sorted(trusted_domains_found),
        "evidence_links": evidence_sorted,
    }


async def trusted_corroboration(queries: list[str], exclude_domain: str | None) -> dict:
    queries = [q.strip() for q in (queries or []) if q and q.strip()]
    if not queries:
        return {"hits": None, "domains": [], "queries_used": [], "engine": "none", "debug": {}, "evidence_links": []}

    claim_query = queries[0]
    exclude = normalize_domain(exclude_domain or "")

    cache_key = f"corro_v7_2::{claim_query}||exclude={exclude}"
    cached = CORRO_CACHE.get(cache_key)
    if cached:
        fetched_at: datetime = cached.get("fetched_at")
        if fetched_at and (datetime.now(timezone.utc) - fetched_at).total_seconds() < 3 * 3600:
            return {
                "hits": cached.get("hits"),
                "domains": cached.get("domains", []),
                "queries_used": cached.get("queries_used", [claim_query]),
                "engine": cached.get("engine", "cache"),
                "debug": cached.get("debug", {}),
                "evidence_links": cached.get("evidence_links", []),
            }

    br = await bing_rss_corroboration_with_links(claim_query, exclude_domain)

    if not br.get("ok"):
        result = {
            "hits": None,
            "domains": [],
            "queries_used": [claim_query],
            "engine": "bing_rss",
            "debug": {
                "bing_status": br.get("status_code"),
                "bing_error": br.get("error"),
                "rss_url": br.get("rss_url"),
                "note": "Bing RSS fetch failed; corroboration unavailable.",
            },
            "evidence_links": [],
        }
        CORRO_CACHE[cache_key] = {**result, "fetched_at": datetime.now(timezone.utc)}
        return result

    all_domains = br.get("all_outlets_domains", []) or []
    sample_all = all_domains[:25]

    result = {
        "hits": br.get("trusted_hits", 0),
        "domains": br.get("trusted_domains", []) or [],
        "queries_used": [claim_query],
        "engine": "bing_rss",
        "debug": {
            "bing_status": br.get("status_code"),
            "rss_url": br.get("rss_url"),
            "resolved_count": br.get("resolved_count"),
            "all_outlets_hits": br.get("all_outlets_hits"),
            "all_outlets_sample": sample_all,
        },
        "evidence_links": br.get("evidence_links", []) or [],
    }
    CORRO_CACHE[cache_key] = {**result, "fetched_at": datetime.now(timezone.utc)}
    return result


# -------------------------
# Extraction
# -------------------------

async def fetch_extract(url: str) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
    }

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
        r = await client.get(url)

        if r.status_code in (401, 403):
            final_url = str(r.url)
            https = final_url.startswith("https://")
            domain = parse_domain(final_url)
            domain_age_days = await rdap_domain_age_days(domain) if domain else None
            return {
                "final_url": final_url,
                "title": "",
                "text_snippet": "",
                "outbound_links_count": 0,
                "https": https,
                "domain": domain,
                "domain_age_days": domain_age_days,
                "blocked": True,
                "corroboration_hits": None,
                "corroboration_domains": [],
                "corroboration_queries": [],
                "corroboration_engine": None,
                "corroboration_debug": {"note": "Blocked by site (401/403)."},
                "corroboration_evidence": [],
            }

        r.raise_for_status()
        html = r.text
        final_url = str(r.url)

    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.text.strip() if soup.title else "")[:300]

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = " ".join(soup.get_text(" ").split())
    text_snippet = text[:800]
    outbound_links = len([a for a in soup.find_all("a", href=True)])

    https = final_url.startswith("https://")
    domain = parse_domain(final_url)
    domain_age_days = await rdap_domain_age_days(domain) if domain else None

    queries = build_corroboration_queries(title, domain)
    corro = await trusted_corroboration(queries, exclude_domain=domain)

    return {
        "final_url": final_url,
        "title": title,
        "text_snippet": text_snippet,
        "outbound_links_count": outbound_links,
        "https": https,
        "domain": domain,
        "domain_age_days": domain_age_days,
        "blocked": False,
        "corroboration_hits": corro.get("hits"),
        "corroboration_domains": corro.get("domains", []),
        "corroboration_queries": corro.get("queries_used", []),
        "corroboration_engine": corro.get("engine"),
        "corroboration_debug": corro.get("debug", {}),
        "corroboration_evidence": corro.get("evidence_links", []),
    }


# -------------------------
# Scoring
# -------------------------

def score_link(signals: dict) -> dict:
    https_score = 100 if signals.get("https") else 30
    citations_score = clamp(min(100, int(signals.get("outbound_links_count", 0) * 4)))

    domain_age_days = signals.get("domain_age_days")
    if domain_age_days is None:
        domain_age_score = 50
    else:
        years = domain_age_days / 365.0
        domain_age_score = clamp(int(20 + min(75, years * 13)))

    source = clamp(int(0.45 * https_score + 0.30 * citations_score + 0.25 * domain_age_score))

    hits = signals.get("corroboration_hits")
    if hits is None:
        cross_verify = 50
    else:
        cross_verify = clamp(int(min(100, hits * 25)))

    ai_manip = 50
    context = 60 if signals.get("title") else 40

    overall = int(round(source * 0.30 + cross_verify * 0.35 + ai_manip * 0.20 + context * 0.15))
    overall = clamp(overall)

    unavailable = ["AI_MANIPULATION"]
    if signals.get("domain_age_days") is None:
        unavailable.append("DOMAIN_AGE")
    if signals.get("corroboration_hits") is None:
        unavailable.append("CROSS_VERIFICATION")

    badges = []
    if signals.get("blocked"):
        badges.append("SITE_BLOCKED_AUTOMATION")

    if isinstance(hits, int) and hits >= 3:
        badges.append("MULTI_SOURCE_CORROBORATION")
    elif isinstance(hits, int) and hits == 0:
        badges.append("NO_TRUSTED_CORROBORATION_FOUND")

    if signals.get("blocked"):
        summary = (
            "This site blocked automated access. Domain and basic signals were still analyzed, "
            "but article content could not be fetched."
        )
    else:
        if hits is None:
            summary = (
                f"Source signals are {('strong' if source >= 70 else 'mixed' if source >= 50 else 'weak')}. "
                f"Trusted-source corroboration was unavailable for this scan."
            )
        else:
            summary = (
                f"Source signals are {('strong' if source >= 70 else 'mixed' if source >= 50 else 'weak')}. "
                f"Trusted-source corroboration found: {hits} other trusted domain(s)."
            )

    return {
        "overall_score": overall,
        "band_label": band_label(overall),
        "badges": badges,
        "summary_text": summary,
        "pillars": {
            "source": source,
            "cross_verify": cross_verify,
            "ai_manip": ai_manip,
            "context": context,
        },
        "evidence": {
            "signals": signals,
            "unavailable_signals": unavailable,
        },
    }


def analyze_image(image_path: str) -> dict:
    signals = {
        "exif_present": False,
        "exif_software": None,
        "width": None,
        "height": None,
        "phash": None,
    }

    with Image.open(image_path) as img:
        signals["width"], signals["height"] = img.size
        signals["phash"] = str(imagehash.phash(img))

    try:
        exif_dict = piexif.load(image_path)
        signals["exif_present"] = True if exif_dict and any(exif_dict.values()) else False

        zeroth = exif_dict.get("0th", {})
        software = zeroth.get(piexif.ImageIFD.Software)
        if software:
            if isinstance(software, bytes):
                software = software.decode("utf-8", errors="ignore")
            signals["exif_software"] = str(software)[:200]
    except Exception:
        signals["exif_present"] = False

    return signals


def score_image(signals: dict) -> dict:
    source = 50
    cross_verify = 50
    ai_manip = 50

    context = 65 if signals.get("exif_present") else 50
    if signals.get("exif_software"):
        context = min(80, context + 10)

    overall = int(round(source * 0.30 + cross_verify * 0.35 + ai_manip * 0.20 + context * 0.15))
    overall = clamp(overall)

    unavailable = ["CROSS_VERIFICATION", "SOURCE_CONTEXT", "AI_MANIPULATION", "REVERSE_IMAGE"]

    summary = (
        "Image fingerprint and metadata extracted. Reverse image matches and AI/manipulation classification "
        "are not enabled yet in this demo."
    )

    return {
        "overall_score": overall,
        "band_label": band_label(overall),
        "badges": [],
        "summary_text": summary,
        "pillars": {
            "source": source,
            "cross_verify": cross_verify,
            "ai_manip": ai_manip,
            "context": context,
        },
        "evidence": {
            "signals": signals,
            "unavailable_signals": unavailable,
        },
    }


# -------------------------
# Explain
# -------------------------

def build_explanation(report: dict) -> dict:
    evidence = report.get("evidence") or {}
    signals = evidence.get("signals") or {}
    missing = evidence.get("unavailable_signals") or []

    highlights = []
    concerns = []
    missing_items = []

    is_link = ("final_url" in signals) or ("domain" in signals) or ("https" in signals)
    is_image = ("phash" in signals) or ("width" in signals) or ("exif_present" in signals)

    hits = signals.get("corroboration_hits")
    if isinstance(hits, int):
        if hits >= 3:
            highlights.append(f"Multiple trusted sources appear to cover similar facts ({hits} matched trusted domain(s)).")
        elif hits in (1, 2):
            highlights.append(f"Some trusted corroboration exists ({hits} matched trusted domain(s)).")
        elif hits == 0 and is_link:
            concerns.append("No matches were found on the trusted corroboration list (not proof of falsehood, but less support).")
    else:
        if is_link:
            missing_items.append("Trusted corroboration check was unavailable.")

    age_days = signals.get("domain_age_days")
    if age_days is None and is_link:
        missing_items.append("Domain age could not be determined.")
    elif isinstance(age_days, int):
        if age_days >= 3650:
            highlights.append("The domain is long-established (older domains are harder to spoof at scale).")
        elif age_days < 180:
            concerns.append("The domain is relatively new (new domains are more commonly used for spam/misinformation).")

    https = signals.get("https")
    if https is True and is_link:
        highlights.append("The link uses HTTPS (basic transport security).")
    elif https is False and is_link:
        concerns.append("The link is not using HTTPS (higher risk).")

    if signals.get("blocked") is True and is_link:
        concerns.append("The site blocked automated access; analysis relied more on domain-level signals.")
    elif is_link and signals.get("title"):
        highlights.append("Page title/content signals were available for analysis.")

    out = signals.get("outbound_links_count")
    if isinstance(out, int) and is_link and signals.get("blocked") is False:
        if out >= 15:
            highlights.append("The page links out to multiple references (a weak proxy for citations).")
        elif out <= 1:
            concerns.append("Few or no outbound links were detected (less transparent sourcing).")

    if is_image:
        exif_present = signals.get("exif_present")
        if exif_present is True:
            highlights.append("The image contains EXIF metadata (can help with provenance, though it can be edited).")
        elif exif_present is False:
            concerns.append("The image has no EXIF metadata (common after re-uploads/edits; reduces provenance clues).")

        if signals.get("exif_software"):
            concerns.append("Editing software is listed in metadata (could be normal, but can indicate manipulation).")

    for m in missing:
        if m == "AI_MANIPULATION":
            missing_items.append("AI/manipulation classification is not enabled in this demo.")
        elif m == "REVERSE_IMAGE":
            missing_items.append("Reverse image search is not enabled in this demo.")
        elif m == "CROSS_VERIFICATION":
            missing_items.append("Cross-verification was not available for this scan.")
        elif m == "DOMAIN_AGE":
            missing_items.append("Domain age lookup was unavailable.")
        else:
            missing_items.append(m.replace("_", " ").title())

    def uniq(xs):
        seen = set()
        out2 = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out2.append(x)
        return out2

    highlights = uniq(highlights)
    concerns = uniq(concerns)
    missing_items = uniq(missing_items)

    guidance = (
        "Treat this as a confidence signal, not a verdict. "
        "If the claim is important, open 2–3 trusted outlets directly and compare details."
    )

    return {
        "highlights": highlights,
        "concerns": concerns,
        "missing": missing_items,
        "guidance": guidance,
    }


# -------------------------
# Scan runners
# -------------------------

async def run_link_scan(scan_id: str, url: str):
    try:
        db_upsert_scan(scan_id, "running")
        signals = await fetch_extract(url)
        report = score_link(signals)
        report["explain"] = build_explanation(report)
        db_upsert_scan(scan_id, "complete", report=report)
    except Exception as e:
        db_upsert_scan(scan_id, "error", error=str(e))


async def run_image_scan(scan_id: str, path_str: str):
    try:
        db_upsert_scan(scan_id, "running")
        signals = analyze_image(path_str)
        report = score_image(signals)
        report["explain"] = build_explanation(report)
        db_upsert_scan(scan_id, "complete", report=report)
    except Exception as e:
        db_upsert_scan(scan_id, "error", error=str(e))


# -------------------------
# Routes
# -------------------------

@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"


@app.get("/version")
def version():
    return {"version": APP_VERSION}


@app.get("/", response_class=HTMLResponse)
def home():
    if not INDEX_FILE.exists():
        return HTMLResponse(f"<h3>Missing:</h3><pre>{INDEX_FILE}</pre>", status_code=500)
    return HTMLResponse(INDEX_FILE.read_text(encoding="utf-8"))


@app.post("/api/v1/scan/link", status_code=202)
async def create_link_scan(payload: dict):
    url = (payload.get("url") or "").strip()
    if not url or not is_url_safe(url):
        raise HTTPException(status_code=400, detail="Invalid or unsafe URL")

    scan_id = str(uuid.uuid4())
    db_upsert_scan(scan_id, "queued")
    asyncio.create_task(run_link_scan(scan_id, url))
    return {"scan_id": scan_id, "status": "queued", "share_url": f"/result/{scan_id}"}


@app.post("/api/v1/scan/image/upload", status_code=202)
async def create_image_scan(image: UploadFile = File(...)):
    if not image.content_type or not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    scan_id = str(uuid.uuid4())
    db_upsert_scan(scan_id, "queued")

    ext = (image.filename.split(".")[-1] if image.filename and "." in image.filename else "jpg").lower()
    if ext not in ("jpg", "jpeg", "png", "webp"):
        ext = "jpg"

    path = UPLOADS_DIR / f"{scan_id}.{ext}"
    data = await image.read()

    if len(data) > 10 * 1024 * 1024:
        db_upsert_scan(scan_id, "error", error="Image too large (max 10MB)")
        return {"scan_id": scan_id, "status": "error", "share_url": f"/result/{scan_id}"}

    path.write_bytes(data)
    asyncio.create_task(run_image_scan(scan_id, str(path)))
    return {"scan_id": scan_id, "status": "queued", "share_url": f"/result/{scan_id}"}


@app.get("/api/v1/scan/{scan_id}")
def get_scan(scan_id: str):
    item = db_get_scan(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")

    resp = {"scan_id": scan_id, "status": item["status"]}

    if item["status"] == "complete":
        report = item.get("report") or {}
        if not report.get("explain"):
            try:
                report["explain"] = build_explanation(report)
                db_upsert_scan(scan_id, "complete", report=report)
            except Exception:
                report["explain"] = {
                    "highlights": [],
                    "concerns": [],
                    "missing": ["Explanation engine failed unexpectedly."],
                    "guidance": "Try rerunning the scan."
                }
        resp["report"] = report

    if item.get("error"):
        resp["error"] = item["error"]

    return resp


# -------------------------
# OG Image
# -------------------------

def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _load_font(size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype("DejaVuSans.ttf", size=size)
    except Exception:
        return ImageFont.load_default()


def _truncate(text: str, max_chars: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 1].rstrip() + "…"


def _band_color(band: str) -> tuple[int, int, int]:
    b = (band or "").lower()
    if "strong" in b:
        return (60, 220, 150)
    if "moderate" in b:
        return (255, 210, 90)
    if "limited" in b:
        return (255, 150, 70)
    if "weak" in b:
        return (255, 110, 110)
    return (200, 210, 230)


@app.get("/og/{scan_id}.png")
def og_image(scan_id: str):
    item = db_get_scan(scan_id)
    status = (item or {}).get("status", "not_found")

    W, H = 1200, 630
    img = Image.new("RGB", (W, H), (11, 16, 32))
    d = ImageDraw.Draw(img)

    d.ellipse((-200, -220, 520, 420), fill=(32, 60, 160))
    d.ellipse((760, -240, 1500, 420), fill=(120, 28, 48))

    veil = Image.new("RGBA", (W, H), (11, 16, 32, 170))
    img = Image.alpha_composite(img.convert("RGBA"), veil).convert("RGBA")
    d = ImageDraw.Draw(img)

    card_x, card_y = 70, 70
    card_w, card_h = W - 140, H - 140
    panel = Image.new("RGBA", (card_w, card_h), (17, 28, 61, 220))
    img.paste(panel, (card_x, card_y), panel)

    d.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                        radius=26, outline=(255, 255, 255, 45), width=2)

    logo_size = 70
    lx, ly = card_x + 38, card_y + 34
    d.rounded_rectangle([lx, ly, lx + logo_size, ly + logo_size], radius=22, fill=(120, 150, 255, 255))
    d.rounded_rectangle([lx + 12, ly + 12, lx + logo_size - 12, ly + logo_size - 12],
                        radius=18, fill=(255, 110, 110, 235))

    f_brand = _load_font(36)
    f_tag = _load_font(22)
    f_h1 = _load_font(52)
    f_big = _load_font(84)
    f_band = _load_font(30)
    f_body = _load_font(26)
    f_small = _load_font(22)

    d.text((lx + logo_size + 18, ly + 2), "VeriScan", font=f_brand, fill=(234, 240, 255, 255))
    d.text((lx + logo_size + 18, ly + 46), "Scan. Analyze. Decide.", font=f_tag, fill=(168, 179, 214, 255))

    score = None
    band = None
    summary = None
    domain = None

    if status == "complete" and item:
        report = item.get("report") or {}
        score = report.get("overall_score")
        band = report.get("band_label")
        summary = (report.get("summary_text") or "").strip()
        signals = ((report.get("evidence") or {}).get("signals") or {})
        domain = signals.get("domain") or ""

    content_x = card_x + 38
    content_y = card_y + 140

    if status in ("queued", "running"):
        d.text((content_x, content_y), "Report processing…", font=f_h1, fill=(234, 240, 255, 255))
        d.text((content_x, content_y + 70), "Check back in a moment.", font=f_body, fill=(168, 179, 214, 255))
    elif status == "error":
        d.text((content_x, content_y), "Report error", font=f_h1, fill=(234, 240, 255, 255))
        d.text((content_x, content_y + 70), "Something went wrong generating this report.", font=f_body, fill=(168, 179, 214, 255))
    elif status == "not_found":
        d.text((content_x, content_y), "Report not found", font=f_h1, fill=(234, 240, 255, 255))
        d.text((content_x, content_y + 70), "This link may have expired on the demo server.", font=f_body, fill=(168, 179, 214, 255))
    else:
        s = score if isinstance(score, int) else 0
        b = band or "Uncertain"
        col = _band_color(b)

        d.text((content_x, content_y), "Confidence", font=f_body, fill=(168, 179, 214, 255))
        d.text((content_x, content_y + 40), f"{s}", font=f_big, fill=(234, 240, 255, 255))

        chip_x = content_x + 170
        chip_y = content_y + 66
        chip_w, chip_h = 260, 54
        d.rounded_rectangle([chip_x, chip_y, chip_x + chip_w, chip_y + chip_h],
                            radius=26,
                            fill=(col[0], col[1], col[2], 60),
                            outline=(col[0], col[1], col[2], 180),
                            width=2)
        d.text((chip_x + 18, chip_y + 12), b, font=f_band, fill=(234, 240, 255, 255))

        d.line([content_x, content_y + 150, card_x + card_w - 38, content_y + 150],
               fill=(255, 255, 255, 35), width=2)

        summ = _truncate(summary or "Probabilistic analysis based on available signals.", 160)
        d.text((content_x, content_y + 175), summ, font=f_body, fill=(234, 240, 255, 255))

        dom = (domain or "").strip()
        if dom:
            d.text((content_x, content_y + 235), f"Domain: {dom}", font=f_small, fill=(168, 179, 214, 255))

    d.text((content_x, card_y + card_h - 48), f"veriscan • report id {scan_id[:8]}",
           font=f_small, fill=(168, 179, 214, 255))

    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG", optimize=True)
    out.seek(0)
    return StreamingResponse(out, media_type="image/png")


# -------------------------
# Share page
# -------------------------

def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@app.get("/result/{scan_id}", response_class=HTMLResponse)
def result_page(scan_id: str, request: Request):
    item = db_get_scan(scan_id)
    status = (item or {}).get("status", "not_found")

    base = str(request.base_url).rstrip("/")
    og_url = f"{base}/result/{scan_id}"
    og_img = f"{base}/og/{scan_id}.png"

    og_title = "VeriScan Report"
    og_desc = "Scan. Analyze. Decide. — Clarity in a world of noise."
    og_type = "website"

    if status == "complete" and item:
        report = item.get("report") or {}
        score = report.get("overall_score")
        band = report.get("band_label")
        summary = (report.get("summary_text") or "").strip()
        if isinstance(score, int) and band:
            og_title = f"VeriScan Report — {score}/100 • {band}"
        if summary:
            og_desc = summary[:180]

    html = """
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__OG_TITLE__</title>

<meta property="og:title" content="__OG_TITLE__" />
<meta property="og:description" content="__OG_DESC__" />
<meta property="og:type" content="__OG_TYPE__" />
<meta property="og:url" content="__OG_URL__" />
<meta property="og:image" content="__OG_IMG__" />

<style>
body { font-family: Arial, sans-serif; background:#0b1020; color:#eaf0ff; margin:0; padding:40px; }
.card { background:#111933; padding:24px; border-radius:16px; max-width:950px; margin:auto; border:1px solid rgba(255,255,255,.12); }
.muted { opacity:.75; }
.score { font-size:42px; font-weight:800; margin-top:10px; }
.band { font-size:18px; opacity:.8; }
.section { margin-top:22px; padding-top:14px; border-top:1px solid rgba(255,255,255,.12); }
ul { margin-top:8px; }
button { padding:10px 14px; border-radius:10px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.08); color:#eaf0ff; cursor:pointer; }
button:hover { background:rgba(255,255,255,.12); }
code { background:rgba(0,0,0,.25); padding:2px 6px; border-radius:8px; }
pre { background:rgba(0,0,0,.25); padding:12px; border-radius:12px; overflow:auto; }
a { color:#b9ccff; text-decoration:none; }
a:hover { text-decoration:underline; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; background:rgba(255,255,255,.09); border:1px solid rgba(255,255,255,.12); margin-right:8px; }
.tagTrusted { background: rgba(60,220,150,.16); border-color: rgba(60,220,150,.25); }
.tagOther { background: rgba(255,210,90,.14); border-color: rgba(255,210,90,.22); }
</style>
</head>
<body>

<div class="card">
  <h1 style="margin:0;">VeriScan Report</h1>
  <div class="muted">Scan ID: <code>__SCAN_ID__</code></div>

  <div id="content" style="margin-top:16px;">Loading...</div>

  <div style="margin-top:20px;">
    <button onclick="copyLink()">Copy Link</button>
  </div>
</div>

<script>
const scanId = __SCAN_ID_JSON__;

function esc(s){
  return String(s || "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;");
}

function copyLink() {
  navigator.clipboard.writeText(window.location.href);
}

function renderEvidence(list){
  if (!list || list.length === 0) {
    return "<div class='muted'>No corroboration links available.</div>";
  }
  return "<div style='margin-top:10px; display:flex; flex-direction:column; gap:10px;'>" + list.map(e => {
    const tag = e.trusted ? "<span class='badge tagTrusted'>Trusted</span>" : "<span class='badge tagOther'>Other outlet</span>";
    const title = esc(e.title || e.domain || e.url);
    const dom = esc(e.domain || "");
    const url = esc(e.url || "");
    return `
      <div style="padding:12px; border-radius:12px; border:1px solid rgba(255,255,255,.12); background:rgba(0,0,0,.20);">
        <div>${tag}<span class="muted">${dom}</span></div>
        <div style="margin-top:6px; font-weight:700;"><a href="${url}" target="_blank" rel="noreferrer">${title}</a></div>
      </div>
    `;
  }).join("") + "</div>";
}

async function load() {
  const res = await fetch("/api/v1/scan/" + scanId);
  const data = await res.json();

  if (data.status !== "complete") {
    document.getElementById("content").innerHTML =
      "<div><b>Status:</b> " + esc(data.status) + "</div>";
    return;
  }

  const r = data.report || {};
  const sig = (r.evidence && r.evidence.signals) ? r.evidence.signals : {};

  let explainHTML = "";
  if (r.explain) {
    const h = r.explain.highlights || [];
    const c = r.explain.concerns || [];
    const m = r.explain.missing || [];
    const g = r.explain.guidance || "";

    const list = (arr) => arr.length ? "<ul>" + arr.map(x => "<li>"+esc(x)+"</li>").join("") + "</ul>"
                                    : "<div class='muted'>None</div>";

    explainHTML = `
      <div class="section">
        <h3 style="margin:0 0 8px;">Explain This Score</h3>
        <b>What helped</b>
        ${list(h)}
        <b>What raised concern</b>
        ${list(c)}
        <b>What we couldn’t verify</b>
        ${list(m)}
        <div class="muted" style="margin-top:10px;">${esc(g)}</div>
      </div>
    `;
  }

  const qs = sig.corroboration_queries || [];
  const qLine = qs.length ? qs.map(esc).join(" • ") : "—";

  const engine = sig.corroboration_engine || "—";
  const debug = sig.corroboration_debug || {};
  const allHits = debug.all_outlets_hits;
  const allSample = debug.all_outlets_sample || [];
  const evidenceLinks = sig.corroboration_evidence || [];

  document.getElementById("content").innerHTML = `
    <div class="score">${r.overall_score}/100</div>
    <div class="band">${esc(r.band_label)}</div>

    <div class="section">
      <b>Summary:</b>
      <div style="margin-top:6px;">${esc(r.summary_text)}</div>
    </div>

    <div class="section">
      <b>Corroboration:</b>
      <div style="margin-top:6px;">
        Engine: <code>${esc(engine)}</code>
        &nbsp; Trusted hits: <code>${esc(String(sig.corroboration_hits ?? "unavailable"))}</code>
        &nbsp; Trusted domains: <code>${esc((sig.corroboration_domains || []).join(", ") || "—")}</code>
      </div>

      <div class="muted" style="margin-top:10px;">
        All outlets found (unique domains): <code>${esc(String(allHits ?? "—"))}</code>
      </div>

      ${allSample.length ? `
        <div class="muted" style="margin-top:8px;">Sample outlets:</div>
        <div style="margin-top:6px;"><code>${esc(allSample.join(", "))}</code></div>
      ` : ""}

      <div class="muted" style="margin-top:8px;">Claim query used: <code>${qLine}</code></div>

      <h3 style="margin:18px 0 6px;">Corroboration Evidence</h3>
      ${renderEvidence(evidenceLinks)}

      <details style="margin-top:14px;">
        <summary class="muted">Debug</summary>
        <pre>${esc(JSON.stringify(debug, null, 2))}</pre>
      </details>
    </div>

    ${explainHTML}
  `;
}

load();
</script>

</body>
</html>
"""

    html = (
        html
        .replace("__OG_TITLE__", _html_escape(og_title))
        .replace("__OG_DESC__", _html_escape(og_desc))
        .replace("__OG_TYPE__", _html_escape(og_type))
        .replace("__OG_URL__", _html_escape(og_url))
        .replace("__OG_IMG__", _html_escape(og_img))
        .replace("__SCAN_ID__", _html_escape(scan_id))
        .replace("__SCAN_ID_JSON__", json.dumps(scan_id))
    )

    return HTMLResponse(html)
