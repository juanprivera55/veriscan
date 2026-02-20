from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, quote_plus
from datetime import datetime, timezone
import uuid
import asyncio
import re
import json
import os
import xml.etree.ElementTree as ET

import httpx
from bs4 import BeautifulSoup
import tldextract

from PIL import Image
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
APP_VERSION = "veriscan-corroboration-v7_6-crossverify-weighted-2026-02-20"  # <-- bumped

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
# Cross-verify weighting (PATCH)
# -------------------------
# You can tune these without changing your response schema.
MAJOR_OUTLETS = {
    # Not all of these are in TRUSTED_DOMAINS; treat as "major" for partial credit
    "ft.com",
    "dw.com",
    "france24.com",
    "latimes.com",
    "chicagotribune.com",
    "theatlantic.com",
    "newyorker.com",
    "time.com",          # already trusted in your list; harmless
    "pbs.org",           # already trusted
}

# "Syndication" and aggregators: should not earn outlet credit by themselves
AGGREGATOR_DOMAINS = {
    "msn.com",
    "aol.com",
    "yahoo.com",
    "news.yahoo.com",
    "news.google.com",
    "google.com",
    "bing.com",
    "flipboard.com",
    "smartnews.com",
}

# Weighted corroboration points:
WEIGHT_TRUSTED = 1.00
WEIGHT_MAJOR = 0.80
WEIGHT_OTHER_NEWS = 0.45
WEIGHT_UNKNOWN = 0.20

# How many points counts as "strong" corroboration
CROSS_VERIFY_STRONG_POINTS = 3.0
CROSS_VERIFY_MAX_POINTS = 5.0  # scaling cap


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
# Corroboration: Bing News RSS + Evidence Links — V7.5
# Fix: filter out ad/analytics URLs so MSN doesn't "resolve" to adsdk.microsoft.com/ast.js
# -------------------------

SYNDICATION_HOSTS = {"msn.com", "yahoo.com", "aol.com"}

# Prefer these keys (publisher-ish) BEFORE generic "url"
SYNDICATION_URL_KEYS = [
    "originalUrl", "originalURL",
    "sourceUrl", "sourceURL",
    "providerUrl", "providerURL",
    "canonicalUrl", "canonicalURL",
    "contentUrl", "contentURL",
    "mainEntityOfPage",
    "entityUrl",
    "articleUrl",
]

# Never accept these domains/keywords as a "publisher"
BAD_URL_SUBSTRINGS = [
    "adsdk.", "doubleclick.", "googlesyndication.", "google-analytics", "analytics.",
    "adservice.", "/ads/", "adserver", "ast.js", ".js?", ".css?", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".ico", "/ast/ast.js"
]


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
    out = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out

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
    d = normalize_domain(dom)
    for td in TRUSTED_DOMAINS:
        tdn = normalize_domain(td)
        if d == tdn or d.endswith("." + tdn):
            return td
    return None


def _abs_url(base_url: str, maybe_url: str) -> str:
    if not maybe_url:
        return ""
    if maybe_url.startswith("http://") or maybe_url.startswith("https://"):
        return maybe_url
    try:
        b = urlparse(base_url)
        if maybe_url.startswith("//"):
            return f"{b.scheme}:{maybe_url}"
        if maybe_url.startswith("/"):
            return f"{b.scheme}://{b.netloc}{maybe_url}"
    except Exception:
        return maybe_url
    return maybe_url


def _looks_like_real_article_url(u: str) -> bool:
    if not u or not u.startswith(("http://", "https://")):
        return False
    ul = u.lower()

    # filter obvious junk (ads/scripts/images)
    for bad in BAD_URL_SUBSTRINGS:
        if bad in ul:
            return False

    # block common static file endings
    if re.search(r"\.(js|css|png|jpg|jpeg|gif|svg|webp|ico)(\?|$)", ul):
        return False

    # must have a domain + path
    d = normalize_domain(parse_domain(u) or "")
    if not d:
        return False

    # avoid microsoft ads host
    if d == "microsoft.com" and ("adsdk" in ul or "ast.js" in ul):
        return False

    return True


def _extract_urls_from_inline_json(html: str) -> list[str]:
    """
    Extract candidate URLs from inline JSON-like blobs.
    IMPORTANT: return in an order that prefers publisher-like URLs.
    """
    if not html:
        return []

    urls = []

    # Key-based extraction
    for key in SYNDICATION_URL_KEYS:
        pattern = rf'"{re.escape(key)}"\s*:\s*"([^"]+)"'
        for m in re.finditer(pattern, html):
            u = m.group(1).replace("\\/", "/").strip()
            if u.startswith(("http://", "https://")):
                urls.append(u)

    # Catch escaped https:\/\/... (append later; noisier)
    for m in re.finditer(r'(https?:\\?/\\?/[^"\s<]+)', html):
        u = m.group(1).replace("\\/", "/").strip()
        if u.startswith(("http://", "https://")):
            urls.append(u)

    # Dedup keep order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _pick_best_publisher_url(candidates: list[str], synd_domain: str) -> str:
    """
    Choose a candidate that:
    - is not syndication host
    - is not Bing
    - looks like a real article URL (not adsdk/microsoft scripts)
    Preference order:
      1) Trusted domains
      2) Anything that looks like article URL
    """
    synd_domain = normalize_domain(synd_domain)

    # 1) Trusted domain candidates first
    for u in candidates:
        if not _looks_like_real_article_url(u):
            continue
        d = normalize_domain(parse_domain(u) or "")
        if not d or d in SYNDICATION_HOSTS or d == synd_domain or "bing.com" in d:
            continue
        if _is_trusted_domain(d):
            return u

    # 2) Any plausible article URL
    for u in candidates:
        if not _looks_like_real_article_url(u):
            continue
        d = normalize_domain(parse_domain(u) or "")
        if not d or d in SYNDICATION_HOSTS or d == synd_domain or "bing.com" in d:
            continue
        return u

    return ""


def _extract_best_publisher_url(html: str, fetched_url: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")

    canon = soup.find("link", rel=lambda x: x and "canonical" in x.lower())
    if canon and canon.get("href"):
        u = _abs_url(fetched_url, canon["href"].strip())
        if _looks_like_real_article_url(u):
            return u

    og = soup.find("meta", attrs={"property": "og:url"})
    if og and og.get("content"):
        u = og["content"].strip()
        if _looks_like_real_article_url(u):
            return u

    tw = soup.find("meta", attrs={"name": "twitter:url"})
    if tw and tw.get("content"):
        u = tw["content"].strip()
        if _looks_like_real_article_url(u):
            return u

    pl = soup.find("meta", attrs={"name": "parsely-link"})
    if pl and pl.get("content"):
        u = pl["content"].strip()
        if _looks_like_real_article_url(u):
            return u

    # JSON-LD
    for s in soup.find_all("script", attrs={"type": "application/ld+json"}):
        if not s.string:
            continue
        raw = s.string.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue

        stack = [data] if isinstance(data, (dict, list)) else []
        while stack:
            obj = stack.pop()
            if isinstance(obj, dict):
                t = obj.get("@type")
                if isinstance(t, str) and ("NewsArticle" in t or t.lower() == "article"):
                    if isinstance(obj.get("url"), str) and _looks_like_real_article_url(obj["url"]):
                        return obj["url"].strip()
                    me = obj.get("mainEntityOfPage")
                    if isinstance(me, dict) and isinstance(me.get("@id"), str) and _looks_like_real_article_url(me["@id"]):
                        return me["@id"].strip()
                    if isinstance(me, str) and _looks_like_real_article_url(me):
                        return me.strip()
                for v in obj.values():
                    if isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(obj, list):
                for v in obj:
                    if isinstance(v, (dict, list)):
                        stack.append(v)

    # Inline JSON candidates (best for MSN/Yahoo/AOL)
    inline_candidates = _extract_urls_from_inline_json(html or "")
    synd_dom = normalize_domain(parse_domain(fetched_url) or "")
    best = _pick_best_publisher_url(inline_candidates, synd_dom)
    if best:
        return best

    return ""


async def _unmask_syndication(url: str, client: httpx.AsyncClient) -> tuple[str, str, dict]:
    dom = normalize_domain(parse_domain(url) or "")

    debug = {
        "synd_url": url,
        "synd_domain": dom,
        "status_code": None,
        "final_url": None,
        "extracted_url": None,
        "note": None,
    }

    if dom not in SYNDICATION_HOSTS:
        debug["note"] = "Not a syndication host"
        return ("", "", debug)

    try:
        r = await client.get(url)
    except Exception as e:
        debug["error"] = str(e)
        debug["note"] = "Fetch error"
        return ("", "", debug)

    debug["status_code"] = r.status_code
    debug["final_url"] = str(r.url)

    # Yahoo often rate limits on hosted IPs
    if r.status_code == 429:
        debug["note"] = "Rate limited (429); skipping unmask"
        return ("", "", debug)

    if r.status_code >= 400:
        debug["note"] = "Blocked or error (>=400)"
        return ("", "", debug)

    html = r.text or ""
    best = _extract_best_publisher_url(html, debug["final_url"])
    debug["extracted_url"] = best or None

    # Only accept if it looks like a real article URL
    if not best or not _looks_like_real_article_url(best):
        debug["note"] = "No valid publisher URL found"
        return ("", "", debug)

    pd = normalize_domain(parse_domain(best) or "")
    if not pd or pd in SYNDICATION_HOSTS:
        debug["note"] = "Extracted URL not usable (missing domain or still syndication)"
        return ("", "", debug)

    debug["note"] = "Resolved"
    return (best, pd, debug)


# -------------------------
# Weighted corroboration (PATCH)
# -------------------------

def _looks_like_news_domain(dom: str) -> bool:
    """
    Lightweight heuristic to give partial credit to legitimate newsroom domains
    even if not in TRUSTED_DOMAINS.
    """
    d = normalize_domain(dom)
    if not d:
        return False
    if d in TRUSTED_DOMAINS or d in MAJOR_OUTLETS:
        return True
    # common newsroom-ish keywords
    for kw in ("news", "times", "post", "tribune", "journal", "press", "gazette", "herald"):
        if kw in d:
            return True
    return False


def _classify_outlet(dom: str) -> str:
    d = normalize_domain(dom)
    if not d:
        return "unknown"
    if d in AGGREGATOR_DOMAINS:
        return "aggregator"
    if _is_trusted_domain(d):
        return "trusted"
    if d in MAJOR_OUTLETS:
        return "major"
    if _looks_like_news_domain(d):
        return "other_news"
    return "unknown"


def _compute_weighted_corroboration(domains: list[str], exclude_domain: str | None) -> dict:
    """
    Returns:
      points, breakdown counts, unique_domains_used
    Excludes aggregators and the scanned article domain.
    """
    exclude = normalize_domain(exclude_domain or "")

    uniq = []
    seen = set()
    for d in domains or []:
        dn = normalize_domain(d)
        if not dn:
            continue
        if exclude and (dn == exclude or dn.endswith("." + exclude)):
            continue
        if dn in seen:
            continue
        seen.add(dn)
        uniq.append(dn)

    points = 0.0
    breakdown = {"trusted": 0, "major": 0, "other_news": 0, "unknown": 0, "aggregator_ignored": 0}
    used = []

    for dn in uniq:
        cls = _classify_outlet(dn)
        if cls == "aggregator":
            breakdown["aggregator_ignored"] += 1
            continue

        if cls == "trusted":
            breakdown["trusted"] += 1
            points += WEIGHT_TRUSTED
        elif cls == "major":
            breakdown["major"] += 1
            points += WEIGHT_MAJOR
        elif cls == "other_news":
            breakdown["other_news"] += 1
            points += WEIGHT_OTHER_NEWS
        else:
            breakdown["unknown"] += 1
            points += WEIGHT_UNKNOWN

        used.append(dn)

    return {
        "points": round(points, 2),
        "breakdown": breakdown,
        "unique_domains_used": used,
        "unique_domains_total": len(uniq),
    }


def _cross_verify_score_from_points(points: float) -> int:
    """
    Map corroboration points -> 0..100 score.
    - Caps at CROSS_VERIFY_MAX_POINTS.
    - Guarantees a strong floor once you cross strong threshold.
    """
    if points <= 0:
        return 0
    capped = min(points, CROSS_VERIFY_MAX_POINTS)
    score = int(round((capped / CROSS_VERIFY_MAX_POINTS) * 100))
    if points >= CROSS_VERIFY_STRONG_POINTS:
        score = max(score, 85)
    return clamp(score)


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

    unwrapped = []
    for it in items:
        u = _unwrap_bing_news_link(it["link"])
        unwrapped.append({"title": it.get("title", ""), "link": u})

    # Resolve bing.com redirects (cap)
    N_RESOLVE_BING = 12
    resolved_bing = 0
    for it in unwrapped:
        dom = normalize_domain(parse_domain(it["link"]) or "")
        if (dom == "bing.com" or dom.endswith(".bing.com")) and resolved_bing < N_RESOLVE_BING:
            it["link"] = await _resolve_final_url(it["link"])
            resolved_bing += 1

    # Build evidence items
    evidence = []
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

        evidence.append({
            "title": (it.get("title") or "").strip()[:220],
            "domain": dom,
            "url": link,
            "trusted": False,
            "resolved_from": None,
        })

    # --- Syndication unmasking (MSN/Yahoo/AOL) with safe filtering ---
    MAX_SYNDICATION_RESOLVE = 6
    synd_targets = [e for e in evidence if e["domain"] in SYNDICATION_HOSTS][:MAX_SYNDICATION_RESOLVE]

    synd_map = {}      # original_url -> (publisher_url, publisher_domain)
    synd_debug = []    # per-link debug
    synd_ok = 0

    if synd_targets:
        headers2 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.bing.com/",
        }
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers2) as client2:
                for e in synd_targets:
                    pub_url, pub_dom, dbg = await _unmask_syndication(e["url"], client2)
                    synd_debug.append(dbg)
                    # only apply mapping if it's real (not scripts/ads)
                    if pub_url and pub_dom and _looks_like_real_article_url(pub_url):
                        synd_map[e["url"]] = (pub_url, pub_dom)
                        synd_ok += 1
        except Exception as e:
            synd_debug.append({"error": str(e)})

    # Apply syndication mapping
    for e in evidence:
        if e["url"] in synd_map:
            pub_url, pub_dom = synd_map[e["url"]]
            if exclude and (pub_dom == exclude or pub_dom.endswith("." + exclude)):
                continue
            e["resolved_from"] = e["domain"]
            e["domain"] = pub_dom
            e["url"] = pub_url

    # Unique outlets (all, including non-trusted)
    all_domains = [e["domain"] for e in evidence]
    uniq_outlets = []
    seen = set()
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            uniq_outlets.append(d)

    # Trusted hits
    trusted_domains_found = set()
    for e in evidence:
        tm = _is_trusted_domain(e["domain"])
        if tm:
            e["trusted"] = True
            trusted_domains_found.add(tm)

    # Sort evidence: trusted first
    evidence_sorted = sorted(
        evidence,
        key=lambda x: (0 if x["trusted"] else 1, x["domain"], -len(x.get("title") or "")),
    )

    TOP_EVIDENCE = 10
    evidence_sorted = evidence_sorted[:TOP_EVIDENCE]

    # Weighted corroboration points (PATCH)
    weighted = _compute_weighted_corroboration(uniq_outlets, exclude_domain)

    return {
        "ok": True,
        "status_code": 200,
        "rss_url": rss_url,
        "resolved_bing_count": resolved_bing,
        "syndication_attempted": len(synd_targets),
        "syndication_resolved": synd_ok,
        "syndication_debug": synd_debug[:12],
        "all_outlets_hits": len(uniq_outlets),
        "all_outlets_domains": uniq_outlets,
        "trusted_hits": len(trusted_domains_found),
        "trusted_domains": sorted(trusted_domains_found),
        "evidence_links": evidence_sorted,
        # PATCH
        "weighted_points": weighted["points"],
        "weighted_breakdown": weighted["breakdown"],
        "weighted_unique_used": weighted["unique_domains_used"],
        "weighted_unique_total": weighted["unique_domains_total"],
    }


async def trusted_corroboration(queries: list[str], exclude_domain: str | None) -> dict:
    queries = [q.strip() for q in (queries or []) if q and q.strip()]
    if not queries:
        return {
            "hits": None,
            "domains": [],
            "queries_used": [],
            "engine": "none",
            "debug": {},
            "evidence_links": [],
            # PATCH
            "all_outlets_hits": 0,
            "all_outlets_domains": [],
            "weighted_points": 0.0,
            "weighted_breakdown": {},
        }

    claim_query = queries[0]
    exclude = normalize_domain(exclude_domain or "")

    cache_key = f"corro_v7_6::{claim_query}||exclude={exclude}"
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
                # PATCH
                "all_outlets_hits": cached.get("all_outlets_hits", 0),
                "all_outlets_domains": cached.get("all_outlets_domains", []),
                "weighted_points": cached.get("weighted_points", 0.0),
                "weighted_breakdown": cached.get("weighted_breakdown", {}),
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
            # PATCH
            "all_outlets_hits": 0,
            "all_outlets_domains": [],
            "weighted_points": 0.0,
            "weighted_breakdown": {},
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
            "resolved_bing_count": br.get("resolved_bing_count"),
            "all_outlets_hits": br.get("all_outlets_hits"),
            "all_outlets_sample": sample_all,
            "syndication_attempted": br.get("syndication_attempted"),
            "syndication_resolved": br.get("syndication_resolved"),
            "syndication_debug": br.get("syndication_debug", []),
            # PATCH (show why cross_verify improved)
            "weighted_points": br.get("weighted_points", 0.0),
            "weighted_breakdown": br.get("weighted_breakdown", {}),
            "weighted_unique_used": br.get("weighted_unique_used", [])[:25],
            "weighted_params": {
                "trusted": WEIGHT_TRUSTED,
                "major": WEIGHT_MAJOR,
                "other_news": WEIGHT_OTHER_NEWS,
                "unknown": WEIGHT_UNKNOWN,
                "strong_points_target": CROSS_VERIFY_STRONG_POINTS,
                "max_points_cap": CROSS_VERIFY_MAX_POINTS,
            },
        },
        "evidence_links": br.get("evidence_links", []) or [],
        # PATCH
        "all_outlets_hits": br.get("all_outlets_hits", 0),
        "all_outlets_domains": br.get("all_outlets_domains", []) or [],
        "weighted_points": br.get("weighted_points", 0.0),
        "weighted_breakdown": br.get("weighted_breakdown", {}),
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
                # PATCH
                "corroboration_all_outlets_hits": None,
                "corroboration_all_outlets_domains": [],
                "corroboration_weighted_points": None,
                "corroboration_weighted_breakdown": {},
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

    # PATCH: store extra corroboration signals for scoring & debug
    weighted_points = corro.get("weighted_points", 0.0)
    weighted_breakdown = corro.get("weighted_breakdown", {})
    all_outlets_hits = corro.get("all_outlets_hits", 0)
    all_outlets_domains = corro.get("all_outlets_domains", []) or []

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
        # PATCH
        "corroboration_all_outlets_hits": all_outlets_hits,
        "corroboration_all_outlets_domains": all_outlets_domains[:25],
        "corroboration_weighted_points": weighted_points,
        "corroboration_weighted_breakdown": weighted_breakdown,
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

    # -------------------------
    # CROSS VERIFY (PATCH)
    # -------------------------
    # Keep the old "trusted hits" behavior for display
    hits = signals.get("corroboration_hits")

    # New: use weighted corroboration points (trusted + major + other outlets)
    weighted_points = signals.get("corroboration_weighted_points")
    if weighted_points is None:
        cross_verify = 50
    else:
        cross_verify = _cross_verify_score_from_points(float(weighted_points))

    ai_manip = 50
    context = 60 if signals.get("title") else 40

    overall = int(round(source * 0.30 + cross_verify * 0.35 + ai_manip * 0.20 + context * 0.15))
    overall = clamp(overall)

    unavailable = ["AI_MANIPULATION"]
    if signals.get("domain_age_days") is None:
        unavailable.append("DOMAIN_AGE")
    if signals.get("corroboration_weighted_points") is None:
        unavailable.append("CROSS_VERIFICATION")

    badges = []
    if signals.get("blocked"):
        badges.append("SITE_BLOCKED_AUTOMATION")

    # Badge logic: prefer weighted corroboration but keep trusted-based badge too
    if isinstance(hits, int) and hits >= 3:
        badges.append("MULTI_SOURCE_CORROBORATION")
    elif isinstance(hits, int) and hits == 0:
        badges.append("NO_TRUSTED_CORROBORATION_FOUND")

    # Optional extra badge based on weighted corroboration
    try:
        if isinstance(weighted_points, (int, float)) and float(weighted_points) >= CROSS_VERIFY_STRONG_POINTS:
            badges.append("WIDELY_CORROBORATED_WEIGHTED")
    except Exception:
        pass

    # Summary: show both trusted corroboration and total corroboration for clarity
    all_hits = signals.get("corroboration_all_outlets_hits")
    if signals.get("blocked"):
        summary = (
            "This site blocked automated access. Domain and basic signals were still analyzed, "
            "but article content could not be fetched."
        )
    else:
        strength = ("strong" if source >= 70 else "mixed" if source >= 50 else "weak")
        if weighted_points is None:
            summary = (
                f"Source signals are {strength}. "
                f"Corroboration was unavailable for this scan."
            )
        else:
            # Keep your original phrasing, but add total outlets so the score feels justified
            trusted_part = f"Trusted-source corroboration found: {hits} other trusted domain(s)." if isinstance(hits, int) else "Trusted-source corroboration unavailable."
            total_part = f" Total outlets found: {all_hits}." if isinstance(all_hits, int) else ""
            summary = f"Source signals are {strength}. {trusted_part}{total_part}"

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

    # Existing trusted hits highlight
    hits = signals.get("corroboration_hits")
    if isinstance(hits, int):
        if hits >= 3:
            highlights.append(f"Multiple trusted sources appear to cover similar facts ({hits} matched trusted domain(s)).")
        elif hits in (1, 2):
            highlights.append(f"Some trusted corroboration exists ({hits} matched trusted domain(s)).")
        elif hits == 0:
            concerns.append("No matches were found on the trusted corroboration list (not proof of falsehood, but less support).")

    # PATCH: weighted corroboration highlight
    wp = signals.get("corroboration_weighted_points")
    wb = signals.get("corroboration_weighted_breakdown") or {}
    if isinstance(wp, (int, float)):
        if float(wp) >= CROSS_VERIFY_STRONG_POINTS:
            highlights.append("Multiple independent outlets appear to corroborate similar facts (weighted corroboration is strong).")
        elif float(wp) >= 1.0:
            highlights.append("Some cross-outlet corroboration appears in broader coverage (weighted corroboration is moderate).")
        elif float(wp) == 0:
            concerns.append("Cross-outlet corroboration appears limited in current search results (this can also happen with syndicated/aggregated results).")

        # Optional: small breakdown line in debug-friendly way
        if isinstance(wb, dict) and any(k in wb for k in ("trusted", "major", "other_news", "unknown")):
            highlights.append(
                f"Corroboration mix: trusted={wb.get('trusted',0)}, major={wb.get('major',0)}, other={wb.get('other_news',0)}."
            )

    age_days = signals.get("domain_age_days")
    if isinstance(age_days, int) and age_days >= 3650:
        highlights.append("The domain is long-established (older domains are harder to spoof at scale).")

    if signals.get("https") is True:
        highlights.append("The link uses HTTPS (basic transport security).")

    if signals.get("title"):
        highlights.append("Page title/content signals were available for analysis.")

    out = signals.get("outbound_links_count")
    if isinstance(out, int) and out >= 15:
        highlights.append("The page links out to multiple references (a weak proxy for citations).")

    for m in missing:
        if m == "AI_MANIPULATION":
            missing_items.append("AI/manipulation classification is not enabled in this demo.")

    guidance = (
        "Treat this as a confidence signal, not a verdict. "
        "If the claim is important, open 2–3 trusted outlets directly and compare details."
    )

    return {
        "highlights": list(dict.fromkeys(highlights)),
        "concerns": list(dict.fromkeys(concerns)),
        "missing": list(dict.fromkeys(missing_items)),
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
            report["explain"] = build_explanation(report)
            db_upsert_scan(scan_id, "complete", report=report)
        resp["report"] = report

    if item.get("error"):
        resp["error"] = item["error"]

    return resp


# -------------------------
# Share page (shows corroboration evidence + debug)
# -------------------------

def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@app.get("/result/{scan_id}", response_class=HTMLResponse)
def result_page(scan_id: str, request: Request):
    base = str(request.base_url).rstrip("/")
    og_url = f"{base}/result/{scan_id}"
    og_title = "VeriScan Report"
    og_desc = "Scan. Analyze. Decide. — Clarity in a world of noise."

    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{_html_escape(og_title)}</title>
<meta property="og:title" content="{_html_escape(og_title)}" />
<meta property="og:description" content="{_html_escape(og_desc)}" />
<meta property="og:type" content="website" />
<meta property="og:url" content="{_html_escape(og_url)}" />
<style>
body {{ font-family: Arial, sans-serif; background:#0b1020; color:#eaf0ff; margin:0; padding:40px; }}
.card {{ background:#111933; padding:24px; border-radius:16px; max-width:980px; margin:auto; border:1px solid rgba(255,255,255,.12); }}
.muted {{ opacity:.75; }}
.section {{ margin-top:22px; padding-top:14px; border-top:1px solid rgba(255,255,255,.12); }}
code {{ background:rgba(0,0,0,.25); padding:2px 6px; border-radius:8px; }}
a {{ color:#b9ccff; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.badge {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; background:rgba(255,255,255,.09); border:1px solid rgba(255,255,255,.12); margin-right:8px; }}
.tagTrusted {{ background: rgba(60,220,150,.16); border-color: rgba(60,220,150,.25); }}
.tagOther {{ background: rgba(255,210,90,.14); border-color: rgba(255,210,90,.22); }}
</style>
</head>
<body>
<div class="card">
  <h1 style="margin:0;">VeriScan Report</h1>
  <div class="muted">Scan ID: <code>{_html_escape(scan_id)}</code></div>
  <div id="content" style="margin-top:16px;">Loading...</div>
</div>

<script>
const scanId = {json.dumps(scan_id)};

function esc(s){{
  return String(s || "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;");
}}

function renderEvidence(list){{
  if (!list || list.length === 0) {{
    return "<div class='muted'>No corroboration links available.</div>";
  }}
  return "<div style='margin-top:10px; display:flex; flex-direction:column; gap:10px;'>" + list.map(e => {{
    const tag = e.trusted ? "<span class='badge tagTrusted'>Trusted</span>" : "<span class='badge tagOther'>Other outlet</span>";
    const title = esc(e.title || e.domain || e.url);
    const dom = esc(e.domain || "");
    const url = esc(e.url || "");
    const rf = e.resolved_from ? `<div class="muted" style="margin-top:4px;">Resolved from: <code>${{esc(e.resolved_from)}}</code></div>` : "";
    return `
      <div style="padding:12px; border-radius:12px; border:1px solid rgba(255,255,255,.12); background:rgba(0,0,0,.20);">
        <div>${{tag}}<span class="muted">${{dom}}</span></div>
        <div style="margin-top:6px; font-weight:700;"><a href="${{url}}" target="_blank" rel="noreferrer">${{title}}</a></div>
        ${{rf}}
      </div>
    `;
  }}).join("") + "</div>";
}}

async function load(){{
  const res = await fetch("/api/v1/scan/" + scanId);
  const data = await res.json();
  if (data.status !== "complete"){{
    document.getElementById("content").innerHTML = "<div><b>Status:</b> " + esc(data.status) + "</div>";
    return;
  }}

  const r = data.report || {{}};
  const sig = (r.evidence && r.evidence.signals) ? r.evidence.signals : {{}};
  const debug = sig.corroboration_debug || {{}};
  const evidenceLinks = sig.corroboration_evidence || [];

  document.getElementById("content").innerHTML = `
    <div style="font-size:44px; font-weight:800;">${{r.overall_score}}/100</div>
    <div class="muted" style="margin-top:2px;">${{esc(r.band_label)}}</div>

    <div class="section">
      <b>Summary</b>
      <div style="margin-top:6px;">${{esc(r.summary_text)}}</div>
    </div>

    <div class="section">
      <b>Corroboration</b>
      <div style="margin-top:8px;">
        Trusted hits: <code>${{esc(String(sig.corroboration_hits ?? "unavailable"))}}</code>
        &nbsp; Trusted domains: <code>${{esc((sig.corroboration_domains || []).join(", ") || "—")}}</code>
      </div>

      <div class="muted" style="margin-top:10px;">
        Weighted points: <code>${{esc(String(sig.corroboration_weighted_points ?? "—"))}}</code>
      </div>

      <div class="muted" style="margin-top:10px;">
        Syndication resolved: <code>${{esc(String(debug.syndication_resolved ?? "0"))}}</code> /
        attempted <code>${{esc(String(debug.syndication_attempted ?? "0"))}}</code>
      </div>

      <h3 style="margin:18px 0 6px;">Corroboration Evidence</h3>
      ${{renderEvidence(evidenceLinks)}}

      <details style="margin-top:14px;">
        <summary class="muted">Debug</summary>
        <pre style="background:rgba(0,0,0,.25); padding:12px; border-radius:12px; overflow:auto;">${{esc(JSON.stringify(debug, null, 2))}}</pre>
      </details>
    </div>
  `;
}}

load();
</script>
</body>
</html>
"""
    return HTMLResponse(html)