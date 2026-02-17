from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import uuid
import asyncio
import re
import json
import io
import os

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


BASE_DIR = Path(__file__).resolve().parent          # .../veriscan/app
STATIC_DIR = BASE_DIR / "static"                    # .../veriscan/app/static
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(title="VeriScan V1 Demo (Hosted)")

UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Caches
DOMAIN_AGE_CACHE: dict[str, dict] = {}
CORRO_CACHE: dict[str, dict] = {}

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
    "who.int",
    "cdc.gov",
    "fda.gov",
    "nih.gov",
}

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SQLITE_PATH = str((BASE_DIR / "veriscan.db").resolve())
POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")


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


def build_search_query(title: str) -> str:
    if not title:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9\s]", " ", title)
    words = [w.lower() for w in cleaned.split() if len(w) >= 4]
    stop = {"this", "that", "with", "from", "will", "have", "your", "what", "when", "where", "said", "says"}
    words = [w for w in words if w not in stop]
    return " ".join(words[:8])


def _is_same_or_subdomain(candidate: str, base: str) -> bool:
    return candidate == base or candidate.endswith("." + base)


async def trusted_corroboration(query: str, exclude_domain: str | None) -> dict:
    if not query:
        return {"hits": 0, "domains": []}

    cache_key = f"{query}||exclude={exclude_domain or ''}"
    cached = CORRO_CACHE.get(cache_key)
    if cached:
        fetched_at: datetime = cached.get("fetched_at")
        if fetched_at and (datetime.now(timezone.utc) - fetched_at).total_seconds() < 12 * 3600:
            return {"hits": cached.get("hits", 0), "domains": cached.get("domains", [])}

    url = "https://duckduckgo.com/html/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://duckduckgo.com/",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as client:
            r = await client.get(url, params={"q": query})
            if r.status_code != 200:
                return {"hits": 0, "domains": []}
            html = r.text
    except Exception:
        return {"hits": 0, "domains": []}

    soup = BeautifulSoup(html, "html.parser")
    links = soup.select("a.result__a")

    found = set()
    exclude = (exclude_domain or "").lower().strip()

    for a in links[:15]:
        href = a.get("href") or ""
        dom = parse_domain(href)
        if not dom:
            continue
        dom = dom.lower()

        if exclude and _is_same_or_subdomain(dom, exclude):
            continue

        for trusted in TRUSTED_DOMAINS:
            t = trusted.lower()
            if dom == t or dom.endswith("." + t) or t.endswith("." + dom):
                found.add(trusted)
                break

    result = {"hits": len(found), "domains": sorted(found)}
    CORRO_CACHE[cache_key] = {"hits": result["hits"], "domains": result["domains"], "fetched_at": datetime.now(timezone.utc)}
    return result


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
                "corroboration_query": "",
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

    query = build_search_query(title)
    corro = await trusted_corroboration(query, exclude_domain=domain)

    return {
        "final_url": final_url,
        "title": title,
        "text_snippet": text_snippet,
        "outbound_links_count": outbound_links,
        "https": https,
        "domain": domain,
        "domain_age_days": domain_age_days,
        "blocked": False,
        "corroboration_hits": corro.get("hits", 0),
        "corroboration_domains": corro.get("domains", []),
        "corroboration_query": query,
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
    cross_verify = 50 if hits is None else clamp(int(min(100, hits * 25)))

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
        summary = (
            f"Source signals are {('strong' if source >= 70 else 'mixed' if source >= 50 else 'weak')}. "
            f"Trusted-source corroboration found: {hits if isinstance(hits, int) else 'N/A'} other trusted domain(s)."
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
# ✅ Explain this score
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
            missing_items.append("Trusted corroboration check was unavailable for this scan.")

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
        report["explain"] = build_explanation(report)   # ✅ store explain for new scans
        db_upsert_scan(scan_id, "complete", report=report)
    except Exception as e:
        db_upsert_scan(scan_id, "error", error=str(e))


async def run_image_scan(scan_id: str, path_str: str):
    try:
        db_upsert_scan(scan_id, "running")
        signals = analyze_image(path_str)
        report = score_image(signals)
        report["explain"] = build_explanation(report)   # ✅ store explain for new scans
        db_upsert_scan(scan_id, "complete", report=report)
    except Exception as e:
        db_upsert_scan(scan_id, "error", error=str(e))


# -------------------------
# Routes
# -------------------------

@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"


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


# ✅✅✅ PATCHED ENDPOINT: ALWAYS returns report.explain (even for old scans)
@app.get("/api/v1/scan/{scan_id}")
def get_scan(scan_id: str):
    item = db_get_scan(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")

    resp = {"scan_id": scan_id, "status": item["status"]}

    if item["status"] == "complete":
        report = item.get("report") or {}

        # ---- PATCH: compute explain if missing ----
        try:
            if not report.get("explain"):
                report["explain"] = build_explanation(report)
                db_upsert_scan(scan_id, "complete", report=report)
        except Exception:
            report["explain"] = {
                "highlights": [],
                "concerns": [],
                "missing": ["Explanation engine failed unexpectedly."],
                "guidance": "Try rerunning the scan."
            }
        # -----------------------------------------

        resp["report"] = report

    if item.get("error"):
        resp["error"] = item["error"]

    return resp


# -------------------------
# OG Image (unchanged)
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
# Share page (includes Explain UI)
# -------------------------

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
    elif status in ("queued", "running"):
        og_title = "VeriScan Report — Processing…"
        og_desc = "This report is being generated. Check back in a moment."
    elif status == "error":
        og_title = "VeriScan Report — Error"
        og_desc = "There was an error generating this report."
    else:
        og_title = "VeriScan Report — Not found"
        og_desc = "This link may have expired on the demo server."

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{_html_escape(og_title)}</title>

  <meta property="og:title" content="{_html_escape(og_title)}" />
  <meta property="og:description" content="{_html_escape(og_desc)}" />
  <meta property="og:type" content="{_html_escape(og_type)}" />
  <meta property="og:url" content="{_html_escape(og_url)}" />
  <meta property="og:image" content="{_html_escape(og_img)}" />
  <meta property="og:image:width" content="1200" />
  <meta property="og:image:height" content="630" />

  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="{_html_escape(og_title)}" />
  <meta name="twitter:description" content="{_html_escape(og_desc)}" />
  <meta name="twitter:image" content="{_html_escape(og_img)}" />

  <style>
    :root{{
      --bg:#0b1020;
      --muted:#a8b3d6;
      --text:#eaf0ff;
      --line:rgba(255,255,255,.10);
      --shadow: 0 12px 30px rgba(0,0,0,.35);
      --radius:16px;
      --radius2:22px;
    }}
    *{{ box-sizing:border-box; }}
    body{{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color:var(--text);
      background: radial-gradient(1200px 900px at 10% 0%, rgba(90,120,255,.22), transparent 60%),
                  radial-gradient(900px 700px at 95% 10%, rgba(255,110,110,.14), transparent 55%),
                  var(--bg);
    }}
    a{{ color:#cfe0ff; text-decoration:none; }}
    a:hover{{ text-decoration:underline; }}
    .wrap{{ max-width:980px; margin:0 auto; padding:28px 16px 60px; }}
    .topbar{{ display:flex; gap:12px; align-items:center; justify-content:space-between; margin-bottom:18px; flex-wrap:wrap; }}
    .brand{{ display:flex; align-items:center; gap:10px; }}
    .logo{{ width:40px; height:40px; border-radius:14px;
      background: linear-gradient(135deg, rgba(120,150,255,.95), rgba(255,110,110,.75));
      box-shadow: 0 10px 26px rgba(0,0,0,.35);
    }}
    .brand h1{{ font-size:18px; margin:0; letter-spacing:.2px; }}
    .brand .tag{{ font-size:12px; color:var(--muted); margin-top:2px; }}

    .pill{{ display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border:1px solid var(--line);
      border-radius:999px; background: rgba(255,255,255,.06); color: var(--muted); font-size:12px; white-space:nowrap; }}
    .pill strong{{ color:var(--text); font-weight:800; }}

    .card{{ background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.03));
      border:1px solid var(--line); border-radius: var(--radius2); box-shadow: var(--shadow); overflow:hidden; }}
    .hd{{ padding:16px 18px; border-bottom:1px solid var(--line); background: rgba(255,255,255,.03);
      display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }}
    .hd h2{{ margin:0; font-size:14px; letter-spacing:.25px; color:#d9e4ff; font-weight:800; }}
    .bd{{ padding:18px; }}
    .muted{{ color:var(--muted); }}
    .tiny{{ font-size:12px; }}
    .row{{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}

    .btn{{ display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 12px;
      border-radius: 14px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.08);
      color: var(--text); cursor:pointer; font-weight:750; font-size:13px; }}
    .btn:hover{{ background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.22); }}

    .statusBox{{ margin-top:0; padding:14px; border-radius: var(--radius); border: 1px solid var(--line);
      background: rgba(0,0,0,.20); }}
    .spinner{{ width:16px; height:16px; border-radius:50%; border:2px solid rgba(255,255,255,.18); border-top-color: rgba(255,255,255,.9);
      animation: spin .8s linear infinite; }}
    @keyframes spin{{ to {{ transform: rotate(360deg); }} }}

    .scoreTop{{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; margin-bottom:12px; }}
    .scoreTitle{{ display:flex; flex-direction:column; gap:6px; max-width:520px; }}
    .scoreTitle h3{{ margin:0; font-size:18px; letter-spacing:.2px; font-weight:900; }}
    .chip{{ display:inline-flex; align-items:center; gap:8px; padding:7px 10px; border-radius:999px;
      font-size:12px; font-weight:900; border:1px solid var(--line); background: rgba(255,255,255,.06); width:fit-content; }}
    .chip strong{{ font-weight:950; }}
    .chip.strong{{ border-color: rgba(60,220,150,.55); background: rgba(60,220,150,.12); }}
    .chip.moderate{{ border-color: rgba(255,210,90,.55); background: rgba(255,210,90,.12); }}
    .chip.limited{{ border-color: rgba(255,150,70,.55); background: rgba(255,150,70,.12); }}
    .chip.weak{{ border-color: rgba(255,110,110,.60); background: rgba(255,110,110,.12); }}
    .chip.uncertain{{ border-color: rgba(255,255,255,.18); background: rgba(255,255,255,.06); }}

    .meter{{ width:320px; max-width:100%; }}
    .meterTop{{ display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }}
    .meterTop .num{{ font-size:28px; font-weight:950; }}
    .meterTop .lab{{ font-size:12px; color:var(--muted); }}
    .bar{{ height:12px; border-radius:999px; background: rgba(255,255,255,.10); border:1px solid var(--line); overflow:hidden; }}
    .bar > div{{ height:100%; width:0%;
      background: linear-gradient(90deg, rgba(255,110,110,.95), rgba(255,210,90,.95), rgba(60,220,150,.95)); }}

    .badges{{ display:flex; gap:8px; flex-wrap:wrap; margin: 10px 0 6px; }}
    .badge{{ display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px;
      border: 1px solid var(--line); background: rgba(255,255,255,.06); font-size:12px; font-weight:800; }}
    .badge.good{{ border-color: rgba(60,220,150,.50); background: rgba(60,220,150,.12); }}
    .badge.warn{{ border-color: rgba(255,210,90,.50); background: rgba(255,210,90,.12); }}
    .badge.bad{{ border-color: rgba(255,110,110,.55); background: rgba(255,110,110,.12); }}
    .badge.neutral{{ border-color: rgba(255,255,255,.16); background: rgba(255,255,255,.06); color: var(--muted); }}

    .miniGrid{{ display:grid; grid-template-columns: repeat(2,1fr); gap:10px; margin-top:12px; }}
    @media (max-width: 520px){{ .miniGrid{{ grid-template-columns: 1fr; }} }}
    .mini{{ padding:12px; border-radius: var(--radius); border:1px solid var(--line); background: rgba(0,0,0,.18); }}
    .mini .k{{ font-size:12px; color: var(--muted); margin-bottom:6px; }}
    .mini .v{{ font-size:16px; font-weight:900; }}
    .mini .v.small{{ font-size:13px; font-weight:800; }}

    .explainGrid{{ display:grid; grid-template-columns: 1fr; gap:10px; margin-top:12px; }}
    .list{{ margin:8px 0 0; padding-left:18px; color: #eaf0ff; }}
    .list li{{ margin:6px 0; }}
    .hint{{ margin-top:10px; }}

    details{{ margin-top:14px; border-top:1px solid var(--line); padding-top:12px; }}
    summary{{ cursor:pointer; color:#dbe7ff; font-weight:900; font-size:13px; }}
    pre{{ margin-top:10px; padding:12px; border-radius:14px; background: rgba(0,0,0,.26); border: 1px solid var(--line);
      overflow:auto; color: #dfe8ff; font-size:12px; line-height:1.4; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>VeriScan</h1>
          <div class="tag">Shareable report • Scan. Analyze. Decide.</div>
        </div>
      </div>
      <div class="pill"><strong>Report</strong> • ID: {_html_escape(scan_id)}</div>
    </div>

    <div class="card">
      <div class="hd">
        <h2>Result</h2>
        <div class="row">
          <a class="btn" href="/">New scan</a>
          <button class="btn" onclick="copyLink()">Copy link</button>
        </div>
      </div>
      <div class="bd">
        <div id="status" class="statusBox">
          <div class="row" style="justify-content:space-between;">
            <div id="statusText"><b>Status:</b> loading…</div>
            <div id="spin" class="spinner"></div>
          </div>
          <div id="statusSub" class="muted tiny" style="margin-top:6px;"></div>
        </div>

        <div id="report" style="display:none; margin-top:14px;"></div>
      </div>
    </div>
  </div>

<script>
const scanId = {json.dumps(scan_id)};
let timer = null;

function esc(s){{
  return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
}}

function bandClass(label){{
  const l = (label || '').toLowerCase();
  if (l.includes('strong')) return 'strong';
  if (l.includes('moderate')) return 'moderate';
  if (l.includes('limited')) return 'limited';
  if (l.includes('weak')) return 'weak';
  return 'uncertain';
}}

function badgeStyle(name){{
  const n = (name || '').toUpperCase();
  if (n.includes('MULTI_SOURCE')) return 'good';
  if (n.includes('NO_TRUSTED')) return 'warn';
  if (n.includes('BLOCKED')) return 'bad';
  return 'neutral';
}}

function copyLink(){{
  const full = window.location.href;
  navigator.clipboard.writeText(full).then(() => {{
    document.getElementById('statusSub').textContent = "Copied link to clipboard.";
    setTimeout(() => {{ document.getElementById('statusSub').textContent = ""; }}, 1800);
  }}).catch(() => {{
    document.getElementById('statusSub').textContent = "Couldn’t copy automatically. Copy the URL from the address bar.";
  }});
}}

function renderExplain(explain){{
  if (!explain) return '';

  const h = (explain.highlights || []);
  const c = (explain.concerns || []);
  const m = (explain.missing || []);
  const g = (explain.guidance || '');

  const list = (items) => items.length
    ? `<ul class="list">${items.map(x => `<li>${esc(x)}</li>`).join('')}</ul>`
    : `<div class="muted tiny">None</div>`;

  return `
    <div class="mini" style="margin-top:12px;">
      <div class="k">Explain this score</div>
      <div class="explainGrid">
        <div class="mini" style="background: rgba(0,0,0,.12);">
          <div class="k">What helped</div>
          ${list(h)}
        </div>
        <div class="mini" style="background: rgba(0,0,0,.12);">
          <div class="k">What raised concern</div>
          ${list(c)}
        </div>
        <div class="mini" style="background: rgba(0,0,0,.12);">
          <div class="k">What we couldn’t verify</div>
          ${list(m)}
        </div>
        <div class="muted tiny hint">${esc(g)}</div>
      </div>
    </div>
  `;
}}

function renderReadableReport(r){{
  const score = r.overall_score ?? 0;
  const label = r.band_label ?? 'Uncertain';
  const cls = bandClass(label);

  const signals = (r.evidence && r.evidence.signals) ? r.evidence.signals : {{}};
  const unavailable = (r.evidence && r.evidence.unavailable_signals) ? r.evidence.unavailable_signals : [];

  const isLink = ("final_url" in signals) || ("domain" in signals) || ("https" in signals);
  const isImage = ("phash" in signals) || ("width" in signals) || ("exif_present" in signals);

  const badges = (r.badges && r.badges.length)
    ? `<div class="badges">${{r.badges.map(b => `<span class="badge ${{badgeStyle(b)}}">${{esc(b)}}</span>`).join('')}}</div>`
    : `<div class="badges"><span class="badge neutral">No badges</span></div>`;

  const src = r.pillars?.source ?? 50;
  const cross = r.pillars?.cross_verify ?? 50;
  const ai = r.pillars?.ai_manip ?? 50;
  const ctx = r.pillars?.context ?? 50;

  const yesNo = (v) => (v === true ? "Yes" : v === false ? "No" : "—");
  const fmtDays = (d) => (typeof d === "number" ? `${{d.toLocaleString()}} days` : "Unknown");
  const fmtCount = (n) => (typeof n === "number" ? n.toLocaleString() : "—");
  const fmtText = (t) => (t ? esc(String(t)) : "—");

  const finalUrl = signals.final_url || "—";
  const domain = signals.domain || "—";
  const https = signals.https;
  const blocked = signals.blocked;
  const domainAge = signals.domain_age_days;
  const outbound = signals.outbound_links_count;

  const corroHits = signals.corroboration_hits;
  const corroDomains = signals.corroboration_domains || [];
  const corroQuery = signals.corroboration_query || "";

  const corroLine =
    (typeof corroHits === "number")
      ? `${{corroHits}} trusted domain(s)${{corroDomains.length ? ` — ${{corroDomains.slice(0,6).join(", ")}}${{corroDomains.length>6?"…":""}}` : ""}}`
      : "Unavailable";

  const w = signals.width, h = signals.height;
  const exif = signals.exif_present;
  const exifSoft = signals.exif_software;
  const phash = signals.phash;

  let meaning = r.summary_text || "";
  if (isLink && blocked === true) {{
    meaning += " Some sites block automated access; results are based on domain-level signals only.";
  }}
  if (isLink && typeof corroHits === "number" && corroHits === 0) {{
    meaning += " No matches were found on the trusted corroboration list (this does not automatically mean false).";
  }}

  let keyFactsHtml = "";
  if (isLink) {{
    keyFactsHtml = `
      <div class="miniGrid">
        <div class="mini"><div class="k">Final URL</div><div class="v small" style="word-break:break-all;">${{fmtText(finalUrl)}}</div></div>
        <div class="mini"><div class="k">Domain</div><div class="v">${{fmtText(domain)}}</div></div>
        <div class="mini"><div class="k">HTTPS</div><div class="v">${{yesNo(https)}}</div></div>
        <div class="mini"><div class="k">Blocked by site</div><div class="v">${{yesNo(blocked)}}</div></div>
        <div class="mini"><div class="k">Domain age</div><div class="v">${{fmtDays(domainAge)}}</div></div>
        <div class="mini"><div class="k">Outbound links</div><div class="v">${{fmtCount(outbound)}}</div></div>
      </div>

      <div style="margin-top:12px;" class="mini">
        <div class="k">Trusted corroboration</div>
        <div class="v">${{esc(corroLine)}}</div>
        ${{corroQuery ? `<div class="muted tiny" style="margin-top:6px;">Search query used: <span style="opacity:.9">${{esc(corroQuery)}}</span></div>` : ""}}
      </div>
    `;
  }} else if (isImage) {{
    keyFactsHtml = `
      <div class="miniGrid">
        <div class="mini"><div class="k">Dimensions</div><div class="v">${{(w && h) ? `${{w}} × ${{h}}` : "—"}}</div></div>
        <div class="mini"><div class="k">EXIF present</div><div class="v">${{yesNo(exif)}}</div></div>
        <div class="mini"><div class="k">EXIF software</div><div class="v small" style="word-break:break-word;">${{fmtText(exifSoft)}}</div></div>
        <div class="mini"><div class="k">Image fingerprint (pHash)</div><div class="v small">${{fmtText(phash)}}</div></div>
      </div>
    `;
  }} else {{
    keyFactsHtml = `<div class="mini"><div class="k">Key facts</div><div class="v">No structured signals found.</div></div>`;
  }}

  const pillarsHtml = `
    <div class="miniGrid" style="margin-top:12px;">
      <div class="mini"><div class="k">Source reliability</div><div class="v">${{src}}</div></div>
      <div class="mini"><div class="k">Cross-verification</div><div class="v">${{cross}}</div></div>
      <div class="mini"><div class="k">AI / manipulation</div><div class="v">${{ai}}</div></div>
      <div class="mini"><div class="k">Context integrity</div><div class="v">${{ctx}}</div></div>
    </div>
  `;

  const techHtml = `
    <details>
      <summary>Show technical details (raw)</summary>
      ${{unavailable.length ? `<div class="muted tiny" style="margin-top:10px;">Unavailable signals: ${{esc(unavailable.join(", "))}}</div>` : ""}}
      <pre>${{esc(JSON.stringify(r.evidence || {{}}, null, 2))}}</pre>
    </details>
    <p class="muted tiny" style="margin-top:10px;">
      VeriScan provides probabilistic analysis based on available signals. This is not a definitive verdict.
    </p>
  `;

  const explainHtml = renderExplain(r.explain);

  return `
    <div class="scoreTop">
      <div class="scoreTitle">
        <h3>Confidence Score</h3>
        <div class="chip ${{cls}}"><strong>${{score}}</strong> • ${{esc(label)}}</div>
        <div class="muted tiny">${{esc(meaning)}}</div>
        ${{badges}}
      </div>

      <div class="meter">
        <div class="meterTop">
          <div class="num">${{score}}</div>
          <div class="lab">0 = uncertain • 100 = strong</div>
        </div>
        <div class="bar"><div style="width:${{Math.max(0, Math.min(100, score))}}%;"></div></div>
      </div>
    </div>

    <div class="mini" style="margin-top:6px;">
      <div class="k">Report summary</div>
      <div class="v">${{esc(r.summary_text || "—")}}</div>
    </div>

    ${{keyFactsHtml}}
    ${{pillarsHtml}}
    ${{explainHtml}}
    ${{techHtml}}
  `;
}}

async function poll(){{
  const res = await fetch(`/api/v1/scan/${{scanId}}`);
  const raw = await res.text();
  let data = {{}};
  try {{ data = JSON.parse(raw); }} catch(e) {{}}

  if (!res.ok) {{
    document.getElementById('statusText').innerHTML = `<b>Status:</b> error`;
    document.getElementById('statusSub').innerHTML = `<span class="tiny muted">${{esc(raw)}}</span>`;
    document.getElementById('spin').style.display = 'none';
    clearInterval(timer);
    return;
  }}

  const st = data.status || 'unknown';

  if (st === 'queued' || st === 'running') {{
    document.getElementById('statusText').innerHTML = `<b>Status:</b> ${{esc(st)}}`;
    document.getElementById('statusSub').textContent = "Analyzing…";
    document.getElementById('spin').style.display = 'block';
  }} else {{
    document.getElementById('statusText').innerHTML = `<b>Status:</b> ${{esc(st)}}`;
    document.getElementById('statusSub').textContent = "";
    document.getElementById('spin').style.display = 'none';
  }}

  if (st === 'complete') {{
    clearInterval(timer);
    document.getElementById('report').style.display = 'block';
    document.getElementById('report').innerHTML = renderReadableReport(data.report);
  }} else if (st === 'error') {{
    clearInterval(timer);
    document.getElementById('statusSub').innerHTML = `<span class="tiny muted">${{esc(data.error || "")}}</span>`;
  }}
}}

timer = setInterval(poll, 900);
poll();
</script>
</body>
</html>"""
    return HTMLResponse(html)

