from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import uuid
import asyncio
import re

import httpx
from bs4 import BeautifulSoup
import tldextract

from PIL import Image
import imagehash
import piexif

BASE_DIR = Path(__file__).resolve().parent          # .../veriscan/app
STATIC_DIR = BASE_DIR / "static"                    # .../veriscan/app/static
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(title="VeriScan V1 Demo (Hosted)")

# In-memory store for demo (resets on restart)
SCANS: dict[str, dict] = {}

# Uploads folder (local disk in the container)
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# In-memory cache for domain age (30-day TTL)
DOMAIN_AGE_CACHE: dict[str, dict] = {}  # domain -> {"age_days": int|None, "fetched_at": datetime}

# In-memory cache for corroboration results (short TTL so repeated scans are fast)
CORRO_CACHE: dict[str, dict] = {}  # cache_key -> {"hits": int, "domains": list[str], "fetched_at": datetime}

# Trusted domains allowlist (keep small + defensible in V1)
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
    # Government/health (strong signal)
    "who.int",
    "cdc.gov",
    "fda.gov",
    "nih.gov",
}


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
    """
    Turn a headline into a compact search query.
    Keep it short so it matches across outlets.
    """
    if not title:
        return ""

    cleaned = re.sub(r"[^A-Za-z0-9\s]", " ", title)
    words = [w.lower() for w in cleaned.split() if len(w) >= 4]

    stop = {"this", "that", "with", "from", "will", "have", "your", "what", "when", "where", "said", "says"}
    words = [w for w in words if w not in stop]

    return " ".join(words[:8])


def _is_same_or_subdomain(candidate: str, base: str) -> bool:
    # candidate == base OR candidate is a subdomain of base
    return candidate == base or candidate.endswith("." + base)


async def trusted_corroboration(query: str, exclude_domain: str | None) -> dict:
    """
    Uses DuckDuckGo HTML search (demo-level) and counts unique trusted domains present in results,
    excluding the scanned domain (and its subdomains) so corroboration means "other outlets".
    Returns: {"hits": int, "domains": [..]}
    """
    if not query:
        return {"hits": 0, "domains": []}

    # Cache key includes exclude_domain to avoid mixing results
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

        # Exclude the scanned domain & its subdomains
        if exclude and _is_same_or_subdomain(dom, exclude):
            continue

        # Match allowlist
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

        # If blocked, return minimal signals instead of crashing
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

    # Corroboration (trusted domains), excluding the scanned domain
    query = build_search_query(title)
    corro = await trusted_corroboration(query, exclude_domain=domain)
    corroboration_hits = corro.get("hits", 0)
    corroboration_domains = corro.get("domains", [])

    return {
        "final_url": final_url,
        "title": title,
        "text_snippet": text_snippet,
        "outbound_links_count": outbound_links,
        "https": https,
        "domain": domain,
        "domain_age_days": domain_age_days,
        "blocked": False,
        "corroboration_hits": corroboration_hits,
        "corroboration_domains": corroboration_domains,
        "corroboration_query": query,
    }


def score_link(signals: dict) -> dict:
    https_score = 100 if signals.get("https") else 30
    citations_score = clamp(min(100, int(signals.get("outbound_links_count", 0) * 4)))

    domain_age_days = signals.get("domain_age_days")
    if domain_age_days is None:
        domain_age_score = 50
    else:
        years = domain_age_days / 365.0
        domain_age_score = clamp(int(20 + min(75, years * 13)))  # ~1yr=33, 5yr~85, 10yr~95

    source = clamp(int(0.45 * https_score + 0.30 * citations_score + 0.25 * domain_age_score))

    hits = signals.get("corroboration_hits")
    if hits is None:
        cross_verify = 50
    else:
        cross_verify = clamp(int(min(100, hits * 25)))  # 0->0,1->25,2->50,3->75,4+->100

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
        if isinstance(hits, int):
            summary = (
                f"Source signals are {('strong' if source >= 70 else 'mixed' if source >= 50 else 'weak')}. "
                f"Trusted-source corroboration found: {hits} other trusted domain(s)."
            )
        else:
            summary = (
                f"Source signals are {('strong' if source >= 70 else 'mixed' if source >= 50 else 'weak')}. "
                "Trusted-source corroboration is unavailable for this scan."
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


async def run_link_scan(scan_id: str, url: str):
    try:
        SCANS[scan_id] = {"status": "running"}
        signals = await fetch_extract(url)
        report = score_link(signals)
        SCANS[scan_id] = {"status": "complete", "report": report}
    except Exception as e:
        SCANS[scan_id] = {"status": "error", "error": str(e)}


async def run_image_scan(scan_id: str, path_str: str):
    try:
        SCANS[scan_id] = {"status": "running"}
        signals = analyze_image(path_str)
        report = score_image(signals)
        SCANS[scan_id] = {"status": "complete", "report": report}
    except Exception as e:
        SCANS[scan_id] = {"status": "error", "error": str(e)}


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
    SCANS[scan_id] = {"status": "queued"}

    asyncio.create_task(run_link_scan(scan_id, url))

    return {"scan_id": scan_id, "status": "queued"}


@app.post("/api/v1/scan/image/upload", status_code=202)
async def create_image_scan(image: UploadFile = File(...)):
    if not image.content_type or not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {"status": "queued"}

    ext = (image.filename.split(".")[-1] if image.filename and "." in image.filename else "jpg").lower()
    if ext not in ("jpg", "jpeg", "png", "webp"):
        ext = "jpg"

    path = UPLOADS_DIR / f"{scan_id}.{ext}"
    data = await image.read()

    if len(data) > 10 * 1024 * 1024:
        SCANS[scan_id] = {"status": "error", "error": "Image too large (max 10MB)"}
        return {"scan_id": scan_id, "status": "queued"}

    path.write_bytes(data)

    asyncio.create_task(run_image_scan(scan_id, str(path)))

    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/v1/scan/{scan_id}")
def get_scan(scan_id: str):
    item = SCANS.get(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    return {"scan_id": scan_id, **item}

