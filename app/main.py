from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import uuid
import asyncio
import re
import json

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
DOMAIN_AGE_CACHE: dict[str, dict] = {}

# In-memory cache for corroboration results (short TTL)
CORRO_CACHE: dict[str, dict] = {}

# Trusted domains allowlist
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

    return {"scan_id": scan_id, "status": "queued", "share_url": f"/result/{scan_id}"}


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
        return {"scan_id": scan_id, "status": "queued", "share_url": f"/result/{scan_id}"}

    path.write_bytes(data)

    asyncio.create_task(run_image_scan(scan_id, str(path)))

    return {"scan_id": scan_id, "status": "queued", "share_url": f"/result/{scan_id}"}


@app.get("/api/v1/scan/{scan_id}")
def get_scan(scan_id: str):
    item = SCANS.get(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    return {"scan_id": scan_id, **item}


def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@app.get("/result/{scan_id}", response_class=HTMLResponse)
def result_page(scan_id: str):
    # Polished share page: loads status & renders report when ready.
    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>VeriScan Report</title>
  <style>
    :root{{
      --bg:#0b1020;
      --line:rgba(255,255,255,.10);
      --muted:#a8b3d6;
      --text:#eaf0ff;
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
    .topbar{{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; flex-wrap:wrap; }}
    .brand{{ display:flex; align-items:center; gap:10px; }}
    .logo{{ width:40px; height:40px; border-radius:14px;
      background: linear-gradient(135deg, rgba(120,150,255,.95), rgba(255,110,110,.75));
      box-shadow: 0 10px 26px rgba(0,0,0,.35);
    }}
    .brand h1{{ font-size:18px; margin:0; letter-spacing:.2px; }}
    .brand .tag{{ font-size:12px; color:var(--muted); margin-top:2px; }}
    .pill{{ display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border:1px solid var(--line);
      border-radius:999px; background: rgba(255,255,255,.06); color: var(--muted); font-size:12px; white-space:nowrap; }}
    .pill strong{{ color:var(--text); }}
    .card{{ background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.03));
      border:1px solid var(--line); border-radius: var(--radius2); box-shadow: var(--shadow); overflow:hidden; }}
    .hd{{ padding:16px 18px; border-bottom:1px solid var(--line); background: rgba(255,255,255,.03);
      display:flex; align-items:center; justify-content:space-between; gap:10px; }}
    .hd h2{{ margin:0; font-size:14px; letter-spacing:.25px; color:#d9e4ff; font-weight:750; }}
    .bd{{ padding:18px; }}
    .muted{{ color:var(--muted); }}
    .tiny{{ font-size:12px; }}
    .row{{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
    .btn{{ display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 12px;
      border-radius: 14px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.08);
      color: var(--text); cursor:pointer; font-weight:650; font-size:13px; }}
    .btn:hover{{ background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.22); }}
    .scoreTop{{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; margin-bottom:12px; }}
    .scoreTitle h3{{ margin:0; font-size:18px; letter-spacing:.2px; font-weight:800; }}
    .chip{{ display:inline-flex; align-items:center; gap:8px; padding:7px 10px; border-radius: 999px;
      font-size:12px; font-weight:800; border:1px solid var(--line); background: rgba(255,255,255,.06); width: fit-content; }}
    .chip strong{{ font-weight:900; }}
    .chip.strong{{ border-color: rgba(60,220,150,.55); background: rgba(60,220,150,.12); }}
    .chip.moderate{{ border-color: rgba(255,210,90,.55); background: rgba(255,210,90,.12); }}
    .chip.limited{{ border-color: rgba(255,150,70,.55); background: rgba(255,150,70,.12); }}
    .chip.weak{{ border-color: rgba(255,110,110,.60); background: rgba(255,110,110,.12); }}
    .chip.uncertain{{ border-color: rgba(255,255,255,.18); background: rgba(255,255,255,.06); }}
    .meter{{ width:320px; max-width: 100%; }}
    .meterTop{{ display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }}
    .meterTop .num{{ font-size:28px; font-weight:900; }}
    .meterTop .lab{{ font-size:12px; color:var(--muted); }}
    .bar{{ height:12px; border-radius:999px; background: rgba(255,255,255,.10); border:1px solid var(--line); overflow:hidden; }}
    .bar > div{{ height:100%; width:0%; background: linear-gradient(90deg, rgba(255,110,110,.95), rgba(255,210,90,.95), rgba(60,220,150,.95)); }}
    .badges{{ display:flex; gap:8px; flex-wrap:wrap; margin: 10px 0 6px; }}
    .badge{{ display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius: 999px;
      border: 1px solid var(--line); background: rgba(255,255,255,.06); font-size:12px; font-weight:700; }}
    .badge.good{{ border-color: rgba(60,220,150,.50); background: rgba(60,220,150,.12); }}
    .badge.warn{{ border-color: rgba(255,210,90,.50); background: rgba(255,210,90,.12); }}
    .badge.bad{{ border-color: rgba(255,110,110,.55); background: rgba(255,110,110,.12); }}
    .badge.neutral{{ border-color: rgba(255,255,255,.16); background: rgba(255,255,255,.06); color: var(--muted); }}
    .miniGrid{{ display:grid; grid-template-columns: repeat(2, 1fr); gap:10px; margin-top:12px; }}
    @media (max-width: 520px){{ .miniGrid{{ grid-template-columns: 1fr; }} }}
    .mini{{ padding:12px; border-radius: var(--radius); border:1px solid var(--line); background: rgba(0,0,0,.18); }}
    .mini .k{{ font-size:12px; color: var(--muted); margin-bottom:6px; }}
    .mini .v{{ font-size:16px; font-weight:850; }}
    details{{ margin-top:14px; border-top:1px solid var(--line); padding-top:12px; }}
    summary{{ cursor:pointer; color:#dbe7ff; font-weight:800; font-size:13px; }}
    pre{{ margin-top:10px; padding:12px; border-radius:14px; background: rgba(0,0,0,.26); border: 1px solid var(--line);
      overflow:auto; color: #dfe8ff; font-size:12px; line-height:1.4; }}
    .statusBox{{ margin-top:14px; padding:14px; border-radius: var(--radius); border: 1px solid var(--line);
      background: rgba(0,0,0,.20); }}
    .spinner{{ width:16px; height:16px; border-radius:50%; border:2px solid rgba(255,255,255,.18); border-top-color: rgba(255,255,255,.9);
      animation: spin .8s linear infinite; }}
    @keyframes spin{{ to {{ transform: rotate(360deg); }} }}
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

        <div id="report" style="display:none;"></div>
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

function renderReport(r){{
  const score = r.overall_score ?? 0;
  const label = r.band_label ?? 'Uncertain';
  const cls = bandClass(label);

  const badges = (r.badges && r.badges.length)
    ? `<div class="badges">${{r.badges.map(b => `<span class="badge ${{badgeStyle(b)}}">${{esc(b)}}</span>`).join('')}}</div>`
    : `<div class="badges"><span class="badge neutral">No badges</span></div>`;

  const signals = (r.evidence && r.evidence.signals) ? r.evidence.signals : {{}};
  const corroHits = signals.corroboration_hits;
  const corroDomains = signals.corroboration_domains || [];
  const domainAge = signals.domain_age_days;

  const corroText = (typeof corroHits === 'number')
    ? `${{corroHits}} trusted domain(s) ${{corroDomains.length ? `(${{corroDomains.slice(0,4).join(', ')}}${{corroDomains.length>4?'…':''}})` : ''}}`
    : 'Unavailable';

  const ageText = (typeof domainAge === 'number')
    ? `${{domainAge.toLocaleString()}} days`
    : 'Unknown';

  const src = r.pillars?.source ?? 50;
  const cross = r.pillars?.cross_verify ?? 50;
  const ai = r.pillars?.ai_manip ?? 50;
  const ctx = r.pillars?.context ?? 50;

  document.getElementById('report').style.display = 'block';
  document.getElementById('report').innerHTML = `
    <div class="scoreTop">
      <div class="scoreTitle">
        <h3>Confidence Score</h3>
        <div class="chip ${{cls}}"><strong>${{score}}</strong> • ${{esc(label)}}</div>
        <div class="muted tiny">${{esc(r.summary_text || '')}}</div>
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

    <div class="miniGrid">
      <div class="mini">
        <div class="k">Trusted corroboration</div>
        <div class="v">${{esc(corroText)}}</div>
      </div>
      <div class="mini">
        <div class="k">Domain age</div>
        <div class="v">${{esc(ageText)}}</div>
      </div>
      <div class="mini">
        <div class="k">Source reliability</div>
        <div class="v">${{src}}</div>
      </div>
      <div class="mini">
        <div class="k">Cross-verification</div>
        <div class="v">${{cross}}</div>
      </div>
      <div class="mini">
        <div class="k">AI / manipulation</div>
        <div class="v">${{ai}}</div>
      </div>
      <div class="mini">
        <div class="k">Context integrity</div>
        <div class="v">${{ctx}}</div>
      </div>
    </div>

    <details>
      <summary>Details & evidence</summary>
      <pre>${{esc(JSON.stringify(r.evidence || {{}}, null, 2))}}</pre>
    </details>
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
    renderReport(data.report);
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
    return HTMLResponse(page)


