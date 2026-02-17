@app.get("/result/{scan_id}", response_class=HTMLResponse)
def result_page(scan_id: str):
    # Build OG/Twitter meta tags using whatever we have server-side.
    item = SCANS.get(scan_id)
    status = (item or {}).get("status", "not_found")

    og_title = "VeriScan Report"
    og_desc = "Scan. Analyze. Decide. — Clarity in a world of noise."
    og_type = "website"
    og_url = f"/result/{scan_id}"

    if status == "complete":
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

    # NOTE: We keep the page’s JS-driven UI, but OG tags are now server-rendered for link previews.
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{_html_escape(og_title)}</title>

  <!-- Open Graph -->
  <meta property="og:title" content="{_html_escape(og_title)}" />
  <meta property="og:description" content="{_html_escape(og_desc)}" />
  <meta property="og:type" content="{_html_escape(og_type)}" />
  <meta property="og:url" content="{_html_escape(og_url)}" />

  <!-- Twitter -->
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="{_html_escape(og_title)}" />
  <meta name="twitter:description" content="{_html_escape(og_desc)}" />

  <!-- Optional: a simple in-app “preview image” endpoint you can add later:
       <meta property="og:image" content="/og/{scan_id}.png" />
       <meta name="twitter:image" content="/og/{scan_id}.png" />
  -->

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

    /* Report UI styles (same as before) */
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
