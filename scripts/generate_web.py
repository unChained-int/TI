#!/usr/bin/env python3
"""
scripts/generate_web.py
Liest reports/latest.md und baut web/index.html + web/report.html.
Parst das exakte Format von malware_report.py v6.
"""
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
WEB_DIR      = Path("web")
WEB_DIR.mkdir(exist_ok=True)

BASE_URL = "https://unchained-int.github.io/TI"


# ─── Parser ───────────────────────────────────────────────────────────────────

def parse_report(md: str) -> dict:
    d = {}

    # Datum aus erster Zeile "# MalwareBazaar – DD.MM.YYYY HH:MM UTC"
    m = re.search(r"# MalwareBazaar\s*[–-]\s*(.+)", md)
    d["created"] = m.group(1).strip() if m else "?"

    # Neue Samples
    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    d["new_samples"] = int(m.group(1)) if m else 0

    # Überblick-Tabelle parsen
    def ov(label):
        m = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*\*?\*?([^|\n*]+?)\*?\*?\s*\|", md)
        return m.group(1).strip() if m else "?"

    d["total"]       = ov("Neue Samples").replace("**","")
    d["kritisch"]    = ov("Kritisch").replace("**","")
    d["top_score"]   = ov("Höchster Score").split("–")[0].replace("**","").strip()
    d["top_sha"]     = re.search(r"Höchster Score.*?([0-9a-f]{16})", md)
    d["top_sha"]     = d["top_sha"].group(1) if d["top_sha"] else ""
    d["top_family"]  = ov("Häufigste Familie").replace("**","").split("(")[0].strip()
    d["top_type"]    = ov("Häufigster Typ").replace("**","").split("(")[0].strip()
    d["main_plat"]   = ov("Hauptplattform").replace("**","")
    d["vt_enriched"] = ov("VT-angereichert").replace("**","")
    d["mitre_mapped"]= ov("MITRE gemappt").replace("**","")
    d["avg_size"]    = ov("Ø Dateigröße").replace("**","")

    # Risiko-Zahlen aus Level-Tabelle
    for lvl, key in [("🔴 KRITISCH","r_krit"),("🟠 HOCH","r_hoch"),
                     ("🟡 MITTEL","r_mittel"),("🟢 NIEDRIG","r_niedrig")]:
        m = re.search(re.escape(lvl) + r"\s*\|\s*(\d+)", md)
        d[key] = int(m.group(1)) if m else 0

    # Dateitypen-Tabelle
    d["file_types"] = []
    in_ft = False
    for line in md.split("\n"):
        if "## Dateitypen" in line: in_ft = True; continue
        if in_ft and line.startswith("## "): break
        if in_ft and line.startswith("|") and not line.startswith("|---") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and parts[0] != "Typ":
                name = parts[0].replace("`","")
                cnt  = parts[1]
                pct  = parts[2].split("%")[0].strip() + "%" if "%" in parts[2] else parts[2]
                d["file_types"].append({"name": name, "count": cnt, "pct": pct})

    # Familien-Tabelle
    d["families"] = []
    in_fam = False
    for line in md.split("\n"):
        if "## Familien" in line: in_fam = True; continue
        if in_fam and line.startswith("## "): break
        if in_fam and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4 and parts[0] != "#":
                d["families"].append({"rank": parts[0], "name": parts[1], "count": parts[2], "pct": parts[3]})

    # Klassifikation
    d["categories"] = []
    in_cat = False
    for line in md.split("\n"):
        if "## Klassifikation" in line: in_cat = True; continue
        if in_cat and line.startswith("## "): break
        if in_cat and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4 and parts[0] != "Kategorie":
                d["categories"].append({"name": parts[0].replace("**",""), "count": parts[1], "pct": parts[2], "conf": parts[3]})

    # Plattformen
    d["platforms"] = []
    in_plat = False
    for line in md.split("\n"):
        if "## Betroffene Plattformen" in line: in_plat = True; continue
        if in_plat and line.startswith("## "): break
        if in_plat and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and "Plattform" not in parts[0]:
                d["platforms"].append({"name": parts[0], "count": parts[1], "pct": parts[2]})

    # Vektoren
    d["vectors"] = []
    in_vec = False
    for line in md.split("\n"):
        if "## Infektionsvektoren" in line: in_vec = True; continue
        if in_vec and line.startswith("## "): break
        if in_vec and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and parts[0] != "Vektor":
                d["vectors"].append({"name": parts[0], "count": parts[1], "pct": parts[2]})

    # MITRE Taktiken
    d["mitre"] = []
    in_mit = False
    for line in md.split("\n"):
        if "## MITRE ATT&CK" in line: in_mit = True; continue
        if in_mit and line.startswith("## "): break
        if in_mit and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2 and parts[0] != "Taktik":
                d["mitre"].append({"tactic": parts[0], "count": parts[1]})

    # Top-10 Risk-Tabelle
    d["top10"] = []
    in_top = False
    for line in md.split("\n"):
        if "**Top 10 nach Score:**" in line: in_top = True; continue
        if in_top and line.startswith("## "): break
        if in_top and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 7 and "SHA256" not in parts[0]:
                sha_m = re.search(r"\[([0-9a-f]{14,16})", parts[0])
                url_m = re.search(r"\(https://bazaar[^)]+\)", parts[0])
                d["top10"].append({
                    "sha":    sha_m.group(1) + "…" if sha_m else parts[0][:16],
                    "url":    url_m.group(0)[1:-1] if url_m else "#",
                    "family": parts[1],
                    "cat":    parts[2],
                    "score":  parts[3].replace("**",""),
                    "level":  parts[4],
                    "s_sev":  parts[5] if len(parts) > 5 else "?",
                    "s_det":  parts[6] if len(parts) > 6 else "?",
                    "vt":     parts[7] if len(parts) > 7 else "–",
                })

    # VT-Blöcke
    d["vt_blocks"] = []
    vt_sections = re.split(r"### \[([0-9a-f]{20,64})[^]]*\]\(([^)]+)\)", md)
    for i in range(1, len(vt_sections), 3):
        sha_full = vt_sections[i]
        link     = vt_sections[i+1] if i+1 < len(vt_sections) else "#"
        body     = vt_sections[i+2] if i+2 < len(vt_sections) else ""
        fm = re.search(r"\*\*Familie:\*\* (.+)", body)
        dm = re.search(r"Erkannt von:\*\* (\d+) von (\d+) Engines \((.+?)%\)", body)
        nm = re.search(r"Häufigster Name:\*\* (.+)", body)
        rm = re.search(r"VT-Reputation:\*\* (.+)", body)
        engines = re.findall(r"\|\s*(.+?)\s*\|\s*`(.+?)`\s*\|", body)
        d["vt_blocks"].append({
            "sha":     sha_full[:20] + "…",
            "sha_full": sha_full,
            "link":    link,
            "family":  fm.group(1).strip() if fm else "?",
            "detected": dm.group(1) if dm else "?",
            "total":   dm.group(2) if dm else "?",
            "rate":    dm.group(3) if dm else "?",
            "top_name": nm.group(1).strip() if nm else "?",
            "rep":     rm.group(1).strip() if rm else "?",
            "engines": [(e.strip(), r.strip()) for e, r in engines if e.strip() != "Engine"],
        })

    # Tags
    d["tags"] = re.findall(r"- \*\*(.+?)\*\* \((\d+)×\)", md)

    # Delta
    d["delta"] = re.findall(r"^- ((?:neu:|↑|↓|weg:).+)$", md, re.MULTILINE)

    # Herkunftsländer
    d["origin_countries"] = []
    in_orig = False
    for line in md.split("\n"):
        if "## Herkunftsländer" in line: in_orig = True; continue
        if in_orig and line.startswith("## "): break
        if in_orig and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4 and parts[0] not in ("#","Land","Country"):
                # Format: | 1 | 🇩🇪 DE | 23 | 23.0% |
                flag_code = parts[1] if len(parts) > 1 else ""
                count_str = parts[2] if len(parts) > 2 else "0"
                pct_str   = parts[3] if len(parts) > 3 else "0%"
                cc = re.search(r"\b([A-Z]{2})\b", flag_code)
                m_flag = re.search(r"([\U0001F1E0-\U0001F1FF]{2})", flag_code)
                if cc:
                    m_cnt = re.search(r"\d+", count_str)
                    d["origin_countries"].append({
                        "code":  cc.group(1),
                        "flag":  m_flag.group(1) if m_flag else "🌐",
                        "label": flag_code.strip(),
                        "count": int(m_cnt.group()) if m_cnt else 0,
                        "pct":   pct_str.strip(),
                    })

    # Statistik-Tabelle
    d["stats"] = {}
    in_stat = False
    for line in md.split("\n"):
        if "## Statistik" in line: in_stat = True; continue
        if in_stat and line.startswith("## "): break
        if in_stat and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) == 2 and parts[0] != "Kennzahl":
                d["stats"][parts[0]] = parts[1]

    return d


def load_history() -> dict:
    if not HISTORY_FILE.exists():
        return {"labels": [], "datasets": []}
    try:
        hist = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"labels": [], "datasets": []}

    from collections import Counter
    runs = sorted(hist.items())[-14:]
    all_fams: Counter = Counter()
    for _, data in runs:
        all_fams.update(data.get("families", {}))
    top5 = [f for f, _ in all_fams.most_common(5)]
    labels   = [ts[:10] for ts, _ in runs]
    palette  = ["#ff4444","#ff8800","#ffcc00","#44ff88","#44aaff"]
    datasets = []
    for i, fam in enumerate(top5):
        vals = [data.get("families",{}).get(fam, 0) for _, data in runs]
        datasets.append({
            "label": fam[:28],
            "data": vals,
            "borderColor": palette[i % 5],
            "backgroundColor": palette[i % 5] + "22",
            "tension": 0.4,
            "pointRadius": 4,
            "pointHoverRadius": 7,
        })
    return {"labels": labels, "datasets": datasets}


# ─── HTML Generator ───────────────────────────────────────────────────────────

def build_dashboard(d: dict, hist: dict) -> str:
    total    = d.get("total", "0")
    created  = d.get("created", "?")
    r_krit   = d.get("r_krit",   0)
    r_hoch   = d.get("r_hoch",   0)
    r_mittel = d.get("r_mittel", 0)
    r_niedrig= d.get("r_niedrig",0)

    # Chart-Daten für Dateitypen
    ft_labels = [x["name"] for x in d.get("file_types", [])[:8]]
    ft_values = []
    for x in d.get("file_types", [])[:8]:
        m = re.search(r"\d+", x["count"])
        ft_values.append(int(m.group()) if m else 0)

    # Chart-Daten für Kategorien (Donut)
    cat_labels = [x["name"] for x in d.get("categories", [])]
    cat_values = []
    for x in d.get("categories", []):
        m = re.search(r"\d+", x["count"])
        cat_values.append(int(m.group()) if m else 0)
    cat_colors = ["#ff4444","#ff8800","#ffcc00","#44ff88","#44aaff","#aa44ff","#ff44aa","#44ffcc","#ffaa44","#8844ff"]

    # Familien-Tabelle HTML
    fam_rows = ""
    for x in d.get("families", []):
        pct_val = re.search(r"[\d.]+", x["pct"])
        pct_num = float(pct_val.group()) if pct_val else 0
        bar_w   = int(pct_num * 2)  # max 200px bei 100%
        fam_rows += f"""<tr>
          <td class="rank">{x['rank']}</td>
          <td class="family-name">{x['name']}</td>
          <td class="count">{x['count']}</td>
          <td class="pct-cell">
            <span class="pct-text">{x['pct']}</span>
            <div class="pct-bar" style="width:{bar_w}px"></div>
          </td>
        </tr>"""

    # Plattform-Karten
    plat_cards = ""
    plat_icons = {"Windows":"🪟","Linux":"🐧","macOS":"🍎","Android":"🤖",
                  "iOS":"📱","IoT/OT":"📡","Web":"🌐","Dokument":"📄","Archiv":"📦","Unbekannt":"❓"}
    for x in d.get("platforms", []):
        pct_val = re.search(r"[\d.]+", x["pct"])
        pct_num = float(pct_val.group()) if pct_val else 0
        name_clean = re.sub(r"[^\w/]", "", x["name"]).strip()
        icon = plat_icons.get(name_clean, "❓")
        for k, v in plat_icons.items():
            if k in x["name"]:
                icon = v; break
        plat_cards += f"""<div class="plat-card">
          <span class="plat-icon">{icon}</span>
          <span class="plat-name">{x['name']}</span>
          <span class="plat-count">{x['count']}</span>
          <div class="plat-bar-bg"><div class="plat-bar-fill" style="width:{min(pct_num,100)}%"></div></div>
          <span class="plat-pct">{x['pct']}</span>
        </div>"""

    # Top-10 Risk Tabelle
    top10_rows = ""
    level_colors = {"🔴 KRITISCH": "#ff4444", "🟠 HOCH": "#ff8800", "🟡 MITTEL": "#ffcc00", "🟢 NIEDRIG": "#44ff88"}
    for x in d.get("top10", []):
        col = level_colors.get(x["level"], "#888")
        top10_rows += f"""<tr>
          <td><a href="{x['url']}" target="_blank" class="sha-link">{x['sha']}</a></td>
          <td>{x['family']}</td>
          <td><span class="cat-badge">{x['cat']}</span></td>
          <td class="score-cell" style="color:{col}"><strong>{x['score']}</strong></td>
          <td style="color:{col}">{x['level']}</td>
          <td class="mono">{x['s_det']}</td>
          <td class="vt-cell">{x['vt']}</td>
        </tr>"""

    # VT Blöcke
    vt_html = ""
    for b in d.get("vt_blocks", []):
        engine_rows = ""
        for eng, res in b["engines"]:
            engine_rows += f"<tr><td class='eng-name'>{eng}</td><td class='eng-result'><code>{res}</code></td></tr>"
        vt_html += f"""<div class="vt-block">
          <div class="vt-header">
            <a href="{b['link']}" target="_blank" class="vt-sha">{b['sha']}</a>
            <span class="vt-family">{b['family']}</span>
            <span class="vt-rate" style="color:{'#ff4444' if float(b['rate'] or 0) > 50 else '#ff8800'}">{b['detected']}/{b['total']} ({b['rate']}%)</span>
          </div>
          <div class="vt-meta">
            <span>Häufigster Name: <strong>{b['top_name']}</strong></span>
            <span>Reputation: <strong>{b['rep']}</strong></span>
          </div>
          <details class="engine-details">
            <summary>{len(b['engines'])} erkennende Engines</summary>
            <table class="engine-table">{engine_rows}</table>
          </details>
        </div>"""

    # Tags
    tags_html = ""
    for tag, cnt in d.get("tags", [])[:20]:
        tags_html += f'<span class="tag-pill">{tag} <span class="tag-cnt">{cnt}</span></span>'

    # MITRE
    mitre_html = ""
    for x in d.get("mitre", []):
        mitre_html += f'<div class="mitre-row"><span class="mitre-tac">{x["tactic"]}</span><span class="mitre-cnt">{x["count"]}</span></div>'

    # Delta
    delta_html = ""
    for item in d.get("delta", []):
        icon = "🆕" if item.startswith("neu:") else "📈" if "↑" in item else "📉" if "↓" in item else "✅"
        delta_html += f'<div class="delta-item">{icon} {item}</div>'
    if not delta_html:
        delta_html = '<div class="delta-item">Keine Änderungen erfasst.</div>'

    # ── Origin Country Karte (Top oben) ──────────────────────────────────
    countries = d.get("origin_countries", [])
    total_samples_n = r_krit + r_hoch + r_mittel + r_niedrig

    # DE-Anteil berechnen
    de_entry   = next((c for c in countries if c["code"] == "DE"), None)
    de_count   = de_entry["count"] if de_entry else 0
    de_pct     = de_entry["pct"]   if de_entry else "0%"
    de_rank    = next((i+1 for i,c in enumerate(countries) if c["code"] == "DE"), None)

    # Top-Land (Pfeil oben)
    top_country    = countries[0] if countries else None
    second_country = countries[1] if len(countries) > 1 else None

    # Karten-HTML: Top-Land oben (Pfeil ↑), DE mittig, Land darunter (Pfeil ↓)
    if top_country:
        above_flag  = top_country["flag"]
        above_code  = top_country["code"]
        above_count = top_country["count"]
        above_pct   = top_country["pct"]
    else:
        above_flag = above_code = above_count = above_pct = "?"

    # Zweiter Platz (unter DE)
    below = second_country if second_country and second_country["code"] != "DE" else (countries[2] if len(countries) > 2 else None)
    below_flag  = below["flag"]  if below else "🌐"
    below_code  = below["code"]  if below else "?"
    below_count = below["count"] if below else 0
    below_pct   = below["pct"]   if below else "0%"

    # Alle Länder als Balken-Liste
    country_bars = ""
    max_cnt = countries[0]["count"] if countries else 1
    for i, c in enumerate(countries[:12]):
        bar_w  = int(c["count"] / max(max_cnt, 1) * 180)
        is_de  = c["code"] == "DE"
        color  = "var(--blue)" if is_de else ("var(--red)" if i == 0 else "var(--cyan)" if i < 3 else "var(--dim)")
        bold   = "font-weight:700;color:var(--blue)" if is_de else ""
        country_bars += f"""<div class="country-row">
          <span class="country-flag">{c['flag']}</span>
          <span class="country-code" style="{bold}">{c['code']}</span>
          <div class="country-bar-bg"><div class="country-bar-fill" style="width:{bar_w}px;background:{color}"></div></div>
          <span class="country-count">{c['count']}</span>
          <span class="country-pct">{c['pct']}</span>
        </div>"""

    hist_json = json.dumps(hist)
    ft_json   = json.dumps({"labels": ft_labels, "data": ft_values})
    cat_json  = json.dumps({"labels": cat_labels, "data": cat_values, "colors": cat_colors[:len(cat_labels)]})
    risk_json = json.dumps({
        "labels": ["Kritisch","Hoch","Mittel","Niedrig"],
        "data":   [r_krit, r_hoch, r_mittel, r_niedrig],
        "colors": ["#ff4444","#ff8800","#ffcc00","#44ff88"],
    })

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MalwareBazaar TI – {created}</title>
  <link rel="alternate" type="application/rss+xml" title="MalwareBazaar TI Feed" href="{BASE_URL}/rss.xml">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

    :root {{
      --bg0:    #080a0f;
      --bg1:    #0d1117;
      --bg2:    #13161e;
      --bg3:    #1a1f2e;
      --border: #1e2538;
      --border2:#252d3d;
      --text:   #c9d1d9;
      --muted:  #586069;
      --dim:    #3d4451;
      --red:    #ff4444;
      --orange: #ff8800;
      --yellow: #ffcc00;
      --green:  #00d26a;
      --blue:   #58a6ff;
      --cyan:   #39d5cf;
      --purple: #bc8cff;
      --mono:   'JetBrains Mono', monospace;
      --sans:   'DM Sans', sans-serif;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      background: var(--bg0);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* ── Scanlines overlay ── */
    body::before {{
      content: '';
      position: fixed; inset: 0; pointer-events: none; z-index: 9999;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
    }}

    /* ── Header ── */
    .header {{
      background: linear-gradient(180deg, #0a0d14 0%, var(--bg1) 100%);
      border-bottom: 1px solid var(--border);
      padding: 0 2rem;
      position: sticky; top: 0; z-index: 100;
      display: flex; align-items: center; justify-content: space-between;
      height: 56px;
    }}
    .header-left {{ display: flex; align-items: center; gap: 1rem; }}
    .header-logo {{ font-family: var(--mono); font-size: 1rem; font-weight: 700; color: var(--red); letter-spacing: -0.02em; }}
    .header-logo span {{ color: var(--muted); font-weight: 400; }}
    .header-ts {{ font-family: var(--mono); font-size: 0.72rem; color: var(--muted); }}
    .header-right {{ display: flex; gap: 1rem; align-items: center; }}
    .header-link {{
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
      text-decoration: none; padding: 0.25rem 0.6rem;
      border: 1px solid var(--border2); border-radius: 4px;
      transition: color 0.15s, border-color 0.15s;
    }}
    .header-link:hover {{ color: var(--blue); border-color: var(--blue); }}
    .live-dot {{
      width: 7px; height: 7px; border-radius: 50%; background: var(--green);
      box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite;
    }}
    @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}

    /* ── Layout ── */
    .page {{ max-width: 1440px; margin: 0 auto; padding: 1.5rem 2rem 4rem; }}

    /* ── KPI Bar ── */
    .kpi-bar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }}
    .kpi {{
      background: var(--bg1);
      padding: 1.25rem 1.5rem;
      display: flex; flex-direction: column; gap: 0.3rem;
      transition: background 0.15s;
    }}
    .kpi:hover {{ background: var(--bg2); }}
    .kpi-label {{ font-family: var(--mono); font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }}
    .kpi-val   {{ font-family: var(--mono); font-size: 1.9rem; font-weight: 700; line-height: 1; }}
    .kpi-sub   {{ font-size: 0.72rem; color: var(--dim); }}
    .kv-red    {{ color: var(--red);    }}
    .kv-orange {{ color: var(--orange); }}
    .kv-yellow {{ color: var(--yellow); }}
    .kv-green  {{ color: var(--green);  }}
    .kv-blue   {{ color: var(--blue);   }}
    .kv-cyan   {{ color: var(--cyan);   }}
    .kv-white  {{ color: var(--text);   }}

    /* ── Section title ── */
    .sec {{ margin-top: 2rem; }}
    .sec-title {{
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em;
      padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
      margin-bottom: 1rem; display: flex; align-items: center; gap: 0.6rem;
    }}
    .sec-title::before {{ content: '//'; color: var(--dim); }}

    /* ── Grid layouts ── */
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
    .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }}
    @media(max-width:900px) {{ .grid-2,.grid-3 {{ grid-template-columns: 1fr; }} }}

    /* ── Card ── */
    .card {{
      background: var(--bg1); border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden;
    }}
    .card-head {{
      padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
      font-family: var(--mono); font-size: 0.75rem; font-weight: 600;
      color: var(--text); display: flex; align-items: center; justify-content: space-between;
    }}
    .card-body {{ padding: 1rem; }}
    .chart-wrap {{ position: relative; height: 240px; }}

    /* ── Tables ── */
    .data-table {{ width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 0.78rem; }}
    .data-table th {{
      padding: 0.5rem 0.75rem; text-align: left;
      color: var(--muted); font-weight: 600; font-size: 0.68rem;
      text-transform: uppercase; letter-spacing: 0.06em;
      border-bottom: 1px solid var(--border);
    }}
    .data-table td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); color: var(--text); }}
    .data-table tr:last-child td {{ border-bottom: none; }}
    .data-table tr:hover td {{ background: var(--bg2); }}
    .rank {{ color: var(--muted); width: 2rem; }}
    .family-name {{ font-weight: 600; }}
    .count {{ text-align: right; color: var(--cyan); }}
    .pct-cell {{ display: flex; align-items: center; gap: 0.5rem; min-width: 120px; }}
    .pct-text {{ color: var(--muted); width: 3rem; text-align: right; font-size: 0.72rem; }}
    .pct-bar {{ height: 3px; background: var(--blue); border-radius: 2px; opacity: 0.7; transition: width 0.5s; }}
    .score-cell {{ font-size: 1rem; }}
    .sha-link {{ color: var(--cyan); text-decoration: none; font-family: var(--mono); font-size: 0.75rem; }}
    .sha-link:hover {{ color: var(--blue); text-decoration: underline; }}
    .cat-badge {{
      background: var(--bg3); border: 1px solid var(--border2);
      border-radius: 3px; padding: 0.1rem 0.4rem; font-size: 0.7rem; color: var(--muted);
    }}
    .mono {{ font-family: var(--mono); font-size: 0.75rem; }}
    .vt-cell {{ color: var(--green); font-family: var(--mono); }}

    /* ── Plattform cards ── */
    .plat-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 0.75rem; }}
    .plat-card {{
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 6px; padding: 0.75rem;
      display: flex; flex-direction: column; gap: 0.3rem;
    }}
    .plat-icon {{ font-size: 1.4rem; }}
    .plat-name {{ font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: var(--text); }}
    .plat-count {{ font-family: var(--mono); font-size: 1.3rem; color: var(--blue); font-weight: 700; }}
    .plat-bar-bg {{ background: var(--bg3); border-radius: 2px; height: 3px; overflow: hidden; }}
    .plat-bar-fill {{ background: var(--blue); height: 100%; transition: width 0.6s; }}
    .plat-pct {{ font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }}

    /* ── MITRE ── */
    .mitre-row {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.4rem 0; border-bottom: 1px solid var(--border);
      font-family: var(--mono); font-size: 0.78rem;
    }}
    .mitre-row:last-child {{ border-bottom: none; }}
    .mitre-tac {{ color: var(--text); }}
    .mitre-cnt {{
      background: var(--bg3); color: var(--cyan);
      padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.72rem;
    }}

    /* ── VT Blocks ── */
    .vt-block {{
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem;
    }}
    .vt-header {{ display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem; }}
    .vt-sha {{ font-family: var(--mono); font-size: 0.78rem; color: var(--cyan); text-decoration: none; }}
    .vt-sha:hover {{ text-decoration: underline; }}
    .vt-family {{ font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }}
    .vt-rate {{ font-family: var(--mono); font-size: 0.85rem; font-weight: 700; margin-left: auto; }}
    .vt-meta {{ display: flex; gap: 2rem; font-size: 0.78rem; color: var(--muted); margin-bottom: 0.6rem; }}
    .vt-meta strong {{ color: var(--text); }}
    .engine-details summary {{
      cursor: pointer; font-family: var(--mono); font-size: 0.75rem; color: var(--blue);
      padding: 0.25rem 0; user-select: none;
    }}
    .engine-details summary:hover {{ color: var(--cyan); }}
    .engine-table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    .engine-table tr:hover td {{ background: var(--bg3); }}
    .engine-table td {{ padding: 0.25rem 0.5rem; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 0.73rem; }}
    .eng-name {{ color: var(--muted); width: 35%; }}
    .eng-result code {{ color: var(--yellow); background: var(--bg3); padding: 0.1rem 0.3rem; border-radius: 2px; font-size: 0.72rem; }}

    /* ── Tags ── */
    .tags-wrap {{ display: flex; flex-wrap: wrap; gap: 0.4rem; }}
    .tag-pill {{
      background: var(--bg3); border: 1px solid var(--border2);
      border-radius: 4px; padding: 0.2rem 0.6rem;
      font-family: var(--mono); font-size: 0.73rem; color: var(--text);
      display: flex; align-items: center; gap: 0.4rem;
    }}
    .tag-cnt {{
      background: var(--bg0); color: var(--cyan);
      border-radius: 3px; padding: 0 0.3rem; font-size: 0.68rem;
    }}

    /* ── Delta ── */
    .delta-list {{ display: flex; flex-direction: column; gap: 0.4rem; }}
    .delta-item {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text); padding: 0.35rem 0.6rem; background: var(--bg2); border-radius: 4px; border-left: 2px solid var(--dim); }}

    /* ── Trend chart ── */
    .trend-wrap {{ position: relative; height: 260px; }}

    /* ── Footer ── */
    footer {{
      margin-top: 3rem; padding: 1.5rem 2rem;
      border-top: 1px solid var(--border);
      text-align: center; font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }}
    footer a {{ color: var(--blue); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}

    /* ── Origin Country Karte ── */
    .origin-map {{
      background: var(--bg1);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.5rem;
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 1rem;
      align-items: stretch;
    }}
    .origin-column {{
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 0.4rem; min-width: 90px;
    }}
    .origin-arrow {{ font-size: 1.4rem; color: var(--muted); }}
    .origin-flag  {{ font-size: 2.2rem; line-height: 1; }}
    .origin-code  {{ font-family: var(--mono); font-size: 0.9rem; font-weight: 700; color: var(--text); }}
    .origin-count {{
      font-family: var(--mono); font-size: 1.6rem; font-weight: 700;
      color: var(--red); line-height: 1;
    }}
    .origin-pct   {{ font-size: 0.72rem; color: var(--muted); }}
    .origin-de-col {{
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 0.35rem; border-left: 1px solid var(--border2); border-right: 1px solid var(--border2);
      padding: 0 1.5rem;
    }}
    .origin-de-label {{ font-family: var(--mono); font-size: 0.65rem; color: var(--muted); text-transform: uppercase; letter-spacing:0.1em; }}
    .origin-de-flag  {{ font-size: 2.8rem; line-height: 1; }}
    .origin-de-count {{ font-family: var(--mono); font-size: 2.4rem; font-weight: 700; color: var(--blue); line-height: 1; }}
    .origin-de-pct   {{ font-size: 0.78rem; color: var(--blue); opacity: 0.8; }}
    .origin-de-rank  {{ font-size: 0.72rem; color: var(--muted); }}
    .origin-bars     {{ display: flex; flex-direction: column; gap: 0.35rem; flex: 1; justify-content: center; }}
    .country-row     {{ display: flex; align-items: center; gap: 0.5rem; }}
    .country-flag    {{ font-size: 1rem; width: 22px; text-align: center; }}
    .country-code    {{ font-family: var(--mono); font-size: 0.72rem; color: var(--muted); width: 28px; }}
    .country-bar-bg  {{ flex: 1; height: 4px; background: var(--bg3); border-radius: 2px; overflow:hidden; max-width: 180px; }}
    .country-bar-fill{{ height: 100%; border-radius: 2px; transition: width 0.4s ease; }}
    .country-count   {{ font-family: var(--mono); font-size: 0.72rem; color: var(--text); width: 28px; text-align:right; }}
    .country-pct     {{ font-family: var(--mono); font-size: 0.68rem; color: var(--muted); width: 38px; text-align:right; }}
    @media(max-width:600px) {{
      .origin-map {{ grid-template-columns: 1fr; }}
      .origin-de-col {{ border: none; border-top: 1px solid var(--border2); border-bottom: 1px solid var(--border2); padding: 1rem 0; }}
    }}
  </style>
</head>
<body>

<header class="header">
  <div class="header-left">
    <div class="live-dot"></div>
    <div class="header-logo">malware<span>-</span>intel</div>
    <div class="header-ts">{created}</div>
  </div>
  <div class="header-right">
    <a href="{BASE_URL}/rss.xml" class="header-link">RSS</a>
    <a href="{BASE_URL}/rss_kpi.xml" class="header-link">KPI-RSS</a>
    <a href="{BASE_URL}/reports/latest.md" class="header-link" target="_blank">report.md</a>
    <a href="https://bazaar.abuse.ch" class="header-link" target="_blank">bazaar</a>
  </div>
</header>

<main class="page">

  <!-- Origin Country Karte -->
  <div class="origin-map">
    <!-- Linke Spalte: Top-Land (Pfeil hoch) -->
    <div class="origin-column">
      <div class="origin-arrow">↑</div>
      <div class="origin-flag">{above_flag}</div>
      <div class="origin-code">{above_code}</div>
      <div class="origin-count">{above_count}</div>
      <div class="origin-pct">{above_pct}</div>
    </div>

    <!-- Mitte: Deutschland -->
    <div class="origin-de-col">
      <div class="origin-de-label">Origin Country</div>
      <div class="origin-de-flag">🇩🇪</div>
      <div class="origin-de-count">{de_count if de_count else '–'}</div>
      <div class="origin-de-pct">{de_pct}</div>
      <div class="origin-de-rank">{'Rang #' + str(de_rank) if de_rank else 'nicht in Top 15'}</div>
    </div>

    <!-- Rechte Spalte: alle Länder als Balken -->
    <div class="origin-bars">
      {country_bars if country_bars else '<span style="color:var(--muted);font-size:0.78rem">Keine Origin-Country-Daten<br>(benötigt ≥1 Run mit v2)</span>'}
    </div>
  </div>

  <!-- KPI Bar -->
  <div class="kpi-bar">
    <div class="kpi">
      <div class="kpi-label">Neue Samples</div>
      <div class="kpi-val kv-white">{total}</div>
      <div class="kpi-sub">dieser Run</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🔴 Kritisch</div>
      <div class="kpi-val kv-red">{r_krit}</div>
      <div class="kpi-sub">Score ≥ 75</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟠 Hoch</div>
      <div class="kpi-val kv-orange">{r_hoch}</div>
      <div class="kpi-sub">Score 55–74</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟡 Mittel</div>
      <div class="kpi-val kv-yellow">{r_mittel}</div>
      <div class="kpi-sub">Score 35–54</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟢 Niedrig</div>
      <div class="kpi-val kv-green">{r_niedrig}</div>
      <div class="kpi-sub">Score &lt; 35</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Top Score</div>
      <div class="kpi-val kv-red">{d.get('top_score','?')}</div>
      <div class="kpi-sub">{d.get('top_sha','')[:12]}…</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">VT enriched</div>
      <div class="kpi-val kv-blue">{d.get('vt_enriched','?')}</div>
      <div class="kpi-sub">Samples</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">MITRE mapped</div>
      <div class="kpi-val kv-cyan">{d.get('mitre_mapped','?')}</div>
      <div class="kpi-sub">Samples</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Ø Größe</div>
      <div class="kpi-val kv-white" style="font-size:1.2rem">{d.get('avg_size','?')}</div>
      <div class="kpi-sub">Dateigröße</div>
    </div>
  </div>

  <!-- Charts Row -->
  <div class="grid-3 sec">
    <div class="card">
      <div class="card-head">Risiko-Verteilung</div>
      <div class="card-body"><div class="chart-wrap"><canvas id="riskChart"></canvas></div></div>
    </div>
    <div class="card">
      <div class="card-head">Top Dateitypen</div>
      <div class="card-body"><div class="chart-wrap"><canvas id="ftChart"></canvas></div></div>
    </div>
    <div class="card">
      <div class="card-head">Kategorien</div>
      <div class="card-body"><div class="chart-wrap"><canvas id="catChart"></canvas></div></div>
    </div>
  </div>

  <!-- Trend Chart -->
  <div class="sec card">
    <div class="card-head">Familien-Trend <span style="color:var(--muted);font-weight:400">letzte 14 Runs</span></div>
    <div class="card-body"><div class="trend-wrap"><canvas id="trendChart"></canvas></div></div>
  </div>

  <!-- Familien + Plattformen -->
  <div class="grid-2 sec">
    <div class="card">
      <div class="card-head">Top Malware-Familien</div>
      <div class="card-body" style="padding:0">
        <table class="data-table">
          <thead><tr><th>#</th><th>Familie</th><th>Anz.</th><th>Anteil</th></tr></thead>
          <tbody>{fam_rows}</tbody>
        </table>
      </div>
    </div>
    <div class="card">
      <div class="card-head">Betroffene Plattformen</div>
      <div class="card-body">
        <div class="plat-grid">{plat_cards}</div>
      </div>
    </div>
  </div>

  <!-- Top 10 Risk -->
  <div class="sec card">
    <div class="card-head">Top 10 nach Risiko-Score</div>
    <div class="card-body" style="padding:0;overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>SHA256</th><th>Familie</th><th>Kategorie</th><th>Score</th><th>Level</th><th>S_det</th><th>VT</th></tr></thead>
        <tbody>{top10_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- MITRE + Delta -->
  <div class="grid-2 sec">
    <div class="card">
      <div class="card-head">MITRE ATT&amp;CK Taktiken</div>
      <div class="card-body">{mitre_html if mitre_html else '<span style="color:var(--muted)">Keine Daten</span>'}</div>
    </div>
    <div class="card">
      <div class="card-head">Änderungen gegenüber Vorrun</div>
      <div class="card-body"><div class="delta-list">{delta_html}</div></div>
    </div>
  </div>

  <!-- VirusTotal -->
  {"<div class='sec'><div class='sec-title'>VirusTotal Ergebnisse</div>" + vt_html + "</div>" if vt_html else ""}

  <!-- Tags -->
  <div class="sec card">
    <div class="card-head">Häufigste Tags</div>
    <div class="card-body"><div class="tags-wrap">{tags_html}</div></div>
  </div>

</main>

<footer>
  Daten: <a href="https://bazaar.abuse.ch" target="_blank">MalwareBazaar (abuse.ch)</a> ×
  <a href="https://virustotal.com" target="_blank">VirusTotal</a> —
  nur für Threat-Intelligence und Bildungszwecke —
  <a href="{BASE_URL}/rss.xml">RSS</a>
</footer>

<script>
const HIST = {hist_json};
const FT   = {ft_json};
const CAT  = {cat_json};
const RISK = {risk_json};

const mono = "'JetBrains Mono', monospace";
const defaults = {{
  plugins: {{
    legend: {{ labels: {{ color: '#586069', font: {{ family: mono, size: 11 }} }} }},
  }},
  scales: {{
    x: {{ ticks: {{ color: '#586069', font: {{ family: mono, size: 11 }} }}, grid: {{ color: '#1e2538' }} }},
    y: {{ ticks: {{ color: '#586069', font: {{ family: mono, size: 11 }} }}, grid: {{ color: '#1e2538' }} }},
  }},
}};

// Risiko Doughnut
new Chart(document.getElementById('riskChart'), {{
  type: 'doughnut',
  data: {{
    labels: RISK.labels,
    datasets: [{{ data: RISK.data, backgroundColor: RISK.colors, borderWidth: 0, hoverOffset: 6 }}],
  }},
  options: {{
    cutout: '70%',
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }}, padding: 12 }} }},
    }},
  }},
}});

// Dateitypen Horizontal Bar
new Chart(document.getElementById('ftChart'), {{
  type: 'bar',
  data: {{
    labels: FT.labels,
    datasets: [{{
      data: FT.data,
      backgroundColor: '#58a6ff22',
      borderColor: '#58a6ff',
      borderWidth: 1,
      borderRadius: 3,
    }}],
  }},
  options: {{
    indexAxis: 'y',
    ...defaults,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#586069', font: {{ family: mono, size: 10 }} }}, grid: {{ color: '#1e2538' }} }},
      y: {{ ticks: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }} }}, grid: {{ display: false }} }},
    }},
  }},
}});

// Kategorien Doughnut
new Chart(document.getElementById('catChart'), {{
  type: 'doughnut',
  data: {{
    labels: CAT.labels,
    datasets: [{{ data: CAT.data, backgroundColor: CAT.colors, borderWidth: 0, hoverOffset: 6 }}],
  }},
  options: {{
    cutout: '60%',
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 10 }}, padding: 8, boxWidth: 10 }} }},
    }},
  }},
}});

// Trend
if (HIST.labels && HIST.labels.length > 1) {{
  new Chart(document.getElementById('trendChart'), {{
    type: 'line',
    data: {{ labels: HIST.labels, datasets: HIST.datasets }},
    options: {{
      ...defaults,
      plugins: {{
        legend: {{ labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }}, padding: 16 }} }},
      }},
      scales: {{
        x: {{ ticks: {{ color: '#586069', font: {{ family: mono, size: 10 }} }}, grid: {{ color: '#1e2538' }} }},
        y: {{ beginAtZero: true, ticks: {{ color: '#586069', font: {{ family: mono, size: 11 }} }}, grid: {{ color: '#1e2538' }} }},
      }},
    }},
  }});
}} else {{
  document.getElementById('trendChart').parentElement.innerHTML =
    '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#586069;font-family:' + mono + ';font-size:0.75rem">Trend wird nach mehreren Runs sichtbar</div>';
}}
</script>
</body>
</html>"""


def main():
    # Report laden
    latest = REPORTS_DIR / "latest.md"
    if not latest.exists():
        reports = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)
        if not reports:
            print("[!] Kein Report gefunden.")
            return
        latest = reports[0]

    print(f"[*] Parse {latest.name} ...")
    md   = latest.read_text(encoding="utf-8")
    d    = parse_report(md)
    hist = load_history()

    print(f"    Datum:    {d['created']}")
    print(f"    Samples:  {d['total']}")
    print(f"    Familien: {len(d['families'])}")
    print(f"    VT:       {len(d['vt_blocks'])} Blöcke")

    html = build_dashboard(d, hist)
    out  = WEB_DIR / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"[+] Dashboard → {out}")


if __name__ == "__main__":
    main()
