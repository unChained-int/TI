import json
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
FEED_FILE    = Path("feed.json")
WEB_DIR      = Path("web")
WEB_DIR.mkdir(exist_ok=True)

BASE_URL = "https://unchained-int.github.io/TI"


# ─── Parser ───────────────────────────────────────────────────────────────────

def parse_report(md: str) -> dict:
    d = {}
    m = re.search(r"# MalwareBazaar\s*[–-]\s*(.+)", md)
    d["created"] = m.group(1).strip() if m else "?"

    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    d["new_samples"] = int(m.group(1)) if m else 0

    def ov(label):
        m = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*\*?\*?([^|\n*]+?)\*?\*?\s*\|", md)
        return m.group(1).strip() if m else "?"

    d["total"]        = ov("Neue Samples").replace("**","")
    d["kritisch"]     = ov("Kritisch").replace("**","")
    d["top_score"]    = ov("Höchster Score").split("–")[0].replace("**","").strip()
    d["top_sha"]      = re.search(r"Höchster Score.*?([0-9a-f]{16})", md)
    d["top_sha"]      = d["top_sha"].group(1) if d["top_sha"] else ""
    d["top_family"]   = ov("Häufigste Familie").replace("**","").split("(")[0].strip()
    d["top_type"]     = ov("Häufigster Typ").replace("**","").split("(")[0].strip()
    d["main_plat"]    = ov("Hauptplattform").replace("**","")
    d["vt_enriched"]  = ov("VT-angereichert").replace("**","")
    d["mitre_mapped"] = ov("MITRE gemappt").replace("**","")
    d["avg_size"]     = ov("Ø Dateigröße").replace("**","")

    for lvl, key in [("🔴 KRITISCH","r_krit"),("🟠 HOCH","r_hoch"),
                     ("🟡 MITTEL","r_mittel"),("🟢 NIEDRIG","r_niedrig")]:
        m = re.search(re.escape(lvl) + r"\s*\|\s*(\d+)", md)
        d[key] = int(m.group(1)) if m else 0

    def parse_table(section_header):
        rows = []
        active = False
        for line in md.split("\n"):
            if section_header in line: active = True; continue
            if active and line.startswith("## "): break
            if active and line.startswith("|") and "|---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts:
                    rows.append(parts)
        return rows

    # Dateitypen
    d["file_types"] = []
    for parts in parse_table("## Dateitypen"):
        if len(parts) >= 3 and parts[0] != "Typ" and parts[0].startswith("`"):
            d["file_types"].append({"name": parts[0].replace("`",""), "count": parts[1],
                                    "pct": parts[2].split("%")[0] + "%" if "%" in parts[2] else parts[2]})

    # Familien
    d["families"] = []
    for parts in parse_table("## Familien"):
        if len(parts) >= 4 and parts[0].isdigit():
            d["families"].append({"rank": parts[0], "name": parts[1], "count": parts[2], "pct": parts[3]})

    # Klassifikation
    d["categories"] = []
    for parts in parse_table("## Klassifikation"):
        if len(parts) >= 4 and parts[0] not in ("Kategorie",""):
            d["categories"].append({"name": parts[0].replace("**",""), "count": parts[1], "pct": parts[2], "conf": parts[3]})

    # Plattformen
    d["platforms"] = []
    for parts in parse_table("## Betroffene Plattformen"):
        if len(parts) >= 3 and "Plattform" not in parts[0]:
            d["platforms"].append({"name": parts[0], "count": parts[1], "pct": parts[2]})

    # Vektoren
    d["vectors"] = []
    for parts in parse_table("## Infektionsvektoren"):
        if len(parts) >= 3 and parts[0] != "Vektor":
            d["vectors"].append({"name": parts[0], "count": parts[1], "pct": parts[2]})

    # MITRE
    d["mitre"] = []
    for parts in parse_table("## MITRE ATT&CK"):
        if len(parts) >= 2 and parts[0] not in ("Taktik",""):
            d["mitre"].append({"tactic": parts[0], "count": parts[1]})

    # Top-10 Risk
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
                weekly = "⭐" in parts[0]
                # VT-Rate aus Spalte (neu)
                vt_rate = parts[5] if len(parts) > 5 else "?"
                dq      = parts[6] if len(parts) > 6 else "?"
                defender= parts[7] if len(parts) > 7 else "?"
                d["top10"].append({
                    "sha":      sha_m.group(1) + "…" if sha_m else parts[0][:16],
                    "url":      url_m.group(0)[1:-1] if url_m else "#",
                    "family":   parts[1],
                    "cat":      parts[2],
                    "score":    parts[3].replace("**",""),
                    "level":    parts[4],
                    "vt_rate":  vt_rate,
                    "quality":  dq,
                    "defender": defender,
                    "is_weekly": weekly,
                })

    # VT-Blöcke (erweitert: Qualität + Defender)
    d["vt_blocks"] = []
    vt_sections = re.split(r"### \[([0-9a-f]{20,64})[^]]*\]\(([^)]+)\)", md)
    for i in range(1, len(vt_sections), 3):
        sha_full = vt_sections[i]
        link     = vt_sections[i+1] if i+1 < len(vt_sections) else "#"
        body     = vt_sections[i+2] if i+2 < len(vt_sections) else ""
        fm  = re.search(r"\*\*Familie:\*\* (.+)", body)
        dm  = re.search(r"Erkannt von:\*\* (\d+) von (\d+) Engines \((.+?)%\)", body)
        qm  = re.search(r"Erkennungsqualität:\*\* (.+)", body)
        defm= re.search(r"Microsoft Defender:\*\* (.+)", body)
        nm  = re.search(r"Häufigster Name:\*\* (.+)", body)
        rm  = re.search(r"VT-Reputation:\*\* (.+)", body)
        engines = re.findall(r"\|\s*(.+?)\s*\|\s*`(.+?)`\s*\|", body)
        rate = float(dm.group(3)) / 100 if dm else 0
        # Farblogik: niedrig = ROT (evasiv), hoch = GRÜN
        if rate < 0.10:    rate_color = "#ff4444"
        elif rate < 0.30:  rate_color = "#ff8800"
        elif rate < 0.60:  rate_color = "#ffcc00"
        else:              rate_color = "#00d26a"
        d["vt_blocks"].append({
            "sha":        sha_full[:20] + "…",
            "sha_full":   sha_full,
            "link":       link,
            "family":     fm.group(1).strip() if fm else "?",
            "detected":   dm.group(1) if dm else "?",
            "total":      dm.group(2) if dm else "?",
            "rate":       dm.group(3) if dm else "?",
            "rate_color": rate_color,
            "quality":    qm.group(1).strip() if qm else "?",
            "defender":   defm.group(1).strip() if defm else "?",
            "top_name":   nm.group(1).strip() if nm else "?",
            "rep":        rm.group(1).strip() if rm else "?",
            "engines":    [(e.strip(), r.strip()) for e, r in engines if e.strip() != "Engine"],
            "is_weekly":  "⭐" in (sha_full + body[:50]),
        })

    # Tags
    d["tags"] = re.findall(r"- \*\*(.+?)\*\* \((\d+)×\)", md)

    # Delta 24h + 7d
    d["delta_24h"] = re.findall(r"^- ((?:neu:|↑|↓|weg:).+)$",
                                 md[md.find("## Änderungen – 24h"):md.find("## Änderungen – 7d")],
                                 re.MULTILINE)
    d["delta_7d"] = re.findall(r"^- ((?:neu:|↑|↓|weg:).+)$",
                                md[md.find("## Änderungen – 7d"):],
                                re.MULTILINE)

    # Herkunftsländer
    d["origin_countries"] = []
    in_orig = False
    for line in md.split("\n"):
        if "## Herkunftsländer" in line: in_orig = True; continue
        if in_orig and line.startswith("## "): break
        if in_orig and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4 and parts[0] not in ("#","Land","Country"):
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

    # AV-Zuverlässigkeit (aus Bericht extrahieren falls vorhanden)
    d["av_table"] = []
    in_av = False
    for line in md.split("\n"):
        if "## AV-Zuverlässigkeit" in line: in_av = True; continue
        if in_av and line.startswith("## "): break
        if in_av and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4 and parts[0].isdigit():
                d["av_table"].append({"rank": parts[0], "engine": parts[1], "score": parts[2], "stats": parts[3]})

    # Wochen-Sample SHA
    m = re.search(r"⭐ \*\*Wochen-Sample aktiv:\*\* `([0-9a-f]+)", md)
    d["weekly_sha"] = m.group(1) if m else ""

    # Statistik
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


def load_history_charts() -> tuple[dict, dict]:
    """Gibt Chart-Daten für 24h- und 7d-Trend zurück."""
    if not HISTORY_FILE.exists():
        empty = {"labels": [], "datasets": []}
        return empty, empty

    try:
        hist = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        empty = {"labels": [], "datasets": []}
        return empty, empty

    now       = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d  = now - timedelta(days=7)

    runs_all = sorted(hist.items())

    def build_chart(runs, title_suffix=""):
        all_fams = Counter()
        for _, data in runs:
            all_fams.update(data.get("families", {}))
        top5     = [f for f, _ in all_fams.most_common(5)]
        labels   = [ts[:10] + " " + ts[11:16] for ts, _ in runs]
        palette  = ["#ff4444","#ff8800","#ffcc00","#44ff88","#44aaff"]
        datasets = []
        for i, fam in enumerate(top5):
            vals = [data.get("families",{}).get(fam, 0) for _, data in runs]
            datasets.append({
                "label": fam[:25],
                "data": vals,
                "borderColor": palette[i % 5],
                "backgroundColor": palette[i % 5] + "22",
                "tension": 0.4, "pointRadius": 3, "pointHoverRadius": 6,
            })
        return {"labels": labels, "datasets": datasets}

    # 24h: nur Runs der letzten 24h
    runs_24h = []
    for ts_str, data in runs_all:
        try:
            ts = datetime.fromisoformat(ts_str)
            if not ts.tzinfo:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff_24h:
                runs_24h.append((ts_str, data))
        except Exception:
            pass

    # 7d: letzte 7 Tage (max 14 Datenpunkte für Übersichtlichkeit)
    runs_7d = []
    for ts_str, data in runs_all:
        try:
            ts = datetime.fromisoformat(ts_str)
            if not ts.tzinfo:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff_7d:
                runs_7d.append((ts_str, data))
        except Exception:
            pass
    # 7d auf max 14 Punkte reduzieren (gleichmäßig sampeln)
    if len(runs_7d) > 14:
        step = len(runs_7d) // 14
        runs_7d_sampled = runs_7d[::step][:14]
    else:
        runs_7d_sampled = runs_7d

    chart_24h = build_chart(runs_24h) if runs_24h else {"labels": [], "datasets": []}
    chart_7d  = build_chart(runs_7d_sampled) if runs_7d_sampled else {"labels": [], "datasets": []}

    return chart_24h, chart_7d


def load_feed_24h_7d() -> dict:
    """Lädt 24h/7d Aggregat aus feed.json (wenn vorhanden)."""
    if not FEED_FILE.exists():
        return {}
    try:
        return json.loads(FEED_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ─── HTML Generator ───────────────────────────────────────────────────────────

def build_dashboard(d: dict, chart_24h: dict, chart_7d: dict, feed: dict) -> str:
    created   = d.get("created", "?")
    r_krit    = d.get("r_krit",   0)
    r_hoch    = d.get("r_hoch",   0)
    r_mittel  = d.get("r_mittel", 0)
    r_niedrig = d.get("r_niedrig",0)

    # 24h-Aggregat aus feed.json (bevorzugt über einzelnen Run)
    agg24 = feed.get("24h", {})
    agg24_krit    = agg24.get("risk", {}).get("kritisch", r_krit)
    agg24_hoch    = agg24.get("risk", {}).get("hoch",     r_hoch)
    agg24_mittel  = agg24.get("risk", {}).get("mittel",   r_mittel)
    agg24_niedrig = agg24.get("risk", {}).get("niedrig",  r_niedrig)
    agg24_total   = agg24.get("total_samples", d.get("new_samples", 0))
    agg24_crit_rate = agg24.get("critical_rate_pct", 0)

    # 7d-Aggregat
    agg7d = feed.get("7d", {})
    agg7d_krit   = agg7d.get("risk", {}).get("kritisch", 0)
    agg7d_total  = agg7d.get("total_samples", 0)

    # Wochen-Sample Info
    weekly_info = feed.get("weekly_sample", {})
    weekly_sha  = d.get("weekly_sha", "")

    # Chart-Daten für Dateitypen
    ft_labels = [x["name"] for x in d.get("file_types", [])[:8]]
    ft_values = []
    for x in d.get("file_types", [])[:8]:
        m = re.search(r"\d+", x["count"])
        ft_values.append(int(m.group()) if m else 0)

    # Chart-Daten für Kategorien
    cat_labels = [x["name"] for x in d.get("categories", [])]
    cat_values = []
    for x in d.get("categories", []):
        m = re.search(r"\d+", x["count"])
        cat_values.append(int(m.group()) if m else 0)
    cat_colors = ["#ff4444","#ff8800","#ffcc00","#44ff88","#44aaff","#aa44ff","#ff44aa","#44ffcc","#ffaa44","#8844ff"]

    # Risiko-Chart (24h statt nur letzter Run)
    risk_json = json.dumps({
        "labels": ["Kritisch","Hoch","Mittel","Niedrig"],
        "data":   [agg24_krit, agg24_hoch, agg24_mittel, agg24_niedrig],
        "colors": ["#ff4444","#ff8800","#ffcc00","#44ff88"],
    })

    # Familien-Tabelle HTML
    fam_rows = ""
    for x in d.get("families", []):
        pct_val = re.search(r"[\d.]+", x["pct"])
        pct_num = float(pct_val.group()) if pct_val else 0
        bar_w   = int(pct_num * 2)
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
        icon = next((v for k, v in plat_icons.items() if k in x["name"]), "❓")
        plat_cards += f"""<div class="plat-card">
          <span class="plat-icon">{icon}</span>
          <span class="plat-name">{x['name']}</span>
          <span class="plat-count">{x['count']}</span>
          <div class="plat-bar-bg"><div class="plat-bar-fill" style="width:{min(pct_num,100)}%"></div></div>
          <span class="plat-pct">{x['pct']}</span>
        </div>"""

    # Top-10 Risk Tabelle (mit VT-Rate Farbe + Defender)
    top10_rows = ""
    level_colors = {"🔴 KRITISCH":"#ff4444","🟠 HOCH":"#ff8800","🟡 MITTEL":"#ffcc00","🟢 NIEDRIG":"#44ff88"}
    for x in d.get("top10", []):
        col = level_colors.get(x["level"], "#888")
        # VT-Rate Farbe: NIEDRIG = ROT
        vt_rate_str = x.get("vt_rate", "–")
        try:
            vt_rate_val = float(vt_rate_str.replace("%","")) / 100
            if vt_rate_val < 0.10:    vt_col = "#ff4444"
            elif vt_rate_val < 0.30:  vt_col = "#ff8800"
            elif vt_rate_val < 0.60:  vt_col = "#ffcc00"
            else:                     vt_col = "#00d26a"
        except:
            vt_col = "#888"
        weekly_star = "⭐ " if x.get("is_weekly") else ""
        defender_sym = "🛡️✓" if "JA" in x.get("defender","") else ("🛡️✗" if "NEIN" in x.get("defender","") else "?")
        top10_rows += f"""<tr>
          <td>{weekly_star}<a href="{x['url']}" target="_blank" class="sha-link">{x['sha']}</a></td>
          <td>{x['family']}</td>
          <td><span class="cat-badge">{x['cat']}</span></td>
          <td class="score-cell" style="color:{col}"><strong>{x['score']}</strong></td>
          <td style="color:{col}">{x['level']}</td>
          <td class="mono" style="color:{vt_col}" title="Niedrig = evasiv = gefährlich">{vt_rate_str}</td>
          <td class="mono" style="font-size:0.72rem">{x.get('quality','–')[:20]}</td>
          <td class="mono">{defender_sym}</td>
        </tr>"""

    # VT-Blöcke (mit korrekter Farblogik)
    vt_html = ""
    for b in d.get("vt_blocks", []):
        engine_rows = ""
        for eng, res in b["engines"]:
            is_mandatory = any(m.lower() in eng.lower() for m in ["microsoft","defender"])
            marker = " 🛡️" if is_mandatory else ""
            engine_rows += f"<tr><td class='eng-name'>{eng}{marker}</td><td class='eng-result'><code>{res}</code></td></tr>"
        weekly_badge = '<span class="weekly-badge">⭐ WOCHEN-SAMPLE</span>' if b.get("is_weekly") else ""
        # Qualitäts-Badge
        q = b.get("quality", "?")
        if "KAUM" in q:         q_col = "#ff4444"
        elif "SCHWACH" in q:    q_col = "#ff8800"
        elif "MÄSSIG" in q:     q_col = "#ffcc00"
        elif "GUT" in q:        q_col = "#00d26a"
        else:                   q_col = "#888"
        defender_info = b.get("defender", "?")
        def_col = "#00d26a" if "JA" in defender_info else ("#ff4444" if "NEIN" in defender_info else "#888")
        vt_html += f"""<div class="vt-block {'weekly-block' if b.get('is_weekly') else ''}">
          <div class="vt-header">
            <a href="{b['link']}" target="_blank" class="vt-sha">{b['sha']}</a>
            {weekly_badge}
            <span class="vt-family">{b['family']}</span>
            <span class="vt-rate" style="color:{b['rate_color']}" title="NIEDRIG = evasiv = gefährlich">{b['detected']}/{b['total']} ({b['rate']}%)</span>
          </div>
          <div class="vt-meta">
            <span>Qualität: <strong style="color:{q_col}">{q}</strong></span>
            <span>Häufigster Name: <strong>{b['top_name']}</strong></span>
            <span>Reputation: <strong>{b['rep']}</strong></span>
            <span>🛡️ Defender: <strong style="color:{def_col}">{defender_info[:40]}</strong></span>
          </div>
          <details class="engine-details">
            <summary>{len(b['engines'])} erkennende Engines — Klick für Details</summary>
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

    # Delta 24h + 7d
    def build_delta_html(items):
        html = ""
        for item in (items or []):
            icon = "🆕" if item.startswith("neu:") else "📈" if "↑" in item else "📉" if "↓" in item else "✅"
            html += f'<div class="delta-item">{icon} {item}</div>'
        return html or '<div class="delta-item">Keine Änderungen erfasst.</div>'

    delta_24h_html = build_delta_html(d.get("delta_24h", []))
    delta_7d_html  = build_delta_html(d.get("delta_7d", []))

    # AV-Zuverlässigkeit
    av_html = ""
    av_data = feed.get("av_reliability", [])
    if av_data:
        for item in av_data[:10]:
            score = item.get("score", 0)
            bar_w = int(score * 150)
            col   = "#00d26a" if score >= 0.7 else "#ffcc00" if score >= 0.4 else "#ff8800" if score >= 0.2 else "#ff4444"
            mandatory_mark = " 🛡️" if item.get("is_mandatory") else ""
            av_html += f"""<div class="av-row">
              <span class="av-engine">{item.get('engine','?')[:30]}{mandatory_mark}</span>
              <div class="av-bar-bg"><div class="av-bar-fill" style="width:{bar_w}px;background:{col}"></div></div>
              <span class="av-score" style="color:{col}">{item.get('score_pct','?')}</span>
              <span class="av-stats">{item.get('detected','?')}/{item.get('seen','?')}</span>
            </div>"""

    # Wochen-Sample Box
    weekly_box = ""
    if weekly_sha or weekly_info:
        sha_display = weekly_sha or weekly_info.get("sha256", "?")
        sig_display = weekly_info.get("signature", "?")
        days_left   = weekly_info.get("days_remaining", "?")
        age_days    = weekly_info.get("age_days", "?")
        weekly_box  = f"""<div class="weekly-box sec">
          <div class="weekly-header">⭐ Wochen-Sample — dauerhaft getrackt (Windows-PE)</div>
          <div class="weekly-body">
            <div class="weekly-info">
              <span class="mono" style="color:var(--cyan)">{sha_display[:32]}…</span>
              <span style="color:var(--muted)">Familie: <strong style="color:var(--text)">{sig_display}</strong></span>
              <span style="color:var(--muted)">Aktiv seit: <strong style="color:var(--yellow)">{age_days} Tagen</strong> — noch {days_left} Tage</span>
            </div>
          </div>
        </div>"""

    # Origin Country Karte
    countries  = d.get("origin_countries", [])
    de_entry   = next((c for c in countries if c["code"] == "DE"), None)
    de_count   = de_entry["count"] if de_entry else 0
    de_pct     = de_entry["pct"]   if de_entry else "0%"
    de_rank    = next((i+1 for i,c in enumerate(countries) if c["code"] == "DE"), None)
    top_country= countries[0] if countries else None

    above_flag  = top_country["flag"]  if top_country else "🌐"
    above_code  = top_country["code"]  if top_country else "?"
    above_count = top_country["count"] if top_country else 0
    above_pct   = top_country["pct"]   if top_country else "0%"

    country_bars = ""
    max_cnt = countries[0]["count"] if countries else 1
    for i, c in enumerate(countries[:12]):
        bar_w = int(c["count"] / max(max_cnt, 1) * 180)
        is_de = c["code"] == "DE"
        color = "var(--blue)" if is_de else ("var(--red)" if i == 0 else "var(--cyan)" if i < 3 else "var(--dim)")
        bold  = "font-weight:700;color:var(--blue)" if is_de else ""
        country_bars += f"""<div class="country-row">
          <span class="country-flag">{c['flag']}</span>
          <span class="country-code" style="{bold}">{c['code']}</span>
          <div class="country-bar-bg"><div class="country-bar-fill" style="width:{bar_w}px;background:{color}"></div></div>
          <span class="country-count">{c['count']}</span>
          <span class="country-pct">{c['pct']}</span>
        </div>"""

    chart24_json = json.dumps(chart_24h)
    chart7d_json = json.dumps(chart_7d)
    ft_json      = json.dumps({"labels": ft_labels, "data": ft_values})
    cat_json     = json.dumps({"labels": cat_labels, "data": cat_values, "colors": cat_colors[:len(cat_labels)]})

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
      background: var(--bg0); color: var(--text);
      font-family: var(--sans); font-size: 14px; line-height: 1.6; min-height: 100vh;
    }}
    body::before {{
      content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 9999;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
    }}

    .header {{
      background: linear-gradient(180deg, #0a0d14 0%, var(--bg1) 100%);
      border-bottom: 1px solid var(--border);
      padding: 0 2rem; position: sticky; top: 0; z-index: 100;
      display: flex; align-items: center; justify-content: space-between; height: 56px;
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

    .page {{ max-width: 1440px; margin: 0 auto; padding: 1.5rem 2rem 4rem; }}

    /* ── KPI Bars ── */
    .kpi-section-label {{
      font-family: var(--mono); font-size: 0.65rem; color: var(--muted);
      text-transform: uppercase; letter-spacing: 0.1em;
      padding: 0.4rem 0.6rem; background: var(--bg2);
      border: 1px solid var(--border); border-radius: 4px 4px 0 0;
      border-bottom: none; display: inline-block; margin-top: 1.5rem;
    }}
    .kpi-bar {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1px; background: var(--border);
      border: 1px solid var(--border); border-radius: 0 8px 8px 8px; overflow: hidden;
      margin-bottom: 0.5rem;
    }}
    .kpi {{
      background: var(--bg1); padding: 1.25rem 1.5rem;
      display: flex; flex-direction: column; gap: 0.3rem; transition: background 0.15s;
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

    /* ── Sections ── */
    .sec {{ margin-top: 2rem; }}
    .sec-title {{
      font-family: var(--mono); font-size: 0.72rem; font-weight: 600;
      color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em;
      padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
      margin-bottom: 1rem; display: flex; align-items: center; gap: 0.6rem;
    }}
    .sec-title::before {{ content: '//'; color: var(--dim); }}

    /* ── Grids ── */
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
    .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }}
    @media(max-width:900px) {{ .grid-2,.grid-3 {{ grid-template-columns: 1fr; }} }}

    /* ── Cards ── */
    .card {{ background: var(--bg1); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    .card-head {{
      padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
      font-family: var(--mono); font-size: 0.75rem; font-weight: 600;
      color: var(--text); display: flex; align-items: center; justify-content: space-between;
    }}
    .card-body {{ padding: 1rem; }}
    .chart-wrap {{ position: relative; height: 220px; }}
    .trend-wrap  {{ position: relative; height: 250px; }}

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
    .pct-bar {{ height: 3px; background: var(--blue); border-radius: 2px; opacity: 0.7; }}
    .score-cell {{ font-size: 1rem; }}
    .sha-link {{ color: var(--cyan); text-decoration: none; font-family: var(--mono); font-size: 0.75rem; }}
    .sha-link:hover {{ color: var(--blue); text-decoration: underline; }}
    .cat-badge {{ background: var(--bg3); border: 1px solid var(--border2); border-radius: 3px; padding: 0.1rem 0.4rem; font-size: 0.7rem; color: var(--muted); }}
    .mono {{ font-family: var(--mono); font-size: 0.75rem; }}

    /* ── VT Erklärung ── */
    .vt-explain {{
      background: var(--bg2); border: 1px solid var(--border2);
      border-left: 3px solid var(--red);
      border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 1rem;
      font-family: var(--mono); font-size: 0.75rem;
    }}
    .vt-explain-title {{ color: var(--red); font-weight: 700; margin-bottom: 0.4rem; }}
    .vt-legend {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 0.4rem; }}
    .vt-leg-item {{ display: flex; align-items: center; gap: 0.4rem; }}
    .vt-leg-dot {{ width: 8px; height: 8px; border-radius: 50%; }}

    /* ── Plattform ── */
    .plat-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px,1fr)); gap: 0.75rem; }}
    .plat-card {{
      background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
      padding: 0.75rem; display: flex; flex-direction: column; gap: 0.3rem;
    }}
    .plat-icon {{ font-size: 1.4rem; }}
    .plat-name {{ font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: var(--text); }}
    .plat-count {{ font-family: var(--mono); font-size: 1.3rem; color: var(--blue); font-weight: 700; }}
    .plat-bar-bg {{ background: var(--bg3); border-radius: 2px; height: 3px; overflow: hidden; }}
    .plat-bar-fill {{ background: var(--blue); height: 100%; }}
    .plat-pct {{ font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }}

    /* ── MITRE ── */
    .mitre-row {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.4rem 0; border-bottom: 1px solid var(--border);
      font-family: var(--mono); font-size: 0.78rem;
    }}
    .mitre-row:last-child {{ border-bottom: none; }}
    .mitre-tac {{ color: var(--text); }}
    .mitre-cnt {{ background: var(--bg3); color: var(--cyan); padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.72rem; }}

    /* ── VT Blöcke ── */
    .vt-block {{
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem;
    }}
    .weekly-block {{ border-color: var(--yellow); box-shadow: 0 0 12px rgba(255,204,0,0.1); }}
    .weekly-badge {{
      background: var(--yellow); color: #000;
      font-family: var(--mono); font-size: 0.68rem; font-weight: 700;
      padding: 0.15rem 0.5rem; border-radius: 3px;
    }}
    .vt-header {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; }}
    .vt-sha {{ font-family: var(--mono); font-size: 0.78rem; color: var(--cyan); text-decoration: none; }}
    .vt-sha:hover {{ text-decoration: underline; }}
    .vt-family {{ font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }}
    .vt-rate {{ font-family: var(--mono); font-size: 0.85rem; font-weight: 700; margin-left: auto; }}
    .vt-meta {{ display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.78rem; color: var(--muted); margin-bottom: 0.6rem; }}
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
    .tag-cnt {{ background: var(--bg0); color: var(--cyan); border-radius: 3px; padding: 0 0.3rem; font-size: 0.68rem; }}

    /* ── Delta ── */
    .delta-list {{ display: flex; flex-direction: column; gap: 0.4rem; }}
    .delta-item {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text); padding: 0.35rem 0.6rem; background: var(--bg2); border-radius: 4px; border-left: 2px solid var(--dim); }}

    /* ── Trend Tabs ── */
    .trend-tabs {{ display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 0; }}
    .trend-tab {{
      font-family: var(--mono); font-size: 0.73rem; padding: 0.5rem 1rem;
      color: var(--muted); cursor: pointer; border: none; background: none;
      border-bottom: 2px solid transparent; transition: all 0.15s;
    }}
    .trend-tab.active {{ color: var(--blue); border-bottom-color: var(--blue); }}
    .trend-tab:hover {{ color: var(--text); }}

    /* ── AV Widget ── */
    .av-row {{
      display: flex; align-items: center; gap: 0.75rem; padding: 0.35rem 0;
      border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 0.73rem;
    }}
    .av-row:last-child {{ border-bottom: none; }}
    .av-engine {{ width: 200px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .av-bar-bg {{ flex: 1; height: 4px; background: var(--bg3); border-radius: 2px; overflow: hidden; max-width: 150px; }}
    .av-bar-fill {{ height: 100%; border-radius: 2px; }}
    .av-score {{ width: 45px; text-align: right; font-weight: 700; }}
    .av-stats {{ color: var(--muted); font-size: 0.68rem; }}

    /* ── Wochen-Sample Box ── */
    .weekly-box {{
      background: var(--bg1); border: 1px solid var(--yellow);
      border-radius: 8px; overflow: hidden;
      box-shadow: 0 0 20px rgba(255,204,0,0.06);
    }}
    .weekly-header {{
      padding: 0.75rem 1rem; background: rgba(255,204,0,0.08);
      border-bottom: 1px solid var(--yellow);
      font-family: var(--mono); font-size: 0.8rem; font-weight: 700; color: var(--yellow);
    }}
    .weekly-body {{ padding: 1rem; display: flex; flex-direction: column; gap: 0.4rem; }}
    .weekly-info {{ display: flex; flex-direction: column; gap: 0.3rem; font-family: var(--mono); font-size: 0.78rem; }}

    /* ── Origin Country ── */
    .origin-map {{
      background: var(--bg1); border: 1px solid var(--border); border-radius: 8px;
      padding: 1.25rem 1.5rem; margin-bottom: 0;
      display: grid; grid-template-columns: auto 1fr auto; gap: 1rem; align-items: stretch;
    }}
    .origin-column {{ display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.4rem; min-width: 80px; }}
    .origin-arrow {{ font-size: 1.4rem; color: var(--muted); }}
    .origin-flag  {{ font-size: 2.2rem; line-height: 1; }}
    .origin-code  {{ font-family: var(--mono); font-size: 0.9rem; font-weight: 700; color: var(--text); }}
    .origin-count {{ font-family: var(--mono); font-size: 1.6rem; font-weight: 700; color: var(--red); line-height: 1; }}
    .origin-pct   {{ font-size: 0.72rem; color: var(--muted); }}
    .origin-de-col {{
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 0.35rem; border-left: 1px solid var(--border2); border-right: 1px solid var(--border2); padding: 0 1.5rem;
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
    .country-bar-fill{{ height: 100%; border-radius: 2px; }}
    .country-count   {{ font-family: var(--mono); font-size: 0.72rem; color: var(--text); width: 28px; text-align:right; }}
    .country-pct     {{ font-family: var(--mono); font-size: 0.68rem; color: var(--muted); width: 38px; text-align:right; }}
    @media(max-width:600px) {{
      .origin-map {{ grid-template-columns: 1fr; }}
      .origin-de-col {{ border: none; border-top: 1px solid var(--border2); border-bottom: 1px solid var(--border2); padding: 1rem 0; }}
    }}

    footer {{
      margin-top: 3rem; padding: 1.5rem 2rem;
      border-top: 1px solid var(--border);
      text-align: center; font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }}
    footer a {{ color: var(--blue); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}
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
    <a href="{BASE_URL}/feed.json" class="header-link">API</a>
    <a href="{BASE_URL}/reports/latest.md" class="header-link" target="_blank">report.md</a>
    <a href="https://bazaar.abuse.ch" class="header-link" target="_blank">bazaar</a>
  </div>
</header>

<main class="page">

  <!-- VT-Rate Erklärung (prominent oben) -->
  <div class="vt-explain sec">
    <div class="vt-explain-title">⚠️ Wichtig: VT-Erkennungsrate-Logik</div>
    <div>Eine <strong>niedrige</strong> Erkennungsrate bedeutet <strong>gefährlich</strong> — die Malware ist evasiv und umgeht die meisten Antivirenprogramme.</div>
    <div class="vt-legend">
      <div class="vt-leg-item"><div class="vt-leg-dot" style="background:#ff4444"></div><span style="color:#ff4444">&lt;10% erkannt = kaum erkannt = maximal evasiv</span></div>
      <div class="vt-leg-item"><div class="vt-leg-dot" style="background:#ff8800"></div><span style="color:#ff8800">10–30% = schwach erkannt</span></div>
      <div class="vt-leg-item"><div class="vt-leg-dot" style="background:#ffcc00"></div><span style="color:#ffcc00">30–60% = mäßig erkannt</span></div>
      <div class="vt-leg-item"><div class="vt-leg-dot" style="background:#00d26a"></div><span style="color:#00d26a">≥60% = gut erkannt = breit abgedeckt</span></div>
    </div>
  </div>

  {weekly_box}

  <!-- Origin Country -->
  <div class="sec">
    <div class="origin-map">
      <div class="origin-column">
        <div class="origin-arrow">↑</div>
        <div class="origin-flag">{above_flag}</div>
        <div class="origin-code">{above_code}</div>
        <div class="origin-count">{above_count}</div>
        <div class="origin-pct">{above_pct}</div>
      </div>
      <div class="origin-de-col">
        <div class="origin-de-label">Origin Country</div>
        <div class="origin-de-flag">🇩🇪</div>
        <div class="origin-de-count">{de_count if de_count else '–'}</div>
        <div class="origin-de-pct">{de_pct}</div>
        <div class="origin-de-rank">{'Rang #' + str(de_rank) if de_rank else 'nicht in Top 15'}</div>
      </div>
      <div class="origin-bars">
        {country_bars if country_bars else '<span style="color:var(--muted);font-size:0.78rem">Keine Origin-Country-Daten</span>'}
      </div>
    </div>
  </div>

  <!-- KPI Bar: 24h Aggregat -->
  <div class="kpi-section-label">24h-Aggregat (alle Runs der letzten 24 Stunden)</div>
  <div class="kpi-bar">
    <div class="kpi">
      <div class="kpi-label">Samples (24h)</div>
      <div class="kpi-val kv-white">{agg24_total}</div>
      <div class="kpi-sub">alle Runs</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🔴 Kritisch (24h)</div>
      <div class="kpi-val kv-red">{agg24_krit}</div>
      <div class="kpi-sub">Score ≥ 75</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟠 Hoch (24h)</div>
      <div class="kpi-val kv-orange">{agg24_hoch}</div>
      <div class="kpi-sub">Score 55–74</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟡 Mittel (24h)</div>
      <div class="kpi-val kv-yellow">{agg24_mittel}</div>
      <div class="kpi-sub">Score 35–54</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">🟢 Niedrig (24h)</div>
      <div class="kpi-val kv-green">{agg24_niedrig}</div>
      <div class="kpi-sub">Score &lt; 35</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Kritisch-Rate</div>
      <div class="kpi-val kv-red" style="font-size:1.4rem">{agg24_crit_rate}%</div>
      <div class="kpi-sub">der 24h-Samples</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">7d Kritisch</div>
      <div class="kpi-val kv-red" style="font-size:1.4rem">{agg7d_krit}</div>
      <div class="kpi-sub">letzte 7 Tage</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">7d Samples</div>
      <div class="kpi-val kv-white" style="font-size:1.4rem">{agg7d_total}</div>
      <div class="kpi-sub">letzte 7 Tage</div>
    </div>
  </div>

  <!-- Letzter Run KPIs -->
  <div class="kpi-section-label">Letzter Run</div>
  <div class="kpi-bar">
    <div class="kpi">
      <div class="kpi-label">Neue Samples</div>
      <div class="kpi-val kv-white">{d.get('total','?')}</div>
      <div class="kpi-sub">dieser Run</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Top Score</div>
      <div class="kpi-val kv-red">{d.get('top_score','?')}</div>
      <div class="kpi-sub">{d.get('top_sha','')[:12]}…</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">VT enriched</div>
      <div class="kpi-val kv-blue">{d.get('vt_enriched','?')}</div>
      <div class="kpi-sub">Samples (4 rand+1 week)</div>
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
      <div class="card-head">Risiko-Verteilung <span style="color:var(--muted);font-weight:400">24h-Aggregat</span></div>
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

  <!-- Trend: 24h & 7d -->
  <div class="sec card">
    <div class="card-head">
      Familien-Trend
      <div class="trend-tabs">
        <button class="trend-tab active" onclick="showTrend('24h', this)">24h-Verlauf</button>
        <button class="trend-tab" onclick="showTrend('7d', this)">7d-Verlauf</button>
      </div>
    </div>
    <div class="card-body">
      <div class="trend-wrap" id="trend-24h"><canvas id="trendChart24h"></canvas></div>
      <div class="trend-wrap" id="trend-7d" style="display:none"><canvas id="trendChart7d"></canvas></div>
    </div>
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
      <div class="card-body"><div class="plat-grid">{plat_cards}</div></div>
    </div>
  </div>

  <!-- Top 10 Risk -->
  <div class="sec card">
    <div class="card-head">
      Top 10 nach Risiko-Score
      <span style="color:var(--muted);font-size:0.7rem;font-weight:400">VT-Rate: ROT = kaum erkannt = evasiv = gefährlich</span>
    </div>
    <div class="card-body" style="padding:0;overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>SHA256</th><th>Familie</th><th>Kategorie</th><th>Score</th><th>Level</th><th title="Niedrig=Evasiv=Gefährlich">VT-Rate ⚠️</th><th>Erkennungsqualität</th><th>🛡️Defender</th></tr></thead>
        <tbody>{top10_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- MITRE + Delta (24h) -->
  <div class="grid-2 sec">
    <div class="card">
      <div class="card-head">MITRE ATT&amp;CK Taktiken</div>
      <div class="card-body">{mitre_html if mitre_html else '<span style="color:var(--muted)">Keine Daten</span>'}</div>
    </div>
    <div class="card">
      <div class="card-head">Delta 24h vs. Vortag</div>
      <div class="card-body"><div class="delta-list">{delta_24h_html}</div></div>
    </div>
  </div>

  <!-- Delta 7d -->
  <div class="sec card">
    <div class="card-head">Delta 7d-Vergleich</div>
    <div class="card-body"><div class="delta-list">{delta_7d_html}</div></div>
  </div>

  <!-- AV-Zuverlässigkeit -->
  {'<div class="sec card"><div class="card-head">AV-Engine Zuverlässigkeit <span style=\"color:var(--muted);font-weight:400\">🛡️ = Microsoft Defender (Pflicht)</span></div><div class="card-body">' + av_html + '</div></div>' if av_html else ''}

  <!-- VirusTotal -->
  {"<div class='sec'><div class='sec-title'>VirusTotal Ergebnisse (4 zufällig + ⭐ Wochen-Sample)</div>" + vt_html + "</div>" if vt_html else ""}

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
  <a href="{BASE_URL}/rss.xml">RSS</a> ·
  <a href="{BASE_URL}/feed.json">API (feed.json)</a>
</footer>

<script>
const CHART_24H = {chart24_json};
const CHART_7D  = {chart7d_json};
const FT        = {ft_json};
const CAT       = {cat_json};
const RISK      = {risk_json};

const mono = "'JetBrains Mono', monospace";
const gridColor = '#1e2538';
const tickColor = '#586069';

const baseOpts = {{
  responsive: true,
  maintainAspectRatio: false,
  plugins: {{
    legend: {{ labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }}, padding: 10 }} }},
  }},
  scales: {{
    x: {{ ticks: {{ color: tickColor, font: {{ family: mono, size: 10 }} }}, grid: {{ color: gridColor }} }},
    y: {{ ticks: {{ color: tickColor, font: {{ family: mono, size: 10 }} }}, grid: {{ color: gridColor }} }},
  }},
}};

// Risiko Doughnut (24h-Aggregat)
new Chart(document.getElementById('riskChart'), {{
  type: 'doughnut',
  data: {{ labels: RISK.labels, datasets: [{{ data: RISK.data, backgroundColor: RISK.colors, borderWidth: 0, hoverOffset: 6 }}] }},
  options: {{
    cutout: '70%', responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }}, padding: 12 }} }} }},
  }},
}});

// Dateitypen Bar
new Chart(document.getElementById('ftChart'), {{
  type: 'bar',
  data: {{ labels: FT.labels, datasets: [{{ data: FT.data, backgroundColor: '#58a6ff22', borderColor: '#58a6ff', borderWidth: 1, borderRadius: 3 }}] }},
  options: {{
    ...baseOpts, indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: tickColor, font: {{ family: mono, size: 10 }} }}, grid: {{ color: gridColor }} }},
      y: {{ ticks: {{ color: '#c9d1d9', font: {{ family: mono, size: 11 }} }}, grid: {{ display: false }} }},
    }},
  }},
}});

// Kategorien Doughnut
new Chart(document.getElementById('catChart'), {{
  type: 'doughnut',
  data: {{ labels: CAT.labels, datasets: [{{ data: CAT.data, backgroundColor: CAT.colors, borderWidth: 0, hoverOffset: 6 }}] }},
  options: {{
    cutout: '60%', responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9', font: {{ family: mono, size: 10 }}, padding: 8, boxWidth: 10 }} }} }},
  }},
}});

// Trend Chart Builder
function buildTrendChart(canvasId, data) {{
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (!data.labels || data.labels.length < 2) {{
    canvas.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#586069;font-family:' + mono + ';font-size:0.75rem">Wird nach mehreren Runs sichtbar</div>';
    return;
  }}
  new Chart(canvas, {{
    type: 'line',
    data: {{ labels: data.labels, datasets: data.datasets }},
    options: {{
      ...baseOpts,
      scales: {{
        x: {{ ticks: {{ color: tickColor, font: {{ family: mono, size: 10 }}, maxRotation: 45 }}, grid: {{ color: gridColor }} }},
        y: {{ beginAtZero: true, ticks: {{ color: tickColor, font: {{ family: mono, size: 10 }} }}, grid: {{ color: gridColor }} }},
      }},
    }},
  }});
}}

buildTrendChart('trendChart24h', CHART_24H);
buildTrendChart('trendChart7d', CHART_7D);

// Tab-Umschaltung
function showTrend(which, btn) {{
  document.getElementById('trend-24h').style.display = which === '24h' ? 'block' : 'none';
  document.getElementById('trend-7d').style.display  = which === '7d'  ? 'block' : 'none';
  document.querySelectorAll('.trend-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
}}
</script>
</body>
</html>"""


def main():
    latest = REPORTS_DIR / "latest.md"
    if not latest.exists():
        reports = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)
        if not reports:
            print("[!] Kein Report gefunden.")
            return
        latest = reports[0]

    print(f"[*] Parse {latest.name} ...")
    md    = latest.read_text(encoding="utf-8")
    d     = parse_report(md)
    feed  = load_feed_24h_7d()
    chart_24h, chart_7d = load_history_charts()

    print(f"    Datum:    {d['created']}")
    print(f"    Samples:  {d['total']}")
    print(f"    Familien: {len(d['families'])}")
    print(f"    VT:       {len(d['vt_blocks'])} Blöcke")
    print(f"    24h-Trend: {len(chart_24h.get('labels',[]))} Punkte")
    print(f"    7d-Trend:  {len(chart_7d.get('labels',[]))} Punkte")

    html = build_dashboard(d, chart_24h, chart_7d, feed)
    out  = WEB_DIR / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"[+] Dashboard → {out}")


if __name__ == "__main__":
    main()
