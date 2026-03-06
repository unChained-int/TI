#!/usr/bin/env python3
"""
Generiert web/index.html – visuelles Dashboard aus dem letzten Report.
Liest: reports/latest.md + malware_history.json
Output: web/index.html (GitHub Pages ready)
"""
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
WEB_DIR      = Path("web")
WEB_DIR.mkdir(exist_ok=True)

BASE_URL = "https://DEIN_USERNAME.github.io/DEIN_REPO"


def parse_latest_report() -> dict:
    """Parst reports/latest.md und extrahiert strukturierte Daten."""
    latest = REPORTS_DIR / "latest.md"
    if not latest.exists():
        reports = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)
        if not reports:
            return {}
        latest = reports[0]

    md = latest.read_text(encoding="utf-8")

    def extract_table(section_header: str) -> list[tuple]:
        """Extrahiert Zeilen aus der ersten Markdown-Tabelle nach einem Header."""
        pattern = re.escape(section_header)
        m = re.search(pattern, md)
        if not m:
            return []
        after = md[m.end():]
        rows  = []
        in_table = False
        for line in after.split("\n"):
            if line.startswith("|---") or line.startswith("| ---"):
                in_table = True
                continue
            if in_table:
                if not line.startswith("|"):
                    break
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts:
                    rows.append(tuple(parts))
        return rows

    def extract_value(label: str) -> str:
        m = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*\*?\*?([^|*\n]+?)\*?\*?\s*\|", md)
        return m.group(1).strip() if m else "?"

    # Risiko-Verteilung
    risk = {
        "kritisch": int(re.search(r"🔴 KRITISCH.*?(\d+)", md).group(1)) if re.search(r"🔴 KRITISCH.*?(\d+)", md) else 0,
        "hoch":     int(re.search(r"🟠 HOCH.*?(\d+)", md).group(1))     if re.search(r"🟠 HOCH.*?(\d+)", md)     else 0,
        "mittel":   int(re.search(r"🟡 MITTEL.*?(\d+)", md).group(1))   if re.search(r"🟡 MITTEL.*?(\d+)", md)   else 0,
        "niedrig":  int(re.search(r"🟢 NIEDRIG.*?(\d+)", md).group(1))  if re.search(r"🟢 NIEDRIG.*?(\d+)", md)  else 0,
    }

    # Total
    total_m = re.search(r"\*\*(\d+)\*\*\s*Samples", md) or re.search(r"Samples.*?\*\*(\d+)\*\*", md)
    total = int(total_m.group(1)) if total_m else 0

    # Erstellungsdatum
    date_m = re.search(r"\*\*Erstellt:\*\*\s*(.+?)\s*\|", md)
    created = date_m.group(1).strip() if date_m else "unbekannt"

    # Top-Dateitypen
    ft_rows  = extract_table("## 📊 Top Dateitypen")
    # Top-Familien
    fam_rows = extract_table("## 🦠 Top Malware-Familien")
    # Kategorien
    cat_rows = extract_table("## 🏷️ Klassifikation")
    # Plattformen
    plat_rows = extract_table("## 💻 Betroffene Plattformen")
    # Vektoren
    vec_rows = extract_table("## 🎯 Infektionsvektoren")

    return {
        "created": created,
        "total":   total,
        "risk":    risk,
        "ft_rows": ft_rows,
        "fam_rows": fam_rows,
        "cat_rows": cat_rows,
        "plat_rows": plat_rows,
        "vec_rows": vec_rows,
        "report_url": f"{BASE_URL}/reports/latest.md",
    }


def load_history_chart_data() -> dict:
    """Liest malware_history.json für den Trend-Chart."""
    if not HISTORY_FILE.exists():
        return {"labels": [], "datasets": []}
    try:
        hist = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"labels": [], "datasets": []}

    sorted_runs = sorted(hist.items())[-14:]   # letzte 14 Runs

    # Top-5 Familien über alle Runs
    all_fams: Counter = Counter()
    for ts, data in sorted_runs:
        all_fams.update(data.get("families", {}))
    top5 = [f for f, _ in all_fams.most_common(5)]

    labels = [ts[:10] for ts, _ in sorted_runs]
    colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6"]
    datasets = []
    for i, fam in enumerate(top5):
        values = [hist_data.get("families", {}).get(fam, 0)
                  for _, hist_data in sorted_runs]
        datasets.append({
            "label": fam[:30],
            "data": values,
            "borderColor": colors[i % len(colors)],
            "backgroundColor": colors[i % len(colors)] + "33",
            "tension": 0.4,
        })

    return {"labels": labels, "datasets": datasets}


def rows_to_chart_data(rows: list[tuple], name_idx=0, val_idx=1) -> dict:
    """Konvertiert Tabellen-Rows in Chart.js-Daten."""
    labels, values = [], []
    for row in rows[:8]:
        if len(row) > max(name_idx, val_idx):
            labels.append(row[name_idx].replace("`","").replace("**","")[:25])
            # Anteil extrahieren
            val_str = row[val_idx] if val_idx < len(row) else "0"
            m = re.search(r"[\d.]+", val_str.replace(",","."))
            values.append(float(m.group()) if m else 0)
    return {"labels": labels, "data": values}


def build_html(data: dict, history: dict) -> str:
    if not data:
        return "<html><body><h1>Kein Report gefunden</h1></body></html>"

    risk     = data.get("risk", {})
    total    = data.get("total", 0)
    created  = data.get("created", "?")
    ft_chart = rows_to_chart_data(data.get("ft_rows", []), 1, 2)
    fam_chart = rows_to_chart_data(data.get("fam_rows", []), 1, 2)

    risk_total = sum(risk.values()) or 1
    risk_chart = {
        "labels": ["🔴 Kritisch", "🟠 Hoch", "🟡 Mittel", "🟢 Niedrig"],
        "data":   [risk["kritisch"], risk["hoch"], risk["mittel"], risk["niedrig"]],
        "colors": ["#ef4444", "#f97316", "#eab308", "#22c55e"],
    }

    # Platform-Tabelle
    plat_html = ""
    for row in data.get("plat_rows", [])[:8]:
        if len(row) >= 2:
            name = row[0]
            cnt  = row[1] if len(row) > 1 else "?"
            pct  = row[2] if len(row) > 2 else ""
            plat_html += f'<tr><td>{name}</td><td class="text-right font-bold">{cnt}</td><td class="text-right text-gray-400">{pct}</td></tr>\n'

    # Familien-Tabelle
    fam_html = ""
    for row in data.get("fam_rows", [])[:10]:
        if len(row) >= 3:
            rank = row[0]
            name = row[1].replace("*","")
            cnt  = row[2] if len(row) > 2 else "?"
            pct  = row[3] if len(row) > 3 else ""
            fam_html += f'<tr><td class="text-gray-500">{rank}</td><td class="font-mono text-sm">{name[:35]}</td><td class="text-right font-bold">{cnt}</td><td class="text-right text-gray-400">{pct}</td></tr>\n'

    history_json = json.dumps(history)
    ft_json      = json.dumps(ft_chart)
    risk_json    = json.dumps(risk_chart)

    html = f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🦠 MalwareBazaar Threat Intelligence Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:     #0f1117;
      --card:   #1a1d27;
      --border: #2a2d3e;
      --text:   #e2e8f0;
      --muted:  #64748b;
      --red:    #ef4444;
      --orange: #f97316;
      --yellow: #eab308;
      --green:  #22c55e;
      --blue:   #3b82f6;
      --purple: #a855f7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }}

    .header {{
      background: linear-gradient(135deg, #1a1d27 0%, #0f1117 100%);
      border-bottom: 1px solid var(--border);
      padding: 1.5rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
    }}
    .header-title {{ display: flex; align-items: center; gap: 0.75rem; }}
    .header-title h1 {{ font-size: 1.4rem; font-weight: 700; }}
    .header-meta {{ color: var(--muted); font-size: 0.85rem; }}
    .badge {{
      display: inline-block; padding: 0.2rem 0.6rem;
      border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
      background: rgba(59,130,246,0.15); color: var(--blue); border: 1px solid rgba(59,130,246,0.3);
    }}
    .rss-link {{
      color: var(--orange); text-decoration: none; font-size: 0.85rem;
      display: flex; align-items: center; gap: 0.4rem;
    }}
    .rss-link:hover {{ text-decoration: underline; }}

    main {{ max-width: 1400px; margin: 0 auto; padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem; }}

    /* KPI Cards */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; }}
    .kpi-card {{
      background: var(--card); border: 1px solid var(--border); border-radius: 12px;
      padding: 1.25rem; display: flex; flex-direction: column; gap: 0.5rem;
    }}
    .kpi-label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-value {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
    .kpi-sub {{ font-size: 0.75rem; color: var(--muted); }}
    .kpi-red    {{ color: var(--red);    border-color: rgba(239,68,68,0.3); }}
    .kpi-orange {{ color: var(--orange); border-color: rgba(249,115,22,0.3); }}
    .kpi-yellow {{ color: var(--yellow); border-color: rgba(234,179,8,0.3); }}
    .kpi-green  {{ color: var(--green);  border-color: rgba(34,197,94,0.3); }}
    .kpi-blue   {{ color: var(--blue);   border-color: rgba(59,130,246,0.3); }}

    /* Charts Grid */
    .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1.5rem; }}
    .chart-card {{
      background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem;
    }}
    .chart-card h3 {{ font-size: 0.95rem; font-weight: 600; margin-bottom: 1rem; color: var(--text); }}
    .chart-container {{ position: relative; height: 260px; }}

    /* Tables */
    .table-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }}
    .table-card {{
      background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
    }}
    .table-card h3 {{ padding: 1.25rem 1.5rem; font-size: 0.95rem; font-weight: 600; border-bottom: 1px solid var(--border); }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 0.65rem 1.5rem; font-size: 0.85rem; border-bottom: 1px solid var(--border); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255,255,255,0.03); }}
    .text-right {{ text-align: right; }}
    .font-bold {{ font-weight: 700; }}
    .font-mono {{ font-family: monospace; }}
    .text-gray-400 {{ color: #9ca3af; }}
    .text-gray-500 {{ color: var(--muted); }}
    .text-sm {{ font-size: 0.8rem; }}

    /* Trend Chart */
    .trend-card {{
      background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem;
    }}
    .trend-card h3 {{ font-size: 0.95rem; font-weight: 600; margin-bottom: 1rem; }}
    .trend-container {{ position: relative; height: 280px; }}

    footer {{
      text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem;
      border-top: 1px solid var(--border); margin-top: 1rem;
    }}
    footer a {{ color: var(--blue); text-decoration: none; }}
  </style>
</head>
<body>

<header class="header">
  <div class="header-title">
    <span style="font-size:1.8rem">🦠</span>
    <div>
      <h1>MalwareBazaar Threat Intelligence</h1>
      <div class="header-meta">Report: {created} &nbsp;·&nbsp; <span class="badge">{total} Samples</span></div>
    </div>
  </div>
  <div style="display:flex;gap:1rem;align-items:center">
    <a href="{BASE_URL}/rss.xml" class="rss-link">📡 RSS Feed</a>
    <a href="{data.get('report_url','#')}" class="rss-link" target="_blank">📄 Markdown Report</a>
  </div>
</header>

<main>

  <!-- KPI Cards -->
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Samples Total</div>
      <div class="kpi-value kpi-blue">{total}</div>
      <div class="kpi-sub">Letzte 24h (API-Limit 100)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">🔴 Kritisch</div>
      <div class="kpi-value kpi-red">{risk.get('kritisch', 0)}</div>
      <div class="kpi-sub">Score ≥ 75/100</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">🟠 Hoch</div>
      <div class="kpi-value kpi-orange">{risk.get('hoch', 0)}</div>
      <div class="kpi-sub">Score 55–74</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">🟡 Mittel</div>
      <div class="kpi-value kpi-yellow">{risk.get('mittel', 0)}</div>
      <div class="kpi-sub">Score 35–54</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">🟢 Niedrig</div>
      <div class="kpi-value kpi-green">{risk.get('niedrig', 0)}</div>
      <div class="kpi-sub">Score &lt; 35</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>📊 Risiko-Verteilung</h3>
      <div class="chart-container"><canvas id="riskChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>📁 Top Dateitypen</h3>
      <div class="chart-container"><canvas id="ftChart"></canvas></div>
    </div>
  </div>

  <!-- Trend Chart -->
  <div class="trend-card">
    <h3>📈 Familien-Trend (letzte 14 Runs)</h3>
    <div class="trend-container"><canvas id="trendChart"></canvas></div>
  </div>

  <!-- Tabellen -->
  <div class="table-grid">
    <div class="table-card">
      <h3>🦠 Top Malware-Familien</h3>
      <table>
        <thead><tr><th style="width:2rem">#</th><th>Familie</th><th class="text-right">Anz.</th><th class="text-right">Anteil</th></tr></thead>
        <tbody>{fam_html}</tbody>
      </table>
    </div>
    <div class="table-card">
      <h3>💻 Betroffene Plattformen</h3>
      <table>
        <thead><tr><th>Plattform</th><th class="text-right">Anz.</th><th class="text-right">Anteil</th></tr></thead>
        <tbody>{plat_html}</tbody>
      </table>
    </div>
  </div>

</main>

<footer>
  Daten: <a href="https://bazaar.abuse.ch" target="_blank">MalwareBazaar (abuse.ch)</a> ×
  <a href="https://virustotal.com" target="_blank">VirusTotal</a> &nbsp;·&nbsp;
  Nur für Threat-Intelligence und Bildungszwecke &nbsp;·&nbsp;
  <a href="{BASE_URL}/rss.xml">RSS</a>
</footer>

<script>
const HISTORY = {history_json};
const FT      = {ft_json};
const RISK    = {risk_json};

const chartDefaults = {{
  plugins: {{
    legend: {{ labels: {{ color: '#e2e8f0', font: {{ size: 12 }} }} }},
  }},
  scales: {{
    x: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }} }},
    y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }} }},
  }},
}};

// Risiko Doughnut
new Chart(document.getElementById('riskChart'), {{
  type: 'doughnut',
  data: {{
    labels: RISK.labels,
    datasets: [{{ data: RISK.data, backgroundColor: RISK.colors, borderWidth: 2, borderColor: '#1a1d27' }}],
  }},
  options: {{
    plugins: {{
      legend: {{ position: 'right', labels: {{ color: '#e2e8f0' }} }},
    }},
    cutout: '65%',
  }},
}});

// Dateitypen Bar
new Chart(document.getElementById('ftChart'), {{
  type: 'bar',
  data: {{
    labels: FT.labels,
    datasets: [{{
      label: 'Samples',
      data: FT.data,
      backgroundColor: '#3b82f633',
      borderColor: '#3b82f6',
      borderWidth: 1,
    }}],
  }},
  options: {{
    ...chartDefaults,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }} }},
      y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }} }},
    }},
  }},
}});

// Trend Line
if (HISTORY.labels && HISTORY.labels.length > 0) {{
  new Chart(document.getElementById('trendChart'), {{
    type: 'line',
    data: {{ labels: HISTORY.labels, datasets: HISTORY.datasets }},
    options: {{
      ...chartDefaults,
      plugins: {{
        legend: {{ labels: {{ color: '#e2e8f0' }} }},
      }},
      scales: {{
        x: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }} }},
        y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2a2d3e' }}, beginAtZero: true }},
      }},
    }},
  }});
}}
</script>
</body>
</html>"""
    return html


if __name__ == "__main__":
    print("[*] Lade Report-Daten ...")
    data    = parse_latest_report()
    history = load_history_chart_data()
    html    = build_html(data, history)
    out     = WEB_DIR / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"[+] Dashboard geschrieben → {out.resolve()}")
