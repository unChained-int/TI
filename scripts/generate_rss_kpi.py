#!/usr/bin/env python3
"""
scripts/generate_rss_kpi.py  —  v1
KPI-only RSS Feed: rein Zahlen, Fakten, keine Analyse-Texte.
Parallel zu rss.xml → rss_kpi.xml

Ideal für:
  - Monitoring-Tools (Grafana, Splunk, Zabbix)
  - Scripts die Schwellenwerte überwachen
  - Automatisierte Alerts
  - Feeds in Excel / Power BI
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR = Path("reports")
OUTPUT      = Path("rss_kpi.xml")
BASE_URL    = "https://unchained-int.github.io/TI"

FLAG = {
    "US":"🇺🇸","DE":"🇩🇪","CN":"🇨🇳","RU":"🇷🇺","GB":"🇬🇧","FR":"🇫🇷",
    "BR":"🇧🇷","IN":"🇮🇳","JP":"🇯🇵","KR":"🇰🇷","UA":"🇺🇦","NL":"🇳🇱",
    "PL":"🇵🇱","TR":"🇹🇷","IT":"🇮🇹","ES":"🇪🇸","CA":"🇨🇦","AU":"🇦🇺",
    "SE":"🇸🇪","CH":"🇨🇭","AT":"🇦🇹","BE":"🇧🇪","HK":"🇭🇰","SG":"🇸🇬",
    "ID":"🇮🇩","MX":"🇲🇽","RO":"🇷🇴","BG":"🇧🇬","CZ":"🇨🇿","HU":"🇭🇺",
    "PT":"🇵🇹","NO":"🇳🇴","FI":"🇫🇮","DK":"🇩🇰","TH":"🇹🇭","VN":"🇻🇳",
    "PK":"🇵🇰","NG":"🇳🇬","IR":"🇮🇷","SA":"🇸🇦","IL":"🇮🇱","AR":"🇦🇷",
    "ZA":"🇿🇦","EG":"🇪🇬","MY":"🇲🇾","PH":"🇵🇭","BD":"🇧🇩","unknown":"🌐",
}

def rfc822(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")

def parse_date_from_filename(name: str) -> datetime | None:
    m = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})", name)
    if m:
        return datetime.strptime(
            f"{m.group(1)} {m.group(2)}:{m.group(3)}:00", "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    return None

def extract_kpis(md: str, filename: str) -> dict:
    d = {}

    # Timestamp
    dt = parse_date_from_filename(filename)
    d["dt"]         = dt
    d["ts"]         = dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "?"
    d["ts_display"] = dt.strftime("%d.%m.%Y %H:%M UTC") if dt else "?"

    # Samples
    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    d["new_samples"] = int(m.group(1)) if m else 0

    # Risiko
    for emoji, key in [("🔴 KRITISCH","kritisch"),("🟠 HOCH","hoch"),
                       ("🟡 MITTEL","mittel"),("🟢 NIEDRIG","niedrig")]:
        m = re.search(re.escape(emoji) + r"\s*\|\s*(\d+)", md)
        d[key] = int(m.group(1)) if m else 0

    total = d["kritisch"] + d["hoch"] + d["mittel"] + d["niedrig"]
    d["total_risk_samples"] = total
    d["kritisch_pct"] = round(d["kritisch"] / max(total,1) * 100, 1)

    # Top Score
    m = re.search(r"Höchster Score[^|]*\|\s*\*?\*?([\d.]+)/100", md)
    d["top_score"] = float(m.group(1)) if m else 0.0

    m = re.search(r"Höchster Score.*?([0-9a-f]{16,20})", md)
    d["top_score_sha"] = m.group(1) if m else ""

    # Durchschnittlicher Score
    m = re.search(r"Ø Risiko-Score\s*\|\s*([\d.]+)/100", md)
    d["avg_score"] = float(m.group(1)) if m else 0.0

    # Familien
    top_fam = re.findall(r"\|\s*\d+\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["families"] = [{"name": f.strip(), "count": int(c), "pct": float(p)}
                     for f, c, p in top_fam[:10]]
    d["top_family"]   = d["families"][0]["name"] if d["families"] else "?"
    d["unique_families"] = len(d["families"])

    # Dateitypen
    ft = re.findall(r"\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["file_types"] = [{"type": t.strip(), "count": int(c), "pct": float(p)}
                       for t, c, p in ft[:8]]
    d["top_filetype"] = d["file_types"][0]["type"] if d["file_types"] else "?"

    # Plattformen
    plat = re.findall(r"\|\s*(?:🪟|🐧|🍎|🤖|📱|📡|🌐|📄|📦|❓)\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["platforms"] = [{"name": n.strip(), "count": int(c), "pct": float(p)}
                      for n, c, p in plat[:8]]

    # Origin Countries
    d["origin_countries"] = []
    in_orig = False
    for line in md.split("\n"):
        if "## Herkunftsländer" in line or "## Origin" in line:
            in_orig = True; continue
        if in_orig and line.startswith("## "): break
        if in_orig and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and parts[0] not in ("Land", "Country", "#", "Flag"):
                # Format: | 🇩🇪 DE | 23 | 23.0% | oder | 1 | DE | 23 | 23.0% |
                for p in parts:
                    cc = re.search(r"\b([A-Z]{2})\b", p)
                    if cc:
                        code = cc.group(1)
                        nums = [x for x in parts if re.match(r"^\d+$", x)]
                        pcts = [x for x in parts if re.match(r"^[\d.]+%$", x)]
                        d["origin_countries"].append({
                            "code":  code,
                            "flag":  FLAG.get(code, "🌐"),
                            "count": int(nums[0]) if nums else 0,
                            "pct":   pcts[0] if pcts else "?",
                        })
                        break

    d["top_country"] = d["origin_countries"][0]["code"] if d["origin_countries"] else "?"

    # VT
    m = re.search(r"Samples mit VT\s*\|\s*(\d+)/(\d+)", md)
    d["vt_enriched"]  = int(m.group(1)) if m else 0
    d["vt_total"]     = int(m.group(2)) if m else 0

    # Durchschnittliche VT-Rate
    rates = [float(x) for x in re.findall(r"(\d+\.\d+)%\)", md) if float(x) > 0]
    d["avg_vt_rate"] = round(sum(rates)/len(rates), 1) if rates else 0.0

    # MITRE
    m = re.search(r"Samples mit MITRE\s*\|\s*(\d+)/(\d+)", md)
    d["mitre_mapped"] = int(m.group(1)) if m else 0

    # Dateigröße
    m = re.search(r"Ø Dateigröße\s*\|\s*([\d.]+)\s*MB", md)
    d["avg_size_mb"] = float(m.group(1)) if m else 0.0

    # SHA256-Liste (vollständig)
    d["sha256_list"] = re.findall(r"[0-9a-f]{64}", md)[:20]

    return d


def build_kpi_item(kpi: dict, rf: Path) -> str:
    """Baut ein Item mit reinen Zahlen — kein Fließtext, keine Analyse."""
    ts     = kpi["ts_display"]
    n      = kpi["new_samples"]
    krit   = kpi["kritisch"]
    hoch   = kpi["hoch"]
    mittel = kpi["mittel"]
    niedrig= kpi["niedrig"]
    score  = kpi["top_score"]

    if n == 0:
        return f"""    <item>
      <title>[TI-KPI] {ts} | 0 neue Samples</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description>0 neue Samples (SHA-Dedup: alles bereits bekannt)</description>
      <pubDate>{rfc822(kpi['dt'])}</pubDate>
      <guid isPermaLink="false">kpi-{rf.stem}</guid>
      <ti:samples>0</ti:samples>
    </item>"""

    title = (f"[TI-KPI] {ts} | "
             f"N={n} | 🔴{krit} 🟠{hoch} 🟡{mittel} 🟢{niedrig} | "
             f"Score={score} | {escape(kpi['top_family'])[:20]}")

    # Reine Daten-Felder als XML-Attribute
    kpi_fields = f"""      <ti:timestamp>{kpi['ts']}</ti:timestamp>
      <ti:samples>{n}</ti:samples>
      <ti:risk_kritisch>{krit}</ti:risk_kritisch>
      <ti:risk_hoch>{hoch}</ti:risk_hoch>
      <ti:risk_mittel>{mittel}</ti:risk_mittel>
      <ti:risk_niedrig>{niedrig}</ti:risk_niedrig>
      <ti:risk_total>{kpi['total_risk_samples']}</ti:risk_total>
      <ti:kritisch_pct>{kpi['kritisch_pct']}</ti:kritisch_pct>
      <ti:top_score>{score}</ti:top_score>
      <ti:avg_score>{kpi['avg_score']}</ti:avg_score>
      <ti:top_family>{escape(kpi['top_family'])}</ti:top_family>
      <ti:unique_families>{kpi['unique_families']}</ti:unique_families>
      <ti:top_filetype>{escape(kpi['top_filetype'])}</ti:top_filetype>
      <ti:top_country>{kpi['top_country']}</ti:top_country>
      <ti:vt_enriched>{kpi['vt_enriched']}</ti:vt_enriched>
      <ti:avg_vt_rate>{kpi['avg_vt_rate']}</ti:avg_vt_rate>
      <ti:mitre_mapped>{kpi['mitre_mapped']}</ti:mitre_mapped>
      <ti:avg_size_mb>{kpi['avg_size_mb']}</ti:avg_size_mb>"""

    # Kompakte Description: nur Tabelle mit Zahlen
    rows_risk = "".join(
        f"<tr><td>{lbl}</td><td style='text-align:right;font-weight:bold'>{val}</td>"
        f"<td style='text-align:right;color:#888'>{round(val/max(kpi['total_risk_samples'],1)*100,1)}%</td></tr>"
        for lbl, val in [("🔴 Kritisch", krit),("🟠 Hoch", hoch),
                          ("🟡 Mittel", mittel),("🟢 Niedrig", niedrig)]
    )

    rows_fam = "".join(
        f"<tr><td style='font-family:monospace'>{escape(f['name'][:28])}</td>"
        f"<td style='text-align:right'>{f['count']}</td>"
        f"<td style='text-align:right;color:#888'>{f['pct']}%</td></tr>"
        for f in kpi["families"][:8]
    )

    rows_ft = "".join(
        f"<tr><td style='font-family:monospace'>{escape(f['type'])}</td>"
        f"<td style='text-align:right'>{f['count']}</td>"
        f"<td style='text-align:right;color:#888'>{f['pct']}%</td></tr>"
        for f in kpi["file_types"][:6]
    )

    rows_country = "".join(
        f"<tr><td>{c['flag']} {c['code']}</td>"
        f"<td style='text-align:right'>{c['count']}</td>"
        f"<td style='text-align:right;color:#888'>{c['pct']}</td></tr>"
        for c in kpi["origin_countries"][:10]
    )

    rows_sha = "".join(
        f"<tr><td style='font-family:monospace;font-size:0.8em'>"
        f"<a href='https://bazaar.abuse.ch/sample/{s}/'>{s[:32]}…</a></td></tr>"
        for s in kpi["sha256_list"][:10]
    )

    style = "border-collapse:collapse;width:100%;font-size:13px;margin-bottom:12px"
    th_style = "background:#1a1a2e;color:#aaa;padding:3px 8px;text-align:left"
    td_style = "padding:3px 8px;border-bottom:1px solid #222"

    desc = f"""<table style='{style}'>
<tr><th colspan='3' style='{th_style}'>RISIKO</th></tr>
<tr><th style='{th_style}'>Level</th><th style='{th_style}'>N</th><th style='{th_style}'>%</th></tr>
{rows_risk}
<tr><td colspan='2'><b>Top Score</b></td><td style='text-align:right'><b>{score}/100</b></td></tr>
<tr><td colspan='2'>Ø Score</td><td style='text-align:right'>{kpi['avg_score']}/100</td></tr>
</table>

<table style='{style}'>
<tr><th colspan='3' style='{th_style}'>FAMILIEN (Top 8)</th></tr>
<tr><th style='{th_style}'>Familie</th><th style='{th_style}'>N</th><th style='{th_style}'>%</th></tr>
{rows_fam}
</table>

<table style='{style}'>
<tr><th colspan='3' style='{th_style}'>DATEITYPEN</th></tr>
<tr><th style='{th_style}'>Typ</th><th style='{th_style}'>N</th><th style='{th_style}'>%</th></tr>
{rows_ft}
</table>

{"<table style='" + style + "'><tr><th colspan='3' style='" + th_style + "'>HERKUNFTSLÄNDER</th></tr>" + rows_country + "</table>" if rows_country else ""}

<table style='{style}'>
<tr><th colspan='3' style='{th_style}'>KENNZAHLEN</th></tr>
<tr><td>VT-angereichert</td><td colspan='2' style='text-align:right'>{kpi['vt_enriched']}/{kpi['vt_total']}</td></tr>
<tr><td>Ø VT-Erkennungsrate</td><td colspan='2' style='text-align:right'>{kpi['avg_vt_rate']}%</td></tr>
<tr><td>MITRE gemappt</td><td colspan='2' style='text-align:right'>{kpi['mitre_mapped']}</td></tr>
<tr><td>Ø Dateigröße</td><td colspan='2' style='text-align:right'>{kpi['avg_size_mb']} MB</td></tr>
<tr><td>Eindeutige Familien</td><td colspan='2' style='text-align:right'>{kpi['unique_families']}</td></tr>
</table>

<table style='{style}'>
<tr><th style='{th_style}'>IOC SHA256 (Auszug)</th></tr>
{rows_sha}
</table>"""

    pub = rfc822(kpi["dt"]) if kpi["dt"] else rfc822(datetime.now(timezone.utc))

    return f"""    <item>
      <title>{escape(title)}</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description>{escape(desc)}</description>
      <content:encoded><![CDATA[{desc}]]></content:encoded>
      <pubDate>{pub}</pubDate>
      <guid isPermaLink="false">kpi-{rf.stem}</guid>
      <category>KPI</category>
      <category>Threat Intelligence</category>
{kpi_fields}
    </item>"""


def main():
    now   = datetime.now(timezone.utc)
    files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)[:30]

    if not files:
        print("[!] Keine Reports.")
        return

    items = []
    for rf in files:
        md  = rf.read_text(encoding="utf-8")
        kpi = extract_kpis(md, rf.name)
        items.append(build_kpi_item(kpi, rf))

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:content="http://purl.org/rss/1.0/modules/content/"
  xmlns:ti="https://unchained-int.github.io/TI/ns/">
  <channel>
    <title>MalwareBazaar TI – KPI Feed</title>
    <link>{BASE_URL}</link>
    <description>Reine Kennzahlen: Risiko-Counts, Familien, Dateitypen, Origin Countries, VT-Raten. Keine Analyse-Texte. Maschinenlesbar via ti:* Namespace.</description>
    <language>de-DE</language>
    <lastBuildDate>{rfc822(now)}</lastBuildDate>
    <ttl>144</ttl>
    <atom:link href="{BASE_URL}/rss_kpi.xml" rel="self" type="application/rss+xml"/>
    <atom:link href="{BASE_URL}/rss.xml" rel="related" type="application/rss+xml" title="Vollständiger Report-Feed"/>
{chr(10).join(items)}
  </channel>
</rss>"""

    OUTPUT.write_text(rss, encoding="utf-8")
    print(f"[+] rss_kpi.xml  →  {len(items)} Items")


if __name__ == "__main__":
    main()
