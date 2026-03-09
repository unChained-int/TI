import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR = Path("reports")
OUTPUT = Path("rss_kpi_pa.xml")           # anderer Name, damit man beide Varianten parallel haben kann
BASE_URL = "https://unchained-int.github.io/TI"

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
    dt = parse_date_from_filename(filename)
    d["dt"] = dt
    d["ts"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "?"
    d["ts_display"] = dt.strftime("%d.%m.%Y %H:%M UTC") if dt else "?"

    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    d["new_samples"] = int(m.group(1)) if m else 0

    for emoji, key in [("🔴 KRITISCH","kritisch"), ("🟠 HOCH","hoch"),
                       ("🟡 MITTEL","mittel"), ("🟢 NIEDRIG","niedrig")]:
        m = re.search(re.escape(emoji) + r"\s*\|\s*(\d+)", md)
        d[key] = int(m.group(1)) if m else 0

    total = d["kritisch"] + d["hoch"] + d["mittel"] + d["niedrig"]
    d["total_risk_samples"] = total
    d["kritisch_pct"] = round(d["kritisch"] / max(total, 1) * 100, 1)

    m = re.search(r"Höchster Score[^|]*\|\s*\*?\*?([\d.]+)/100", md)
    d["top_score"] = float(m.group(1)) if m else 0.0

    m = re.search(r"Ø Risiko-Score\s*\|\s*([\d.]+)/100", md)
    d["avg_score"] = float(m.group(1)) if m else 0.0

    top_fam = re.findall(r"\|\s*\d+\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["families"] = [{"name": f.strip(), "count": int(c), "pct": float(p)}
                     for f, c, p in top_fam[:10]]
    d["top_family"] = d["families"][0]["name"] if d["families"] else "?"
    d["unique_families"] = len(d["families"])

    ft = re.findall(r"\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["file_types"] = [{"type": t.strip(), "count": int(c), "pct": float(p)}
                       for t, c, p in ft[:8]]
    d["top_filetype"] = d["file_types"][0]["type"] if d["file_types"] else "?"

    plat = re.findall(r"\|\s*(?:🪟|🐧|🍎|🤖|📱|📡|🌐|📄|📦|❓)\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md)
    d["platforms"] = [{"name": n.strip(), "count": int(c), "pct": float(p)}
                      for n, c, p in plat[:8]]

    # Origin Countries (vereinfacht – bleibt gleich)
    d["origin_countries"] = []
    in_orig = False
    for line in md.split("\n"):
        if "## Herkunftsländer" in line or "## Origin" in line:
            in_orig = True
            continue
        if in_orig and line.startswith("## "):
            break
        if in_orig and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and parts[0] not in ("Land", "Country", "#", "Flag"):
                for p in parts:
                    cc = re.search(r"\b([A-Z]{2})\b", p)
                    if cc:
                        code = cc.group(1)
                        nums = [x for x in parts if re.match(r"^\d+$", x)]
                        pcts = [x for x in parts if re.match(r"^[\d.]+%$", x)]
                        d["origin_countries"].append({
                            "code": code,
                            "flag": FLAG.get(code, "🌐"),
                            "count": int(nums[0]) if nums else 0,
                            "pct": pcts[0] if pcts else "?"
                        })
                        break
    d["top_country"] = d["origin_countries"][0]["code"] if d["origin_countries"] else "?"

    m = re.search(r"Samples mit VT\s*\|\s*(\d+)/(\d+)", md)
    d["vt_enriched"] = int(m.group(1)) if m else 0
    d["vt_total"] = int(m.group(2)) if m else 0

    rates = [float(x) for x in re.findall(r"(\d+\.\d+)%\)", md) if float(x) > 0]
    d["avg_vt_rate"] = round(sum(rates)/len(rates), 1) if rates else 0.0

    m = re.search(r"Samples mit MITRE\s*\|\s*(\d+)/(\d+)", md)
    d["mitre_mapped"] = int(m.group(1)) if m else 0

    m = re.search(r"Ø Dateigröße\s*\|\s*([\d.]+)\s*MB", md)
    d["avg_size_mb"] = float(m.group(1)) if m else 0.0

    d["sha256_list"] = re.findall(r"[0-9a-f]{64}", md)[:20]

    return d


def build_kpi_item(kpi: dict, rf: Path) -> str:
    ts = kpi["ts_display"]
    n = kpi["new_samples"]
    krit = kpi["kritisch"]
    hoch = kpi["hoch"]
    mittel = kpi["mittel"]
    niedrig = kpi["niedrig"]
    score = kpi["top_score"]

    if n == 0:
        title = f"[TI-KPI] {ts} | 0 neue Samples"
        desc = "Keine neuen Samples (alle bereits bekannt / SHA-Dedup)"
        kpi_plain = "<samples>0</samples>"
    else:
        title = (
            f"[TI-KPI] {ts} | "
            f"N={n} | 🔴{krit} 🟠{hoch} 🟡{mittel} 🟢{niedrig} | "
            f"Score={score} | {escape(kpi['top_family'])[:24]}"
        )

        kpi_plain = f"""\
      <samples>{n}</samples>
      <risk_critical>{krit}</risk_critical>
      <risk_high>{hoch}</risk_high>
      <risk_medium>{mittel}</risk_medium>
      <risk_low>{niedrig}</risk_low>
      <risk_total>{kpi['total_risk_samples']}</risk_total>
      <critical_pct>{kpi['kritisch_pct']}</critical_pct>
      <top_score>{score}</top_score>
      <avg_score>{kpi['avg_score']}</avg_score>
      <top_family>{escape(kpi['top_family'])}</top_family>
      <unique_families>{kpi['unique_families']}</unique_families>
      <top_filetype>{escape(kpi['top_filetype'])}</top_filetype>
      <top_country>{kpi['top_country']}</top_country>
      <vt_enriched>{kpi['vt_enriched']}</vt_enriched>
      <avg_vt_rate>{kpi['avg_vt_rate']}</avg_vt_rate>
      <mitre_mapped>{kpi['mitre_mapped']}</mitre_mapped>
      <avg_size_mb>{kpi['avg_size_mb']}</avg_size_mb>"""

        # HTML-Tabelle für Menschen / Power BI / Excel bleibt erhalten
        rows_risk = "".join(
            f"<tr><td>{lbl}</td><td style='text-align:right;font-weight:bold'>{val}</td>"
            f"<td style='text-align:right;color:#888'>{round(val / max(kpi['total_risk_samples'],1) * 100, 1)}%</td></tr>"
            for lbl, val in [("🔴 Kritisch", krit), ("🟠 Hoch", hoch),
                             ("🟡 Mittel", mittel), ("🟢 Niedrig", niedrig)]
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
        desc = f"""<table style="{style}">
<tr><th colspan="3" style="{th_style}">RISIKO</th></tr>
<tr><th style="{th_style}">Level</th><th style="{th_style}">N</th><th style="{th_style}">%</th></tr>
{rows_risk}
<tr><td colspan="2"><b>Top Score</b></td><td style="text-align:right"><b>{score}/100</b></td></tr>
<tr><td colspan="2">Ø Score</td><td style="text-align:right">{kpi['avg_score']}/100</td></tr>
</table>

<table style="{style}">
<tr><th colspan="3" style="{th_style}">TOP FAMILIEN</th></tr>
<tr><th style="{th_style}">Familie</th><th style="{th_style}">Anz</th><th style="{th_style}">%</th></tr>
{rows_fam}
</table>

<table style="{style}">
<tr><th colspan="3" style="{th_style}">DATEITYPEN</th></tr>
<tr><th style="{th_style}">Typ</th><th style="{th_style}">Anz</th><th style="{th_style}">%</th></tr>
{rows_ft}
</table>

{"<table style='" + style + "'><tr><th colspan='3' style='" + th_style + "'>HERKUNFTSLÄNDER</th></tr>" + rows_country + "</table>" if rows_country else ""}

<table style="{style}">
<tr><th colspan="3" style="{th_style}">SONSTIGE KENNZAHLEN</th></tr>
<tr><td>VT-angereichert</td><td colspan="2" style="text-align:right">{kpi['vt_enriched']}/{kpi['vt_total']}</td></tr>
<tr><td>Ø VT-Rate</td><td colspan="2" style="text-align:right">{kpi['avg_vt_rate']}%</td></tr>
<tr><td>MITRE ATT&CK gemappt</td><td colspan="2" style="text-align:right">{kpi['mitre_mapped']}</td></tr>
<tr><td>Ø Dateigröße</td><td colspan="2" style="text-align:right">{kpi['avg_size_mb']} MB</td></tr>
<tr><td>Eindeutige Familien</td><td colspan="2" style="text-align:right">{kpi['unique_families']}</td></tr>
</table>

<table style="{style}">
<tr><th style="{th_style}">IOC SHA256 (Top 10)</th></tr>
{rows_sha}
</table>"""

    pub = rfc822(kpi["dt"]) if kpi["dt"] else rfc822(datetime.now(timezone.utc))

    return f""" <item>
      <title>{escape(title)}</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description><![CDATA[{desc}]]></description>
      <pubDate>{pub}</pubDate>
      <guid isPermaLink="false">kpi-{rf.stem}</guid>
      <category>KPI</category>
      <category>Threat Intelligence</category>
      {kpi_plain}
    </item>"""


def main():
    now = datetime.now(timezone.utc)
    files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)[:30]
    if not files:
        print("[!] Keine Reports gefunden.")
        return

    items = []
    for rf in files:
        md = rf.read_text(encoding="utf-8")
        kpi = extract_kpis(md, rf.name)
        items.append(build_kpi_item(kpi, rf))

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>MalwareBazaar TI – KPI Feed (Power Automate Edition)</title>
    <link>{BASE_URL}</link>
    <description>Kennzahlen aus MalwareBazaar 24h Reports – maschinenlesbar ohne Namespace für Power Automate, Logic Apps, Excel, Power BI. Felder: samples, risk_critical, top_score, avg_vt_rate, ...</description>
    <language>de-DE</language>
    <lastBuildDate>{rfc822(now)}</lastBuildDate>
    <ttl>144</ttl>
    <atom:link href="{BASE_URL}/rss_kpi_pa.xml" rel="self" type="application/rss+xml"/>
{chr(10).join(items)}
  </channel>
</rss>"""

    OUTPUT.write_text(rss, encoding="utf-8")
    print(f"[+] {OUTPUT.name} → {len(items)} Items erstellt")


if __name__ == "__main__":
    main()
