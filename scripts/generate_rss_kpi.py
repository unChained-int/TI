import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR = Path("reports")
OUTPUT      = Path("rss_kpi.xml")
BASE_URL    = "https://unchained-int.github.io/TI"


def rfc822(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def parse_date(filename: str) -> datetime:
    m = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})", filename)
    if m:
        return datetime.strptime(
            f"{m.group(1)} {m.group(2)}:{m.group(3)}:00", "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def extract(md: str, filename: str) -> dict:
    d = {}
    dt = parse_date(filename)
    d["dt"] = dt
    d["ts"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    d["date"] = dt.strftime("%Y-%m-%d %H:%M UTC")

    # Samples
    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    d["samples"] = int(m.group(1)) if m else 0

    # Risiko
    for emoji, key in [("🔴 KRITISCH","kritisch"),("🟠 HOCH","hoch"),
                       ("🟡 MITTEL","mittel"),("🟢 NIEDRIG","niedrig")]:
        m = re.search(re.escape(emoji) + r"\s*\|\s*(\d+)", md)
        d[key] = int(m.group(1)) if m else 0

    total = d["kritisch"] + d["hoch"] + d["mittel"] + d["niedrig"]
    d["risk_total"]   = total
    d["kritisch_pct"] = round(d["kritisch"] / max(total, 1) * 100, 1)
    d["hoch_pct"]     = round(d["hoch"]     / max(total, 1) * 100, 1)
    d["mittel_pct"]   = round(d["mittel"]   / max(total, 1) * 100, 1)
    d["niedrig_pct"]  = round(d["niedrig"]  / max(total, 1) * 100, 1)

    # Scores
    m = re.search(r"Höchster Score[^|]*\|\s*\*?\*?([\d.]+)/100", md)
    d["top_score"] = float(m.group(1)) if m else 0.0

    m = re.search(r"Ø Risiko-Score\s*\|\s*([\d.]+)/100", md)
    d["avg_score"] = float(m.group(1)) if m else 0.0

    # Top Dateityp
    m = re.search(r"\|\s*`([^`]+)`\s*\|\s*\d+\s*\|", md)
    d["top_filetype"] = m.group(1).strip() if m else "?"

    # Top Country
    m = re.search(r"## Herkunftsländer.*?\|\s*1\s*\|[^|]*?([A-Z]{2})[^|]*\|\s*(\d+)", md, re.DOTALL)
    d["top_country"] = m.group(1) if m else "?"

    # VT
    m = re.search(r"Samples mit VT\s*\|\s*(\d+)/(\d+)", md)
    d["vt_enriched"] = int(m.group(1)) if m else 0
    d["vt_total"]    = int(m.group(2)) if m else 0

    rates = [float(x) for x in re.findall(r"(\d+\.\d+)%\)", md) if 0 < float(x) <= 100]
    d["avg_vt_rate"] = round(sum(rates) / len(rates), 1) if rates else 0.0

    # MITRE
    m = re.search(r"Samples mit MITRE\s*\|\s*(\d+)/(\d+)", md)
    d["mitre_mapped"] = int(m.group(1)) if m else 0

    # Dateigröße
    m = re.search(r"Ø Dateigröße\s*\|\s*([\d.]+)\s*MB", md)
    d["avg_size_mb"] = float(m.group(1)) if m else 0.0

    # IOC Anzahl
    shas = re.findall(r"[0-9a-f]{64}", md)
    d["ioc_count"] = len(shas)

    # Familien-Liste aus Tabelle
    fams = re.findall(r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%", md, re.MULTILINE)
    d["families"] = [(name.strip(), int(cnt), float(pct)) for _, name, cnt, pct in fams[:15]]
    d["unique_families"] = len(d["families"])
    d["top_family"] = d["families"][0][0] if d["families"] else "?"

    return d


def build_item(kpi: dict, rf: Path) -> str:
    n = kpi["samples"]

    # Title: kompakt, alle wichtigen Zahlen
    title = (f"TI {kpi['date']} | "
             f"Samples={n} | "
             f"KRIT={kpi['kritisch']} HOCH={kpi['hoch']} MITTEL={kpi['mittel']} NIEDRIG={kpi['niedrig']} | "
             f"TopScore={kpi['top_score']}")

    # Description: plain text, zeilenweise, Power Automate lesbar
    lines = [
        f"DATUM:            {kpi['date']}",
        f"SAMPLES:          {n}",
        f"",
        f"--- RISIKO ---",
        f"KRITISCH:         {kpi['kritisch']} ({kpi['kritisch_pct']}%)",
        f"HOCH:             {kpi['hoch']} ({kpi['hoch_pct']}%)",
        f"MITTEL:           {kpi['mittel']} ({kpi['mittel_pct']}%)",
        f"NIEDRIG:          {kpi['niedrig']} ({kpi['niedrig_pct']}%)",
        f"",
        f"--- SCORES ---",
        f"TOP_SCORE:        {kpi['top_score']}/100",
        f"AVG_SCORE:        {kpi['avg_score']}/100",
        f"",
        f"--- METADATEN ---",
        f"TOP_FILETYPE:     {kpi['top_filetype']}",
        f"TOP_COUNTRY:      {kpi['top_country']}",
        f"UNIQUE_FAMILIES:  {kpi['unique_families']}",
        f"IOC_COUNT:        {kpi['ioc_count']}",
        f"",
        f"--- VIRUSTOTAL ---",
        f"VT_ENRICHED:      {kpi['vt_enriched']}/{kpi['vt_total']}",
        f"AVG_VT_RATE:      {kpi['avg_vt_rate']}%",
        f"",
        f"--- MITRE ---",
        f"MITRE_MAPPED:     {kpi['mitre_mapped']}",
        f"",
        f"--- DATEIGRÖSSE ---",
        f"AVG_SIZE_MB:      {kpi['avg_size_mb']} MB",
        f"",
        f"--- BEDROHUNGEN ---",
    ]

    # Familien-Liste am Ende
    for name, cnt, pct in kpi["families"]:
        lines.append(f"{name}: {cnt} ({pct}%)")

    description = "\n".join(lines)
    pub = rfc822(kpi["dt"])

    return f"""    <item>
      <title>{escape(title)}</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description>{escape(description)}</description>
      <pubDate>{pub}</pubDate>
      <guid isPermaLink="false">kpi-{rf.stem}</guid>
      <category>KPI</category>
    </item>"""


def main():
    now   = datetime.now(timezone.utc)
    files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)[:30]

    if not files:
        print("[!] Keine Reports gefunden.")
        return

    items = []
    for rf in files:
        md  = rf.read_text(encoding="utf-8")
        kpi = extract(md, rf.name)
        items.append(build_item(kpi, rf))

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>MalwareBazaar TI – KPI</title>
    <link>{BASE_URL}</link>
    <description>KPI Feed. Alle Werte als plain text. Power Automate ready.</description>
    <language>de-DE</language>
    <lastBuildDate>{rfc822(now)}</lastBuildDate>
    <ttl>120</ttl>
    <atom:link href="{BASE_URL}/rss_kpi.xml" rel="self" type="application/rss+xml"/>
{chr(10).join(items)}
  </channel>
</rss>"""

    OUTPUT.write_text(rss, encoding="utf-8")
    print(f"[+] rss_kpi.xml → {len(items)} Items")


if __name__ == "__main__":
    main()
