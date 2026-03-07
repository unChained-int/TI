#!/usr/bin/env python3
"""
scripts/generate_rss.py
Baut rss.xml aus allen Reports der letzten 24h.
Jeder Feed-Eintrag enthält die vollen Statistiken:
  - Anzahl Samples, Familien, Dateitypen
  - Risiko-Verteilung
  - VT-Ergebnisse mit expliziten Engine-Namen
  - MITRE-Techniken
  - IOC-Liste (SHA256)
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
IOC_DIR      = Path("iocs")
OUTPUT       = Path("rss.xml")

BASE_URL = "https://unchained-int.github.io/TI"


def rfc822(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def parse_report(md: str) -> dict:
    """Extrahiert alle relevanten Daten aus einem Markdown-Report."""
    data = {}

    # Datum aus erster Zeile
    m = re.search(r"# MalwareBazaar – (.+)", md)
    data["created"] = m.group(1).strip() if m else "unbekannt"

    # Neue Samples
    m = re.search(r"\*\*(\d+) neue Samples\*\*", md)
    data["new_samples"] = int(m.group(1)) if m else 0

    # Risiko
    for lvl, key in [("🔴 KRITISCH","kritisch"),("🟠 HOCH","hoch"),
                     ("🟡 MITTEL","mittel"),("🟢 NIEDRIG","niedrig")]:
        m = re.search(re.escape(lvl) + r"\s*\|\s*(\d+)", md)
        data[key] = int(m.group(1)) if m else 0

    # Höchster Score
    m = re.search(r"Höchster Score.*?\*\*(\d+(?:\.\d+)?)/100\*\*.*?([0-9a-f]{16})", md)
    if m:
        data["top_score"]  = m.group(1)
        data["top_sha"]    = m.group(2)

    # Häufigste Familie
    m = re.search(r"Häufigste Familie.*?\*\*(.+?)\*\*", md)
    data["top_family"] = m.group(1).strip() if m else "unbekannt"

    # Häufigster Typ
    m = re.search(r"Häufigster Typ.*?`(.+?)`", md)
    data["top_type"] = m.group(1).strip() if m else "?"

    # VT-Block: alle Sections mit Engine-Tabellen extrahieren
    vt_sections = []
    vt_parts = re.split(r"### \[([0-9a-f]{20})", md)
    for i in range(1, len(vt_parts), 2):
        sha_prefix = vt_parts[i]
        body       = vt_parts[i+1] if i+1 < len(vt_parts) else ""

        detected_m = re.search(r"Erkannt von:\*\* (\d+) von (\d+) Engines \((.+?)%\)", body)
        top_name_m = re.search(r"Häufigster Name:\*\* (.+)", body)
        engines    = re.findall(r"\|\s*(.+?)\s*\|\s*`(.+?)`\s*\|", body)

        vt_sections.append({
            "sha":      sha_prefix + "…",
            "detected": detected_m.group(1) if detected_m else "?",
            "total":    detected_m.group(2) if detected_m else "?",
            "rate":     detected_m.group(3) if detected_m else "?",
            "top_name": top_name_m.group(1).strip() if top_name_m else "?",
            "engines":  [(e.strip(), r.strip()) for e, r in engines if e != "Engine"],
        })
    data["vt_sections"] = vt_sections

    # SHA256-Liste (aus IOC-Abschnitt bzw. Top-Tabelle)
    data["top_shas"] = re.findall(r"\[([0-9a-f]{12,16})…?\]\(https://bazaar", md)[:10]

    # MITRE-Taktiken
    tactics = re.findall(r"\|\s*([A-Z][A-Za-z ]+?)\s*\|\s*(\d+)\s*\|", md)
    data["mitre_tactics"] = [(t.strip(), int(c)) for t, c in tactics
                              if t not in ("Taktik","Kategorie","Plattform","Vektor","Typ","Level","Kennzahl")][:8]

    # Delta-Zeilen
    data["delta"] = re.findall(r"- ((?:neu|↑|↓|weg):.+)", md)

    return data


def build_item_description(data: dict, report_file: Path) -> str:
    """Baut den vollständigen HTML-Body für einen RSS-Eintrag."""
    h = []
    a = h.append

    a(f"<p><strong>Stand:</strong> {data.get('created','?')}</p>")
    a(f"<p><strong>Neue Samples dieser Session:</strong> {data.get('new_samples',0)}</p>")

    # Risiko
    a("<h3>Risiko-Verteilung</h3><ul>")
    a(f"<li>🔴 Kritisch: <strong>{data.get('kritisch',0)}</strong></li>")
    a(f"<li>🟠 Hoch: <strong>{data.get('hoch',0)}</strong></li>")
    a(f"<li>🟡 Mittel: <strong>{data.get('mittel',0)}</strong></li>")
    a(f"<li>🟢 Niedrig: <strong>{data.get('niedrig',0)}</strong></li>")
    a("</ul>")

    if data.get("top_score"):
        a(f"<p><strong>Höchster Score:</strong> {data['top_score']}/100 "
          f"({data.get('top_sha','?')}…)</p>")

    a(f"<p><strong>Häufigste Familie:</strong> {escape(data.get('top_family','?'))}</p>")
    a(f"<p><strong>Häufigster Typ:</strong> {escape(data.get('top_type','?'))}</p>")

    # VT-Ergebnisse mit Engines
    if data.get("vt_sections"):
        a("<h3>VirusTotal-Ergebnisse</h3>")
        for sec in data["vt_sections"]:
            a(f"<h4>{escape(sec['sha'])}</h4>")
            a(f"<p>Erkannt: <strong>{sec['detected']}/{sec['total']}</strong> "
              f"({sec['rate']}%) – <em>{escape(sec['top_name'])}</em></p>")
            if sec["engines"]:
                a(f"<p>Erkennende Engines ({len(sec['engines'])}):</p>")
                a("<table><tr><th>Engine</th><th>Name</th></tr>")
                for engine, result in sec["engines"]:
                    a(f"<tr><td>{escape(engine)}</td><td><code>{escape(result)}</code></td></tr>")
                a("</table>")

    # MITRE
    if data.get("mitre_tactics"):
        a("<h3>MITRE ATT&amp;CK Taktiken</h3><ul>")
        for tac, cnt in data["mitre_tactics"]:
            a(f"<li>{escape(tac)}: {cnt} Samples</li>")
        a("</ul>")

    # Delta
    if data.get("delta"):
        a("<h3>Änderungen gegenüber letztem Run</h3><ul>")
        for d in data["delta"]:
            a(f"<li>{escape(d)}</li>")
        a("</ul>")

    # SHA256 IOC-Liste
    if data.get("top_shas"):
        a("<h3>Sample-Hashes (Auszug)</h3><ul>")
        for sha in data["top_shas"]:
            url = f"https://bazaar.abuse.ch/sample/{sha}"
            a(f'<li><a href="{url}">{escape(sha)}…</a></li>')
        a("</ul>")

    # Link zum vollen Report
    report_url = f"{BASE_URL}/reports/{report_file.name}"
    a(f'<p><a href="{report_url}">→ Vollständiger Report (Markdown)</a></p>')

    return "\n".join(h)


def build_rss(items_xml: list, now: datetime) -> str:
    items_str = "\n".join(items_xml)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>MalwareBazaar Threat Intel</title>
    <link>{BASE_URL}</link>
    <description>Automatisierter Malware-Feed – neue Samples, Familien, VT-Ergebnisse, IOCs. Daten von MalwareBazaar (abuse.ch) x VirusTotal.</description>
    <language>de-DE</language>
    <lastBuildDate>{rfc822(now)}</lastBuildDate>
    <ttl>144</ttl>
    <atom:link href="{BASE_URL}/rss.xml" rel="self" type="application/rss+xml"/>
{items_str}
  </channel>
</rss>"""


def main():
    now = datetime.now(timezone.utc)

    # Alle Reports, neueste zuerst, max 30 Einträge
    report_files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)[:30]
    if not report_files:
        print("[!] Keine Reports gefunden.")
        OUTPUT.write_text(build_rss([], now), encoding="utf-8")
        return

    items_xml = []
    for rf in report_files:
        md = rf.read_text(encoding="utf-8")
        if "Keine neuen Samples" in md[:200]:
            # Leerer Run – kurzer Eintrag
            m = re.search(r"# MalwareBazaar – (.+)", md)
            created = m.group(1).strip() if m else rf.stem

            # Datum aus Dateiname
            dm = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})", rf.name)
            pub_dt = datetime.strptime(f"{dm.group(1)} {dm.group(2)}:{dm.group(3)}:00",
                                       "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if dm else now
            items_xml.append(f"""    <item>
      <title>MalwareBazaar – {escape(created)} – keine neuen Samples</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description>Alle bekannten SHA256 bereits verarbeitet – kein neues Material in diesem Run.</description>
      <pubDate>{rfc822(pub_dt)}</pubDate>
      <guid isPermaLink="false">{BASE_URL}/reports/{rf.name}</guid>
    </item>""")
            continue

        data   = parse_report(md)
        dm     = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})", rf.name)
        pub_dt = datetime.strptime(f"{dm.group(1)} {dm.group(2)}:{dm.group(3)}:00",
                                   "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if dm else now

        crit   = data.get("kritisch", 0)
        total  = data.get("new_samples", 0)
        fam    = data.get("top_family","?")
        title  = (f"MalwareBazaar – {data.get('created','?')} – "
                  f"{total} neue Samples – {crit} kritisch – {fam}")

        desc     = build_item_description(data, rf)
        desc_esc = escape(desc)

        items_xml.append(f"""    <item>
      <title>{escape(title)}</title>
      <link>{BASE_URL}/reports/{rf.name}</link>
      <description>{desc_esc}</description>
      <content:encoded><![CDATA[{desc}]]></content:encoded>
      <pubDate>{rfc822(pub_dt)}</pubDate>
      <guid isPermaLink="false">{BASE_URL}/reports/{rf.name}</guid>
      <category>Threat Intelligence</category>
      <category>Malware</category>
      <category>IOC</category>
    </item>""")

    rss = build_rss(items_xml, now)
    OUTPUT.write_text(rss, encoding="utf-8")
    print(f"[+] rss.xml  →  {len(items_xml)} Einträge")


if __name__ == "__main__":
    main()
