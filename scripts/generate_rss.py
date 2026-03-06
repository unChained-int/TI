#!/usr/bin/env python3
"""
Generiert einen RSS 2.0 Feed aus den letzten Malware-Reports.
Liest reports/latest.md und malware_history.json.
Output: rss.xml (im Root, damit GitHub Pages es direkt serviert)
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR = Path("reports")
HISTORY_FILE = Path("malware_history.json")
OUTPUT_FILE  = Path("rss.xml")

# GitHub Pages URL – ANPASSEN!
BASE_URL = "https://unchained-int.github.io/TI"


def rfc822(dt: datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def extract_summary(md_text: str) -> str:
    """Extrahiert Executive Summary aus dem Markdown."""
    lines = md_text.split("\n")
    in_summary = False
    summary_lines = []
    for line in lines:
        if "## 📋 Executive Summary" in line:
            in_summary = True
            continue
        if in_summary and line.startswith("## "):
            break
        if in_summary and line.strip():
            # Tabellen-Zeilen in lesbaren Text umwandeln
            if "|" in line and not line.startswith("|---"):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) == 2:
                    summary_lines.append(f"{parts[0]}: {parts[1]}")
    return " | ".join(summary_lines[:6])


def build_rss() -> str:
    now = datetime.now(timezone.utc)

    # Alle Reports (neueste zuerst)
    report_files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)

    items_xml = []
    for i, report_file in enumerate(report_files[:20]):   # max 20 Einträge
        md_text = report_file.read_text(encoding="utf-8")

        # Datum aus Dateiname: MalwareBazaar_24h_Report_YYYY-MM-DD_HH-MM-UTC.md
        m = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-UTC", report_file.name)
        if m:
            pub_dt = datetime.strptime(
                f"{m.group(1)} {m.group(2)}:{m.group(3)}:00", "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        else:
            pub_dt = now

        summary = extract_summary(md_text) or "Keine Zusammenfassung verfügbar."

        # Kritische Samples zählen
        crit_match = re.search(r"🔴 KRITISCH.*?\*\*(\d+)\*\*", md_text)
        crit_count = crit_match.group(1) if crit_match else "?"

        title   = f"🦠 MalwareBazaar Report {pub_dt.strftime('%d.%m.%Y %H:%M UTC')} – {crit_count} Kritisch"
        link    = f"{BASE_URL}/reports/{report_file.name}"
        desc    = escape(summary)
        pub_str = rfc822(pub_dt)
        guid    = f"{BASE_URL}/reports/{report_file.name}"

        items_xml.append(f"""    <item>
      <title>{escape(title)}</title>
      <link>{link}</link>
      <description>{desc}</description>
      <pubDate>{pub_str}</pubDate>
      <guid isPermaLink="true">{guid}</guid>
      <category>Threat Intelligence</category>
      <category>Malware</category>
    </item>""")

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>🦠 MalwareBazaar Threat Intelligence Feed</title>
    <link>{BASE_URL}</link>
    <description>Automatisierter täglicher Malware-Report – MalwareBazaar × VirusTotal</description>
    <language>de-DE</language>
    <lastBuildDate>{rfc822(now)}</lastBuildDate>
    <ttl>1440</ttl>
    <atom:link href="{BASE_URL}/rss.xml" rel="self" type="application/rss+xml"/>
    <image>
      <url>https://bazaar.abuse.ch/img/mbazaar.png</url>
      <title>MalwareBazaar Threat Intel</title>
      <link>{BASE_URL}</link>
    </image>
{chr(10).join(items_xml)}
  </channel>
</rss>"""
    return rss


if __name__ == "__main__":
    rss_content = build_rss()
    OUTPUT_FILE.write_text(rss_content, encoding="utf-8")
    print(f"[+] RSS Feed geschrieben → {OUTPUT_FILE.resolve()}")
    print(f"    Einträge: {rss_content.count('<item>')}")
