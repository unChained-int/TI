#!/usr/bin/env python3
"""
scripts/generate_feed_json.py
Erzeugt feed.json — maschinenlesbare KPIs aus allen Reports.

Verwendung durch andere Tools:
  - SIEM / Splunk / Elastic: feed.json direkt ingestieren
  - Python: data = requests.get(".../feed.json").json()
  - Excel: Daten → Aus dem Web → URL einfügen
  - PowerShell: Invoke-WebRequest + ConvertFrom-Json
  - Pi-hole / Blocklist: ioc_hashes[] direkt verwenden
  - Grafana: JSON-Datasource Plugin

Format:
  {
    "meta": { "generated": "...", "source": "..." },
    "latest": { KPIs des letzten Runs },
    "24h_aggregate": { aggregierte KPIs aller Runs der letzten 24h },
    "history": [ { ts, kritisch, hoch, ... } ],  ← für Zeitreihen-Charts
    "ioc_hashes": [ "sha256...", ... ],           ← direkt importierbar
    "top_families": { "Mirai": 13, ... },
    "vt_summary": [ { sha, detected, total, engines: [...] } ]
  }
"""
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
IOC_DIR      = Path("iocs")
OUTPUT       = Path("feed.json")
BASE_URL     = "https://unchained-int.github.io/TI"


def parse_date_from_filename(name: str) -> datetime | None:
    m = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})", name)
    if m:
        return datetime.strptime(
            f"{m.group(1)} {m.group(2)}:{m.group(3)}:00", "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    return None


def parse_risk(md: str) -> dict:
    out = {}
    for emoji, key in [("🔴 KRITISCH","kritisch"),("🟠 HOCH","hoch"),
                       ("🟡 MITTEL","mittel"),("🟢 NIEDRIG","niedrig")]:
        m = re.search(re.escape(emoji) + r"\s*\|\s*(\d+)", md)
        out[key] = int(m.group(1)) if m else 0
    return out


def parse_families(md: str) -> dict:
    fams = {}
    in_fam = False
    for line in md.split("\n"):
        if "## Familien" in line: in_fam = True; continue
        if in_fam and line.startswith("## "): break
        if in_fam and line.startswith("|") and "|---" not in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3 and parts[0] != "#" and parts[0].isdigit():
                name = parts[1]
                m    = re.search(r"\d+", parts[2])
                if m: fams[name] = int(m.group())
    return fams


def parse_vt(md: str) -> list:
    blocks = []
    parts  = re.split(r"### \[([0-9a-f]{20,64})[^\]]*\]\(([^)]+)\)", md)
    for i in range(1, len(parts), 3):
        sha  = parts[i]
        link = parts[i+1] if i+1 < len(parts) else ""
        body = parts[i+2] if i+2 < len(parts) else ""
        dm   = re.search(r"Erkannt von:\*\* (\d+) von (\d+) Engines \(([\d.]+)%\)", body)
        engines = []
        for row in re.findall(r"\|\s*(.+?)\s*\|\s*`(.+?)`\s*\|", body):
            eng = row[0].lstrip("| ").strip()
            if eng and eng.lower() not in ("engine",""):
                engines.append({"engine": eng, "result": row[1].strip()})
        blocks.append({
            "sha256":    sha,
            "url":       link,
            "detected":  int(dm.group(1)) if dm else 0,
            "total":     int(dm.group(2)) if dm else 0,
            "rate_pct":  float(dm.group(3)) if dm else 0.0,
            "engines":   engines,
        })
    return blocks


def parse_iocs_from_md(md: str) -> list:
    """Extrahiert vollständige SHA256-Hashes aus dem Report."""
    return re.findall(r"[0-9a-f]{64}", md)


def main():
    now   = datetime.now(timezone.utc)
    files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)

    if not files:
        print("[!] Keine Reports gefunden.")
        return

    # ── Letzter Run ────────────────────────────────────────────────────────
    latest_md = files[0].read_text(encoding="utf-8")
    latest_dt = parse_date_from_filename(files[0].name) or now
    latest_risk = parse_risk(latest_md)

    m = re.search(r"\*\*(\d+) neue Samples\*\*", latest_md)
    latest_samples = int(m.group(1)) if m else 0

    m = re.search(r"Häufigste Familie[^|]*\|\s*\*?\*?([^|*\n]+?)\*?\*?\s*\|", latest_md)
    top_family = m.group(1).replace("**","").split("(")[0].strip() if m else "?"

    m = re.search(r"Höchster Score[^|]*\|\s*\*?\*?([\d.]+)/100", latest_md)
    top_score = float(m.group(1)) if m else 0.0

    latest_vt  = parse_vt(latest_md)
    latest_fam = parse_families(latest_md)
    latest_iocs = parse_iocs_from_md(latest_md)

    # ── 24h-Aggregat ───────────────────────────────────────────────────────
    cutoff_24h = now - timedelta(hours=24)
    agg_samples = 0
    agg_risk    = Counter()
    agg_fams    = Counter()
    agg_iocs    = set()
    history_pts = []

    for rf in files:
        dt = parse_date_from_filename(rf.name)
        if not dt or dt < cutoff_24h:
            continue
        md   = rf.read_text(encoding="utf-8")
        risk = parse_risk(md)
        fams = parse_families(md)
        m    = re.search(r"\*\*(\d+) neue Samples\*\*", md)
        n    = int(m.group(1)) if m else 0

        agg_samples += n
        for k, v in risk.items():
            agg_risk[k] += v
        agg_fams.update(fams)
        agg_iocs.update(parse_iocs_from_md(md))

        history_pts.append({
            "timestamp":  dt.isoformat(),
            "ts_display": dt.strftime("%d.%m. %H:%M"),
            "samples":    n,
            **risk,
        })

    history_pts.sort(key=lambda x: x["timestamp"])

    # ── IOCs aus iocs/-Verzeichnis (vollständiger Export) ─────────────────
    all_ioc_hashes = []
    if IOC_DIR.exists():
        for ioc_file in sorted(IOC_DIR.glob("iocs_*.txt"), reverse=True)[:3]:
            txt = ioc_file.read_text(encoding="utf-8")
            hashes = re.findall(r"^([0-9a-f]{64})", txt, re.MULTILINE)
            all_ioc_hashes.extend(hashes)
    all_ioc_hashes = list(dict.fromkeys(all_ioc_hashes))  # dedupliziert

    # ── Output ────────────────────────────────────────────────────────────
    feed = {
        "meta": {
            "generated":    now.isoformat(),
            "generated_ts": int(now.timestamp()),
            "source":       "MalwareBazaar (abuse.ch) × VirusTotal",
            "feed_url":     f"{BASE_URL}/feed.json",
            "rss_url":      f"{BASE_URL}/rss.xml",
            "dashboard":    f"{BASE_URL}/web/index.html",
            "reports":      f"{BASE_URL}/reports/",
        },

        # Letzter Run
        "latest": {
            "timestamp":   latest_dt.isoformat(),
            "ts_display":  latest_dt.strftime("%d.%m.%Y %H:%M UTC"),
            "new_samples": latest_samples,
            "top_score":   top_score,
            "top_family":  top_family,
            "risk":        latest_risk,
            "families":    latest_fam,
            "vt_count":    len(latest_vt),
            "report_url":  f"{BASE_URL}/reports/{files[0].name}",
        },

        # 24h-Aggregat – das ist der echte KPI-Block
        "24h": {
            "window":          "last_24h",
            "total_samples":   agg_samples,
            "unique_iocs":     len(agg_iocs),
            "risk": {
                "kritisch":    agg_risk.get("kritisch", 0),
                "hoch":        agg_risk.get("hoch",     0),
                "mittel":      agg_risk.get("mittel",   0),
                "niedrig":     agg_risk.get("niedrig",  0),
            },
            "top_families":    dict(agg_fams.most_common(15)),
            "critical_rate_pct": round(
                agg_risk.get("kritisch",0) / max(agg_samples,1) * 100, 1
            ),
        },

        # Zeitreihe für Charts / Grafana
        "history": history_pts,

        # IOC-Listen – direkt maschinenlesbar
        "ioc_hashes":          all_ioc_hashes[:200],   # Top 200 nach Score
        "ioc_hashes_24h":      list(agg_iocs)[:200],   # letzte 24h

        # VT-Details des letzten Runs
        "vt_results": latest_vt,

        # Nutzungs-Hinweise
        "usage": {
            "pi_hole":      "ioc_hashes als custom blocklist (als txt-Datei über iocs/*.txt)",
            "python":       "import requests; d = requests.get('URL/feed.json').json(); print(d['latest']['risk'])",
            "powershell":   "$d = Invoke-WebRequest 'URL/feed.json' | ConvertFrom-Json; $d.latest.risk",
            "excel":        "Daten → Aus dem Web → URL: .../feed.json",
            "splunk":       "index=threat_intel | inputlookup feed.json",
            "curl_example": f"curl -s {BASE_URL}/feed.json | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d['24h']['risk'])\"",
        }
    }

    OUTPUT.write_text(json.dumps(feed, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] feed.json geschrieben")
    print(f"    Letzter Run:  {latest_dt.strftime('%d.%m.%Y %H:%M')} UTC — {latest_samples} Samples")
    print(f"    24h gesamt:   {agg_samples} Samples — {len(agg_iocs)} unique IOCs")
    print(f"    IOC-Hashes:   {len(all_ioc_hashes)} (aus iocs/)")
    print(f"    VT-Blöcke:    {len(latest_vt)}")


if __name__ == "__main__":
    main()
