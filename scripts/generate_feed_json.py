import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPORTS_DIR  = Path("reports")
HISTORY_FILE = Path("malware_history.json")
IOC_DIR      = Path("iocs")
AV_STATS     = Path("av_reliability.json")
WEEKLY_FILE  = Path("weekly_sample.json")
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
    """
    Parst VT-Blöcke inkl. Erkennungsqualität (neu in v2).
    """
    blocks = []
    parts  = re.split(r"### \[([0-9a-f]{20,64})[^\]]*\]\(([^)]+)\)", md)
    for i in range(1, len(parts), 3):
        sha  = parts[i]
        link = parts[i+1] if i+1 < len(parts) else ""
        body = parts[i+2] if i+2 < len(parts) else ""
        dm   = re.search(r"Erkannt von:\*\* (\d+) von (\d+) Engines \(([\d.]+)%\)", body)
        qm   = re.search(r"Erkennungsqualität:\*\* (.+)", body)
        defm = re.search(r"Microsoft Defender:\*\* (.+)", body)

        engines = []
        for row in re.findall(r"\|\s*(.+?)\s*\|\s*`(.+?)`\s*\|", body):
            eng = row[0].lstrip("| ").strip()
            if eng and eng.lower() not in ("engine",""):
                engines.append({"engine": eng, "result": row[1].strip()})

        rate = float(dm.group(3)) / 100 if dm else 0.0
        # Farblogik: niedrig = ROT (evasiv), hoch = GRÜN
        if rate < 0.10:    rate_color = "#ff4444"
        elif rate < 0.30:  rate_color = "#ff8800"
        elif rate < 0.60:  rate_color = "#ffcc00"
        else:              rate_color = "#00d26a"

        blocks.append({
            "sha256":    sha,
            "sha_short": sha[:20] + "…",
            "url":       link,
            "detected":  int(dm.group(1)) if dm else 0,
            "total":     int(dm.group(2)) if dm else 0,
            "rate_pct":  float(dm.group(3)) if dm else 0.0,
            "rate":      rate,
            "rate_color": rate_color,
            "quality":   qm.group(1).strip() if qm else "?",
            "defender":  defm.group(1).strip() if defm else "?",
            "engines":   engines,
            "is_weekly": "⭐ WOCHEN-SAMPLE" in body,
        })
    return blocks


def parse_iocs_from_md(md: str) -> list:
    return re.findall(r"[0-9a-f]{64}", md)


def load_av_stats() -> dict:
    if not AV_STATS.exists():
        return {}
    try:
        return json.loads(AV_STATS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_weekly() -> dict:
    if not WEEKLY_FILE.exists():
        return {}
    try:
        return json.loads(WEEKLY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def main():
    now   = datetime.now(timezone.utc)
    files = sorted(REPORTS_DIR.glob("MalwareBazaar_24h_Report_*.md"), reverse=True)

    if not files:
        print("[!] Keine Reports gefunden.")
        return

    # ── Letzter Run ──────────────────────────────────────────────────────────
    latest_md  = files[0].read_text(encoding="utf-8")
    latest_dt  = parse_date_from_filename(files[0].name) or now
    latest_risk = parse_risk(latest_md)

    m = re.search(r"\*\*(\d+) neue Samples\*\*", latest_md)
    latest_samples = int(m.group(1)) if m else 0

    m = re.search(r"Häufigste Familie[^|]*\|\s*\*?\*?([^|*\n]+?)\*?\*?\s*\|", latest_md)
    top_family = m.group(1).replace("**","").split("(")[0].strip() if m else "?"

    m = re.search(r"Höchster Score[^|]*\|\s*\*?\*?([\d.]+)/100", latest_md)
    top_score = float(m.group(1)) if m else 0.0

    latest_vt   = parse_vt(latest_md)
    latest_fam  = parse_families(latest_md)
    latest_iocs = parse_iocs_from_md(latest_md)

    # ── 24h-Aggregat ─────────────────────────────────────────────────────────
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d  = now - timedelta(days=7)

    # 24h
    agg24_samples = 0
    agg24_risk    = Counter()
    agg24_fams    = Counter()
    agg24_iocs    = set()
    history_24h   = []

    # 7d
    agg7d_samples = 0
    agg7d_risk    = Counter()
    agg7d_fams    = Counter()
    history_7d    = []

    for rf in files:
        dt = parse_date_from_filename(rf.name)
        if not dt or dt < cutoff_7d:
            continue
        try:
            md = rf.read_text(encoding="utf-8")
        except Exception:
            continue
        risk = parse_risk(md)
        fams = parse_families(md)
        m2   = re.search(r"\*\*(\d+) neue Samples\*\*", md)
        n    = int(m2.group(1)) if m2 else 0

        # 7d immer
        agg7d_samples += n
        for k, v in risk.items():
            agg7d_risk[k] += v
        agg7d_fams.update(fams)

        history_7d.append({
            "timestamp":  dt.isoformat(),
            "ts_display": dt.strftime("%d.%m. %H:%M"),
            "samples":    n,
            **risk,
        })

        # 24h zusätzlich
        if dt >= cutoff_24h:
            agg24_samples += n
            for k, v in risk.items():
                agg24_risk[k] += v
            agg24_fams.update(fams)
            agg24_iocs.update(parse_iocs_from_md(md))

            history_24h.append({
                "timestamp":  dt.isoformat(),
                "ts_display": dt.strftime("%d.%m. %H:%M"),
                "samples":    n,
                **risk,
            })

    history_24h.sort(key=lambda x: x["timestamp"])
    history_7d.sort(key=lambda x: x["timestamp"])

    # ── IOCs aus iocs/-Verzeichnis ────────────────────────────────────────────
    all_ioc_hashes = []
    if IOC_DIR.exists():
        for ioc_file in sorted(IOC_DIR.glob("iocs_*.txt"), reverse=True)[:3]:
            txt    = ioc_file.read_text(encoding="utf-8")
            hashes = re.findall(r"^([0-9a-f]{64})", txt, re.MULTILINE)
            all_ioc_hashes.extend(hashes)
    all_ioc_hashes = list(dict.fromkeys(all_ioc_hashes))

    # ── AV-Zuverlässigkeit ───────────────────────────────────────────────────
    av_stats = load_av_stats()
    av_ranking = []
    MANDATORY_AV = ["Microsoft", "Windows Defender", "Defender"]
    for eng, data in sorted(av_stats.items(),
                             key=lambda x: -x[1].get("detected",0) / max(x[1].get("seen",1),1)):
        seen = data.get("seen", 0)
        det  = data.get("detected", 0)
        score = round(det / seen, 3) if seen > 0 else 0.0
        av_ranking.append({
            "engine":       eng,
            "score":        score,
            "score_pct":    f"{score:.1%}",
            "detected":     det,
            "seen":         seen,
            "is_mandatory": any(m.lower() in eng.lower() for m in MANDATORY_AV),
        })

    # ── Wochen-Sample ────────────────────────────────────────────────────────
    weekly = load_weekly()
    weekly_info = {}
    if weekly:
        set_at   = datetime.fromisoformat(weekly.get("set_at", "2000-01-01T00:00:00+00:00"))
        age_days = (now - set_at).days
        weekly_info = {
            "sha256":         weekly.get("sha256"),
            "signature":      weekly.get("signature"),
            "file_type":      weekly.get("file_type"),
            "set_at":         weekly.get("set_at"),
            "age_days":       age_days,
            "days_remaining": max(0, 7 - age_days),
        }

    # ── Output ───────────────────────────────────────────────────────────────
    feed = {
        "meta": {
            "generated":     now.isoformat(),
            "generated_ts":  int(now.timestamp()),
            "source":        "MalwareBazaar (abuse.ch) × VirusTotal",
            "feed_url":      f"{BASE_URL}/feed.json",
            "rss_url":       f"{BASE_URL}/rss.xml",
            "dashboard":     f"{BASE_URL}/web/index.html",
            "version":       "3.0",
            "note_vt_rate":  "NIEDRIGE Rate = evasiv = GEFÄHRLICHER. 1/70 erkannt = rot = schlecht.",
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

        # 24h-Aggregat
        "24h": {
            "window":           "last_24h",
            "total_samples":    agg24_samples,
            "unique_iocs":      len(agg24_iocs),
            "risk": {
                "kritisch": agg24_risk.get("kritisch", 0),
                "hoch":     agg24_risk.get("hoch",     0),
                "mittel":   agg24_risk.get("mittel",   0),
                "niedrig":  agg24_risk.get("niedrig",  0),
            },
            "top_families":      dict(agg24_fams.most_common(15)),
            "critical_rate_pct": round(
                agg24_risk.get("kritisch",0) / max(agg24_samples,1) * 100, 1
            ),
        },

        # 7d-Aggregat (NEU)
        "7d": {
            "window":           "last_7d",
            "total_samples":    agg7d_samples,
            "risk": {
                "kritisch": agg7d_risk.get("kritisch", 0),
                "hoch":     agg7d_risk.get("hoch",     0),
                "mittel":   agg7d_risk.get("mittel",   0),
                "niedrig":  agg7d_risk.get("niedrig",  0),
            },
            "top_families":      dict(agg7d_fams.most_common(15)),
            "critical_rate_pct": round(
                agg7d_risk.get("kritisch",0) / max(agg7d_samples,1) * 100, 1
            ),
        },

        # Zeitreihen
        "history":    history_24h,   # letzte 24h – für Dashboard-Chart
        "history_7d": history_7d,    # letzte 7d  – für Trend-Chart

        # IOC-Listen
        "ioc_hashes":     all_ioc_hashes[:200],
        "ioc_hashes_24h": list(agg24_iocs)[:200],

        # VT-Details
        "vt_results": latest_vt,

        # AV-Zuverlässigkeit (NEU)
        "av_reliability": av_ranking[:20],

        # Wochen-Sample (NEU)
        "weekly_sample": weekly_info,

        # Nutzungs-Hinweise
        "usage": {
            "power_automate":  "GET /kpis → kompakte KPIs für Power Automate HTTP-Aktion",
            "python":          "import requests; d = requests.get('URL/feed.json').json(); print(d['24h']['risk'])",
            "powershell":      "$d = Invoke-WebRequest 'URL/feed.json' | ConvertFrom-Json; $d.'24h'.risk",
            "excel":           "Daten → Aus dem Web → URL: .../feed.json",
            "splunk":          "index=threat_intel | inputlookup feed.json",
            "curl_24h":        f"curl -s {BASE_URL}/feed.json | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d['24h']['risk'])\"",
            "curl_7d":         f"curl -s {BASE_URL}/feed.json | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d['7d']['risk'])\"",
        }
    }

    OUTPUT.write_text(json.dumps(feed, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] feed.json v2 geschrieben")
    print(f"    Letzter Run:  {latest_dt.strftime('%d.%m.%Y %H:%M')} UTC — {latest_samples} Samples")
    print(f"    24h gesamt:   {agg24_samples} Samples — {len(agg24_iocs)} unique IOCs")
    print(f"    7d gesamt:    {agg7d_samples} Samples")
    print(f"    IOC-Hashes:   {len(all_ioc_hashes)} (aus iocs/)")
    print(f"    VT-Blöcke:    {len(latest_vt)}")
    print(f"    AV-Engines:   {len(av_stats)} getrackt")
    print(f"    Wochen-Sample: {weekly_info.get('sha256','–')[:20] + '…' if weekly_info else 'keins'}")


if __name__ == "__main__":
    main()
