# 🦠 MalwareBazaar Threat Intelligence – Setup & Push Anleitung

## Schritt-für-Schritt: Von 0 zu GitHub Actions

---

## 1️⃣  Voraussetzungen installieren

```powershell
# Python prüfen
python --version   # muss 3.10+ sein

# Git prüfen
git --version

# Requests installieren (für lokale Tests)
pip install requests
```

---

## 2️⃣  GitHub Repository erstellen

1. Gehe zu **https://github.com/new**
2. Repository-Name: `malware-intel` (oder beliebig)
3. Sichtbarkeit: **Public** ← wichtig für GitHub Pages
4. **README** NICHT anlegen (wir pushen selbst)
5. Klick **Create repository**

---

## 3️⃣  Lokales Projekt einrichten & pushen

```powershell


# Alle Dateien hinzufügen
git add .
git commit -m "🦠 Initial commit – MalwareBazaar Threat Intel v6"

# Pushen
git push -u origin main
```

---

## 4️⃣  API-Keys als GitHub Secrets hinterlegen

> ⚠️ **NIEMALS** API-Keys direkt in Code committen!
> Die Keys im Script sind nur für lokalen Test – für GitHub Actions nutzen wir Secrets.

1. Gehe zu deinem Repo → **Settings** → **Secrets and variables** → **Actions**
2. Klick **New repository secret**


---

## 5️⃣  GitHub Pages aktivieren

1. Repo → **Settings** → **Pages**
2. Source: **Deploy from a branch**
3. Branch: **main** / Folder: **`/web`**
4. Klick **Save**

Nach dem ersten Actions-Run ist dein Dashboard erreichbar unter:
```
https://DEIN_USERNAME.github.io/malware-intel/
```

---

## 6️⃣  BASE_URL anpassen

In beiden Scripts BASE_URL auf deine GitHub-Pages-URL setzen:

```powershell
# scripts/generate_rss.py  – Zeile 14
BASE_URL = "https://DEIN_USERNAME.github.io/malware-intel"

# scripts/generate_web.py  – Zeile 17
BASE_URL = "https://DEIN_USERNAME.github.io/malware-intel"
```

Dann committen & pushen:
```powershell
git add .
git commit -m "🔧 Set BASE_URL"
git push
```

---

## 7️⃣  Ersten Run manuell starten

1. Repo → **Actions**
2. Workflow **"🦠 MalwareBazaar Daily Report"** auswählen
3. **Run workflow** → **Run workflow** klicken
4. Logs beobachten (~3 Minuten)

---

## 8️⃣  Projektstruktur nach erstem Run

```
malware-intel/
├── .github/
│   └── workflows/
│       └── daily_report.yml      ← Automatisierung
├── scripts/
│   ├── generate_rss.py           ← RSS Feed Generator
│   └── generate_web.py           ← Dashboard Generator
├── web/
│   └── index.html                ← 🌐 Dashboard (GitHub Pages)
├── reports/
│   ├── latest.md                 ← Aktuellster Report
│   └── MalwareBazaar_24h_Report_2026-03-06_06-00-UTC.md
├── iocs/
│   └── iocs_2026-03-06_06-00-UTC.txt   ← IOC Export
├── logs/
│   └── malware_report_2026-03-06.log
├── raw/
│   └── MalwareBazaar_raw_2026-03-06_06-00-UTC.json
├── malware_history.json           ← Für Delta/Trending
├── malware_report.py              ← Haupt-Script v6
├── rss.xml                        ← 📡 RSS Feed
├── _config.yml
└── .gitignore
```

---

## 🔄 Automatisierung

Der Workflow läuft täglich um **06:00 UTC** automatisch.

Manuell starten: **Actions → Run workflow**

Dry-Run (kein API-Call, nutzt letztes JSON):
```powershell
python malware_report.py --dry-run
```

---

## 📡 RSS Feed abonnieren

URL für RSS-Reader (z.B. Feedly, Inoreader):
```
https://DEIN_USERNAME.github.io/malware-intel/rss.xml
```

---

## ⚠️ Sicherheitshinweise

- Script **nur in VM / isolierter Umgebung** ausführen
- **Keine** Malware-Samples ausführen – nur Metadaten
- API-Keys regelmäßig rotieren
- Bei Kompromittierung: Secrets sofort in GitHub löschen
