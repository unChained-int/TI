# 🦠 MalwareBazaar Threat Intelligence Dashboard

Automatisierter **täglicher Report** über die neuesten Malware-Samples von [MalwareBazaar](https://bazaar.abuse.ch)  
mit Risiko-Bewertung, VirusTotal-Anreicherung, MITRE ATT&CK-Mapping, IOC-Export und GitHub Pages Dashboard.

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/unChained-int/TI/daily_report.yml?branch=main&style=flat-square&logo=github)](https://github.com/unChained-int/TI/actions)
[![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square&logo=python)](https://www.python.org)


**Live Dashboard:** https://unchained-int.github.io/TI/web/index.html  
**RSS-Feed:** https://unchained-int.github.io/TI/rss.xml

## Aktueller Stand (Beispiel – Stand März 2026)

- **Dominante Bedrohung:** Mirai-Botnet (IoT/Linux) – 50 % der Samples
- **Häufigste Plattformen:** Linux (51 %) · Windows (44 %)
- **Kritische Samples:** ~57 % mit Risiko-Score ≥ 75/100
- **MITRE-Mapping:** ~60 % der Samples
- **Tägliche Aktualisierung:** 06:00 UTC via GitHub Actions

## Inhalte des täglichen Reports

- Executive Summary mit KPIs
- Top Dateitypen, Familien & Kategorien
- Risiko-Verteilung (🔴 Kritisch / 🟠 Hoch / 🟡 Mittel / 🟢 Niedrig)
- Betroffene Plattformen & wahrscheinliche Infektionsvektoren
- MITRE ATT&CK Taktiken & Techniken (für bekannte Familien)
- VirusTotal-Anreicherung (Top-Samples)
- Häufigste Tags & statistische Kennzahlen
- Neueste 5 Samples + Delta zum Vortag
- Export: Markdown, JSON (raw), IOCs (TXT), RSS, Web-Dashboard
Sicherheitshinweise ⚠️

## Keine Malware-Samples herunterladen oder ausführen!
Nur Metadaten, Hashes, Tags und VT-Ergebnisse werden verarbeitet
API-Keys niemals in Code committen → immer Secrets/Umgebungsvariablen
Bei Kompromittierung: Secrets sofort rotieren/löschen
Projekt nur in isolierter VM/Umgebung ausführen

## Danksagung
Daten von:
## MalwareBazaar (abuse.ch) × VirusTotal
