# MalwareBazaar – 19.10.2026 04:27 UTC

Dieser Run hat **53 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **54** |
| Kritisch (≥75) | **22** |
| Höchster Score | **94.6/100** – 423dc680eb304393… |
| Häufigste Familie | **unbekannt** (26x) |
| Häufigster Typ | **elf** (21x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 11 Samples |
| Ø Dateigröße | 7.56 MB (σ=21.86) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 21 | 38.9%  ███████ |
| `exe` | 17 | 31.5%  ██████ |
| `macho` | 9 | 16.7%  ███ |
| `zip` | 3 | 5.6%  █ |
| `sh` | 1 | 1.9%   |
| `msi` | 1 | 1.9%   |
| `vbs` | 1 | 1.9%   |
| `js` | 1 | 1.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 26 | 48.1% |
| 2 | Mirai | 9 | 16.7% |
| 3 | AMOS | 5 | 9.3% |
| 4 | VShell | 2 | 3.7% |
| 5 | ValleyRAT | 2 | 3.7% |
| 6 | Snowlight | 2 | 3.7% |
| 7 | RemcosRAT | 1 | 1.9% |
| 8 | Phorpiex | 1 | 1.9% |
| 9 | Detected | 1 | 1.9% |
| 10 | B!ml | 1 | 1.9% |
| 11 | RemusStealer | 1 | 1.9% |
| 12 | njrat | 1 | 1.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 11 | 20.4% | 35% |
| Linux-Malware | 9 | 16.7% | 45% |
| Botnet/IoT | 9 | 16.7% | 95% |
| Andere / Unbekannt | 8 | 14.8% | 20% |
| Infostealer | 6 | 11.1% | 92% |
| RAT | 4 | 7.4% | 85% |
| Loader | 2 | 3.7% | 70% |
| Trojaner | 2 | 3.7% | 65% |
| Skript/Dropper | 2 | 3.7% | 35% |
| Ransomware | 1 | 1.9% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 22 | 40.7% |
| 🟠 HOCH | 2 | 3.7% |
| 🟡 MITTEL | 22 | 40.7% |
| 🟢 NIEDRIG | 8 | 14.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [423dc680eb3043…](https://bazaar.abuse.ch/sample/423dc680eb30439391632cf05fde7dbc6d81f31e382454989051cd04e51705d1/) | WannaCry | Ransomware | **94.6** | 🔴 KRITISCH | – | – | ? |
| [57a23842ad1e35…](https://bazaar.abuse.ch/sample/57a23842ad1e35d74a7668ab2112de54d92b2a70f6949d7f892002aeb5d69db6/) | RemcosRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [40dc77a48faae5…](https://bazaar.abuse.ch/sample/40dc77a48faae52f4ab7e2fbac202427947ffd48fc4e3dc6ed9f9b4403dc590c/) | AMOS | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [eae1ad551a79a4…](https://bazaar.abuse.ch/sample/eae1ad551a79a4c8333b098258aab12566f538efcc0c8a3166bcf2f26a0ae2c5/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [447cc1be6fdca7…](https://bazaar.abuse.ch/sample/447cc1be6fdca78d738314f2d56b7981d7369247cdf8e97d548946f6f9919244/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [0119e2bc228137…](https://bazaar.abuse.ch/sample/0119e2bc2281379155fe73917dc347f31501873867e7d8174b71c8cdbf0e5c8f/) | AMOS | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [ff9c8f57fa3ec4…](https://bazaar.abuse.ch/sample/ff9c8f57fa3ec4c935c343bc636dee3253e6b6e4dbbd0d64e7898f0c7f7c5598/) | AMOS | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [6b39054cd0facc…](https://bazaar.abuse.ch/sample/6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c/) | njrat | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [2ad9f14bb36743…](https://bazaar.abuse.ch/sample/2ad9f14bb36743f1e361f2039aedf0b369958a254b618e172b0240f58191ba47/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [2fcb0f77a76ae4…](https://bazaar.abuse.ch/sample/2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04/) | B!ml | Trojaner | **83.1** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |

### VT-Erkennung: Was bedeutet die Rate?

> ⚠️ **Niedrige Rate ≠ harmlos!** Eine Malware die nur 1/70 Engines erkennen = hochgradig evasiv.
> Sie ist GEFÄHRLICHER weil sie Antivirenprogramme umgeht.
> | Rate | Bedeutung | Farbe |
> |------|-----------|-------|
> | < 10% | ⚠️ KAUM ERKANNT – maximal evasiv | 🔴 ROT |
> | 10–40% | 🟡 SCHWACH ERKANNT | 🟠 ORANGE |
> | 40–70% | 🟠 MÄSSIG ERKANNT | 🟡 GELB |
> | ≥ 70% | ✅ GUT ERKANNT – breite Abdeckung | 🟢 GRÜN |

## AV-Zuverlässigkeit (Erkennungsrate pro Engine)

> Basiert auf allen bisher gesehenen VT-Ergebnissen.
> **Microsoft Defender** ist Pflicht-Check — wird immer explizit ausgewiesen.

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6055/7486 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6055/7486 |
| 3 | ESET-NOD32 | 77.4% | 5793/7486 |
| 4 | Kaspersky | 76.3% | 5710/7485 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5348/7483 |
| 8 | Rising | 68.7% | 5142/7486 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4958/7482 |
| 11 | Tencent | 65.2% | 4735/7260 |
| 12 | Avast | 65.2% | 4875/7482 |
| 13 | AVG | 65.2% | 4875/7481 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4581/7479 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 24 | 44.4% |
| 🪟 Windows | 17 | 31.5% |
| 🍎 macOS | 9 | 16.7% |
| 📦 Archiv | 3 | 5.6% |
| ❓ Unbekannt | 1 | 1.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 45 | 83.3% |
| MaaS-Loader | 5 | 9.3% |
| C2 / Nachladen | 1 | 1.9% |
| Trojanisierte Software | 1 | 1.9% |
| Drive-By / Exploit-Kit | 1 | 1.9% |
| Exploit / N-Day | 1 | 1.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 25 | 46.3% |
| 2 | 🇩🇪 DE | 14 | 25.9% |
| 3 | 🌐 EG | 6 | 11.1% |
| 4 | 🇳🇱 NL | 6 | 11.1% |
| 5 | 🇨🇭 CH | 2 | 3.7% |
| 6 | 🌐 Unbekannt | 1 | 1.9% |

## MITRE ATT&CK

> 11 von 54 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 9 |
| Lateral Movement | 9 |
| Command and Control | 2 |
| Collection | 2 |

<details><summary>57a23842ad1e35d74a76… – RemcosRAT | 🔴 KRITISCH 88.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a1284c71db02401df198…](https://bazaar.abuse.ch/sample/a1284c71db02401df19887a51a738b39fcd5c96716a26bf6cfd0f7de3a5619a3/)

- **Familie:** Detected
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Detected
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Varist | `E32/Kaiji.A.gen!Camelot` |

### [2fcb0f77a76ae4afe0f8…](https://bazaar.abuse.ch/sample/2fcb0f77a76ae4afe0f8edb6e487f7cd31723af5f05d8b99742905b4cf645a04/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [c6504ab6ba9ab6453092…](https://bazaar.abuse.ch/sample/c6504ab6ba9ab6453092ac9da059559b4dde092aae898cd1cbdd930c6e5fa2f1/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BR [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BR [Drp]` |
| Antiy-AVL | `Trojan/Linux.Agent` |
| Avast | `ELF:Downloader-BR [Drp]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `DR/LINUX.Downloade.BR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2961` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Dropper.DR/LINUX.Downloade.BR` |
| Fortinet | `ELF/Agent.2270!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Rising | `Downloader.Agent/Linux!1.14466 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| ZoneAlarm | `Linux/Dldr-WW` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [d3a26db9b714a3b54c5a…](https://bazaar.abuse.ch/sample/d3a26db9b714a3b54c5a7aea6bef5ad93312e03d1fc120e637b4f228ec8dacc4/)

- **Familie:** Snowlight
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!2610A8C3D062
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Jiangmin | `Trojan.Linux.dws` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!2610A8C3D062` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!2610A8C3D062` |
| Varist | `E32/Agent.BE.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.ab!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.7053573B
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |


## Top Tags

- **elf** (21×)
- **exe** (11×)
- **Mirai** (9×)
- **macho** (9×)
- **AMOS** (5×)
- **ClickFix** (5×)
- **Foxveil** (5×)
- **loader** (5×)
- **Mach-O** (5×)
- **macOS** (5×)
- **zip** (3×)
- **snowlight** (3×)
- **RAT** (3×)
- **VShell** (2×)
- **ValleyRAT** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +3 (23→26)
- ↓ **Mirai** -15 (24→9)
- ↑ **AMOS** +4 (1→5)
- neu: **VShell** (2)
- neu: **ValleyRAT** (2)
- neu: **Snowlight** (2)
- neu: **Phorpiex** (1)
- neu: **Detected** (1)
- neu: **B!ml** (1)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -1 (27→26)
- ↓ **Mirai** -17 (26→9)
- ↑ **AMOS** +4 (1→5)
- neu: **VShell** (2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **Snowlight** (2)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **Phorpiex** (1)
- neu: **Detected** (1)
- neu: **B!ml** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.561 MB |
| σ Dateigröße | 21.862 MB |
| Ø Risiko-Score | 57.5/100 |
| Ø Klassifikations-Konfidenz | 58.0% |
| Samples mit VT | 5/54 |
| Samples mit MITRE | 11/54 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 28 |
| Unbekannte Familien | 8 (14.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:14 | [d8cbb7c00689…](https://bazaar.abuse.ch/sample/d8cbb7c00689d7fd518151cccdc8c24c5b6b44a49ce2e60ae9d74256ac366896/) | `sh` | unbekannt | 32.6 | – | – | 🇩🇪DE |
| 03:59 | [15ccc62d4695…](https://bazaar.abuse.ch/sample/15ccc62d46951d6967d31fa6e8a3ceb13865cd319d6a7876420388a311efe651/) | `elf` | unbekannt | 42.9 | – | – | 🇩🇪DE |
| 03:57 | [d3ec060c8459…](https://bazaar.abuse.ch/sample/d3ec060c8459ece5a17730985c4751976f276c3d16e4487b6d19dfc998980a22/) | `exe` | unbekannt | 38.7 | – | – | 🌐EG |
| 03:47 | [838c6c0f247c…](https://bazaar.abuse.ch/sample/838c6c0f247c3347075a71d18fb4a51b0ecc06c3db3ab337d666092d533129cb/) | `exe` | unbekannt | 38.5 | – | – | 🇺🇸US |
| 03:47 | [6c3731a2777b…](https://bazaar.abuse.ch/sample/6c3731a2777b436a1be8274135298572414024391b77d9c5d9435bfb9d4b7ef6/) | `zip` | unbekannt | 32.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.10.2026 04:27 UTC*