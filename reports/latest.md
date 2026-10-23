# MalwareBazaar – 23.10.2026 09:12 UTC

Dieser Run hat **50 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **51** |
| Kritisch (≥75) | **28** |
| Höchster Score | **93.5/100** – 5e1d7ed440028b43… |
| Häufigste Familie | **unbekannt** (21x) |
| Häufigster Typ | **elf** (23x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 25 Samples |
| Ø Dateigröße | 2.16 MB (σ=6.27) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 23 | 45.1%  █████████ |
| `exe` | 12 | 23.5%  ████ |
| `js` | 7 | 13.7%  ██ |
| `xlsm` | 2 | 3.9%   |
| `vbs` | 2 | 3.9%   |
| `msi` | 1 | 2.0%   |
| `sh` | 1 | 2.0%   |
| `ps1` | 1 | 2.0%   |
| `macho` | 1 | 2.0%   |
| `dmg` | 1 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 21 | 41.2% |
| 2 | Mirai | 18 | 35.3% |
| 3 | RemcosRAT | 2 | 3.9% |
| 4 | AsyncRAT | 1 | 2.0% |
| 5 | Siggen | 1 | 2.0% |
| 6 | CobaltStrike | 1 | 2.0% |
| 7 | Vidar | 1 | 2.0% |
| 8 | GuLoader | 1 | 2.0% |
| 9 | ConnectWise | 1 | 2.0% |
| 10 | Formbook | 1 | 2.0% |
| 11 | XWorm | 1 | 2.0% |
| 12 | AMOS | 1 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 18 | 35.3% | 95% |
| Windows-Malware | 7 | 13.7% | 35% |
| Linux-Malware | 6 | 11.8% | 45% |
| Skript/Dropper | 5 | 9.8% | 35% |
| RAT | 4 | 7.8% | 95% |
| Infostealer | 4 | 7.8% | 90% |
| Maldoc | 2 | 3.9% | 35% |
| Loader | 2 | 3.9% | 85% |
| Post-Exploitation | 1 | 2.0% | 95% |
| Andere / Unbekannt | 1 | 2.0% | 20% |
| Trojaner | 1 | 2.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 28 | 54.9% |
| 🟠 HOCH | 3 | 5.9% |
| 🟡 MITTEL | 19 | 37.3% |
| 🟢 NIEDRIG | 1 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5e1d7ed440028b…](https://bazaar.abuse.ch/sample/5e1d7ed440028b43d375c9ef1c451ae41533ac8db344a0e13d89def501169e8a/) | CobaltStrike | Post-Exploitat | **93.5** | 🔴 KRITISCH | – | – | ? |
| [e34942601a9167…](https://bazaar.abuse.ch/sample/e34942601a91672eb0c9895b5a7a71dd4d7ef19acee1e2d6ec85834549b850f8/) | AsyncRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [6e1d61b20fe325…](https://bazaar.abuse.ch/sample/6e1d61b20fe32532f21af6ecd8566c0efac956041777e204cbc1af4a5d257be6/) | Vidar | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [616a435efaa23a…](https://bazaar.abuse.ch/sample/616a435efaa23abf2b388bd9f3d18a07e9b0a9788d23cf9d957809e16e5a947e/) | Formbook | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [c4c37214391236…](https://bazaar.abuse.ch/sample/c4c3721439123624933ba9e77a2a17afd41b30705af3ad14979bf97eddf158f5/) | RemcosRAT | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [9160b044d2e934…](https://bazaar.abuse.ch/sample/9160b044d2e9341c403f0149f0d8891b25d305e106815441997ccf65784b8e52/) | RemcosRAT | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [77eb79dbe63f91…](https://bazaar.abuse.ch/sample/77eb79dbe63f91fe84036fded99f31c3f50412685a673d5ef503fd9986ccefcf/) | XWorm | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [67b75dbf7e0fa3…](https://bazaar.abuse.ch/sample/67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64/) | AMOS | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [8d1d056a90c422…](https://bazaar.abuse.ch/sample/8d1d056a90c422091097ce654e466ddf142abd5c79bd236aa02fe8ad0fc72e5f/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [034e0da2e576fc…](https://bazaar.abuse.ch/sample/034e0da2e576fce6f751806e1de5722d56310bdc8dab35bce885bcb06328bb72/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6131/7572 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6131/7572 |
| 3 | ESET-NOD32 | 77.3% | 5850/7572 |
| 4 | Kaspersky | 76.0% | 5754/7571 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5393/7569 |
| 8 | Rising | 68.4% | 5182/7572 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5012/7568 |
| 11 | Avast | 65.2% | 4936/7568 |
| 12 | AVG | 65.2% | 4936/7567 |
| 13 | Tencent | 65.0% | 4774/7346 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4635/7565 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 24 | 47.1% |
| 🪟 Windows | 16 | 31.4% |
| ❓ Unbekannt | 7 | 13.7% |
| 📄 Dokument | 2 | 3.9% |
| 🍎 macOS | 2 | 3.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 40 | 78.4% |
| Drive-By / Exploit-Kit | 7 | 13.7% |
| Phishing / E-Mail-Anhang | 2 | 3.9% |
| Trojanisierte Software | 1 | 2.0% |
| MaaS-Loader | 1 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 18 | 35.3% |
| 2 | 🇩🇪 DE | 18 | 35.3% |
| 3 | 🇸🇪 SE | 7 | 13.7% |
| 4 | 🇳🇱 NL | 5 | 9.8% |
| 5 | 🌐 Unbekannt | 2 | 3.9% |
| 6 | 🇨🇭 CH | 1 | 2.0% |

## MITRE ATT&CK

> 25 von 51 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Command and Control | 4 |
| Collection | 4 |
| Credential Access | 3 |
| Execution | 2 |
| Exfiltration | 1 |
| Defense Evasion | 1 |

<details><summary>5e1d7ed440028b43d375… – CobaltStrike | 🔴 KRITISCH 93.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol |
| Credential Access | [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping |

</details>
<details><summary>e34942601a91672eb0c9… – AsyncRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>6e1d61b20fe32532f21a… – Vidar | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>616a435efaa23abf2b38… – Formbook | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>c4c3721439123624933b… – RemcosRAT | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [e036c0c22e841a3129e6…](https://bazaar.abuse.ch/sample/e036c0c22e841a3129e640527575deb5efbb0adadb672db58c4ae5e566fc6dba/)

- **Familie:** Siggen
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux.Siggen.14015
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.Siggen.14015` |
| McAfeeD | `ti!E036C0C22E84` |

### [9ebbda9ca702fbdaa740…](https://bazaar.abuse.ch/sample/9ebbda9ca702fbdaa740349da215de0f9b86962269921cdb335855a4b0ef5d5b/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** BV:Downloader-AEH [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `BV:Downloader-AEH [Drp]` |
| Avast | `BV:Downloader-AEH [Drp]` |
| Avira | `DR/BAT.Downloader.AEH` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2647` |
| F-Secure | `Dropper.DR/BAT.Downloader.AEH` |
| Fortinet | `BASH/Dloader.P!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Rising | `Downloader.Agent/BASH!9.136D0 (XSE:WFNFX0JBVDohwEdTFX2vq48bpNVvpQyr)` |
| Varist | `SH/Mirai.C.gen!Camelot` |
| huorong | `TrojanDownloader/Linux.Agent.bx` |

### [dc5ece812e4e0f7aa6e8…](https://bazaar.abuse.ch/sample/dc5ece812e4e0f7aa6e8203c25bb0c149f13130cc5da0092f2d27944e30a4438/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!755045250DB3
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gp` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!755045250DB3` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| TrellixENS | `LINUX/Mirai-FQU!755045250DB3` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [42f9f668109e0e63bfbd…](https://bazaar.abuse.ch/sample/42f9f668109e0e63bfbd83f803f9ea405bfe7490e553e9939f69bef3cbcd17b0/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux.Generic.Threat
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.AQY` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AQY` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Mirai.AT.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (22×)
- **Mirai** (17×)
- **exe** (11×)
- **js** (7×)
- **xlsm** (2×)
- **RemcosRAT** (2×)
- **vbs** (2×)
- **beenetprotect** (2×)
- **fake-torrent** (2×)
- **LimeTorrents** (2×)
- **signed** (1×)
- **msi** (1×)
- **AsyncRAT** (1×)
- **cowrie** (1×)
- **honeypot** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -23 (44→21)
- ↓ **Mirai** -1 (19→18)
- neu: **AsyncRAT** (1)
- neu: **Siggen** (1)
- neu: **CobaltStrike** (1)
- neu: **Vidar** (1)
- neu: **GuLoader** (1)
- weg: **CoinMiner** (war 8)
- weg: **Kaiji** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -18 (39→21)
- ↓ **Mirai** -5 (23→18)
- ↑ **RemcosRAT** +1 (1→2)
- neu: **AsyncRAT** (1)
- neu: **Siggen** (1)
- neu: **CobaltStrike** (1)
- neu: **Vidar** (1)
- neu: **GuLoader** (1)
- neu: **ConnectWise** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.161 MB |
| σ Dateigröße | 6.269 MB |
| Ø Risiko-Score | 64.4/100 |
| Ø Klassifikations-Konfidenz | 69.8% |
| Samples mit VT | 5/51 |
| Samples mit MITRE | 25/51 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 36 |
| Unbekannte Familien | 1 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 09:09 | [f0699a95fc39…](https://bazaar.abuse.ch/sample/f0699a95fc39bed963289229b613f2b4684ed034e28f8b355fe0b6825a01e774/) | `xlsm` | unbekannt | 39.1 | – | – | 🌐SE |
| 09:09 | [5336bb025eda…](https://bazaar.abuse.ch/sample/5336bb025edac7d5f76f1dc431e310506cdfc5b7c5342dc43ff7a7a3e76cabc4/) | `xlsm` | unbekannt | 39.1 | – | – | 🌐SE |
| 09:05 | [00110ce22687…](https://bazaar.abuse.ch/sample/00110ce22687b3ea3b36a95841909f4c0f1d1a0288206499c2e15de8ea349be4/) | `js` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 08:54 | [b9115303dd35…](https://bazaar.abuse.ch/sample/b9115303dd3567ac75104a5a3d2bc0ce4fd7d697ebf258e61283cdf708d50133/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 08:54 | [73ab77da60d7…](https://bazaar.abuse.ch/sample/73ab77da60d7196bce61405c615f8cd03a3157abffaf4a2447bd79fb8082da9f/) | `msi` | unbekannt | 38.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.10.2026 09:12 UTC*