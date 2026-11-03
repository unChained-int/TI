# MalwareBazaar – 03.11.2026 19:16 UTC

Dieser Run hat **74 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **75** |
| Kritisch (≥75) | **40** |
| Höchster Score | **89.5/100** – 879bc24b7094a306… |
| Häufigste Familie | **unbekannt** (23x) |
| Häufigster Typ | **exe** (34x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 18 Samples |
| Ø Dateigröße | 5.17 MB (σ=8.30) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 34 | 45.3%  █████████ |
| `elf` | 14 | 18.7%  ███ |
| `jar` | 8 | 10.7%  ██ |
| `js` | 4 | 5.3%  █ |
| `sh` | 3 | 4.0%   |
| `ps1` | 3 | 4.0%   |
| `zip` | 2 | 2.7%   |
| `macho` | 1 | 1.3%   |
| `apk` | 1 | 1.3%   |
| `bat` | 1 | 1.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 23 | 30.7% |
| 2 | Mirai | 9 | 12.0% |
| 3 | Silentnet | 6 | 8.0% |
| 4 | Formbook | 5 | 6.7% |
| 5 | ValleyRAT | 5 | 6.7% |
| 6 | PureLogsStealer | 4 | 5.3% |
| 7 | RemcosRAT | 2 | 2.7% |
| 8 | Gafgyt | 2 | 2.7% |
| 9 | SilentNet | 2 | 2.7% |
| 10 | NanoCore | 2 | 2.7% |
| 11 | SnappyClient | 1 | 1.3% |
| 12 | AsyncRAT | 1 | 1.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 17 | 22.7% | 81% |
| Windows-Malware | 16 | 21.3% | 35% |
| RAT | 12 | 16.0% | 85% |
| Botnet/IoT | 11 | 14.7% | 95% |
| Andere / Unbekannt | 11 | 14.7% | 20% |
| Linux-Malware | 4 | 5.3% | 45% |
| Worm | 1 | 1.3% | 75% |
| Android-Malware | 1 | 1.3% | 45% |
| Cryptominer | 1 | 1.3% | 75% |
| Skript/Dropper | 1 | 1.3% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 40 | 53.3% |
| 🟠 HOCH | 2 | 2.7% |
| 🟡 MITTEL | 16 | 21.3% |
| 🟢 NIEDRIG | 17 | 22.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [879bc24b7094a3…](https://bazaar.abuse.ch/sample/879bc24b7094a3064aa9e87f0b0894d0a078888bee29ca637f7c5ca47b2d45f3/) | RemcosRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [669b6cd5e5fc9c…](https://bazaar.abuse.ch/sample/669b6cd5e5fc9cd98ec07dfeff5ccd0852537f2e72b95189533571e5b246a701/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [390f2d35ddea8c…](https://bazaar.abuse.ch/sample/390f2d35ddea8c07a937e316d5e3c09981914ed8a052ac637edce9e1dbc28dbd/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [ec80da754aaa79…](https://bazaar.abuse.ch/sample/ec80da754aaa79387be3b97b0fcf6fdc5d9edcf0b424cf60637942dc9a301faa/) | AsyncRAT | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [8ba2d972cc670a…](https://bazaar.abuse.ch/sample/8ba2d972cc670a6d6f7d3229725d9be3223fa46b96a1e361b4c40a464f6ded15/) | Formbook | Infostealer | **86.7** | 🔴 KRITISCH | – | – | ? |
| [3f8b447863dd61…](https://bazaar.abuse.ch/sample/3f8b447863dd61eaaa59b3160062afe1694038c7099345c4d1cc69c200a84489/) | Formbook | Infostealer | **86.5** | 🔴 KRITISCH | – | – | ? |
| [c2fe4f6af2d5f7…](https://bazaar.abuse.ch/sample/c2fe4f6af2d5f7499437d29137530121aa429e423f4d8a509781c17ccdfe2caa/) | Formbook | Infostealer | **86.4** | 🔴 KRITISCH | – | – | ? |
| [736a1327ed5c3f…](https://bazaar.abuse.ch/sample/736a1327ed5c3f2a17999a47f90083fdb795a4df8a584eb112e4125cf8e9f49a/) | njrat | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [aede15e51e7138…](https://bazaar.abuse.ch/sample/aede15e51e71380edf74b2c0b2e8433026d4ac5f524fb9635f4c7249c45c90db/) | Mirai | Botnet/IoT | **85.3** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [565d2bcc2a67aa…](https://bazaar.abuse.ch/sample/565d2bcc2a67aa9b857105f48cd4df7194239a8725137c0c3c1ec32211fc49eb/) | NanoCore | RAT | **85.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6324/7803 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6324/7803 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6030/7803 |
| 6 | Kaspersky | 75.5% | 5890/7802 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5552/7799 |
| 9 | Rising | 68.3% | 5327/7803 |
| 10 | Varist | 66.2% | 5159/7798 |
| 11 | Avast | 65.1% | 5076/7799 |
| 12 | AVG | 65.1% | 5076/7798 |
| 13 | Tencent | 64.9% | 4917/7577 |
| 14 | McAfeeD | 61.3% | 4781/7795 |
| 15 | huorong | 60.9% | 4745/7795 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 39 | 52.0% |
| 🐧 Linux | 19 | 25.3% |
| ❓ Unbekannt | 13 | 17.3% |
| 📦 Archiv | 2 | 2.7% |
| 🍎 macOS | 1 | 1.3% |
| 🤖 Android | 1 | 1.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 68 | 90.7% |
| Drive-By / Exploit-Kit | 4 | 5.3% |
| USB / Wechselmedium | 1 | 1.3% |
| APK-Sideloading | 1 | 1.3% |
| Trojanisierte Software | 1 | 1.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 16 | 21.3% |
| 2 | 🇫🇷 FR | 15 | 20.0% |
| 3 | 🇩🇪 DE | 13 | 17.3% |
| 4 | 🇸🇪 SE | 10 | 13.3% |
| 5 | 🇷🇴 RO | 6 | 8.0% |
| 6 | 🇳🇱 NL | 4 | 5.3% |
| 7 | 🇭🇺 HU | 3 | 4.0% |
| 8 | 🇬🇧 GB | 2 | 2.7% |
| 9 | 🇧🇷 BR | 2 | 2.7% |
| 10 | 🌐 Unbekannt | 2 | 2.7% |
| 11 | 🌐 CO | 1 | 1.3% |
| 12 | 🇧🇬 BG | 1 | 1.3% |

## MITRE ATT&CK

> 18 von 75 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 9 |
| Lateral Movement | 9 |
| Collection | 8 |
| Credential Access | 5 |
| Command and Control | 4 |
| Execution | 1 |

<details><summary>879bc24b7094a3064aa9… – RemcosRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>669b6cd5e5fc9cd98ec0… – Formbook | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>390f2d35ddea8c07a937… – Formbook | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ec80da754aaa79387be3… – AsyncRAT | 🔴 KRITISCH 87.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>8ba2d972cc670a6d6f7d… – Formbook | 🔴 KRITISCH 86.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3d0342375fa17c28aa40…](https://bazaar.abuse.ch/sample/3d0342375fa17c28aa409d74b6228ff158285b2543933b9930652c161d011290/)

- **Familie:** Mirai
- **Erkannt von:** 37 von 75 Engines (49.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Tsunami.6
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Tsunami.6`

**Erkennende Engines (37/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Tsunami.6` |
| AVG | `ELF:Agent-AYQ [Trj]` |
| AhnLab-V3 | `Linux/Gafgyt.Gen28` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Arcabit | `Trojan.Linux.Tsunami.6` |
| Avast | `ELF:Agent-AYQ [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Mirai.Z` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Tsunami.6` |
| CTX | `elf.unknown.tsunami` |
| ClamAV | `Unix.Dropper.Mirai-7135920-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Gafgyt.AWN trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Gen:Variant.Linux.Tsunami.6 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z` |
| Fortinet | `Linux/Gafgyt.AZG!tr` |
| GData | `Gen:Variant.Linux.Tsunami.6` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.a` |
| McAfeeD | `Trojan:Win/GenericY.GQO` |
| MicroWorld-eScan | `Gen:Variant.Linux.Tsunami.6` |
| Microsoft 🛡️ | `Backdoor:Linux/DemonBot.Aa!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13282 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Lnx/Gafgyt-FEEU!AC79AD758D47` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.bik` |
| TrendMicro | `Backdoor.Linux.BASHLITE.SMJC3` |
| TrendMicro-HouseCall | `Backdoor.Linux.BASHLITE.SMJC3` |
| VIPRE | `Gen:Variant.Linux.Tsunami.6` |
| Varist | `E64/Mirai.BE.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Gafgyt` |
| huorong | `Trojan/Linux.DDoS.h` |

### [1b92367f7a454fcd0b22…](https://bazaar.abuse.ch/sample/1b92367f7a454fcd0b226f83a771cdfcb58b812367f966cf604dcf2c5aa17d3d/)

- **Familie:** Gafgyt
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Linux.Medusa.C.09956800
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Linux.Medusa.C.09956800`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Linux.Medusa.C.09956800` |
| AVG | `BV:Downloader-AAN [Drp]` |
| AhnLab-V3 | `Shell/ElfDownloader.S3` |
| Arcabit | `Generic.Linux.Medusa.C.D97EDC0` |
| Avast | `BV:Downloader-AAN [Drp]` |
| Avira | `HTML/ExpKit.Gen2` |
| BitDefender 🛡️ | `Generic.Linux.Medusa.C.09956800` |
| CTX | `script.unknown.medusa` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.664` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.S trojan` |
| Emsisoft | `Generic.Linux.Medusa.C.09956800 (B)` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| Fortinet | `BASH/UNSTABLE.SH!tr.botnet` |
| GData | `Generic.Linux.Medusa.C.09956800` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| K7GW | `Trojan ( 004102a21 )` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| MicroWorld-eScan | `Generic.Linux.Medusa.C.09956800` |
| Microsoft 🛡️ | `TrojanDownloader:Linux/Morila!MTB` |
| NANO-Antivirus | `Trojan.Script.Downloader.kuopof` |
| Rising | `Downloader.Agent/BASH!1.DB4B (CLASSIC)` |
| Sangfor | `Virus.Generic-Script.Save.ba1` |
| Skyhigh | `Linux/Downloader.k` |
| Sophos | `Linux/Dldr-VH` |
| Symantec | `Downloader.Trojan` |
| Tencent | `Heur:Trojan.Linux.Downloader.e` |
| TrellixENS | `Linux/Downloader.k` |
| TrendMicro | `ELF_MIRAILOD.SM` |
| TrendMicro-HouseCall | `ELF_MIRAILOD.SM` |
| VIPRE | `Generic.Linux.Medusa.C.09956800` |
| Varist | `SH/Mirai.A.gen!Camelot` |
| Xcitium | `TrojWare.Script.TrojanDownloader.Agent.SH@7q1bln` |
| ZoneAlarm | `Linux/Dldr-VH` |
| huorong | `Trojan/BAT.Obfuscated.aar!crit` |

### [aede15e51e71380edf74…](https://bazaar.abuse.ch/sample/aede15e51e71380edf74b2c0b2e8433026d4ac5f524fb9635f4c7249c45c90db/)

- **Familie:** Mirai
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DDoS.3423` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.DDos.dt` |

### [4b91d95e6267ff26e86a…](https://bazaar.abuse.ch/sample/4b91d95e6267ff26e86acc9012c7a3fb65aad57f2e3bf78c92762096424495e7/)

- **Familie:** PureLogsStealer
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.Script.PureLogsStealer.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/Agent.BDR trojan` |
| Kaspersky | `HEUR:Trojan.PowerShell.Cobalt.gen` |
| Lionic | `Trojan.Script.PureLogsStealer.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (34×)
- **elf** (13×)
- **Mirai** (9×)
- **jar** (9×)
- **Torii** (8×)
- **honeypot** (7×)
- **java** (6×)
- **python** (6×)
- **silentnet** (6×)
- **RAT** (5×)
- **cowrie** (5×)
- **Formbook** (5×)
- **ValleyRAT** (5×)
- **stealer** (5×)
- **js** (4×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -9 (32→23)
- ↓ **Mirai** -3 (12→9)
- ↑ **Silentnet** +5 (1→6)
- ↓ **Formbook** -1 (6→5)
- ↑ **ValleyRAT** +4 (1→5)
- neu: **PureLogsStealer** (4)
- ↓ **RemcosRAT** -3 (5→2)
- neu: **Gafgyt** (2)
- ↑ **SilentNet** +1 (1→2)
- ↑ **NanoCore** +1 (1→2)
- weg: **GuLoader** (war 3)
- weg: **XWorm** (war 4)
- weg: **ConnectWise** (war 2)
- weg: **SalatStealer** (war 5)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -5 (28→23)
- ↓ **Mirai** -13 (22→9)
- neu: **Silentnet** (6)
- ↑ **Formbook** +2 (3→5)
- neu: **ValleyRAT** (5)
- neu: **PureLogsStealer** (4)
- neu: **Gafgyt** (2)
- ↑ **SilentNet** +1 (1→2)
- neu: **NanoCore** (2)
- weg: **SalatStealer** (war 11)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.168 MB |
| σ Dateigröße | 8.301 MB |
| Ø Risiko-Score | 60.7/100 |
| Ø Klassifikations-Konfidenz | 61.7% |
| Samples mit VT | 5/75 |
| Samples mit MITRE | 18/75 |
| Eindeutige Familien | 25 |
| Eindeutige Tags | 57 |
| Unbekannte Familien | 11 (14.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:58 | [b9e69245d22c…](https://bazaar.abuse.ch/sample/b9e69245d22cb9ea0122e7b4a46294048bb859d934ece80c78a0fd48f141f35c/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 18:55 | [879bc24b7094…](https://bazaar.abuse.ch/sample/879bc24b7094a3064aa9e87f0b0894d0a078888bee29ca637f7c5ca47b2d45f3/) | `js` | RemcosRAT | 89.5 | – | – | 🇳🇱NL |
| 18:50 | [aa7ee2e197c6…](https://bazaar.abuse.ch/sample/aa7ee2e197c6621037ecf3e68aa3f5fe33836ada3725275360b512eeb3795ca7/) | `exe` | unbekannt | 38.7 | – | – | 🇺🇸US |
| 18:48 | [3af98328cfb0…](https://bazaar.abuse.ch/sample/3af98328cfb0d5e145b6594df772d67528cefc14f7a049dba377399bd31f5c2d/) | `elf` | Mirai | 84.1 | – | – | 🇺🇸US |
| 18:47 | [955cee2898ba…](https://bazaar.abuse.ch/sample/955cee2898bac0ae16f9457bc07817ad3440766ad724f8d0507db1d815af3ef3/) | `sh` | unbekannt | 32.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 03.11.2026 19:16 UTC*