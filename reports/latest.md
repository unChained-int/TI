# MalwareBazaar – 23.10.2026 03:54 UTC

Dieser Run hat **74 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **75** |
| Kritisch (≥75) | **45** |
| Höchster Score | **89.4/100** – 21af7d776011760b… |
| Häufigste Familie | **Mirai** (30x) |
| Häufigster Typ | **elf** (34x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 35 Samples |
| Ø Dateigröße | 5.06 MB (σ=20.80) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 34 | 45.3%  █████████ |
| `exe` | 23 | 30.7%  ██████ |
| `macho` | 13 | 17.3%  ███ |
| `sh` | 2 | 2.7%   |
| `js` | 2 | 2.7%   |
| `msi` | 1 | 1.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 30 | 40.0% |
| 2 | unbekannt | 29 | 38.7% |
| 3 | Adware.OfferCore | 3 | 4.0% |
| 4 | RemcosRAT | 2 | 2.7% |
| 5 | Formbook | 2 | 2.7% |
| 6 | AokigaharaStealer | 1 | 1.3% |
| 7 | SalatStealer | 1 | 1.3% |
| 8 | Malware | 1 | 1.3% |
| 9 | VShell | 1 | 1.3% |
| 10 | Win64:MalwareX-gen [Hack] | 1 | 1.3% |
| 11 | AsyncRAT | 1 | 1.3% |
| 12 | Snowlight | 1 | 1.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 30 | 40.0% | 95% |
| Loader | 13 | 17.3% | 75% |
| Windows-Malware | 10 | 13.3% | 35% |
| Infostealer | 8 | 10.7% | 80% |
| Andere / Unbekannt | 4 | 5.3% | 20% |
| RAT | 4 | 5.3% | 95% |
| Linux-Malware | 3 | 4.0% | 45% |
| Trojaner | 3 | 4.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 60.0% |
| 🟠 HOCH | 13 | 17.3% |
| 🟡 MITTEL | 13 | 17.3% |
| 🟢 NIEDRIG | 4 | 5.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [21af7d77601176…](https://bazaar.abuse.ch/sample/21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43/) | Formbook | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |
| [4e11133df35ffe…](https://bazaar.abuse.ch/sample/4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [1a82e6aebae105…](https://bazaar.abuse.ch/sample/1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9/) | AsyncRAT | RAT | **88.0** | 🔴 KRITISCH | – | – | ? |
| [b6d03e3f9c178c…](https://bazaar.abuse.ch/sample/b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299/) | Formbook | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [ba9810872fd8b1…](https://bazaar.abuse.ch/sample/ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [10ff3c82edf926…](https://bazaar.abuse.ch/sample/10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec/) | DCRat | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [cd1b531e13ccd3…](https://bazaar.abuse.ch/sample/cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [d63bcebff095ba…](https://bazaar.abuse.ch/sample/d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [d41653b6ed41c5…](https://bazaar.abuse.ch/sample/d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [b6aec7e19e75aa…](https://bazaar.abuse.ch/sample/b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6128/7567 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6128/7567 |
| 3 | ESET-NOD32 | 77.3% | 5848/7567 |
| 4 | Kaspersky | 76.0% | 5752/7566 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5390/7564 |
| 8 | Rising | 68.5% | 5180/7567 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5008/7563 |
| 11 | Avast | 65.2% | 4934/7563 |
| 12 | AVG | 65.2% | 4934/7562 |
| 13 | Tencent | 65.0% | 4772/7341 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4631/7560 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 36 | 48.0% |
| 🪟 Windows | 23 | 30.7% |
| 🍎 macOS | 13 | 17.3% |
| ❓ Unbekannt | 2 | 2.7% |
| 📦 Archiv | 1 | 1.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 59 | 78.7% |
| MaaS-Loader | 13 | 17.3% |
| Drive-By / Exploit-Kit | 2 | 2.7% |
| Trojanisierte Software | 1 | 1.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 44 | 58.7% |
| 2 | 🇩🇪 DE | 9 | 12.0% |
| 3 | 🇨🇦 CA | 6 | 8.0% |
| 4 | 🇬🇧 GB | 5 | 6.7% |
| 5 | 🇨🇭 CH | 4 | 5.3% |
| 6 | 🇳🇱 NL | 3 | 4.0% |
| 7 | 🇷🇴 RO | 3 | 4.0% |
| 8 | 🌐 Unbekannt | 1 | 1.3% |

## MITRE ATT&CK

> 35 von 75 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 30 |
| Lateral Movement | 30 |
| Collection | 4 |
| Command and Control | 3 |
| Credential Access | 2 |
| Execution | 1 |

<details><summary>21af7d776011760bce54… – Formbook | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4e11133df35ffece8b92… – RemcosRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>1a82e6aebae1050a62c1… – AsyncRAT | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>b6d03e3f9c178c77eb32… – Formbook | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ba9810872fd8b1de1a70… – RemcosRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [0c0940c543d28b134dd5…](https://bazaar.abuse.ch/sample/0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902/)

- **Familie:** Malware
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.47F80795
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.47F80795` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Kaspersky | `VHO:Trojan.Win32.Convagent.gen` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [c2d65bddfded387376cf…](https://bazaar.abuse.ch/sample/c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94/)

- **Familie:** Win64:MalwareX-gen [Hack]
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Hack]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Hack]` |
| AhnLab-V3 | `HackTool/Win.PSWDump.R801999` |
| Avast | `Win64:MalwareX-gen [Hack]` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.6995BE17` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.DownLoader51.10361` |
| ESET-NOD32 | `Win64/HackTool.PSWDump_AGen.CM trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Kaspersky | `VHO:Trojan.Win32.Sdum.gen` |
| Malwarebytes | `Spyware.Stealer` |
| McAfeeD | `ti!C2D65BDDFDED` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.11e7221f` |
| huorong | `TrojanSpy/Stealer.aa` |

### [3934bb8fe8757867c5f5…](https://bazaar.abuse.ch/sample/3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-AAL [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AAL [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen` |
| Avast | `ELF:Mirai-AAL [Trj]` |
| Avast-Mobile | `ELF:Mirai-UM [Trj]` |
| Avira | `EXP/ELF.Gafgyt.X` |
| ClamAV | `Unix.Trojan.Mirai-6981158-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9838` |
| ESET-NOD32 | `Linux/Mirai.B trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.X` |
| Fortinet | `ELF/Mirai.CXJ!tr` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.in` |
| Kingsoft | `Linux.Backdoor.elf.2023768` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.AZ!xp` |
| Rising | `Exploit.CVE-2017-17215!1.103D2 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.blf` |
| huorong | `Trojan/Linux.Mirai.q` |

### [561095acf398b0edcdbb…](https://bazaar.abuse.ch/sample/561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840/)

- **Familie:** Snowlight
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40681000
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40681000`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Arcabit | `Trojan.Generic.D26CBE28` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| BitDefender 🛡️ | `Trojan.Generic.40681000` |
| CTX | `elf.trojan.vshell` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Generic.40681000 (B)` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| GData | `Trojan.Generic.40681000` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Kingsoft | `Linux.Trojan.Agent.pm` |
| Lionic | `Trojan.Linux.VShell.4!c` |
| McAfeeD | `ti!561095ACF398` |
| MicroWorld-eScan | `Trojan.Generic.40681000` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!3F7CD9C5372C` |
| Sophos | `Linux/Dldr-WW` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| VIPRE | `Trojan.Generic.40681000` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

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

- **elf** (34×)
- **Mirai** (24×)
- **exe** (22×)
- **loader** (13×)
- **macho** (13×)
- **ClickFix** (11×)
- **Foxveil** (11×)
- **Mach-O** (11×)
- **macOS** (11×)
- **honeypot** (6×)
- **Linux** (6×)
- **VShell** (6×)
- **wraith** (6×)
- **gafgyt** (6×)
- **mirai** (6×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +13 (17→30)
- ↓ **unbekannt** -19 (48→29)
- neu: **Adware.OfferCore** (3)
- ↑ **Formbook** +1 (1→2)
- neu: **AokigaharaStealer** (1)
- neu: **SalatStealer** (1)
- neu: **Malware** (1)
- neu: **VShell** (1)
- neu: **Win64:MalwareX-gen [Hack]** (1)
- weg: **CoinMiner** (war 10)
- weg: **Kaiji** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +8 (22→30)
- ↓ **unbekannt** -11 (40→29)
- neu: **Adware.OfferCore** (3)
- ↑ **Formbook** +1 (1→2)
- neu: **AokigaharaStealer** (1)
- neu: **Malware** (1)
- neu: **VShell** (1)
- neu: **Win64:MalwareX-gen [Hack]** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.058 MB |
| σ Dateigröße | 20.805 MB |
| Ø Risiko-Score | 70.3/100 |
| Ø Klassifikations-Konfidenz | 74.7% |
| Samples mit VT | 5/75 |
| Samples mit MITRE | 35/75 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 51 |
| Unbekannte Familien | 4 (5.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:51 | [0db860c62ce8…](https://bazaar.abuse.ch/sample/0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 03:50 | [9c21d2e50468…](https://bazaar.abuse.ch/sample/9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 03:47 | [cd1b531e13cc…](https://bazaar.abuse.ch/sample/cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 03:34 | [faf0bc67308e…](https://bazaar.abuse.ch/sample/faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d/) | `elf` | unbekannt | 43.1 | – | – | 🇩🇪DE |
| 03:34 | [87f4c9758c73…](https://bazaar.abuse.ch/sample/87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1/) | `elf` | unbekannt | 43.1 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.10.2026 03:54 UTC*