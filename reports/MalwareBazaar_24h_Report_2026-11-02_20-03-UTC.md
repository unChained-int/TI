# MalwareBazaar – 02.11.2026 20:03 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **49** |
| Höchster Score | **88.7/100** – 7108d2c7b985267b… |
| Häufigste Familie | **unbekannt** (32x) |
| Häufigster Typ | **js** (48x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 37 Samples |
| Ø Dateigröße | 2.60 MB (σ=5.00) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 48 | 47.5%  █████████ |
| `vbs` | 12 | 11.9%  ██ |
| `elf` | 10 | 9.9%  █ |
| `exe` | 10 | 9.9%  █ |
| `jar` | 10 | 9.9%  █ |
| `sh` | 5 | 5.0%   |
| `zip` | 1 | 1.0%   |
| `php` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `xls` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 32 | 31.7% |
| 2 | AgentTesla | 14 | 13.9% |
| 3 | Formbook | 12 | 11.9% |
| 4 | RemcosRAT | 11 | 10.9% |
| 5 | GuLoader | 9 | 8.9% |
| 6 | XWorm | 6 | 5.9% |
| 7 | Mirai | 4 | 4.0% |
| 8 | DonutLoader | 4 | 4.0% |
| 9 | AsyncRAT | 1 | 1.0% |
| 10 | ConnectWise | 1 | 1.0% |
| 11 | Ngioweb | 1 | 1.0% |
| 12 | ShadowPad | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 20 | 19.8% | 94% |
| Skript/Dropper | 19 | 18.8% | 35% |
| Andere / Unbekannt | 17 | 16.8% | 20% |
| Infostealer | 13 | 12.9% | 93% |
| Loader | 13 | 12.9% | 95% |
| Windows-Malware | 8 | 7.9% | 35% |
| Linux-Malware | 6 | 5.9% | 45% |
| Botnet/IoT | 4 | 4.0% | 95% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 49 | 48.5% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 39 | 38.6% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7108d2c7b98526…](https://bazaar.abuse.ch/sample/7108d2c7b985267bec554335b4a91b8f756b4d1eca463d04051b4d65b065d587/) | AsyncRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [b5b65800543172…](https://bazaar.abuse.ch/sample/b5b658005431729b654316be00bf7f9bc76b230bfdf6f3fdde264a5ebc66c31f/) | Formbook | Infostealer | **86.4** | 🔴 KRITISCH | – | – | ? |
| [8dea760101ac9d…](https://bazaar.abuse.ch/sample/8dea760101ac9d14ec08c7ff2c3a7d2d75017c8229b4902060663137ad2cc4b3/) | RemcosRAT | RAT | **86.3** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [ca6670841f7dd9…](https://bazaar.abuse.ch/sample/ca6670841f7dd9e36d6e630e19a0e0f77167e49334752bb21ec84c92ddc7eb07/) | Formbook | Infostealer | **86.2** | 🔴 KRITISCH | – | – | ? |
| [50cc28505466c5…](https://bazaar.abuse.ch/sample/50cc28505466c5355dc42c7f4199697cde0b9bc4bd7fbfedfeeb42e096b9631a/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [e0124758e57313…](https://bazaar.abuse.ch/sample/e0124758e57313bf9f2a734e2f1076d57d558e3ea5c144ab10f688d4b1702b9b/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [c7e92757ca9be9…](https://bazaar.abuse.ch/sample/c7e92757ca9be9d8f6defa2628d39e8f0cd6ea88c24f48a8691d473a987167eb/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [963cdc4637635e…](https://bazaar.abuse.ch/sample/963cdc4637635e006f8484d32e7ed241936f970d78cbca10af833fa3feccef4f/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [2b103b4a9b3b6c…](https://bazaar.abuse.ch/sample/2b103b4a9b3b6cb639c927c0a839af24b1413a47a0ec7078e38af940e2253f65/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [1b4dd72f4b9b76…](https://bazaar.abuse.ch/sample/1b4dd72f4b9b76a9ff20ee6ee59453de840ed65e224e3099b17a5418302e67a1/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6313/7788 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6313/7788 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6017/7788 |
| 6 | Kaspersky | 75.5% | 5879/7787 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5543/7784 |
| 9 | Rising | 68.3% | 5317/7788 |
| 10 | Varist | 66.2% | 5149/7783 |
| 11 | Avast | 65.1% | 5070/7784 |
| 12 | AVG | 65.1% | 5070/7783 |
| 13 | Tencent | 64.9% | 4908/7562 |
| 14 | McAfeeD | 61.3% | 4772/7780 |
| 15 | huorong | 60.9% | 4735/7780 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 58 | 57.4% |
| 🪟 Windows | 24 | 23.8% |
| 🐧 Linux | 16 | 15.8% |
| 📦 Archiv | 1 | 1.0% |
| 🌐 Web | 1 | 1.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Drive-By / Exploit-Kit | 57 | 56.4% |
| Unbekannt / nicht bestimmbar | 43 | 42.6% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 59 | 58.4% |
| 2 | 🇩🇪 DE | 12 | 11.9% |
| 3 | 🇷🇴 RO | 10 | 9.9% |
| 4 | 🇺🇸 US | 9 | 8.9% |
| 5 | 🇭🇺 HU | 5 | 5.0% |
| 6 | 🇫🇷 FR | 4 | 4.0% |
| 7 | 🌐 EG | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 37 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 23 |
| Command and Control | 12 |
| Credential Access | 12 |
| Execution | 10 |
| Defense Evasion | 9 |
| Initial Access | 4 |
| Lateral Movement | 4 |

<details><summary>7108d2c7b985267bec55… – AsyncRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>b5b658005431729b6543… – Formbook | 🔴 KRITISCH 86.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>8dea760101ac9d14ec08… – RemcosRAT | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>ca6670841f7dd9e36d6e… – Formbook | 🔴 KRITISCH 86.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>50cc28505466c5355dc4… – Formbook | 🔴 KRITISCH 86.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [27ca6bc2a7b05f067b59…](https://bazaar.abuse.ch/sample/27ca6bc2a7b05f067b593dfaac4866a0cff39207d500ab87ffff0c9881f962fc/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux.Mirai
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Mirai.FNP trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nx` |
| Kingsoft | `Linux.Backdoor.Mirai.nx` |
| McAfeeD | `Trojan:Script/Mirai.EHA` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.tnog` |
| Varist | `E32/Mirai.JK.gen!Eldorado` |
| alibabacloud | `DDoS:Linux/Mirai.FTD` |

### [9f72c50f8e66727f7589…](https://bazaar.abuse.ch/sample/9f72c50f8e66727f7589f24254b006c43cd51ba2207a56fc008e399ccca49127/)

- **Familie:** GuLoader
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Malicious (score: 99)
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Downloader/VBS.GuLoader.SC317238` |
| Avira | `DR/SNH` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `PowerShell/CloudEye.PJ trojan` |
| F-Secure | `Dropper.DR/SNH` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Vbs.Trojan.Sagent.Unkl` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

### [8dea760101ac9d14ec08…](https://bazaar.abuse.ch/sample/8dea760101ac9d14ec08c7ff2c3a7d2d75017c8229b4902060663137ad2cc4b3/)

- **Familie:** RemcosRAT
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.Script.RemcosRAT.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Generik.HGFMMHS trojan` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Kingsoft | `Win32.Infected.AutoInfector.a` |
| Lionic | `Trojan.Script.RemcosRAT.4!c` |
| Symantec | `Scr.Malcode!gen` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 56 von 75 Engines (74.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:MSIL/Nanocore!atmn`

**Erkennende Engines (56/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
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
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **js** (48×)
- **AgentTesla** (14×)
- **Formbook** (12×)
- **vbs** (12×)
- **exe** (11×)
- **RemcosRAT** (11×)
- **jar** (10×)
- **java** (10×)
- **python** (10×)
- **silentnet** (10×)
- **elf** (9×)
- **GuLoader** (9×)
- **RAT** (6×)
- **XWorm** (6×)
- **Mirai** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +15 (17→32)
- ↑ **AgentTesla** +12 (2→14)
- ↑ **Formbook** +10 (2→12)
- ↑ **RemcosRAT** +8 (3→11)
- neu: **GuLoader** (9)
- neu: **XWorm** (6)
- ↓ **Mirai** -30 (34→4)
- neu: **DonutLoader** (4)
- neu: **AsyncRAT** (1)
- weg: **LegionLoader** (war 6)
- weg: **ValleyRAT** (war 2)
- weg: **SalatStealer** (war 5)
- weg: **VShell** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +5 (27→32)
- ↑ **AgentTesla** +13 (1→14)
- ↑ **Formbook** +10 (2→12)
- ↑ **RemcosRAT** +10 (1→11)
- neu: **GuLoader** (9)
- ↑ **XWorm** +5 (1→6)
- ↓ **Mirai** -22 (26→4)
- neu: **DonutLoader** (4)
- neu: **AsyncRAT** (1)
- weg: **SalatStealer** (war 13)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.604 MB |
| σ Dateigröße | 5.002 MB |
| Ø Risiko-Score | 58.3/100 |
| Ø Klassifikations-Konfidenz | 62.4% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 37/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 17 (16.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:38 | [65251bafe5e9…](https://bazaar.abuse.ch/sample/65251bafe5e917529571edfca1289fdf2d5bb8b18919c0f104054f42fa4a1cd5/) | `sh` | unbekannt | 32.4 | – | – | 🇩🇪DE |
| 18:47 | [7108d2c7b985…](https://bazaar.abuse.ch/sample/7108d2c7b985267bec554335b4a91b8f756b4d1eca463d04051b4d65b065d587/) | `js` | AsyncRAT | 88.7 | – | – | 🌐HU |
| 18:46 | [a5b2eb64feca…](https://bazaar.abuse.ch/sample/a5b2eb64fecaf7b4ce2b0d725af3c520831948ace1be8ed4f328c5659197aaca/) | `elf` | unbekannt | 42.2 | – | – | 🇺🇸US |
| 18:43 | [5b9e3dd41796…](https://bazaar.abuse.ch/sample/5b9e3dd417961cc21ebd0d146796a64622a840cfd035e5ee0a68535d6b463a43/) | `exe` | unbekannt | 37.9 | – | – | 🌐HU |
| 18:25 | [2aecb30052c6…](https://bazaar.abuse.ch/sample/2aecb30052c62ea30cccec32977be52d2c8ff84f08850c22b0fa43dc285168ad/) | `zip` | unbekannt | 31.3 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 02.11.2026 20:03 UTC*