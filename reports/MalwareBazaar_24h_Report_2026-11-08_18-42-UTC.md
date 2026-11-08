# MalwareBazaar – 08.11.2026 18:42 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **72** |
| Höchster Score | **92.8/100** – 6b0bc2459e5f9051… |
| Häufigste Familie | **Mirai** (38x) |
| Häufigster Typ | **elf** (46x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 48 Samples |
| Ø Dateigröße | 1.98 MB (σ=4.11) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 46 | 45.5%  █████████ |
| `exe` | 27 | 26.7%  █████ |
| `js` | 11 | 10.9%  ██ |
| `jar` | 4 | 4.0%   |
| `sh` | 4 | 4.0%   |
| `vbs` | 4 | 4.0%   |
| `ps1` | 2 | 2.0%   |
| `zip` | 1 | 1.0%   |
| `vbe` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 38 | 37.6% |
| 2 | unbekannt | 23 | 22.8% |
| 3 | WARDENStealer | 10 | 9.9% |
| 4 | AsyncRAT | 4 | 4.0% |
| 5 | AgentTesla | 4 | 4.0% |
| 6 | PureLogsStealer | 4 | 4.0% |
| 7 | Formbook | 3 | 3.0% |
| 8 | AokigaharaStealer | 3 | 3.0% |
| 9 | SilentNet | 2 | 2.0% |
| 10 | FormBook | 2 | 2.0% |
| 11 | XWorm | 2 | 2.0% |
| 12 | Gh0stRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 38 | 37.6% | 95% |
| Infostealer | 26 | 25.7% | 80% |
| RAT | 9 | 8.9% | 91% |
| Linux-Malware | 9 | 8.9% | 45% |
| Skript/Dropper | 8 | 7.9% | 35% |
| Andere / Unbekannt | 6 | 5.9% | 20% |
| Windows-Malware | 3 | 3.0% | 35% |
| Backdoor | 1 | 1.0% | 95% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 72 | 71.3% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 6 | 5.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [6b0bc2459e5f90…](https://bazaar.abuse.ch/sample/6b0bc2459e5f9051b63992e7bb71ffdf6fe40d6767b12e44f3d40a9a69c03703/) | Gh0stRAT | Backdoor | **92.8** | 🔴 KRITISCH | – | – | ? |
| [4361385eafbff1…](https://bazaar.abuse.ch/sample/4361385eafbff183c6cefc71e9c85387a4814a154c006d9631b6c803d7c88f08/) | FormBook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [5c658994584740…](https://bazaar.abuse.ch/sample/5c65899458474072b7893b6fd838153d4f017d6998eb1900531374a5430c1184/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [b40053466bafcd…](https://bazaar.abuse.ch/sample/b40053466bafcd0c0fa9c57bd802e8aa3c28fa95456c89ac866ec540392a5e70/) | FormBook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [59dbf89c137441…](https://bazaar.abuse.ch/sample/59dbf89c137441569e22add76ff1208a846c6b5cd1e695d2960bace52df7765e/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [8ab425690e1105…](https://bazaar.abuse.ch/sample/8ab425690e11052b79ffb5890066483ffb83329a69dceba884db5dbe1ff2d152/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [d458e481a291f6…](https://bazaar.abuse.ch/sample/d458e481a291f6ee8ffeb9eaa6ec2a7442924b1ca5ac6c46a97b0e1a8a0bc0f2/) | Vidar | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [146dab69cf2664…](https://bazaar.abuse.ch/sample/146dab69cf266478814bb9f2844538c3e285b923727b193817e8624bcad33be3/) | AsyncRAT | RAT | **88.0** | 🔴 KRITISCH | – | – | ? |
| [1d7095ccc9853d…](https://bazaar.abuse.ch/sample/1d7095ccc9853d3e04c1b0042d56fcc2e0e68ae2108314e20b6434fa86e6beb0/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [2d5034a1153589…](https://bazaar.abuse.ch/sample/2d5034a1153589921cbefc2534871c0cca264d710eec20db6aae02ba7b5e1638/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6397/7891 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6397/7891 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6096/7891 |
| 6 | Kaspersky | 75.5% | 5954/7890 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5615/7887 |
| 9 | Rising | 68.3% | 5393/7891 |
| 10 | Varist | 66.1% | 5215/7886 |
| 11 | Avast | 65.2% | 5139/7887 |
| 12 | AVG | 65.2% | 5139/7886 |
| 13 | Tencent | 64.9% | 4978/7665 |
| 14 | McAfeeD | 61.4% | 4840/7883 |
| 15 | huorong | 60.9% | 4803/7883 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 50 | 49.5% |
| 🪟 Windows | 34 | 33.7% |
| ❓ Unbekannt | 16 | 15.8% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 88 | 87.1% |
| Drive-By / Exploit-Kit | 11 | 10.9% |
| MaaS-Loader | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 22 | 21.8% |
| 2 | 🇦🇹 AT | 19 | 18.8% |
| 3 | 🇫🇷 FR | 16 | 15.8% |
| 4 | 🇩🇪 DE | 14 | 13.9% |
| 5 | 🇮🇳 IN | 13 | 12.9% |
| 6 | 🇺🇸 US | 10 | 9.9% |
| 7 | 🇧🇷 BR | 4 | 4.0% |
| 8 | 🌐 CO | 1 | 1.0% |
| 9 | 🇳🇱 NL | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 48 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 38 |
| Lateral Movement | 38 |
| Credential Access | 6 |
| Collection | 6 |
| Command and Control | 4 |
| Execution | 4 |
| Exfiltration | 1 |

<details><summary>4361385eafbff183c6ce… – FormBook | 🔴 KRITISCH 88.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>5c65899458474072b789… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>b40053466bafcd0c0fa9… – FormBook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>59dbf89c137441569e22… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [396dec948380f5ad806d…](https://bazaar.abuse.ch/sample/396dec948380f5ad806da0e06dbfbb1fc556df65002ad6616937cb87d0e7576f/)

- **Familie:** Midie
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Midie.189383
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Midie.189383`

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Midie.189383` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5946861` |
| Arcabit | `Trojan.Midie.D2E3C7` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| BitDefender 🛡️ | `Gen:Variant.Midie.189383` |
| Bkav | `W32.Malware.CA9B958A` |
| CTX | `exe.unknown.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Agent.CFJ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Midie.189383 (B)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.81B7!tr` |
| GData | `Gen:Variant.Midie.189383` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.MopsStealer` |
| Kaspersky | `HEUR:HackTool.Win64.Knotweed.gen` |
| Malwarebytes | `Trojan.FakeMS` |
| MaxSecure | `Trojan.W64.300926.Midie.YR` |
| McAfeeD | `ti!396DEC948380` |
| MicroWorld-eScan | `Gen:Variant.Midie.189383` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Agent!8.B1E (TFE:1:hQrGGr5K77F)` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Kryptik.16007680` |
| VIPRE | `Gen:Variant.Midie.189383` |
| Varist | `W64/Agent.NKS.gen!Eldorado` |
| Webroot | `W32.Suspicious.Gen` |
| huorong | `Trojan/W64.Loader.bq` |

### [e7025b9bb138cc9508da…](https://bazaar.abuse.ch/sample/e7025b9bb138cc9508da80b5cbeb70dcadd1642286b849ca28e49be3e7b5aa19/)

- **Familie:** Mirai
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** BV:Downloader-AEH [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `BV:Downloader-AEH [Drp]` |
| Avast | `BV:Downloader-AEH [Drp]` |
| DrWeb | `Linux.DownLoader.2532` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.EPI trojan` |
| Fortinet | `BASH/Dloader.SH!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Sh` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Varist | `URL/Agent.PI!Eldorado` |
| huorong | `Trojan/BAT.Obfuscated.aar!crit` |

### [47bb90ea40b1be56918d…](https://bazaar.abuse.ch/sample/47bb90ea40b1be56918d2531bee35237fe0f37a3fc1f996428353bcd5f012200/)

- **Familie:** PureLogsStealer
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81924442
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81924442`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81924442` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Drp]` |
| AhnLab-V3 | `Malware/Win.Kryptik.C5963235` |
| Alibaba | `Trojan:MSIL/Kryptik.30db0b98` |
| Antiy-AVL | `Trojan/MSIL.Kryptik` |
| Arcabit | `Trojan.Generic.D4E2115A` |
| Avast | `Win32:MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.81924442` |
| Bkav | `W32.Malware.DF842061` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PackedNET.3680` |
| ESET-NOD32 | `MSIL/Kryptik.AREF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81924442 (B)` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| Fortinet | `MSIL/Formbook.AQYE!tr` |
| GData | `Trojan.GenericKD.81924442` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Inject` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-PSW.MSIL.Agensla.gen` |
| Kingsoft | `malware.kb.c.908` |
| Lionic | `Trojan.Win32.Agensla.i!c` |
| Malwarebytes | `Malware.AI.1969057105` |
| McAfeeD | `Real Protect-LS!39C9D7598CE5` |
| MicroWorld-eScan | `Trojan.GenericKD.81924442` |
| Microsoft 🛡️ | `Trojan:MSIL/TelegramRAT.SEE!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Malware.Obfus/MSIL@AI.90 (RDM.MSIL2:htSkbIEs/jdJgh/Pdrj8Qw)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Trojan.Msil.Kryptik.16007790` |
| Trapmine | `malicious.moderate.ml.score` |
| VIPRE | `Trojan.GenericKD.81924442` |
| Varist | `W32/MSIL_Kryptik.NGB.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan[stealer]:MSIL/TelegramRAT.SAM2XJC` |

### [fb92cadf5e4e30648a16…](https://bazaar.abuse.ch/sample/fb92cadf5e4e30648a161066dd3bce5e2ae4957602b0d965ced8612934c4d06a/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Mirai-DAU [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DAU [Trj]` |
| Avast | `ELF:Mirai-DAU [Trj]` |
| Avira | `TR/LINUX.Mirai.DAU` |
| Cynet | `Malicious (score: 99)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DAU` |
| Microsoft 🛡️ | `Trojan:Win32/Egairtigado!rfn` |
| Rising | `Backdoor.Mirai/Linux!1.13415 (CLASSIC)` |

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
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
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

- **Mirai** (38×)
- **exe** (25×)
- **elf** (14×)
- **js** (11×)
- **WARDENStealer** (10×)
- **Torii** (9×)
- **stealer** (8×)
- **Prometei** (6×)
- **Warden** (6×)
- **upx-dec** (5×)
- **jar** (4×)
- **SilentNet** (4×)
- **RAT** (4×)
- **upx** (4×)
- **AsyncRAT** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +6 (32→38)
- ↓ **unbekannt** -4 (27→23)
- ↑ **WARDENStealer** +7 (3→10)
- neu: **AsyncRAT** (4)
- neu: **AgentTesla** (4)
- neu: **PureLogsStealer** (4)
- neu: **Formbook** (3)
- neu: **AokigaharaStealer** (3)
- neu: **SilentNet** (2)
- neu: **FormBook** (2)
- weg: **VShell** (war 3)
- weg: **Snowlight** (war 5)
- weg: **EchoBot** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +17 (21→38)
- ↓ **unbekannt** -9 (32→23)
- ↑ **WARDENStealer** +8 (2→10)
- ↑ **AsyncRAT** +3 (1→4)
- ↑ **AgentTesla** +1 (3→4)
- ↑ **PureLogsStealer** +3 (1→4)
- neu: **AokigaharaStealer** (3)
- neu: **SilentNet** (2)
- neu: **FormBook** (2)
- weg: **SalatStealer** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **VShell** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.985 MB |
| σ Dateigröße | 4.105 MB |
| Ø Risiko-Score | 70.9/100 |
| Ø Klassifikations-Konfidenz | 75.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 48/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 51 |
| Unbekannte Familien | 6 (5.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:40 | [9373ac7748f6…](https://bazaar.abuse.ch/sample/9373ac7748f688281112e94ff42c53dc7fd26a9e928f9af66c3958cf6bac8f99/) | `jar` | unbekannt | 82.2 | – | – | 🇧🇷BR |
| 18:29 | [52c20e217161…](https://bazaar.abuse.ch/sample/52c20e21716164b997c3ca9afc1bf62f5b5c80c8451752146c7f7c72d8eb8043/) | `jar` | SilentNet | 82.0 | – | – | 🇧🇷BR |
| 18:25 | [e18a65b70769…](https://bazaar.abuse.ch/sample/e18a65b707695a7ddae89102f5439fcc539d89b5d5b3bda0eed4a352b1e02298/) | `exe` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 18:24 | [4ddf53b2899d…](https://bazaar.abuse.ch/sample/4ddf53b2899d92348ab30192c9e623b2015a158793fdee819df3e4c77a339d14/) | `exe` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 18:24 | [6b0bc2459e5f…](https://bazaar.abuse.ch/sample/6b0bc2459e5f9051b63992e7bb71ffdf6fe40d6767b12e44f3d40a9a69c03703/) | `exe` | Gh0stRAT | 92.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 08.11.2026 18:42 UTC*