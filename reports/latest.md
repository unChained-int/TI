# MalwareBazaar – 19.11.2026 02:59 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **37** |
| Höchster Score | **88.6/100** – 5975cc213128bdd9… |
| Häufigste Familie | **unbekannt** (43x) |
| Häufigster Typ | **elf** (45x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 31 Samples |
| Ø Dateigröße | 2.43 MB (σ=5.18) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 45 | 44.6%  ████████ |
| `exe` | 38 | 37.6%  ███████ |
| `macho` | 7 | 6.9%  █ |
| `msi` | 7 | 6.9%  █ |
| `dll` | 2 | 2.0%   |
| `apk` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 43 | 42.6% |
| 2 | Mirai | 25 | 24.8% |
| 3 | Snowlight | 9 | 8.9% |
| 4 | ConnectWise | 8 | 7.9% |
| 5 | WARDENStealer | 6 | 5.9% |
| 6 | njrat | 2 | 2.0% |
| 7 | AsyncRAT | 2 | 2.0% |
| 8 | Prometei | 2 | 2.0% |
| 9 | QuasarRAT | 1 | 1.0% |
| 10 | Linux.Generic.Threat | 1 | 1.0% |
| 11 | SalatStealer | 1 | 1.0% |
| 12 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 34 | 33.7% | 35% |
| Botnet/IoT | 25 | 24.8% | 95% |
| Linux-Malware | 20 | 19.8% | 45% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Infostealer | 7 | 6.9% | 75% |
| RAT | 6 | 5.9% | 95% |
| Trojaner | 1 | 1.0% | 65% |
| Android-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 37 | 36.6% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 55 | 54.5% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5975cc213128bd…](https://bazaar.abuse.ch/sample/5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20/) | njrat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [572db981cf481b…](https://bazaar.abuse.ch/sample/572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e/) | QuasarRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [817cccc82f116d…](https://bazaar.abuse.ch/sample/817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [6ca8cb4d1c3b7c…](https://bazaar.abuse.ch/sample/6ca8cb4d1c3b7c61178577e3176ee8b29c108fcf791449fd8eeaa53558c33795/) | AsyncRAT | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [95f9f3d573a0d5…](https://bazaar.abuse.ch/sample/95f9f3d573a0d5edce63ba5cfe063c12b1e98caec911d5eb4d60341dee1caa9a/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [fac87942c0f8a8…](https://bazaar.abuse.ch/sample/fac87942c0f8a830dfe005365f0dc8e739297f9cb22903f21254d1bf548fa695/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [09378ba936f7d2…](https://bazaar.abuse.ch/sample/09378ba936f7d245d9485d94175309ec0ed85661580abf2086aee148e4750ac3/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [f05ce44557afdd…](https://bazaar.abuse.ch/sample/f05ce44557afddf54574723e7ded135a1a740d4e145bb48c49297b43c46efee6/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [0d6cbcf0173626…](https://bazaar.abuse.ch/sample/0d6cbcf0173626d170c6b92f26d05489a5a76aa387c7cc03edd525e9d65cec8b/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [b5c600d265dfa2…](https://bazaar.abuse.ch/sample/b5c600d265dfa288e38b32ac113b9481d12c4cf4ae7cf025d12b730e17b3d207/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6533/8051 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6533/8051 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6229/8051 |
| 6 | Kaspersky | 75.5% | 6081/8050 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5736/8047 |
| 9 | Rising | 68.5% | 5516/8051 |
| 10 | Varist | 66.1% | 5317/8046 |
| 11 | Tencent | 65.2% | 5098/7825 |
| 12 | Avast | 65.2% | 5248/8047 |
| 13 | AVG | 65.2% | 5248/8046 |
| 14 | McAfeeD | 61.5% | 4948/8043 |
| 15 | huorong | 60.9% | 4900/8043 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 47 | 46.5% |
| 🐧 Linux | 46 | 45.5% |
| 🍎 macOS | 7 | 6.9% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 93 | 92.1% |
| Trojanisierte Software | 7 | 6.9% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 35 | 34.7% |
| 2 | 🇫🇷 FR | 35 | 34.7% |
| 3 | 🇩🇪 DE | 26 | 25.7% |
| 4 | 🇳🇱 NL | 3 | 3.0% |
| 5 | 🇯🇵 JP | 1 | 1.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 31 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Command and Control | 6 |
| Collection | 3 |
| Execution | 2 |
| Exfiltration | 1 |

<details><summary>5975cc213128bdd9ebb2… – njrat | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>572db981cf481bb08238… – QuasarRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>817cccc82f116d105019… – AsyncRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>6ca8cb4d1c3b7c611785… – AsyncRAT | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>95f9f3d573a0d5edce63… – Mirai | 🔴 KRITISCH 82.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [43409817d8f82d145797…](https://bazaar.abuse.ch/sample/43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa/)

- **Familie:** Linux.Generic.Threat
- **Erkannt von:** 17 von 74 Engines (23.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux.Generic.Threat
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avira | `DR/LINUX.Downloade.BR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Dropper.DR/LINUX.Downloade.BR` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Downloader.Agent/Linux!8.13C9D (TFE:14:7f7dlmYAy1C)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| Varist | `E32/Agent.DB.gen!Eldorado` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.7a308702` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [92c6da6f9bb94790d24e…](https://bazaar.abuse.ch/sample/92c6da6f9bb94790d24ef471baec6f050fb0304a741f94ef297306eaa3e850a8/)

- **Familie:** RemcosRAT
- **Erkannt von:** 54 von 74 Engines (73.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Generic.Remcos.6D55C784
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Remcos.6D55C784`

**Erkennende Engines (54/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Remcos.6D55C784` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R773767` |
| Alibaba | `Backdoor:Win32/Remcos.d3d2c391` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Generic.Remcos.6D55C784` |
| Avast | `Win64:MalwareX-gen [Rat]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Generic.Remcos.6D55C784` |
| Bkav | `W32.Malware.33A0B3CE` |
| CTX | `exe.unknown.remcos` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DrWeb | `BackDoor.Remcos.729` |
| ESET-NOD32 | `Win64/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Generic.Remcos.6D55C784 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/Remcos.B!tr` |
| GData | `Win32.Backdoor.Remcos.75YGCX` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win64.Remcos.oa!s1` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Backdoor ( 005d11a21 )` |
| K7GW | `Backdoor ( 005d11a21 )` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Kingsoft | `malware.kb.a.965` |
| Lionic | `Trojan.Win32.Remcos.m!c` |
| Malwarebytes | `Remcos.Backdoor.Bot.DDS` |
| MaxSecure | `Trojan.W64.200526.Remcos.YR` |
| McAfeeD | `Trojan:Win/Remcos.EEC` |
| MicroWorld-eScan | `Generic.Remcos.6D55C784` |
| Microsoft 🛡️ | `Backdoor:Win32/Remcos.GA!MTB` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Dropper.jh` |
| Sophos | `Troj/Remcos-AST` |
| Symantec | `Backdoor.Remcos!gen9` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `Artemis!7192B6C8D55D` |
| TrendMicro | `Backdoor.Win64.REMCOS.YXGKRZ` |
| TrendMicro-HouseCall | `Backdoor.Win64.REMCOS.YXGKRZ` |
| VIPRE | `Generic.Remcos.6D55C784` |
| Varist | `W64/Agent.MFA.gen!Eldorado` |
| ViRobot | `Backdoor.Win.Z.Remcos.660480.OY` |
| VirIT | `Trojan.Win64.GenusT.FXPQ` |
| Yandex | `Backdoor.Remcos!ZdiHE+H/5ec` |
| ZoneAlarm | `Troj/Remcos-AST` |
| huorong | `Backdoor/Remcos.k` |

### [125380592cd37699dd63…](https://bazaar.abuse.ch/sample/125380592cd37699dd638f147edba000aa99984a6644c8887b1d0e3845c31774/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!125380592CD3` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `DDoS:Linux/Mirai.CGY` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [ad89371c2c9f159d8312…](https://bazaar.abuse.ch/sample/ad89371c2c9f159d83120ae8d5e1e74cd63dbc3de62c4b58d30b5620e16f3b17/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `DDoS:Linux/Mirai.CGY` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **elf** (44×)
- **exe** (39×)
- **Mirai** (25×)
- **Torii** (24×)
- **Snowlight** (9×)
- **signed** (8×)
- **ConnectWise** (8×)
- **macho** (7×)
- **msi** (7×)
- **WARDENStealer** (6×)
- **rmm-abuse** (5×)
- **ScreenConnect** (5×)
- **AsyncRAT** (2×)
- **dll** (2×)
- **upx-dec** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +24 (19→43)
- ↓ **Mirai** -19 (44→25)
- neu: **Snowlight** (9)
- neu: **ConnectWise** (8)
- ↑ **njrat** +1 (1→2)
- ↓ **Prometei** -4 (6→2)
- neu: **QuasarRAT** (1)
- neu: **Linux.Generic.Threat** (1)
- weg: **CoinMiner** (war 2)
- weg: **AgentTesla** (war 4)
- weg: **Formbook** (war 2)
- weg: **MassLogger** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +20 (23→43)
- ↓ **Mirai** -14 (39→25)
- neu: **Snowlight** (9)
- ↑ **ConnectWise** +7 (1→8)
- ↑ **njrat** +1 (1→2)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **QuasarRAT** (1)
- neu: **Linux.Generic.Threat** (1)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.433 MB |
| σ Dateigröße | 5.179 MB |
| Ø Risiko-Score | 54.7/100 |
| Ø Klassifikations-Konfidenz | 57.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 31/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 24 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 02:15 | [1d8e5258366e…](https://bazaar.abuse.ch/sample/1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5/) | `exe` | unbekannt | 38.4 | – | – | 🇺🇸US |
| 02:14 | [ba38e7dd3354…](https://bazaar.abuse.ch/sample/ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1/) | `exe` | unbekannt | 38.4 | – | – | 🇫🇷FR |
| 01:41 | [e364a0a91254…](https://bazaar.abuse.ch/sample/e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a/) | `elf` | unbekannt | 42.2 | – | – | 🇺🇸US |
| 01:40 | [5975cc213128…](https://bazaar.abuse.ch/sample/5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20/) | `exe` | njrat | 88.6 | – | – | 🇳🇱NL |
| 01:29 | [fd7cdd39be31…](https://bazaar.abuse.ch/sample/fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a/) | `elf` | Snowlight | 42.0 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.11.2026 02:59 UTC*