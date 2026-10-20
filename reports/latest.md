# MalwareBazaar – 20.10.2026 16:33 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **51** |
| Höchster Score | **90.6/100** – 3bfd884a8d270ae7… |
| Häufigste Familie | **unbekannt** (44x) |
| Häufigster Typ | **exe** (28x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 32 Samples |
| Ø Dateigröße | 2.80 MB (σ=7.59) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 28 | 27.7%  █████ |
| `js` | 22 | 21.8%  ████ |
| `elf` | 21 | 20.8%  ████ |
| `jar` | 12 | 11.9%  ██ |
| `ps1` | 6 | 5.9%  █ |
| `doc` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `macho` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 44 | 43.6% |
| 2 | Mirai | 17 | 16.8% |
| 3 | SilentNet | 6 | 5.9% |
| 4 | Formbook | 5 | 5.0% |
| 5 | QuasarRAT | 4 | 4.0% |
| 6 | WARDENStealer | 3 | 3.0% |
| 7 | XWorm | 2 | 2.0% |
| 8 | RemcosRAT | 2 | 2.0% |
| 9 | AgentTesla | 2 | 2.0% |
| 10 | AMOS | 1 | 1.0% |
| 11 | SheetRAT | 1 | 1.0% |
| 12 | CoinMiner | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Skript/Dropper | 18 | 17.8% | 35% |
| Infostealer | 17 | 16.8% | 82% |
| Botnet/IoT | 17 | 16.8% | 95% |
| RAT | 14 | 13.9% | 91% |
| Loader | 11 | 10.9% | 77% |
| Andere / Unbekannt | 9 | 8.9% | 20% |
| Windows-Malware | 8 | 7.9% | 35% |
| Linux-Malware | 4 | 4.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |
| Spyware | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 51 | 50.5% |
| 🟠 HOCH | 11 | 10.9% |
| 🟡 MITTEL | 30 | 29.7% |
| 🟢 NIEDRIG | 9 | 8.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3bfd884a8d270a…](https://bazaar.abuse.ch/sample/3bfd884a8d270ae7f42f4b149bbd57c9cc83868b2f7208a8f1d196527a8bd633/) | AMOS | Infostealer | **90.6** | 🔴 KRITISCH | – | – | ? |
| [7ca1dfc3154381…](https://bazaar.abuse.ch/sample/7ca1dfc3154381c742649930ef86f7d4413150c9d1309f3da6526f842d3e4097/) | XWorm | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [7651bc0f2f611d…](https://bazaar.abuse.ch/sample/7651bc0f2f611d56598da55e8ea79b096fbbeb64693214a93633d448e20a8c6a/) | Formbook | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [58892dcb08a379…](https://bazaar.abuse.ch/sample/58892dcb08a37950e5e7d9ee713d0c720a58c7b974ba0095698198e51d68fecb/) | Formbook | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [f551753a0a2d93…](https://bazaar.abuse.ch/sample/f551753a0a2d93941263ac8bfdddbbcaf7fd7c7c8dee70ac1b2eb3ed790efb54/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [6ef0475a294722…](https://bazaar.abuse.ch/sample/6ef0475a2947228b255910ecb1afbfb67d84422890530465af83dd8962b511ea/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [a2dabcf2835b6d…](https://bazaar.abuse.ch/sample/a2dabcf2835b6d9f7e2d10ece1a23fbab47c531b3b979972dc8ae7e6989f88bd/) | Formbook | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [b85cf17f8ee8e1…](https://bazaar.abuse.ch/sample/b85cf17f8ee8e1830ed682080e7b5f7babdee3ecf6951358533c7359cb6b89fa/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [7f97451f3eb454…](https://bazaar.abuse.ch/sample/7f97451f3eb454915ff6a6f897910565bf30e0aefbf4408f997c87854ef9a492/) | QuasarRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [d3e8b58038d6f2…](https://bazaar.abuse.ch/sample/d3e8b58038d6f274b4a2544871c6a96176b8bd63d2506d0c8d2bc7a8a9eba3d3/) | RemcosRAT | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6082/7514 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6082/7514 |
| 3 | ESET-NOD32 | 77.3% | 5812/7514 |
| 4 | Kaspersky | 76.3% | 5729/7513 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5368/7511 |
| 8 | Rising | 68.7% | 5162/7514 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4977/7510 |
| 11 | Tencent | 65.2% | 4751/7288 |
| 12 | Avast | 65.2% | 4897/7510 |
| 13 | AVG | 65.2% | 4897/7509 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4601/7507 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 40 | 39.6% |
| ❓ Unbekannt | 29 | 28.7% |
| 🐧 Linux | 27 | 26.7% |
| 📄 Dokument | 4 | 4.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 61 | 60.4% |
| Drive-By / Exploit-Kit | 23 | 22.8% |
| C2 / Nachladen | 5 | 5.0% |
| MaaS-Loader | 5 | 5.0% |
| Phishing / E-Mail-Anhang | 4 | 4.0% |
| USB / Wechselmedium | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 52 | 51.5% |
| 2 | 🇩🇪 DE | 24 | 23.8% |
| 3 | 🌐 DK | 15 | 14.9% |
| 4 | 🇭🇺 HU | 6 | 5.9% |
| 5 | 🇳🇱 NL | 2 | 2.0% |
| 6 | 🌐 PT | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 32 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 17 |
| Lateral Movement | 17 |
| Command and Control | 9 |
| Collection | 8 |
| Credential Access | 5 |
| Exfiltration | 4 |
| Execution | 3 |
| Defense Evasion | 1 |

<details><summary>7ca1dfc3154381c74264… – XWorm | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>7651bc0f2f611d56598d… – Formbook | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>58892dcb08a37950e5e7… – Formbook | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>f551753a0a2d93941263… – Formbook | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f12691ae6a495ee68676…](https://bazaar.abuse.ch/sample/f12691ae6a495ee68676ff2337b0e39e55cbc1d55191e5729bb4f7fcdaa6ba60/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| GData | `Linux.Trojan.Mirai.B` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| Tencent | `Linux.Backdoor.Gafgyt.Jcnw` |
| huorong | `Trojan/Linux.CoinMiner.bk` |

### [ee8311e5c3d5c0f3ec57…](https://bazaar.abuse.ch/sample/ee8311e5c3d5c0f3ec57221171c2f7c839390dd31abfb10908f893179016f140/)

- **Familie:** WannaCry
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0147`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0147` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Antiy-AVL | `Trojan[Exploit]/Win64.CVE-2017-0147` |
| Arcabit | `Exploit.CVE-2017-0147` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `EXP/W32.CVE-2017-01.B` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0147` |
| Bkav | `W32.Malware.147B7ACC` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.generic` |
| ClamAV | `Win.Ransomware.Wanna-9769986-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win64/Exploit.CVE-2017-0147.A trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Exploit.CVE-2017-0147 (B)` |
| F-Secure | `Exploit.EXP/W32.CVE-2017-01.B` |
| Fortinet | `W64/Wanna.AK!tr` |
| GData | `Exploit.CVE-2017-0147` |
| Gridinsoft | `Trojan.Win64.Downloader.oa!s1` |
| Ikarus | `Exploit.CVE-2017-0147` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan.Win32.Eb.s` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!EE8311E5C3D5` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Panda | `Trj/GdSda.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Ransom-WannaCry!51106850866D` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5298176` |
| Tencent | `Trojan.Win64.Wanna.a` |
| TrellixENS | `Ransom-WannaCry!51106850866D` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-e4f863f0!Eldorado` |
| VirIT | `Trojan.Win32.Genus.LWU` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `Exploit/EquationDrug.a` |

### [de8e4550241c82dd8add…](https://bazaar.abuse.ch/sample/de8e4550241c82dd8addc993db679e5eb9ec3080dfc74eaeaf0fbba20aefd73e/)

- **Familie:** njrat
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Alibaba | `Trojan:MSIL/Kryptik.70edd753` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.D081D430` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PackedNET.3674` |
| ESET-NOD32 | `MSIL/Kryptik.ARDP trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `MSIL/AgentTesla.ALLB!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Crypt` |
| Kaspersky | `UDS:Backdoor.MSIL.XWorm.gen` |
| Kingsoft | `malware.kb.c.998` |
| Malwarebytes | `Trojan.MalPack.GS` |
| McAfeeD | `Real Protect-LS!F04D95F3A8BB` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Malware.Obfus/MSIL@AI.98 (RDM.MSIL2:M1NN+C08wwqSsYgIHm7yJw)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Msil.Trojan.Kryptik.Jmnw` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| Varist | `W32/MSIL_Agent.JZL.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Webroot | `Win.Trojan.Gen` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **exe** (33×)
- **js** (22×)
- **elf** (21×)
- **Mirai** (17×)
- **jar** (12×)
- **java** (11×)
- **python** (6×)
- **silentnet** (6×)
- **ps1** (6×)
- **dropped-by-GCleaner** (5×)
- **github** (5×)
- **stealer** (5×)
- **Formbook** (5×)
- **F** (4×)
- **loader** (4×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -14 (58→44)
- ↓ **Mirai** -8 (25→17)
- neu: **SilentNet** (6)
- ↑ **Formbook** +4 (1→5)
- neu: **QuasarRAT** (4)
- neu: **WARDENStealer** (3)
- neu: **XWorm** (2)
- neu: **RemcosRAT** (2)
- ↑ **AgentTesla** +1 (1→2)
- weg: **Prometei** (war 2)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +14 (30→44)
- ↓ **Mirai** -6 (23→17)
- neu: **SilentNet** (6)
- ↑ **Formbook** +4 (1→5)
- neu: **QuasarRAT** (4)
- neu: **WARDENStealer** (3)
- neu: **XWorm** (2)
- ↑ **AgentTesla** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.796 MB |
| σ Dateigröße | 7.589 MB |
| Ø Risiko-Score | 64.5/100 |
| Ø Klassifikations-Konfidenz | 65.6% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 32/101 |
| Eindeutige Familien | 25 |
| Eindeutige Tags | 73 |
| Unbekannte Familien | 9 (8.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:23 | [52e1f2b256e2…](https://bazaar.abuse.ch/sample/52e1f2b256e2b9d6547883f885c67fdc55f62dda866b5fc245d4c700352f20de/) | `exe` | unbekannt | 81.1 | – | – | 🌐DK |
| 16:21 | [3bfd884a8d27…](https://bazaar.abuse.ch/sample/3bfd884a8d270ae7f42f4b149bbd57c9cc83868b2f7208a8f1d196527a8bd633/) | `macho` | AMOS | 90.6 | – | – | 🇺🇸US |
| 16:21 | [6d8696a2fd1b…](https://bazaar.abuse.ch/sample/6d8696a2fd1b6df9e3d3203bc2b2a76e5dce67ecf9ddac7baac7253b21ed2650/) | `exe` | SheetRAT | 81.1 | – | – | 🌐DK |
| 16:19 | [7ca1dfc31543…](https://bazaar.abuse.ch/sample/7ca1dfc3154381c742649930ef86f7d4413150c9d1309f3da6526f842d3e4097/) | `exe` | XWorm | 89.6 | – | – | 🌐DK |
| 16:19 | [a378366ea97f…](https://bazaar.abuse.ch/sample/a378366ea97ffeb7c8af2cc9178cff99700fb7de13282e7f7029356f75357192/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.10.2026 16:33 UTC*