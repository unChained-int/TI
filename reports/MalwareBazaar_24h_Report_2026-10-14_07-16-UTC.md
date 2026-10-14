# MalwareBazaar – 14.10.2026 07:16 UTC

Dieser Run hat **66 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **67** |
| Kritisch (≥75) | **45** |
| Höchster Score | **90.5/100** – 2f0e0a4629ff2495… |
| Häufigste Familie | **Mirai** (25x) |
| Häufigster Typ | **elf** (32x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 37 Samples |
| Ø Dateigröße | 3.93 MB (σ=16.52) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 32 | 47.8%  █████████ |
| `exe` | 14 | 20.9%  ████ |
| `js` | 5 | 7.5%  █ |
| `macho` | 3 | 4.5%   |
| `vbs` | 3 | 4.5%   |
| `zip` | 2 | 3.0%   |
| `sh` | 2 | 3.0%   |
| `ps1` | 2 | 3.0%   |
| `wsf` | 1 | 1.5%   |
| `z` | 1 | 1.5%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 25 | 37.3% |
| 2 | unbekannt | 20 | 29.9% |
| 3 | RemcosRAT | 5 | 7.5% |
| 4 | Formbook | 3 | 4.5% |
| 5 | Vidar | 3 | 4.5% |
| 6 | AMOS | 2 | 3.0% |
| 7 | XWorm | 1 | 1.5% |
| 8 | NanoCore | 1 | 1.5% |
| 9 | Guloader!gen3 | 1 | 1.5% |
| 10 | Trojan.Generic.40652902 | 1 | 1.5% |
| 11 | Malware | 1 | 1.5% |
| 12 | DCRat | 1 | 1.5% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 37.3% | 95% |
| Infostealer | 10 | 14.9% | 91% |
| RAT | 8 | 11.9% | 95% |
| Linux-Malware | 7 | 10.4% | 45% |
| Andere / Unbekannt | 5 | 7.5% | 20% |
| Skript/Dropper | 4 | 6.0% | 35% |
| Loader | 4 | 6.0% | 72% |
| Trojaner | 2 | 3.0% | 65% |
| Windows-Malware | 2 | 3.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 67.2% |
| 🟠 HOCH | 4 | 6.0% |
| 🟡 MITTEL | 10 | 14.9% |
| 🟢 NIEDRIG | 8 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2f0e0a4629ff24…](https://bazaar.abuse.ch/sample/2f0e0a4629ff249569ba2cc3dbcf4b8c7eb33be7951bbbcd17d180bbd0b597a5/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [70d629ad657162…](https://bazaar.abuse.ch/sample/70d629ad65716277ecdb508170d397cbed77e40a4845c23ec6589808cd2b4811/) | Vidar | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [62cf3226cf293b…](https://bazaar.abuse.ch/sample/62cf3226cf293b464eb9d01ea63b62a6b3a3635f17fc30cea77c78f36b1def87/) | Vidar | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [ddca535b796c39…](https://bazaar.abuse.ch/sample/ddca535b796c39e34167592ae1e92954c24c10810810cf898c9c090940cd7b06/) | XWorm | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [747368ec46304a…](https://bazaar.abuse.ch/sample/747368ec46304ae98c8fbea3b3ccaa022edd58a9fb108f9b04c5e21968b8e8fb/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [5dd792a3409571…](https://bazaar.abuse.ch/sample/5dd792a340957190674b37ef22d48bf2ccc81748e4840a1218fd834a68899446/) | NanoCore | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [2893ece9d6aadc…](https://bazaar.abuse.ch/sample/2893ece9d6aadcc501dcd72c71abc49dea77f7a6ae384e749133de16ede8c0ea/) | RemcosRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [2dc1de602d1af8…](https://bazaar.abuse.ch/sample/2dc1de602d1af859042d787ac993d9db89e294d2c7461c5a5af178b7322085ff/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [7a2feccbbd016b…](https://bazaar.abuse.ch/sample/7a2feccbbd016be9a383025f686c8fc44bcdbb7a175b9591cf743bca7bafd82f/) | Vidar | Infostealer | **87.6** | 🔴 KRITISCH | – | – | ? |
| [210f503fcd5cc4…](https://bazaar.abuse.ch/sample/210f503fcd5cc49a20fee4f24e818e4849647b70f95d5509df883a2a24c656ad/) | RemcosRAT | RAT | **86.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5953/7361 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5953/7361 |
| 3 | ESET-NOD32 | 77.4% | 5698/7361 |
| 4 | Kaspersky | 76.3% | 5619/7360 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5267/7358 |
| 8 | Rising | 68.7% | 5058/7361 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4888/7357 |
| 11 | Tencent | 65.3% | 4657/7135 |
| 12 | Avast | 65.0% | 4783/7357 |
| 13 | AVG | 65.0% | 4783/7356 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4510/7354 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 35 | 52.2% |
| 🪟 Windows | 19 | 28.4% |
| ❓ Unbekannt | 8 | 11.9% |
| 🍎 macOS | 3 | 4.5% |
| 📦 Archiv | 2 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 58 | 86.6% |
| Drive-By / Exploit-Kit | 5 | 7.5% |
| C2 / Nachladen | 3 | 4.5% |
| USB / Wechselmedium | 1 | 1.5% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 38 | 56.7% |
| 2 | 🇺🇸 US | 9 | 13.4% |
| 3 | 🇨🇭 CH | 7 | 10.4% |
| 4 | 🇳🇱 NL | 3 | 4.5% |
| 5 | 🇭🇺 HU | 2 | 3.0% |
| 6 | 🌐 PE | 2 | 3.0% |
| 7 | 🌐 DK | 1 | 1.5% |
| 8 | 🇷🇴 RO | 1 | 1.5% |
| 9 | 🇯🇵 JP | 1 | 1.5% |
| 10 | 🇧🇷 BR | 1 | 1.5% |
| 11 | 🇫🇷 FR | 1 | 1.5% |
| 12 | 🌐 Unbekannt | 1 | 1.5% |

## MITRE ATT&CK

> 37 von 67 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 11 |
| Credential Access | 6 |
| Command and Control | 5 |
| Exfiltration | 3 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>2f0e0a4629ff249569ba… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>70d629ad65716277ecdb… – Vidar | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>62cf3226cf293b464eb9… – Vidar | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>747368ec46304ae98c8f… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [14658b46ae5b769b56c8…](https://bazaar.abuse.ch/sample/14658b46ae5b769b56c884305deda0bd18d053b46a00820de7e7c66a67732810/)

- **Familie:** Guloader!gen3
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Scr.Guloader!gen3
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `UDS:Trojan.VBS.SAgent.gen` |
| Microsoft 🛡️ | `Trojan:VBS/Sonbokli.A!cl` |
| Symantec | `Scr.Guloader!gen3` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

### [19e34346b27132cbb085…](https://bazaar.abuse.ch/sample/19e34346b27132cbb085359b34e3978117810af8332d7058f421cb49845b087e/)

- **Familie:** Trojan.Generic.40652902
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40652902
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40652902`

**Erkennende Engines (44/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Dropper/Win.MalwareX-gen.R800420` |
| Antiy-AVL | `Trojan/Win32.Tasker` |
| Arcabit | `Trojan.Generic.D26C5066` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Trojan.Generic.40652902` |
| Bkav | `W32.Malware.3198733E` |
| CTX | `exe.trojan.malwarex` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen35.58580` |
| ESET-NOD32 | `Win64/Agent.BKU trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.40652902 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| Fortinet | `W64/Agent.BKU!tr` |
| GData | `Win64.Trojan.Agent.OV97NI` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.sa` |
| K7AntiVirus | `Backdoor ( 005cde331 )` |
| K7GW | `Backdoor ( 005cde331 )` |
| Kaspersky | `Trojan.Win32.Tasker.bmzr` |
| Kingsoft | `malware.kb.a.773` |
| Lionic | `Trojan.Win32.Convagent.m!c` |
| Malwarebytes | `Trojan.MalPack` |
| McAfeeD | `Trojan:Win/Tasker.NE` |
| MicroWorld-eScan | `Trojan.Generic.40652902` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Backdoor.Convagent!8.123DC (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.14b675e4` |
| TrendMicro-HouseCall | `Trojan.Win64.Gen.TL0101JD26ZW` |
| Varist | `W64/ABTrojan.GTXF-6442` |
| VirIT | `Trojan.Win64.Gen_Heur.B` |
| Webroot | `Win.Trojan.Gen` |
| huorong | `TrojanDownloader/Agent.bra` |

### [8b4b63965299fc26e002…](https://bazaar.abuse.ch/sample/8b4b63965299fc26e00270e34e3e0a51eec149cdd042268b9a1f6afc1563272c/)

- **Familie:** Malware
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.B1C94204
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.B1C94204` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |

### [b5ada6b6e0a59cb4ec5a…](https://bazaar.abuse.ch/sample/b5ada6b6e0a59cb4ec5abe4dae7ddfb369f9a4c5e6b247062ca7cf33c4237553/)

- **Familie:** BOG trojan
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BOG trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Linux.Agent` |
| ESET-NOD32 | `Linux/Agent.BOG trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Flooder` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (63/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| Zillya | `Trojan.Rescoms.Win32.2903` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (32×)
- **Mirai** (25×)
- **exe** (12×)
- **js** (5×)
- **ClickFix** (4×)
- **Foxveil** (4×)
- **macOS** (4×)
- **RemcosRAT** (4×)
- **AMOS** (3×)
- **Mach-O** (3×)
- **macho** (3×)
- **RAT** (3×)
- **vbs** (3×)
- **Vidar** (3×)
- **ByteToBreach** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -6 (31→25)
- ↓ **unbekannt** -13 (33→20)
- ↑ **RemcosRAT** +4 (1→5)
- ↑ **Formbook** +1 (2→3)
- neu: **Vidar** (3)
- neu: **XWorm** (1)
- neu: **NanoCore** (1)
- neu: **Guloader!gen3** (1)
- neu: **Trojan.Generic.40652902** (1)
- weg: **CoinMiner** (war 2)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -15 (40→25)
- ↓ **unbekannt** -8 (28→20)
- ↑ **RemcosRAT** +3 (2→5)
- ↑ **Formbook** +1 (2→3)
- ↑ **Vidar** +2 (1→3)
- ↑ **AMOS** +1 (1→2)
- neu: **NanoCore** (1)
- neu: **Guloader!gen3** (1)
- neu: **Trojan.Generic.40652902** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.929 MB |
| σ Dateigröße | 16.525 MB |
| Ø Risiko-Score | 69.5/100 |
| Ø Klassifikations-Konfidenz | 76.0% |
| Samples mit VT | 5/67 |
| Samples mit MITRE | 37/67 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 42 |
| Unbekannte Familien | 5 (7.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 07:05 | [47f72114ab0c…](https://bazaar.abuse.ch/sample/47f72114ab0c5ed3ef41b0abbb6c175d0b64e59abdb2536f42e4c147272da223/) | `elf` | Mirai | 84.4 | – | – | 🌐HU |
| 07:03 | [e266ed2a1b7a…](https://bazaar.abuse.ch/sample/e266ed2a1b7ad7d9ee44bf16167ab80adb8c993503c85d8e3b52c3fa706d091d/) | `elf` | Mirai | 84.4 | – | – | 🌐HU |
| 06:57 | [2f0e0a4629ff…](https://bazaar.abuse.ch/sample/2f0e0a4629ff249569ba2cc3dbcf4b8c7eb33be7951bbbcd17d180bbd0b597a5/) | `exe` | Formbook | 90.5 | – | – | 🇩🇪DE |
| 06:53 | [ddca535b796c…](https://bazaar.abuse.ch/sample/ddca535b796c39e34167592ae1e92954c24c10810810cf898c9c090940cd7b06/) | `exe` | XWorm | 89.4 | – | – | 🌐CH |
| 06:31 | [263a188fc5e6…](https://bazaar.abuse.ch/sample/263a188fc5e675a5530b57c4f48a47c745240f17238cecdf657bc724bfba9832/) | `elf` | unbekannt | 42.7 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.10.2026 07:16 UTC*