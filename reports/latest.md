# MalwareBazaar – 14.10.2026 18:23 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **55** |
| Höchster Score | **96.9/100** – ddf17dbf5744c80c… |
| Häufigste Familie | **unbekannt** (36x) |
| Häufigster Typ | **exe** (80x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 38 Samples |
| Ø Dateigröße | 2.46 MB (σ=3.46) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 80 | 79.2%  ███████████████ |
| `elf` | 19 | 18.8%  ███ |
| `dll` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 36 | 35.6% |
| 2 | Mirai | 18 | 17.8% |
| 3 | Formbook | 8 | 7.9% |
| 4 | DCRat | 8 | 7.9% |
| 5 | AgentTesla | 7 | 6.9% |
| 6 | RemcosRAT | 5 | 5.0% |
| 7 | RemusStealer | 3 | 3.0% |
| 8 | SnakeKeylogger | 3 | 3.0% |
| 9 | njrat | 2 | 2.0% |
| 10 | QuasarRAT | 2 | 2.0% |
| 11 | PhantomStealer | 2 | 2.0% |
| 12 | AsyncRAT | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 44 | 43.6% | 75% |
| RAT | 20 | 19.8% | 95% |
| Botnet/IoT | 19 | 18.8% | 94% |
| Infostealer | 16 | 15.8% | 89% |
| Windows-Malware | 1 | 1.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 55 | 54.5% |
| 🟠 HOCH | 45 | 44.6% |
| 🟡 MITTEL | 1 | 1.0% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ddf17dbf5744c8…](https://bazaar.abuse.ch/sample/ddf17dbf5744c80c47251b34bb7dbb5c47fbcf200380fa1178b8a21a6c043ef6/) | WannaCry | Ransomware | **96.9** | 🔴 KRITISCH | – | – | ? |
| [4884f9e63b6d4a…](https://bazaar.abuse.ch/sample/4884f9e63b6d4a864a99e558e4f00ea612bfc9f7ff9aec65b1a29416b09d7ec6/) | Formbook | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [f85524b8c3d011…](https://bazaar.abuse.ch/sample/f85524b8c3d011caaee3a6bab77dbaf1c0e26b71244f0fc9c0a8e37176115eab/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [e13e1d805c67de…](https://bazaar.abuse.ch/sample/e13e1d805c67de591f734d825629743d31dcfc77cb67f89237474675208817de/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [dd86e3595d51a0…](https://bazaar.abuse.ch/sample/dd86e3595d51a03ab956f5ba4dcf1709b6aa3211c739f61232a5ff284d21a51e/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [d5331e2c9e5d86…](https://bazaar.abuse.ch/sample/d5331e2c9e5d866d4515c825d6eb69de927810f8547fdc9dfb0aa545785a36b6/) | Formbook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [d28343fff34a5e…](https://bazaar.abuse.ch/sample/d28343fff34a5ebc030fb7e1d967acc0df11645e651935b53578787b4786a8fa/) | Formbook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [c0bf4b3795ac1b…](https://bazaar.abuse.ch/sample/c0bf4b3795ac1bd8c9f0874c35308955b48861d6320145a86d8460dcd064f270/) | Formbook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [c053108c5b25c3…](https://bazaar.abuse.ch/sample/c053108c5b25c38bc6d29569d2876396f4e744cad3d867abf4e566b3e4c3c384/) | Formbook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [a924dc51efcc32…](https://bazaar.abuse.ch/sample/a924dc51efcc327e23837f61af68d2f793d36a36183c3cedb3987efca8382583/) | SnakeKeylogger | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5961/7371 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5961/7371 |
| 3 | ESET-NOD32 | 77.4% | 5705/7371 |
| 4 | Kaspersky | 76.4% | 5627/7370 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5273/7368 |
| 8 | Rising | 68.7% | 5065/7371 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4894/7367 |
| 11 | Tencent | 65.3% | 4665/7145 |
| 12 | Avast | 65.0% | 4790/7367 |
| 13 | AVG | 65.0% | 4790/7366 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4516/7364 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 82 | 81.2% |
| 🐧 Linux | 19 | 18.8% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| MaaS-Loader | 71 | 70.3% |
| Unbekannt / nicht bestimmbar | 22 | 21.8% |
| C2 / Nachladen | 7 | 6.9% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇮🇹 IT | 71 | 70.3% |
| 2 | 🇩🇪 DE | 9 | 8.9% |
| 3 | 🇺🇸 US | 8 | 7.9% |
| 4 | 🇳🇱 NL | 6 | 5.9% |
| 5 | 🇪🇸 ES | 4 | 4.0% |
| 6 | 🇨🇭 CH | 2 | 2.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 38 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 19 |
| Lateral Movement | 19 |
| Collection | 15 |
| Command and Control | 11 |
| Credential Access | 8 |
| Exfiltration | 2 |
| Execution | 2 |

<details><summary>4884f9e63b6d4a864a99… – Formbook | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>f85524b8c3d011caaee3… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e13e1d805c67de591f73… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>dd86e3595d51a03ab956… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [6645211f17555aae1809…](https://bazaar.abuse.ch/sample/6645211f17555aae18099d7c99a4c79c170cd26e637c1012373e3f79e9cbac7a/)

- **Familie:** Malware
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.C65D963B
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.C5957298` |
| Bkav | `W32.Malware.C65D963B` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (moderate confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NNK.gen!Eldorado` |

### [ec340fcd3a19f99978cf…](https://bazaar.abuse.ch/sample/ec340fcd3a19f99978cfd326a00108ce04d9c295ef61723dfe12c46fc8be21b9/)

- **Familie:** SnakeKeylogger
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81730128
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81730128`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81730128` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Drp]` |
| AhnLab-V3 | `Trojan/Win.GenKryptik.C5955980` |
| Alibaba | `Trojan:MSIL/Kryptik.dde55cf3` |
| Antiy-AVL | `Trojan/MSIL.GenKryptik` |
| Arcabit | `Trojan.Generic.D4DF1A50` |
| Avast | `Win32:MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.81730128` |
| Bkav | `W32.Malware.FD89DD0` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Inject7.4668` |
| ESET-NOD32 | `MSIL/Kryptik.ARCQ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81730128 (B)` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| Fortinet | `MSIL/FormBook.GNHT!tr` |
| GData | `Trojan.GenericKD.81730128` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.MSIL.AgentTesla` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.XWorm.gen` |
| Kingsoft | `malware.kb.c.936` |
| Malwarebytes | `Trojan.MalPack.PNG.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!B1C6EBE8A0BD` |
| MicroWorld-eScan | `Trojan.GenericKD.81730128` |
| Microsoft 🛡️ | `Trojan:MSIL/XWorm.AH!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Malware.Obfus/MSIL@AI.86 (RDM.MSIL2:3Op31Rf5VIfLpNBZZtlqYA)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Krypt-AQM` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Malware.Win32.Gencirc.14b654cd` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VIPRE | `Trojan.GenericKD.81730128` |
| Varist | `W32/MSIL_Kryptik.MJI3.ge!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Webroot | `W32.Malware.gen` |
| ZoneAlarm | `Troj/Krypt-AQM` |

### [dad922a34e36f47ab37e…](https://bazaar.abuse.ch/sample/dad922a34e36f47ab37eb432187d4046bf7955b440a03b01572b23667a903b8a/)

- **Familie:** DCRat
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Application.MSILHeracles.1054
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.MSILHeracles.1054`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.MSILHeracles.1054` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Pws]` |
| Acronis | `suspicious` |
| AhnLab-V3 | `Trojan/Win.MSILKrypt.R567645` |
| Antiy-AVL | `Trojan/MSIL.Kryptik` |
| Arcabit | `Trojan.Application.MSILHeracles.D41E` |
| Avast | `Win32:MalwareX-gen [Pws]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Application.MSILHeracles.1054` |
| Bkav | `W32.Malware.24220287` |
| CAT-QuickHeal | `Trojan.YakbeexMSIL.ZZ4` |
| CTX | `exe.unknown.msilheracles` |
| ClamAV | `Win.Dropper.TrickBot-10058465-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen20.1081` |
| ESET-NOD32 | `MSIL/Kryptik.AINT trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Application.MSILHeracles.1054 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `MSIL/Kryptik.BAN!tr` |
| GData | `Gen:Variant.Application.MSILHeracles.1054` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Kryptik.oa!s1` |
| Ikarus | `Trojan-Spy.AgentTesla` |
| Jiangmin | `Trojan.MSIL.aohaj` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan.MSIL.Taskun.gen` |
| Malwarebytes | `Generic.Trojan.Crypt.DDS` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Win/Formbook.AL` |
| MicroWorld-eScan | `Gen:Variant.Application.MSILHeracles.1054` |
| Microsoft 🛡️ | `Trojan:MSIL/AgentTesla.ABPF!MTB` |
| NANO-Antivirus | `Trojan.Win32.Kryptik.lhidqu` |
| Panda | `Trj/GdSda.A` |
| Rising | `Trojan.Kryptik!1.1347A (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Siggen` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Krypt-WB` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.DN-Taskun.1201664` |
| Tencent | `Trojan.MSIL.Taskun.kd` |
| TrellixENS | `GenericRXVQ-NJ!03A7AC64C9D9` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `TScope.Trojan.MSIL` |
| VIPRE | `Gen:Variant.Application.MSILHeracles.1054` |
| Varist | `W32/ASRisk.DHPK-3048` |
| VirIT | `Trojan.Win32.GenusT.FIKJ` |
| ZoneAlarm | `Troj/Krypt-WB` |
| huorong | `TrojanDropper/MSIL.Agent.js` |

### [bf792c9bffc98f54c084…](https://bazaar.abuse.ch/sample/bf792c9bffc98f54c084d5934dbf6c7488fab61c861d3ec4fa51c6445a924f1b/)

- **Familie:** RemcosRAT
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Avast | `MalwareX-gen [Drp]` |
| Avira | `DR/W64.MalwareX` |
| Bkav | `W32.Malware.E2F0919E` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.PackedNET.3665` |
| ESET-NOD32 | `MSIL/Kryptik.ANRB trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `MSIL/GetType.AB!tr` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.Noon.gen` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!BF792C9BFFC9` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Obfus/MSIL@AI.100 (RDM.MSIL2:RNoPK8d3Zao5i1a1ScEkbw)` |
| Sangfor | `Suspicious.Win32.Save.pkr` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Msil.Trojan.Kryptik.Ssmw` |
| VirIT | `Trojan.Win64.MSIL_Heur.A` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

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
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **exe** (79×)
- **RGBLoader** (71×)
- **elf** (19×)
- **Mirai** (19×)
- **Formbook** (8×)
- **DCRat** (8×)
- **dropped-by-GCleaner** (7×)
- **AgentTesla** (7×)
- **upx-dec** (6×)
- **upx** (6×)
- **shem** (4×)
- **RemcosRAT** (4×)
- **RemusStealer** (3×)
- **Gafgyt** (3×)
- **SnakeKeylogger** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +5 (31→36)
- ↓ **Mirai** -8 (26→18)
- ↑ **Formbook** +5 (3→8)
- neu: **DCRat** (8)
- neu: **AgentTesla** (7)
- ↑ **RemcosRAT** +3 (2→5)
- ↑ **RemusStealer** +2 (1→3)
- neu: **SnakeKeylogger** (3)
- neu: **njrat** (2)
- neu: **QuasarRAT** (2)
- weg: **SalatStealer** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +8 (28→36)
- ↓ **Mirai** -20 (38→18)
- ↑ **Formbook** +6 (2→8)
- neu: **DCRat** (8)
- ↑ **AgentTesla** +6 (1→7)
- ↑ **RemcosRAT** +3 (2→5)
- neu: **RemusStealer** (3)
- neu: **SnakeKeylogger** (3)
- neu: **njrat** (2)
- neu: **QuasarRAT** (2)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.464 MB |
| σ Dateigröße | 3.465 MB |
| Ø Risiko-Score | 79.6/100 |
| Ø Klassifikations-Konfidenz | 84.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 38/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 41 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:12 | [6645211f1755…](https://bazaar.abuse.ch/sample/6645211f17555aae18099d7c99a4c79c170cd26e637c1012373e3f79e9cbac7a/) | `exe` | Malware | 78.5 | 13.3% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 18:12 | [cc06209b03c2…](https://bazaar.abuse.ch/sample/cc06209b03c2de4eb62b9944775446a2cacdfac6a38d7bd478a85f9c8e05677c/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 18:10 | [c66f94f6f054…](https://bazaar.abuse.ch/sample/c66f94f6f054c6ca06e6561aed88fe54d1ea76bfeb8b5cd8a97c71590f08b063/) | `exe` | DarkTortilla | 38.9 | – | – | 🌐CH |
| 18:06 | [617f17f57063…](https://bazaar.abuse.ch/sample/617f17f570638c1d636914a644cb40b650a285b2b1dde00840985a4427dc1d46/) | `exe` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 17:48 | [42ee0b9c164d…](https://bazaar.abuse.ch/sample/42ee0b9c164d6ee88e01a7cb58fe02ce71de1ecff90ed392052aafc07d268393/) | `elf` | Mirai | 84.0 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.10.2026 18:23 UTC*