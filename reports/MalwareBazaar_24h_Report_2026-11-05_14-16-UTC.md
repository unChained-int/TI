# MalwareBazaar – 05.11.2026 14:16 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **44** |
| Höchster Score | **92.4/100** – 53de6d9138476ce0… |
| Häufigste Familie | **unbekannt** (43x) |
| Häufigster Typ | **js** (37x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 20 Samples |
| Ø Dateigröße | 2.40 MB (σ=3.57) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 37 | 36.6%  ███████ |
| `exe` | 32 | 31.7%  ██████ |
| `elf` | 7 | 6.9%  █ |
| `vbs` | 6 | 5.9%  █ |
| `msi` | 5 | 5.0%   |
| `zip` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `jar` | 2 | 2.0%   |
| `au3` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 43 | 42.6% |
| 2 | AgentTesla | 13 | 12.9% |
| 3 | RemcosRAT | 10 | 9.9% |
| 4 | XWorm | 5 | 5.0% |
| 5 | Formbook | 5 | 5.0% |
| 6 | Mirai | 4 | 4.0% |
| 7 | LxBaseRAT | 3 | 3.0% |
| 8 | NanoCore | 2 | 2.0% |
| 9 | RevStealer | 2 | 2.0% |
| 10 | DonutLoader | 2 | 2.0% |
| 11 | Dacic | 1 | 1.0% |
| 12 | Jalapeno | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 23 | 22.8% | 35% |
| RAT | 23 | 22.8% | 90% |
| Skript/Dropper | 17 | 16.8% | 35% |
| Infostealer | 10 | 9.9% | 87% |
| Trojaner | 8 | 7.9% | 70% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| Botnet/IoT | 4 | 4.0% | 95% |
| Loader | 4 | 4.0% | 85% |
| Linux-Malware | 2 | 2.0% | 45% |
| Cryptominer | 1 | 1.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 44 | 43.6% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 42 | 41.6% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [53de6d9138476c…](https://bazaar.abuse.ch/sample/53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a/) | CobaltStrike | Post-Exploitat | **92.4** | 🔴 KRITISCH | – | – | ? |
| [9cd6f6bee4f966…](https://bazaar.abuse.ch/sample/9cd6f6bee4f966a9e035d0b93edd6ee527cc373f9cb2184e65394051903beb7e/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [ea7f13b5ea86c3…](https://bazaar.abuse.ch/sample/ea7f13b5ea86c34a45333b430881557d00718441ae3d41059832949486da48f5/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [b8153f898e1f2c…](https://bazaar.abuse.ch/sample/b8153f898e1f2c3482fc0204eafdb2c15b096d4c8a9017e8c1ecfa3c94220596/) | NanoCore | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [7df2785dd30be9…](https://bazaar.abuse.ch/sample/7df2785dd30be99752debc4ad573fda10221c31b78f6b737e5648aeaa7207533/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [ef2ec2257a47a4…](https://bazaar.abuse.ch/sample/ef2ec2257a47a49c24533961cb95d5989f36b35308ed54dc16873242427c0de9/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [53a91582b44183…](https://bazaar.abuse.ch/sample/53a91582b441830289f2fecb415dafd0c749650f9da21362f71ab7b4d2c5289a/) | SnakeKeylogger | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [2bc1d95010231a…](https://bazaar.abuse.ch/sample/2bc1d95010231aac179e7b98464a40bdaf7f132b03321c22c6da331c3e2b0b59/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [8a669987d70414…](https://bazaar.abuse.ch/sample/8a669987d704143b37841e4ad831b8e8a6dff38f81b2b2c858b6cb3c71095efb/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [29bee5672bc389…](https://bazaar.abuse.ch/sample/29bee5672bc389151d94beca82fcae697ad066697405cb8a437208672fdd637d/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6344/7833 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6344/7833 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6051/7833 |
| 6 | Kaspersky | 75.4% | 5909/7832 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5574/7829 |
| 9 | Rising | 68.3% | 5347/7833 |
| 10 | Varist | 66.2% | 5180/7828 |
| 11 | Avast | 65.1% | 5093/7829 |
| 12 | AVG | 65.1% | 5093/7828 |
| 13 | Tencent | 64.9% | 4937/7607 |
| 14 | McAfeeD | 61.4% | 4802/7825 |
| 15 | huorong | 60.8% | 4758/7825 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 46 | 45.5% |
| ❓ Unbekannt | 41 | 40.6% |
| 🐧 Linux | 10 | 9.9% |
| 📦 Archiv | 3 | 3.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 57 | 56.4% |
| Drive-By / Exploit-Kit | 37 | 36.6% |
| Trojanisierte Software | 5 | 5.0% |
| MaaS-Loader | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇦🇹 AT | 28 | 27.7% |
| 2 | 🇸🇪 SE | 26 | 25.7% |
| 3 | 🇭🇺 HU | 12 | 11.9% |
| 4 | 🇺🇸 US | 11 | 10.9% |
| 5 | 🇩🇪 DE | 8 | 7.9% |
| 6 | 🇫🇷 FR | 6 | 5.9% |
| 7 | 🇧🇷 BR | 4 | 4.0% |
| 8 | 🇮🇩 ID | 3 | 3.0% |
| 9 | 🌐 NO | 1 | 1.0% |
| 10 | 🇨🇦 CA | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 20 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 15 |
| Command and Control | 11 |
| Credential Access | 6 |
| Initial Access | 4 |
| Lateral Movement | 4 |

<details><summary>53de6d9138476ce0d55f… – CobaltStrike | 🔴 KRITISCH 92.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol |
| Credential Access | [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping |

</details>
<details><summary>9cd6f6bee4f966a9e035… – RemcosRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>ea7f13b5ea86c34a4533… – RemcosRAT | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>7df2785dd30be99752de… – RemcosRAT | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b88e8a73d7f1c39f6f7c…](https://bazaar.abuse.ch/sample/b88e8a73d7f1c39f6f7c32a0e36210d234dae70336d47b24d361c3f452e1e55e/)

- **Familie:** Dacic
- **Erkannt von:** 43 von 75 Engines (57.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Dacic.22824.D48BF5A4
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Dacic.22824.D48BF5A4`

**Erkennende Engines (43/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Dacic.22824.D48BF5A4` |
| APEX | `Malicious` |
| AVG | `Win32:Dh-A [Heur]` |
| AhnLab-V3 | `Malware/Win.Dh.R787050` |
| Antiy-AVL | `Trojan/Win32.Phonzy` |
| Arcabit | `Generic.Dacic.22824.D48BF5A4` |
| Avast | `Win32:Dh-A [Heur]` |
| Avira | `TR/W32.Dh.A` |
| BitDefender 🛡️ | `Generic.Dacic.22824.D48BF5A4` |
| Bkav | `W32.Malware.8F46A8CD` |
| CTX | `exe.unknown.dacic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.DownLoader49.35384` |
| ESET-NOD32 | `Win64/Kryptik.HKG trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Generic.Dacic.22824.D48BF5A4 (B)` |
| F-Secure | `Trojan.TR/W32.Dh.A` |
| Fortinet | `W64/Agent.BPJ!tr` |
| GData | `Generic.Dacic.22824.D48BF5A4` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Jiangmin | `Trojan.Generic.hssry` |
| K7AntiVirus | `Trojan ( 006e45f11 )` |
| K7GW | `Trojan ( 006e45f11 )` |
| Kaspersky | `Trojan.Win64.Patched.t` |
| Kingsoft | `malware.kb.a.973` |
| Malwarebytes | `Trojan.Downloader` |
| McAfeeD | `Real Protect-LS!3243FE67BE2C` |
| MicroWorld-eScan | `Generic.Dacic.22824.D48BF5A4` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Virus.Win64.Virut-Gen.bwpxnc` |
| Rising | `Trojan.Kryptik@AI.89 (RDML:hNTC11wsB8YMs5i7ypgNmg)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Infected.dh` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Virus.Win64.VriutCE.Gen` |
| Trapmine | `malicious.high.ml.score` |
| VIPRE | `Generic.Dacic.22824.D48BF5A4` |
| Varist | `W64/Agent.NPG.gen!Eldorado` |
| VirIT | `Trojan.Win64.Gen_Heur.C` |

### [0211ef164a8a167a3b51…](https://bazaar.abuse.ch/sample/0211ef164a8a167a3b5191c3291685313e2ecea30a0afe72ee4e56e6060e8cde/)

- **Familie:** Jalapeno
- **Erkannt von:** 49 von 75 Engines (65.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Jalapeno.24099
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Jalapeno.24099`

**Erkennende Engines (49/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Jalapeno.24099` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5960369` |
| Alibaba | `Trojan:MSIL/DataCollector.5310968e` |
| Antiy-AVL | `Trojan/MSIL.Agent` |
| Arcabit | `Trojan.Jalapeno.D5E23` |
| Avast | `Win32:MalwareX-gen [Cryp]` |
| Avira | `TR/Dropper.MSIL.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Jalapeno.24099` |
| Bkav | `W32.Malware.BAABEE14` |
| CTX | `exe.unknown.jalapeno` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Agent.YTK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Jalapeno.24099 (B)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen` |
| Fortinet | `MSIL/Agent.YTK!tr` |
| GData | `Gen:Variant.Jalapeno.24099` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan.MSIL.Agent.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| Malwarebytes | `Trojan.MalPack.Confuser` |
| McAfeeD | `Real Protect-LS!773E5F2CAD49` |
| MicroWorld-eScan | `Gen:Variant.Jalapeno.24099` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Agent!8.B1E (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Trojan.dc` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Msil.Trojan.Agent.Mzfl` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!773E5F2CAD49` |
| TrendMicro | `Trojan.MSIL.WACATAC.USBLK426` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Buts.gen` |
| VIPRE | `Gen:Variant.Jalapeno.24099` |
| Varist | `W32/S-3049d5f7!Eldorado` |
| ViRobot | `Trojan.Win.Z.Agent.1017856.AL` |
| alibabacloud | `Trojan[dropper]:MSIL/Wacatac.B9nj` |

### [3e7ca9ab84fd6141efea…](https://bazaar.abuse.ch/sample/3e7ca9ab84fd6141efea3a654343a28675376b289fbfcbcce8d53d5218ad5f52/)

- **Familie:** Malware
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.627EA83
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.R798428` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.627EA83` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/GenKryptik.HVHT trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVHT!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kingsoft | `malware.kb.a.976` |
| Malwarebytes | `Malware.Heuristic.2094` |
| McAfeeD | `ti!3E7CA9AB84FD` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Generic ML PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16006318` |
| Trapmine | `suspicious.low.ml.score` |
| Varist | `W64/Agent.NLJ.gen!Eldorado` |

### [7177e9b1530b149a594f…](https://bazaar.abuse.ch/sample/7177e9b1530b149a594f9a3684548ac431c413fbf493db02a94ba63240871994/)

- **Familie:** Win64:MalwareX-gen [Cryp]
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R799590` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.DC852DF9` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.52091` |
| ESET-NOD32 | `Win64/GenKryptik.HVHT trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVHT!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Malwarebytes | `Malware.AI.2475202567` |
| McAfeeD | `ti!7177E9B1530B` |
| Rising | `Stealer.BroPass!8.13424 (TFE:2:ddhKcc6ceIH)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16006318` |
| Varist | `W64/Agent.NLJ.gen!Eldorado` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** BKDR_NOANCOOE.SM
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:MSIL/Nanocore!atmn`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Elastic | `Windows.Trojan.Nanocore` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| huorong | `Backdoor/MSIL.NanoCore.b` |


## Top Tags

- **js** (37×)
- **exe** (32×)
- **AgentTesla** (13×)
- **RemcosRAT** (10×)
- **elf** (7×)
- **vbs** (6×)
- **msi** (5×)
- **honeypot** (5×)
- **XWorm** (5×)
- **Formbook** (5×)
- **RAT** (5×)
- **banker** (4×)
- **Mirai** (4×)
- **malspam** (4×)
- **malspam-DJP** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +4 (39→43)
- ↑ **AgentTesla** +11 (2→13)
- ↑ **RemcosRAT** +8 (2→10)
- ↑ **XWorm** +3 (2→5)
- ↑ **Formbook** +3 (2→5)
- ↓ **Mirai** -11 (15→4)
- ↑ **LxBaseRAT** +2 (1→3)
- ↑ **NanoCore** +1 (1→2)
- neu: **RevStealer** (2)
- ↑ **DonutLoader** +1 (1→2)
- weg: **SalatStealer** (war 8)
- weg: **WARDENStealer** (war 4)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +12 (31→43)
- ↑ **AgentTesla** +11 (2→13)
- ↑ **RemcosRAT** +8 (2→10)
- ↑ **XWorm** +4 (1→5)
- ↑ **Formbook** +3 (2→5)
- ↓ **Mirai** -17 (21→4)
- neu: **LxBaseRAT** (3)
- ↑ **NanoCore** +1 (1→2)
- neu: **RevStealer** (2)
- neu: **DonutLoader** (2)
- weg: **SalatStealer** (war 7)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.397 MB |
| σ Dateigröße | 3.568 MB |
| Ø Risiko-Score | 59.5/100 |
| Ø Klassifikations-Konfidenz | 59.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 20/101 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:09 | [b88e8a73d7f1…](https://bazaar.abuse.ch/sample/b88e8a73d7f1c39f6f7c32a0e36210d234dae70336d47b24d361c3f452e1e55e/) | `exe` | Dacic | 70.9 | 57.3% | 🟠 MÄSSIG ERKANNT | 🌐HU |
| 14:07 | [3dcfb05d99f9…](https://bazaar.abuse.ch/sample/3dcfb05d99f9c14279392d6ad30ee74d09ccefdacee63047ae24d2932f19ccb8/) | `exe` | AgentTesla | 39.0 | – | – | 🌐HU |
| 14:06 | [0211ef164a8a…](https://bazaar.abuse.ch/sample/0211ef164a8a167a3b5191c3291685313e2ecea30a0afe72ee4e56e6060e8cde/) | `exe` | Jalapeno | 68.8 | 65.3% | 🟠 MÄSSIG ERKANNT | 🌐HU |
| 14:06 | [45146b55c9da…](https://bazaar.abuse.ch/sample/45146b55c9da7cb1308fedbb17e6b647770b8e8a92fa515535c3eda3eaddd49c/) | `exe` | unbekannt | 39.0 | – | – | 🌐HU |
| 14:06 | [3798437d22e8…](https://bazaar.abuse.ch/sample/3798437d22e8366808e812d22b0a8d4789329f356df9677004be0b14ba61da24/) | `exe` | unbekannt | 39.0 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 05.11.2026 14:16 UTC*