# MalwareBazaar – 12.11.2026 02:45 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **79** |
| Höchster Score | **97.4/100** – 5e99c8dc8b2280db… |
| Häufigste Familie | **SalatStealer** (44x) |
| Häufigster Typ | **exe** (70x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 7.07 MB (σ=12.15) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 70 | 69.3%  █████████████ |
| `elf` | 22 | 21.8%  ████ |
| `apk` | 2 | 2.0%   |
| `zip` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |
| `pdf` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 44 | 43.6% |
| 2 | Mirai | 19 | 18.8% |
| 3 | unbekannt | 18 | 17.8% |
| 4 | RevStealer | 7 | 6.9% |
| 5 | WARDENStealer | 3 | 3.0% |
| 6 | Adware.Generic | 2 | 2.0% |
| 7 | ConnectWise | 2 | 2.0% |
| 8 | RemcosRAT | 2 | 2.0% |
| 9 | WannaCry | 1 | 1.0% |
| 10 | B!ml | 1 | 1.0% |
| 11 | Draftor | 1 | 1.0% |
| 12 | SnappyClient | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 57 | 56.4% | 75% |
| Botnet/IoT | 19 | 18.8% | 95% |
| Windows-Malware | 11 | 10.9% | 35% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| RAT | 3 | 3.0% | 88% |
| Linux-Malware | 2 | 2.0% | 45% |
| Trojaner | 2 | 2.0% | 65% |
| Android-Malware | 2 | 2.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 79 | 78.2% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 16 | 15.8% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5e99c8dc8b2280…](https://bazaar.abuse.ch/sample/5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2/) | WannaCry | Ransomware | **97.4** | 🔴 KRITISCH | – | – | ? |
| [6008e63639c9d0…](https://bazaar.abuse.ch/sample/6008e63639c9d09724ea8df3fe28d67d216cdeee07a1be1e833884b55cc1eaba/) | RemcosRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [70422ee91ec13a…](https://bazaar.abuse.ch/sample/70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [cb275fd75a405c…](https://bazaar.abuse.ch/sample/cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3/) | B!ml | Trojaner | **84.3** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [5a1ed238a7fe20…](https://bazaar.abuse.ch/sample/5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [caac7e9d53a806…](https://bazaar.abuse.ch/sample/caac7e9d53a806f42d82c1a5d466e7ab5b1e248d04c45d4c1caadde72b1dcd18/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [878f9156d89cab…](https://bazaar.abuse.ch/sample/878f9156d89cabdc6f03729e55534f4198036fd23cde618f5903c6fcc5daa0b8/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [dbbc9cc2d264c0…](https://bazaar.abuse.ch/sample/dbbc9cc2d264c0213528197d60957931fa6d1016a25f6b92e571ad664bfdf306/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [5d3ec5ede0ac47…](https://bazaar.abuse.ch/sample/5d3ec5ede0ac473a4631846bafe4a8af8a23b7071e2afd2efb75fb495ca29baf/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [7f14bb2310547a…](https://bazaar.abuse.ch/sample/7f14bb2310547aea85ad2aaee8ee98f2a36e7017ba7f033651080c394b0a7f06/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6447/7946 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6447/7946 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6142/7946 |
| 6 | Kaspersky | 75.5% | 5997/7945 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5658/7942 |
| 9 | Rising | 68.4% | 5434/7946 |
| 10 | Varist | 66.1% | 5249/7941 |
| 11 | AVG | 65.2% | 5174/7941 |
| 12 | Avast | 65.1% | 5174/7942 |
| 13 | Tencent | 64.9% | 5014/7720 |
| 14 | McAfeeD | 61.4% | 4874/7938 |
| 15 | huorong | 60.9% | 4835/7938 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 71 | 70.3% |
| 🐧 Linux | 24 | 23.8% |
| 📦 Archiv | 2 | 2.0% |
| 🤖 Android | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 95 | 94.1% |
| APK-Sideloading | 2 | 2.0% |
| MaaS-Loader | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 44 | 43.6% |
| 2 | 🇳🇱 NL | 23 | 22.8% |
| 3 | 🇩🇪 DE | 16 | 15.8% |
| 4 | 🇫🇷 FR | 8 | 7.9% |
| 5 | 🌐 PT | 4 | 4.0% |
| 6 | 🇯🇵 JP | 2 | 2.0% |
| 7 | 🇭🇺 HU | 2 | 2.0% |
| 8 | 🌐 PE | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 21 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 19 |
| Lateral Movement | 19 |
| Command and Control | 2 |
| Collection | 2 |

<details><summary>6008e63639c9d09724ea… – RemcosRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>70422ee91ec13ab03002… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5a1ed238a7fe20561670… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3f8fdf75598d386424b6…](https://bazaar.abuse.ch/sample/3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b/)

- **Familie:** SalatStealer
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Wacatac.B!ml`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Alibaba | `TrojanBanker:Win32/SalatStealer.dbf282f5` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avira | `TR/Crypt.ULPM.Gen` |
| Bkav | `W32.Malware.100682FB` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Gen:Variant.Draftor.8401` |
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Lionic | `Trojan.Win32.Salat.i!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.393319296.susgen` |
| McAfeeD | `Real Protect-LS!8FDFA70E236B` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Salat.lkveux` |
| Paloalto | `generic.ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Agent.Vx21` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570815` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/Trojan.CSAE-0249` |
| ViRobot | `Trojan.Win.Z.Draftor.3592895.D` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |

### [cb275fd75a405c18765b…](https://bazaar.abuse.ch/sample/cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [420729452309ce6a8b9e…](https://bazaar.abuse.ch/sample/420729452309ce6a8b9e31a54e31515f3002f23888a8130f0932e7e08a1d6212/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-COW [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-COW [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-COW [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.COW` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.COW` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `ti!420729452309` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Varist | `E32/Mirai.DK.gen!Eldorado` |
| huorong | `Backdoor/Linux.Mirai.fo` |

### [5a556f114dbd10030c30…](https://bazaar.abuse.ch/sample/5a556f114dbd10030c30f454c0e793b1f2788617ce444d60914d5ee970e90544/)

- **Familie:** Draftor
- **Erkannt von:** 38 von 75 Engines (50.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.25770
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.25770`

**Erkennende Engines (38/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.25770` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Malware/Win.Yogi.C5903166` |
| Antiy-AVL | `Trojan/Win32.Strab` |
| Arcabit | `Trojan.Draftor.D64AA` |
| Avast | `Win32:MalwareX-gen [Trj]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.25770` |
| Bkav | `W32.Malware.C40D935C` |
| CTX | `dll.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/Kryptik.HZLF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Draftor.25770 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `W32/Kryptik.HZKO!tr` |
| GData | `Gen:Variant.Draftor.25770` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Agent` |
| K7AntiVirus | `Trojan ( 006dcde31 )` |
| K7GW | `Trojan ( 006dcde31 )` |
| Kaspersky | `VHO:Trojan.Win32.Strab.gen` |
| Kingsoft | `malware.kb.a.737` |
| Malwarebytes | `Floxif.Virus.FileInfector.DDS` |
| McAfeeD | `Trojan:Win/GenericY.JMM` |
| MicroWorld-eScan | `Gen:Variant.Draftor.25770` |
| Panda | `Trj/GdSda.A` |
| Rising | `Trojan.Kryptik!8.8 (TFE:5:E0WypkGustB)` |
| Skyhigh | `BehavesLike.Win32.Generic.wc` |
| Sophos | `Generic ML PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `suspicious.low.ml.score` |
| VBA32 | `BScope.Exploit.UAC` |
| VIPRE | `Gen:Variant.Draftor.25770` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 56 von 75 Engines (74.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (56/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vlth` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (70×)
- **upx** (24×)
- **upx-dec** (23×)
- **elf** (22×)
- **SalatStealer** (22×)
- **salatstealer** (22×)
- **Mirai** (19×)
- **Torii** (15×)
- **RevStealer** (7×)
- **WARDENStealer** (6×)
- **signed** (3×)
- **Prometei** (3×)
- **SnappyClient** (2×)
- **diicot** (2×)
- **apk** (2×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +27 (17→44)
- ↓ **Mirai** -17 (36→19)
- ↓ **unbekannt** -2 (20→18)
- ↑ **RevStealer** +6 (1→7)
- ↓ **WARDENStealer** -1 (4→3)
- neu: **Adware.Generic** (2)
- neu: **ConnectWise** (2)
- ↓ **RemcosRAT** -2 (4→2)
- neu: **B!ml** (1)
- weg: **GuLoader** (war 3)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +40 (4→44)
- ↓ **Mirai** -4 (23→19)
- ↓ **unbekannt** -13 (31→18)
- ↑ **RevStealer** +5 (2→7)
- neu: **Adware.Generic** (2)
- neu: **ConnectWise** (2)
- ↓ **RemcosRAT** -1 (3→2)
- neu: **WannaCry** (1)
- neu: **B!ml** (1)
- weg: **AgentTesla** (war 3)
- weg: **Formbook** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.072 MB |
| σ Dateigröße | 12.152 MB |
| Ø Risiko-Score | 72.9/100 |
| Ø Klassifikations-Konfidenz | 71.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 21/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 02:44 | [2b51009b5712…](https://bazaar.abuse.ch/sample/2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 02:44 | [5dc3a9c1d44c…](https://bazaar.abuse.ch/sample/5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf/) | `exe` | unbekannt | 82.2 | – | – | 🌐PT |
| 02:41 | [e7b2b38ee085…](https://bazaar.abuse.ch/sample/e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff/) | `exe` | unbekannt | 82.2 | – | – | 🌐PT |
| 02:40 | [7a705f5b3959…](https://bazaar.abuse.ch/sample/7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b/) | `exe` | unbekannt | 39.0 | – | – | 🌐PT |
| 02:39 | [70422ee91ec1…](https://bazaar.abuse.ch/sample/70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51/) | `elf` | Mirai | 84.5 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.11.2026 02:45 UTC*