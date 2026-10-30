# MalwareBazaar – 30.10.2026 19:02 UTC

Dieser Run hat **69 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **70** |
| Kritisch (≥75) | **44** |
| Höchster Score | **87.0/100** – c132469160415d8e… |
| Häufigste Familie | **Mirai** (29x) |
| Häufigster Typ | **elf** (37x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 4.40 MB (σ=7.97) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 37 | 52.9%  ██████████ |
| `exe` | 23 | 32.9%  ██████ |
| `gz` | 2 | 2.9%   |
| `macho` | 1 | 1.4%   |
| `js` | 1 | 1.4%   |
| `zsh` | 1 | 1.4%   |
| `wsf` | 1 | 1.4%   |
| `sh` | 1 | 1.4%   |
| `ps1` | 1 | 1.4%   |
| `rar` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 29 | 41.4% |
| 2 | unbekannt | 15 | 21.4% |
| 3 | NIKRAT | 12 | 17.1% |
| 4 | CoinMiner | 3 | 4.3% |
| 5 | VoidLink | 3 | 4.3% |
| 6 | Tedy | 1 | 1.4% |
| 7 | AgentTesla | 1 | 1.4% |
| 8 | Arechclient2 | 1 | 1.4% |
| 9 | Formbook | 1 | 1.4% |
| 10 | NanoCore | 1 | 1.4% |
| 11 | Prometei | 1 | 1.4% |
| 12 | RemusStealer | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 30 | 42.9% | 94% |
| RAT | 14 | 20.0% | 76% |
| Linux-Malware | 8 | 11.4% | 45% |
| Andere / Unbekannt | 4 | 5.7% | 20% |
| Windows-Malware | 3 | 4.3% | 35% |
| Loader | 3 | 4.3% | 75% |
| Infostealer | 3 | 4.3% | 78% |
| Cryptominer | 3 | 4.3% | 75% |
| Trojaner | 1 | 1.4% | 65% |
| Skript/Dropper | 1 | 1.4% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 44 | 62.9% |
| 🟠 HOCH | 10 | 14.3% |
| 🟡 MITTEL | 11 | 15.7% |
| 🟢 NIEDRIG | 5 | 7.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c132469160415d…](https://bazaar.abuse.ch/sample/c132469160415d8e11bbc1e13d2ff1054cf266c89790f39e8c726bf929639dc6/) | Formbook | Infostealer | **87.0** | 🔴 KRITISCH | – | – | ? |
| [17ed40dea218bd…](https://bazaar.abuse.ch/sample/17ed40dea218bde06337f32e3d3443d07fd24cad9b0da82d6d890716ac6308ff/) | NanoCore | RAT | **86.0** | 🔴 KRITISCH | – | – | ? |
| [9c5c9a361e4ff9…](https://bazaar.abuse.ch/sample/9c5c9a361e4ff93de152a00a451410db8c24633abdb9bbad4da4bd4c47905511/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [2404b5520fa120…](https://bazaar.abuse.ch/sample/2404b5520fa1205f2bccf7a98d35268ac09772b258f4133f0269975d489a8aa9/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [6dcb0490453776…](https://bazaar.abuse.ch/sample/6dcb04904537762c314dc8c56db87d0ef10304e117362d6fd5973714d36e8d87/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [8344f67e89e8b0…](https://bazaar.abuse.ch/sample/8344f67e89e8b05f18e23b2a61252045710b93e84bf9cacb87d818f5f789a998/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [95903968df5d20…](https://bazaar.abuse.ch/sample/95903968df5d20bef98ede34d6147762e0bfff76645368a68d4e304bff2aa9fd/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [d1b80d5f73b327…](https://bazaar.abuse.ch/sample/d1b80d5f73b327fb4077d36b80b248fe1e403d20b9706023eff3be35655bfe33/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [7c1f47ad6e6c72…](https://bazaar.abuse.ch/sample/7c1f47ad6e6c72d6068c48663494516deef1e543862748aa9830457ee45178e9/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [cdd6d3adb812f2…](https://bazaar.abuse.ch/sample/cdd6d3adb812f2b018e06f6ccbf3f141ed40b3a284c60b1dc97421f263d82107/) | Mirai | Botnet/IoT | **81.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6265/7730 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.7% | 22/24 |
| 2 | Microsoft 🛡️ | 81.0% | 6265/7730 |
| 3 | MAX | 77.8% | 7/9 |
| 4 | ESET-NOD32 | 77.3% | 5973/7730 |
| 5 | Kaspersky | 75.5% | 5838/7729 |
| 6 | McAfee-GW-Edition | 75.0% | 3/4 |
| 7 | Google | 71.2% | 5500/7727 |
| 8 | Rising | 68.3% | 5280/7730 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5111/7726 |
| 11 | AVG | 65.2% | 5033/7725 |
| 12 | Avast | 65.1% | 5033/7726 |
| 13 | Tencent | 64.9% | 4871/7504 |
| 14 | McAfeeD | 61.3% | 4732/7723 |
| 15 | huorong | 60.8% | 4696/7723 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 39 | 55.7% |
| 🪟 Windows | 25 | 35.7% |
| ❓ Unbekannt | 4 | 5.7% |
| 🍎 macOS | 1 | 1.4% |
| 📦 Archiv | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 66 | 94.3% |
| MaaS-Loader | 2 | 2.9% |
| Drive-By / Exploit-Kit | 1 | 1.4% |
| Trojanisierte Software | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 32 | 45.7% |
| 2 | 🇳🇱 NL | 12 | 17.1% |
| 3 | 🇫🇷 FR | 9 | 12.9% |
| 4 | 🇺🇸 US | 6 | 8.6% |
| 5 | 🇷🇺 RU | 3 | 4.3% |
| 6 | 🇬🇧 GB | 2 | 2.9% |
| 7 | 🌐 Unbekannt | 2 | 2.9% |
| 8 | 🇨🇦 CA | 1 | 1.4% |
| 9 | 🇨🇭 CH | 1 | 1.4% |
| 10 | 🇧🇷 BR | 1 | 1.4% |
| 11 | 🌐 EE | 1 | 1.4% |

## MITRE ATT&CK

> 30 von 70 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 29 |
| Lateral Movement | 29 |
| Credential Access | 1 |
| Collection | 1 |

<details><summary>c132469160415d8e11bb… – Formbook | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>9c5c9a361e4ff93de152… – Mirai | 🔴 KRITISCH 83.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>2404b5520fa1205f2bcc… – Mirai | 🔴 KRITISCH 83.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6dcb04904537762c314d… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [48a9afbd26bb74b40325…](https://bazaar.abuse.ch/sample/48a9afbd26bb74b40325cb2f2d9357c21cb7291be7d576585c16677ce4cb32ff/)

- **Familie:** Tedy
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Tedy.876284
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Tedy.876284`

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Tedy.876284` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.R801337` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Xkcp` |
| Arcabit | `Trojan.Tedy.DD5EFC` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Tedy.876284` |
| CTX | `exe.unknown.tedy` |
| ESET-NOD32 | `Win64/ShellcodeRunner.BWG trojan` |
| Emsisoft | `Gen:Variant.Tedy.876284 (B)` |
| Fortinet | `W64/Kryptik.FGQ!tr` |
| GData | `Gen:Variant.Tedy.876284` |
| Gridinsoft | `Trojan.Win64.Wacatac.oa!s1` |
| K7AntiVirus | `Trojan ( 006da0f01 )` |
| K7GW | `Trojan ( 006da0f01 )` |
| Kaspersky | `Backdoor.Win32.Xkcp.cbs` |
| Malwarebytes | `Malware.AI.4216773220` |
| MaxSecure | `Trojan.Malware.328690006.susgen` |
| McAfeeD | `ti!48A9AFBD26BB` |
| MicroWorld-eScan | `Gen:Variant.Tedy.876284` |
| Panda | `Trj/GdSda.A` |
| Rising | `Malware.Undefined!8.C (TFE:5:LT5W0LDoNPE)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Tencent | `Trojan.Win64.Inject.16002705` |
| Trapmine | `malicious.moderate.ml.score` |
| VIPRE | `Gen:Variant.Tedy.876284` |
| huorong | `Trojan/Injector.cib` |

### [0fb93dbb9525004f9e5b…](https://bazaar.abuse.ch/sample/0fb93dbb9525004f9e5b1ee4bcd6b6638700bee576413e955c8c96292fa964ee/)

- **Familie:** NIKRAT
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40406095
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40406095`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40406095` |
| Alibaba | `Trojan:Win32/Reconyc.f53cce52` |
| Antiy-AVL | `Trojan/Win32.Reconyc` |
| Arcabit | `Trojan.Generic.D2688C4F` |
| Avira | `TR/W64.Malware` |
| BitDefender 🛡️ | `Trojan.Generic.40406095` |
| Bkav | `W32.Malware.3F16D234` |
| CTX | `exe.trojan.reconyc` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen33.38280` |
| ESET-NOD32 | `WinGo/Agent.ARU trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Trojan.Generic.40406095 (B)` |
| F-Secure | `Trojan.TR/W64.Malware` |
| Fortinet | `W32/Agent.ARU!tr` |
| GData | `Trojan.Generic.40406095` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 005d1f6f1 )` |
| K7GW | `Trojan ( 005d1f6f1 )` |
| Kaspersky | `Trojan.Win32.Reconyc.pxct` |
| Kingsoft | `Win32.Trojan.Reconyc.pxct` |
| Lionic | `Trojan.Win32.Reconyc.4!c` |
| McAfeeD | `ti!0FB93DBB9525` |
| MicroWorld-eScan | `Trojan.Generic.40406095` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Agent!8.B1E (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.W64.Edhl` |
| TrellixENS | `Artemis!22DA02E41C43` |
| TrendMicro | `Trojan.Win32.RECONYC.USBLHH26` |
| TrendMicro-HouseCall | `Trojan.Win32.RECONYC.USBLHH26` |
| VIPRE | `Trojan.Generic.40406095` |
| Varist | `W64/ABTrojan.QTEQ-5452` |
| alibabacloud | `Trojan:Multi/Wacatac.B9nj` |

### [5a39bd95d430a1093b3d…](https://bazaar.abuse.ch/sample/5a39bd95d430a1093b3d179d100389ee2cf60226518b82e02572f3e25df2f803/)

- **Familie:** NIKRAT
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Cerbu.286514
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Cerbu.286514`

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Cerbu.286514` |
| Arcabit | `Trojan.Cerbu.D45F32` |
| BitDefender 🛡️ | `Gen:Variant.Cerbu.286514` |
| Bkav | `W32.Malware.EC69364A` |
| CTX | `exe.unknown.cerbu` |
| ClamAV | `Win.Trojan.Sliver-10044264-0` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| ESET-NOD32 | `WinGo/Packed.Obfuscated.D suspicious application` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Cerbu.286514 (B)` |
| GData | `Gen:Variant.Cerbu.286514` |
| Kaspersky | `HEUR:Exploit.Win32.BypassUAC.b` |
| McAfeeD | `ti!5A39BD95D430` |
| MicroWorld-eScan | `Gen:Variant.Cerbu.286514` |
| Microsoft 🛡️ | `Trojan:Win32/LummaStealer.DO!MTB` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `CXrep/MalGo-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Cerbu.286514` |

### [912d10cd5eb9a4d9e514…](https://bazaar.abuse.ch/sample/912d10cd5eb9a4d9e514ef2b2343a88265517a4f6dba53df1717ced3d966f131/)

- **Familie:** CoinMiner
- **Erkannt von:** 39 von 75 Engines (52.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (39/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R803284` |
| Antiy-AVL | `Trojan/Win64.GenKryptik` |
| Arcabit | `Trojan.Yogi.D170F6` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.76E603F2` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop43.21635` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Trojan ( 006e7fe11 )` |
| K7GW | `Trojan ( 006e7fe11 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| McAfeeD | `ti!912D10CD5EB9` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Trojan.Kryptik!8.8 (TFE:5:0fgpwDhwvhS)` |
| Sangfor | `Trojan.Win64.Kryptik.V2ai` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16007672` |
| TrendMicro | `Trojan.Win64.YOGI.TL0101JS26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win64.YOGI.TL0101JS26ZZ` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Varist | `W64/ABTrojan.YHEY-5989` |
| Webroot | `W32.Malware.Gen` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Antiy-AVL | `Trojan/Win32.SalatStealer` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.62046A21` |
| CTX | `exe.trojan.lummastealer` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent.VO trojan` |
| Elastic | `Multi.Generic.Threat` |
| Emsisoft | `Trojan.LummaStealer.103 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `W32/Agent.VO!tr` |
| GData | `Trojan.LummaStealer.103` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **elf** (37×)
- **Mirai** (23×)
- **exe** (22×)
- **upx-dec** (12×)
- **upx** (12×)
- **NIKRAT** (12×)
- **rat** (12×)
- **Torii** (9×)
- **honeypot** (8×)
- **cowrie** (6×)
- **Prometei** (5×)
- **CoinMiner** (3×)
- **signed** (3×)
- **voidlink** (3×)
- **dota3** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +11 (18→29)
- ↓ **unbekannt** -23 (38→15)
- neu: **NIKRAT** (12)
- ↑ **CoinMiner** +2 (1→3)
- neu: **VoidLink** (3)
- neu: **Tedy** (1)
- neu: **AgentTesla** (1)
- neu: **Arechclient2** (1)
- neu: **Formbook** (1)
- neu: **NanoCore** (1)
- weg: **KATARU** (war 3)
- weg: **WannaCry** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +7 (22→29)
- ↓ **unbekannt** -8 (23→15)
- neu: **NIKRAT** (12)
- ↑ **CoinMiner** +2 (1→3)
- neu: **VoidLink** (3)
- neu: **Tedy** (1)
- neu: **Arechclient2** (1)
- neu: **NanoCore** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.403 MB |
| σ Dateigröße | 7.968 MB |
| Ø Risiko-Score | 68.7/100 |
| Ø Klassifikations-Konfidenz | 74.7% |
| Samples mit VT | 5/70 |
| Samples mit MITRE | 30/70 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 4 (5.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:35 | [9c5c9a361e4f…](https://bazaar.abuse.ch/sample/9c5c9a361e4ff93de152a00a451410db8c24633abdb9bbad4da4bd4c47905511/) | `elf` | Mirai | 83.3 | – | – | 🇳🇱NL |
| 17:34 | [2404b5520fa1…](https://bazaar.abuse.ch/sample/2404b5520fa1205f2bccf7a98d35268ac09772b258f4133f0269975d489a8aa9/) | `elf` | Mirai | 83.3 | – | – | 🇩🇪DE |
| 17:17 | [f9c8040767c9…](https://bazaar.abuse.ch/sample/f9c8040767c9193c44993e7a13ea3275aa4901ea1219c49a0a19955eac6352f1/) | `gz` | unbekannt | 31.2 | – | – | 🇬🇧GB |
| 17:17 | [e3c3827ca3d4…](https://bazaar.abuse.ch/sample/e3c3827ca3d406d5f9e050593c052f5249e39add3cdfdaa1e9186e8bfe3bd68c/) | `gz` | unbekannt | 31.2 | – | – | 🇬🇧GB |
| 17:00 | [3d4135f74f28…](https://bazaar.abuse.ch/sample/3d4135f74f288541d72b716e5bb6edaa266904df94edb005c5c13203e9f09f4b/) | `exe` | unbekannt | 37.4 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 30.10.2026 19:02 UTC*