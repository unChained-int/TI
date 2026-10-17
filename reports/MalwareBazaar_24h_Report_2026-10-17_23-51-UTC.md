# MalwareBazaar – 17.10.2026 23:51 UTC

Dieser Run hat **53 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **54** |
| Kritisch (≥75) | **35** |
| Höchster Score | **96.4/100** – a576ee22dec4bc97… |
| Häufigste Familie | **unbekannt** (39x) |
| Häufigster Typ | **exe** (37x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 8 Samples |
| Ø Dateigröße | 5.52 MB (σ=15.60) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 37 | 68.5%  █████████████ |
| `elf` | 10 | 18.5%  ███ |
| `jar` | 4 | 7.4%  █ |
| `iso` | 1 | 1.9%   |
| `sh` | 1 | 1.9%   |
| `ps1` | 1 | 1.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 39 | 72.2% |
| 2 | Mirai | 6 | 11.1% |
| 3 | WannaCry | 2 | 3.7% |
| 4 | RemusStealer | 1 | 1.9% |
| 5 | RustyStealer | 1 | 1.9% |
| 6 | Win64:Evo-gen [Trj] | 1 | 1.9% |
| 7 | Stealer | 1 | 1.9% |
| 8 | Barys | 1 | 1.9% |
| 9 | RevStealer | 1 | 1.9% |
| 10 | RemcosRAT | 1 | 1.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 26 | 48.1% | 75% |
| Windows-Malware | 6 | 11.1% | 35% |
| Botnet/IoT | 6 | 11.1% | 95% |
| Andere / Unbekannt | 4 | 7.4% | 20% |
| Linux-Malware | 4 | 7.4% | 45% |
| Loader | 3 | 5.6% | 75% |
| Ransomware | 2 | 3.7% | 95% |
| Trojaner | 1 | 1.9% | 65% |
| Skript/Dropper | 1 | 1.9% | 35% |
| RAT | 1 | 1.9% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 35 | 64.8% |
| 🟠 HOCH | 4 | 7.4% |
| 🟡 MITTEL | 11 | 20.4% |
| 🟢 NIEDRIG | 4 | 7.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a576ee22dec4bc…](https://bazaar.abuse.ch/sample/a576ee22dec4bc97fc6082d0dd9c30a582cd0f8aa35ab97d153843f3fac41ff6/) | WannaCry | Ransomware | **96.4** | 🔴 KRITISCH | – | – | ? |
| [a45d9932f01bc4…](https://bazaar.abuse.ch/sample/a45d9932f01bc4fd5fe80558464fcb6848c025483acf5c1c7519d5471abecce4/) | WannaCry | Ransomware | **95.7** | 🔴 KRITISCH | – | – | ? |
| [317961c5a931f9…](https://bazaar.abuse.ch/sample/317961c5a931f95d343d76898a161396baddb7ef1c5d8984d968c8e858d9ccfa/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [d44e6faaf3df35…](https://bazaar.abuse.ch/sample/d44e6faaf3df358593a29faace64a071ab8de0a84c30a5232d8e9081dd668f1b/) | RemusStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [03b5b30c54ea39…](https://bazaar.abuse.ch/sample/03b5b30c54ea39c15b688bca277f2656bf3b755ee1041930830e35f03826759b/) | Mirai | Botnet/IoT | **81.9** | 🔴 KRITISCH | – | – | ? |
| [836074a16c5a67…](https://bazaar.abuse.ch/sample/836074a16c5a67abace8d201753c4c6c4b53980cb8db60f9c569c9378a124853/) | Mirai | Botnet/IoT | **81.9** | 🔴 KRITISCH | – | – | ? |
| [4c3390e7e98e8a…](https://bazaar.abuse.ch/sample/4c3390e7e98e8ae3b46cbd34499a01b7f24bcf934c65d6733bfc93fda3eaa26c/) | RustyStealer | Infostealer | **81.8** | 🔴 KRITISCH | – | – | ? |
| [eab6414636c0f1…](https://bazaar.abuse.ch/sample/eab6414636c0f13c46ea0dfa7172f113d8523e308b35f7b8cf61b958ff92abda/) | Mirai | Botnet/IoT | **81.8** | 🔴 KRITISCH | – | – | ? |
| [9586450399d251…](https://bazaar.abuse.ch/sample/9586450399d2511dc71bd9849dac444a8fadbe46a1052ae3da1abb7cc01596dc/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | – | – | ? |
| [ea2cd2b36208f1…](https://bazaar.abuse.ch/sample/ea2cd2b36208f12d2f7654203056104f06d9a9e45c0ddaaa7e48e0ec071401b6/) | unbekannt | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6027/7453 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6027/7453 |
| 3 | ESET-NOD32 | 77.4% | 5770/7453 |
| 4 | Kaspersky | 76.3% | 5687/7452 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5324/7450 |
| 8 | Rising | 68.7% | 5119/7453 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4941/7449 |
| 11 | Tencent | 65.3% | 4717/7227 |
| 12 | Avast | 65.1% | 4851/7449 |
| 13 | AVG | 65.1% | 4851/7448 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4562/7446 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 38 | 70.4% |
| 🐧 Linux | 11 | 20.4% |
| ❓ Unbekannt | 4 | 7.4% |
| 📦 Archiv | 1 | 1.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 48 | 88.9% |
| C2 / Nachladen | 3 | 5.6% |
| Exploit / N-Day | 2 | 3.7% |
| MaaS-Loader | 1 | 1.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 34 | 63.0% |
| 2 | 🇩🇪 DE | 9 | 16.7% |
| 3 | 🇭🇺 HU | 5 | 9.3% |
| 4 | 🇬🇧 GB | 3 | 5.6% |
| 5 | 🇫🇷 FR | 1 | 1.9% |
| 6 | 🇳🇱 NL | 1 | 1.9% |
| 7 | 🌐 Unbekannt | 1 | 1.9% |

## MITRE ATT&CK

> 8 von 54 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 6 |
| Lateral Movement | 6 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>317961c5a931f95d343d… – Mirai | 🔴 KRITISCH 82.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>03b5b30c54ea39c15b68… – Mirai | 🔴 KRITISCH 81.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [001abd3521887936846c…](https://bazaar.abuse.ch/sample/001abd3521887936846c0739c6fb31752660bda3f66d89bb6764916891c3a7fb/)

- **Familie:** Win64:Evo-gen [Trj]
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.E3514453` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| ESET-NOD32 | `Win64/Kryptik.HRN trojan` |
| Elastic | `malicious (moderate confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!001ABD352188` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.95 (RDML:aygJtW3c47/aVPdFlY5R3g)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |

### [117af8ad60c5dde54a7e…](https://bazaar.abuse.ch/sample/117af8ad60c5dde54a7e9d12d6fd5f921ae59fcae3c782a2d7da200484dc8512/)

- **Familie:** Stealer
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Stealer.996
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Stealer.996`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Stealer.996` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R801231` |
| Antiy-AVL | `Trojan/Win64.Kryptik` |
| Arcabit | `Trojan.Stealer.996` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Stealer.996` |
| Bkav | `W32.Malware.54990CB1` |
| CTX | `dll.unknown.stealer` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/Kryptik_AGen.AUA trojan` |
| Emsisoft | `Gen:Variant.Stealer.996 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/MALD2.49FA!tr` |
| GData | `Gen:Variant.Stealer.996` |
| K7AntiVirus | `Trojan ( 006e7d7c1 )` |
| K7GW | `Trojan ( 006e7d7c1 )` |
| Malwarebytes | `Generic.Trojan.Crypt.DDS` |
| MicroWorld-eScan | `Gen:Variant.Stealer.996` |
| Trapmine | `malicious.high.ml.score` |
| VIPRE | `Gen:Variant.Stealer.996` |

### [e273eb678b8ce2eb5c48…](https://bazaar.abuse.ch/sample/e273eb678b8ce2eb5c486bb0541dba0290b005e1648e900d5a7b9200c846545b/)

- **Familie:** Barys
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Barys.509205
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Barys.509205`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Barys.509205` |
| APEX | `Malicious` |
| Arcabit | `Trojan.Barys.D7C515` |
| BitDefender 🛡️ | `Gen:Variant.Barys.509205` |
| Bkav | `W32.Malware.F0E81FE6` |
| CTX | `exe.unknown.barys` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Spy.Agent.ADK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Barys.509205 (B)` |
| GData | `Gen:Variant.Barys.509205` |
| Gridinsoft | `Trojan.Heur!.02212023` |
| McAfeeD | `ti!E273EB678B8C` |
| MicroWorld-eScan | `Gen:Variant.Barys.509205` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.82 (RDML:8/XwG0NIhmDlCHYBAT87PA)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.high.ml.score` |
| VIPRE | `Gen:Variant.Barys.509205` |

### [efcbc902526573131b2d…](https://bazaar.abuse.ch/sample/efcbc902526573131b2d6380639263df3af40de5eef0188957995e62deab4162/)

- **Familie:** Mirai
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-AIN [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-AIN [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avast | `ELF:Agent-AIN [PUP]` |
| Avira | `PUA/LINUX.Agent.AIN` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/DDoS.Agent.LJ trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.AIN` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Trojan.Linux.Mirai.gen` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.Gfyra` |
| huorong | `Trojan/Linux.DDos.do` |

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

- **exe** (36×)
- **stealer** (21×)
- **DvnX** (19×)
- **YapStealer** (19×)
- **unpacked** (18×)
- **WardenStealer** (18×)
- **elf** (10×)
- **Mirai** (6×)
- **jar** (4×)
- **dropped-by-GCleaner** (2×)
- **signed** (2×)
- **wardenstealer** (2×)
- **dionaea** (2×)
- **WannaCry** (2×)
- **java** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +12 (27→39)
- ↓ **Mirai** -34 (40→6)
- neu: **WannaCry** (2)
- neu: **RemusStealer** (1)
- neu: **RustyStealer** (1)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Stealer** (1)
- neu: **Barys** (1)
- neu: **RevStealer** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +12 (27→39)
- ↓ **Mirai** -22 (28→6)
- neu: **WannaCry** (2)
- neu: **RustyStealer** (1)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Stealer** (1)
- neu: **Barys** (1)
- neu: **RevStealer** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.524 MB |
| σ Dateigröße | 15.602 MB |
| Ø Risiko-Score | 68.1/100 |
| Ø Klassifikations-Konfidenz | 66.7% |
| Samples mit VT | 5/54 |
| Samples mit MITRE | 8/54 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 4 (7.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:32 | [c11c781c7051…](https://bazaar.abuse.ch/sample/c11c781c7051b68fb5b9a9daad209f9ac57711a3f4888bbdf6c64f3fc0239ef9/) | `exe` | unbekannt | 38.8 | – | – | 🇺🇸US |
| 23:28 | [d44e6faaf3df…](https://bazaar.abuse.ch/sample/d44e6faaf3df358593a29faace64a071ab8de0a84c30a5232d8e9081dd668f1b/) | `exe` | RemusStealer | 81.9 | – | – | 🇺🇸US |
| 23:23 | [65e3040b6a66…](https://bazaar.abuse.ch/sample/65e3040b6a661522654f00095964996359b856c50672610e70ec0a2b85c1ad89/) | `exe` | unbekannt | 38.7 | – | – | 🇺🇸US |
| 23:20 | [4c3390e7e98e…](https://bazaar.abuse.ch/sample/4c3390e7e98e8ae3b46cbd34499a01b7f24bcf934c65d6733bfc93fda3eaa26c/) | `exe` | RustyStealer | 81.8 | – | – | 🇫🇷FR |
| 23:10 | [001abd352188…](https://bazaar.abuse.ch/sample/001abd3521887936846c0739c6fb31752660bda3f66d89bb6764916891c3a7fb/) | `exe` | Win64:Evo-gen [Trj] | 80.6 | 24.0% | 🟡 SCHWACH ERKANNT | 🇬🇧GB |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 23:51 UTC*