# MalwareBazaar – 18.10.2026 20:18 UTC

Dieser Run hat **21 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **22** |
| Kritisch (≥75) | **8** |
| Höchster Score | **83.5/100** – 9d8343d6b28777c2… |
| Häufigste Familie | **unbekannt** (13x) |
| Häufigster Typ | **elf** (11x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 8 Samples |
| Ø Dateigröße | 2.17 MB (σ=5.00) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 11 | 50.0%  ██████████ |
| `exe` | 8 | 36.4%  ███████ |
| `macho` | 2 | 9.1%  █ |
| `sh` | 1 | 4.5%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 13 | 59.1% |
| 2 | Mirai | 6 | 27.3% |
| 3 | RemusStealer | 1 | 4.5% |
| 4 | Malware | 1 | 4.5% |
| 5 | RemcosRAT | 1 | 4.5% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 6 | 27.3% | 95% |
| Linux-Malware | 5 | 22.7% | 45% |
| Andere / Unbekannt | 3 | 13.6% | 20% |
| Loader | 3 | 13.6% | 75% |
| Windows-Malware | 2 | 9.1% | 35% |
| Infostealer | 2 | 9.1% | 75% |
| RAT | 1 | 4.5% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 8 | 36.4% |
| 🟠 HOCH | 5 | 22.7% |
| 🟡 MITTEL | 6 | 27.3% |
| 🟢 NIEDRIG | 3 | 13.6% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [9d8343d6b28777…](https://bazaar.abuse.ch/sample/9d8343d6b28777c2d928150bfc83b34e82287a0705768521ea124d9c1078afb9/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [f05cb4c094229e…](https://bazaar.abuse.ch/sample/f05cb4c094229ea4ff59f8667a7cdebfc30b37a82957ec6e6c21d5dfd9d008f0/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [25deb931edba42…](https://bazaar.abuse.ch/sample/25deb931edba425f47c120d7b617891c8458d4742bfc340ac32b17afdbe678c1/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [1dbd6db7e099b2…](https://bazaar.abuse.ch/sample/1dbd6db7e099b2a759db8a464c9f2147412e26b6ed709e26b0358b6cd96f40e3/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [60f95eedea80f6…](https://bazaar.abuse.ch/sample/60f95eedea80f695d8b980b541aa1b79f739294384d1baabf4306413ead3e3be/) | Malware | Infostealer | **82.4** | 🔴 KRITISCH | 14.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [300c08087c2bca…](https://bazaar.abuse.ch/sample/300c08087c2bca4f04e0786ffe2e46b44d2e36124cc21253e0ca9273cb8fbb90/) | RemusStealer | Infostealer | **81.2** | 🔴 KRITISCH | – | – | ? |
| [c1bc3745b3100e…](https://bazaar.abuse.ch/sample/c1bc3745b3100e847acbcda750d4885c096b4d0bae72eb87b0222fc0eee6b052/) | Mirai | Botnet/IoT | **80.7** | 🔴 KRITISCH | 25.3% | 🟡 SCHWACH ERKANNT | ✗ |
| [efa96afac6f6d7…](https://bazaar.abuse.ch/sample/efa96afac6f6d74b607902c0f75b334d42ef5150b675ac228aaae01a42ef1e40/) | Mirai | Botnet/IoT | **79.4** | 🔴 KRITISCH | 33.3% | 🟡 SCHWACH ERKANNT | ✓ |
| [f383629ce62c7e…](https://bazaar.abuse.ch/sample/f383629ce62c7e9a2ba85ae2a2f1a884bb435debb5c5db015ed6c2ae13691871/) | unbekannt | Loader | **74.2** | 🟠 HOCH | – | – | ? |
| [3bc0681c243e8d…](https://bazaar.abuse.ch/sample/3bc0681c243e8d68365d246aea4ebb351dba1d7d753b134d98d48d8a0018e42d/) | unbekannt | Loader | **74.0** | 🟠 HOCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6046/7476 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6046/7476 |
| 3 | ESET-NOD32 | 77.4% | 5787/7476 |
| 4 | Kaspersky | 76.3% | 5705/7475 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5339/7473 |
| 8 | Rising | 68.7% | 5136/7476 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4952/7472 |
| 11 | Tencent | 65.3% | 4731/7250 |
| 12 | Avast | 65.2% | 4869/7472 |
| 13 | AVG | 65.2% | 4869/7471 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4575/7469 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 12 | 54.5% |
| 🪟 Windows | 8 | 36.4% |
| 🍎 macOS | 2 | 9.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 19 | 86.4% |
| C2 / Nachladen | 3 | 13.6% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 11 | 50.0% |
| 2 | 🇩🇪 DE | 7 | 31.8% |
| 3 | 🇳🇱 NL | 3 | 13.6% |
| 4 | 🌐 Unbekannt | 1 | 4.5% |

## MITRE ATT&CK

> 8 von 22 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 6 |
| Lateral Movement | 6 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>9d8343d6b28777c2d928… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>f05cb4c094229ea4ff59… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>25deb931edba425f47c1… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1dbd6db7e099b2a759db… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f0978d161433b3100de3…](https://bazaar.abuse.ch/sample/f0978d161433b3100de3b086fd47afe0efa50a51d7f0faef027ee0657c1fd796/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

### [efa96afac6f6d74b6079…](https://bazaar.abuse.ch/sample/efa96afac6f6d74b607902c0f75b334d42ef5150b675ac228aaae01a42ef1e40/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Generic.40654269
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40654269`

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40654269` |
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Arcabit | `Trojan.Generic.D26C55BD` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| BitDefender 🛡️ | `Trojan.Generic.40654269` |
| CTX | `elf.trojan.generic` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Tool.Linux.Exploit.88` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.I trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| Emsisoft | `Trojan.Generic.40654269 (B)` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| GData | `Trojan.Generic.40654269` |
| Kaspersky | `HEUR:Exploit.Linux.DirtyFrag.c` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| MicroWorld-eScan | `Trojan.Generic.40654269` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.Ntdra` |
| VIPRE | `Trojan.Generic.40654269` |
| huorong | `Exploit/Linux.DirtyFrag.a!crit` |

### [60f95eedea80f695d8b9…](https://bazaar.abuse.ch/sample/60f95eedea80f695d8b980b541aa1b79f739294384d1baabf4306413ead3e3be/)

- **Familie:** Malware
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.2B9C9F0B
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Bkav | `W32.Malware.2B9C9F0B` |
| ESET-NOD32 | `Win64/Injector.AOT trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!60F95EEDEA80` |
| Rising | `Trojan.Kryptik@AI.95 (RDML:syCkfQ9ehUXORYeoBnO4Jg)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Webroot | `Win.Trojan.Gen` |

### [c1bc3745b3100e847acb…](https://bazaar.abuse.ch/sample/c1bc3745b3100e847acbcda750d4885c096b4d0bae72eb87b0222fc0eee6b052/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2021-36260-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2021-36260-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2021-36260-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2021-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10760` |
| ESET-NOD32 | `Linux/Mirai.FNB trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2021-.A` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Trojan/Linux.Mirai.f` |

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

- **elf** (8×)
- **exe** (7×)
- **Mirai** (6×)
- **AMOS** (2×)
- **ClickFix** (2×)
- **Mach-O** (2×)
- **macho** (2×)
- **macOS** (2×)
- **dropped-by-GCleaner** (2×)
- **wraith** (1×)
- **Foxveil** (1×)
- **d52f85** (1×)
- **dropped-by-Amadey** (1×)
- **Remus** (1×)
- **RemusStealer** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -14 (27→13)
- ↓ **Mirai** -16 (22→6)
- neu: **Malware** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -14 (27→13)
- ↓ **Mirai** -21 (27→6)
- neu: **Malware** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.174 MB |
| σ Dateigröße | 5.003 MB |
| Ø Risiko-Score | 61.1/100 |
| Ø Klassifikations-Konfidenz | 63.4% |
| Samples mit VT | 5/22 |
| Samples mit MITRE | 8/22 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 3 (13.6%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:16 | [2d29b6ca233a…](https://bazaar.abuse.ch/sample/2d29b6ca233a505d01e7d48bd0055a7cd2fd8c590d7e9bd132b8e9b55891c826/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 20:16 | [4124a486bff5…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 20:16 | [f0978d161433…](https://bazaar.abuse.ch/sample/f0978d161433b3100de3b086fd47afe0efa50a51d7f0faef027ee0657c1fd796/) | `elf` | unbekannt | 59.0 | 0.0% | ⚠️ KAUM ERKANNT | 🇳🇱NL |
| 20:16 | [2a98267c76bf…](https://bazaar.abuse.ch/sample/2a98267c76bf359f8fd5445f38c485d795b61d4082cd83791059ddb5c6a9698e/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 20:15 | [dfb27e3e2196…](https://bazaar.abuse.ch/sample/dfb27e3e219613753b8863632ac2eb22c8efcefffef84793711f7dca1ce4cd4a/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.10.2026 20:18 UTC*