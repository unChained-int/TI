# MalwareBazaar – 17.10.2026 13:31 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **67** |
| Höchster Score | **84.9/100** – ad24c5b1aeda0f42… |
| Häufigste Familie | **Mirai** (62x) |
| Häufigster Typ | **elf** (79x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 63 Samples |
| Ø Dateigröße | 1.42 MB (σ=3.54) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 79 | 78.2%  ███████████████ |
| `exe` | 14 | 13.9%  ██ |
| `jar` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |
| `py` | 2 | 2.0%   |
| `php` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 62 | 61.4% |
| 2 | unbekannt | 34 | 33.7% |
| 3 | SalatStealer | 2 | 2.0% |
| 4 | RemusStealer | 1 | 1.0% |
| 5 | Trojan.GenericKD.81732442 | 1 | 1.0% |
| 6 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 62 | 61.4% | 95% |
| Linux-Malware | 17 | 16.8% | 45% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Loader | 5 | 5.0% | 75% |
| Windows-Malware | 4 | 4.0% | 35% |
| Infostealer | 3 | 3.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |
| Android-Malware | 1 | 1.0% | 45% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 67 | 66.3% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 22 | 21.8% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ad24c5b1aeda0f…](https://bazaar.abuse.ch/sample/ad24c5b1aeda0f427fb4e1d47aa8376e0801a0c4231b0e3b8f374b908b61bbc1/) | Mirai | Botnet/IoT | **84.9** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [edafbe411eb7b3…](https://bazaar.abuse.ch/sample/edafbe411eb7b3ebf801de468d8ce9dbd08e0a84da9d0af8aca8668f1840abc7/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [240144652ddca5…](https://bazaar.abuse.ch/sample/240144652ddca5c93ada9f898ebdf6c3f0c66272e17c438ca1c1c8b8b710c5ed/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [5a97ccdebd3ace…](https://bazaar.abuse.ch/sample/5a97ccdebd3aceeee438032c9e264df20ee41d30d1e4b87f5eb04ed05a234387/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [746a0dfeb43ed1…](https://bazaar.abuse.ch/sample/746a0dfeb43ed17010c01fce4a34190316ccc1214db5d15f4d04170615a6d2fd/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [7dc728e4b3a833…](https://bazaar.abuse.ch/sample/7dc728e4b3a8333935be5cbdd83334afc45d4c689645a5951247d9c65e6ffae1/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [873a110b03f48d…](https://bazaar.abuse.ch/sample/873a110b03f48d311d1f86fee91fef027e4fda5c9c2ecbf7a190c75317defb75/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [6bae0c771f80bd…](https://bazaar.abuse.ch/sample/6bae0c771f80bd3c78e132f1c6a72fe0103950da50142e1898ac9a7a44b848db/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [b36ba42a31544a…](https://bazaar.abuse.ch/sample/b36ba42a31544a1abbfb7ddb7ea925db61f031914fe89f8a40dff5d860243b63/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [f2d4898329126e…](https://bazaar.abuse.ch/sample/f2d4898329126e280c1c0845ef4fc19ad9e822622b0c38afe4ec5c74f1228591/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6015/7439 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6015/7439 |
| 3 | ESET-NOD32 | 77.4% | 5757/7439 |
| 4 | Kaspersky | 76.3% | 5678/7438 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5315/7436 |
| 8 | Rising | 68.7% | 5110/7439 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4935/7435 |
| 11 | Tencent | 65.3% | 4709/7213 |
| 12 | Avast | 65.1% | 4840/7435 |
| 13 | AVG | 65.1% | 4840/7434 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4554/7432 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 81 | 80.2% |
| 🪟 Windows | 14 | 13.9% |
| ❓ Unbekannt | 4 | 4.0% |
| 🌐 Web | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 95 | 94.1% |
| C2 / Nachladen | 4 | 4.0% |
| MaaS-Loader | 1 | 1.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 59 | 58.4% |
| 2 | 🇺🇸 US | 16 | 15.8% |
| 3 | 🇳🇱 NL | 16 | 15.8% |
| 4 | 🇦🇹 AT | 6 | 5.9% |
| 5 | 🇷🇴 RO | 2 | 2.0% |
| 6 | 🌐 EG | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 63 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 62 |
| Lateral Movement | 62 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>ad24c5b1aeda0f427fb4… – Mirai | 🔴 KRITISCH 84.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>edafbe411eb7b3ebf801… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>240144652ddca5c93ada… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5a97ccdebd3aceeee438… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>746a0dfeb43ed17010c0… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [cf36268ef12f3c613020…](https://bazaar.abuse.ch/sample/cf36268ef12f3c613020fbb014325e4198739d948de26713444d51401d84cec7/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -1
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [ad24c5b1aeda0f427fb4…](https://bazaar.abuse.ch/sample/ad24c5b1aeda0f427fb4e1d47aa8376e0801a0c4231b0e3b8f374b908b61bbc1/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/DDoS.Agent.LJ trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| ESET-NOD32 | `Linux/DDoS.Agent.LJ trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Trojan.Linux.Mirai.gen` |
| Tencent | `Trojan.Linux.Mirai.Gfyra` |
| huorong | `Trojan/Linux.DDos.do` |

### [be0762741f9bb0512319…](https://bazaar.abuse.ch/sample/be0762741f9bb051231959218ca551a0af4e7d13009c3ee0901ab7cbc258ea4c/)

- **Familie:** Trojan.GenericKD.81732442
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81732442
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81732442`

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81732442` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Arcabit | `Trojan.Generic.D4DF235A` |
| BitDefender 🛡️ | `Trojan.GenericKD.81732442` |
| CTX | `exe.trojan.generic` |
| Emsisoft | `Trojan.GenericKD.81732442 (B)` |
| GData | `Trojan.GenericKD.81732442` |
| Lionic | `Trojan.UKP.Generic.4!c` |
| Malwarebytes | `MachineLearning/Anomalous.97%` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| MicroWorld-eScan | `Trojan.GenericKD.81732442` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| TrellixENS | `Artemis!D60B4B7E40E2` |
| TrendMicro-HouseCall | `Trojan.MSIL.Gen.TL0101JF26Z1` |
| VIPRE | `Trojan.GenericKD.81732442` |
| alibabacloud | `Suspicious` |

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

- **elf** (76×)
- **Mirai** (56×)
- **exe** (13×)
- **upx-dec** (12×)
- **upx** (12×)
- **dropped-by-GCleaner** (4×)
- **A** (3×)
- **Prometei** (2×)
- **psw** (2×)
- **signed** (2×)
- **infostealer** (2×)
- **salat** (2×)
- **salatstealer** (2×)
- **jar** (2×)
- **java** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +35 (27→62)
- ↑ **unbekannt** +5 (29→34)
- neu: **SalatStealer** (2)
- neu: **Trojan.GenericKD.81732442** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +33 (29→62)
- ↑ **unbekannt** +7 (27→34)
- neu: **SalatStealer** (2)
- neu: **Trojan.GenericKD.81732442** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.422 MB |
| σ Dateigröße | 3.539 MB |
| Ø Risiko-Score | 70.0/100 |
| Ø Klassifikations-Konfidenz | 76.6% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 63/101 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 36 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:28 | [75500ccec4a4…](https://bazaar.abuse.ch/sample/75500ccec4a41420572bcb4187dad82b4a072e1116384d9b120628c905821f22/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 13:28 | [e6faa9b088f4…](https://bazaar.abuse.ch/sample/e6faa9b088f4bf2425faebe05b1fce1e3ec3178ebf4d889b655d087a913dd4c9/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 13:24 | [edafbe411eb7…](https://bazaar.abuse.ch/sample/edafbe411eb7b3ebf801de468d8ce9dbd08e0a84da9d0af8aca8668f1840abc7/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 13:22 | [dbc3776087a7…](https://bazaar.abuse.ch/sample/dbc3776087a78b2a0543372171a1986713437db826cf9dbbb83035d8e463ce2a/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 13:22 | [301a497eeca8…](https://bazaar.abuse.ch/sample/301a497eeca8517ff0f4c7924671688f028f686e90d6fcd9a09d424f772857fc/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 13:31 UTC*