# MalwareBazaar – 19.10.2026 19:43 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **39** |
| Höchster Score | **89.5/100** – 379a2944024fe73f… |
| Häufigste Familie | **unbekannt** (58x) |
| Häufigster Typ | **elf** (37x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 31 Samples |
| Ø Dateigröße | 3.43 MB (σ=8.02) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 37 | 36.6%  ███████ |
| `exe` | 27 | 26.7%  █████ |
| `jar` | 15 | 14.9%  ██ |
| `sh` | 13 | 12.9%  ██ |
| `msi` | 5 | 5.0%   |
| `zip` | 2 | 2.0%   |
| `macho` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 58 | 57.4% |
| 2 | Mirai | 21 | 20.8% |
| 3 | Prometei | 8 | 7.9% |
| 4 | RemusStealer | 2 | 2.0% |
| 5 | Vidar | 2 | 2.0% |
| 6 | Blackmoon | 2 | 2.0% |
| 7 | AMOS | 2 | 2.0% |
| 8 | Gafgyt | 2 | 2.0% |
| 9 | Formbook | 1 | 1.0% |
| 10 | RatonRAT | 1 | 1.0% |
| 11 | SalatStealer | 1 | 1.0% |
| 12 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 24 | 23.8% | 20% |
| Botnet/IoT | 23 | 22.8% | 95% |
| Infostealer | 14 | 13.9% | 82% |
| Windows-Malware | 13 | 12.9% | 35% |
| Linux-Malware | 12 | 11.9% | 45% |
| Loader | 10 | 9.9% | 75% |
| Trojaner | 4 | 4.0% | 65% |
| RAT | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 39 | 38.6% |
| 🟠 HOCH | 13 | 12.9% |
| 🟡 MITTEL | 25 | 24.8% |
| 🟢 NIEDRIG | 24 | 23.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [379a2944024fe7…](https://bazaar.abuse.ch/sample/379a2944024fe73ff4af0d02eeb4764918f3009aa236207e0edd616cbfb84ccc/) | Vidar | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [0d8f1752831cd4…](https://bazaar.abuse.ch/sample/0d8f1752831cd45fbf6e4786cfd7e36997ab9835efdcfb7950b1db52e59f63f2/) | Vidar | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [7306389f13becd…](https://bazaar.abuse.ch/sample/7306389f13becd510de6c1a5cafc5012200394fd48d9735b55d421dbfc2ccf29/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [2c555676092b25…](https://bazaar.abuse.ch/sample/2c555676092b2589b17bce425ea8406b68456011e9f21fe6d87382ac08106bf2/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [cf28f44cfec738…](https://bazaar.abuse.ch/sample/cf28f44cfec7384cd572f5457a2d7e4a09fd72f7a29264393961fa4493b29c19/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [1c42d0dcc75b8e…](https://bazaar.abuse.ch/sample/1c42d0dcc75b8e43749b4b9d243ab63eb2bda47597640349f5eabe99c47b9ebb/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [0f96b9023d2e29…](https://bazaar.abuse.ch/sample/0f96b9023d2e29858e14d720b58eec4c3a7eb0ace253c24c88a3114f110576c2/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [099e3632e7f748…](https://bazaar.abuse.ch/sample/099e3632e7f7489d98c58ebcf7250daedca67459b1853e9e1c7f6343e4536fea/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [810ca411ac18c8…](https://bazaar.abuse.ch/sample/810ca411ac18c898fed72098881bc4b76c5b361d3d672f47a9eecf11aa4c3e44/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [76d4f71afaa6e8…](https://bazaar.abuse.ch/sample/76d4f71afaa6e81b07c3e634e7d2a29540179fd7e096f4bb7fd16c2272c56ea4/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6065/7496 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6065/7496 |
| 3 | ESET-NOD32 | 77.4% | 5801/7496 |
| 4 | Kaspersky | 76.3% | 5717/7495 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5356/7493 |
| 8 | Rising | 68.7% | 5150/7496 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4965/7492 |
| 11 | Tencent | 65.2% | 4742/7270 |
| 12 | Avast | 65.2% | 4883/7492 |
| 13 | AVG | 65.2% | 4883/7491 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4587/7489 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 50 | 49.5% |
| 🪟 Windows | 32 | 31.7% |
| ❓ Unbekannt | 15 | 14.9% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 83 | 82.2% |
| C2 / Nachladen | 11 | 10.9% |
| Trojanisierte Software | 5 | 5.0% |
| MaaS-Loader | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 50 | 49.5% |
| 2 | 🌐 DK | 15 | 14.9% |
| 3 | 🇩🇪 DE | 14 | 13.9% |
| 4 | 🇳🇱 NL | 10 | 9.9% |
| 5 | 🇫🇷 FR | 7 | 6.9% |
| 6 | 🌐 PT | 2 | 2.0% |
| 7 | 🇨🇭 CH | 1 | 1.0% |
| 8 | 🌐 EG | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 31 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 21 |
| Lateral Movement | 21 |
| Credential Access | 7 |
| Collection | 7 |
| Exfiltration | 6 |
| Execution | 3 |
| Persistence | 3 |

<details><summary>379a2944024fe73ff4af… – Vidar | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>0d8f1752831cd45fbf6e… – Vidar | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>7306389f13becd510de6… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d6d16e69a38f871d1860…](https://bazaar.abuse.ch/sample/d6d16e69a38f871d1860b9dbfa6250dc64705a63c7d2ab17404f6aed5428797f/)

- **Familie:** Prometei
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.Variadic.Prometei.A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.Variadic.Prometei.A`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Bd]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5738937` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Prometei` |
| Arcabit | `Trojan.Variadic.Prometei.A` |
| Avast | `Win32:MalwareX-gen [Bd]` |
| Avira | `TR/Crypt.FKM.Gen` |
| BitDefender 🛡️ | `Gen:Heur.Variadic.Prometei.A` |
| Bkav | `W32.Malware.F07799F9` |
| CAT-QuickHeal | `Trojan.Prometei.S36755234` |
| CTX | `exe.unknown.prometei` |
| ClamAV | `Win.Trojan.Prometei-8977166-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Siggen2.5729` |
| ESET-NOD32 | `Win32/Agent.AHGC trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.Variadic.Prometei.A (B)` |
| F-Secure | `Trojan.TR/Crypt.FKM.Gen` |
| Fortinet | `W32/Agent.AHGC!tr` |
| GData | `Gen:Heur.Variadic.Prometei.A` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Heur!.03812021` |
| Ikarus | `Trojan.Crypt` |
| Jiangmin | `Backdoor.Prometei.b` |
| K7AntiVirus | `Trojan ( 005c3ccc1 )` |
| K7GW | `Trojan ( 005c3ccc1 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Prometei.gen` |
| Kingsoft | `malware.kb.a.1000` |
| Malwarebytes | `Trojan.BitCoinMiner` |
| MaxSecure | `Downloader.W32.Agent.pef` |
| McAfeeD | `Real Protect-LS!FAC7BEBB1C1A` |
| MicroWorld-eScan | `Gen:Heur.Variadic.Prometei.A` |
| Microsoft 🛡️ | `Trojan:Win32/Prometei.CCIR!MTB` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.Prometei!1.DBEA (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Prometei` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Prometei-R` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Prometei.16002171` |
| Trapmine | `malicious.high.ml.score` |
| TrendMicro | `Backdoor.Win32.PROMETEI.SMPI` |
| TrendMicro-HouseCall | `Backdoor.Win32.PROMETEI.SMPI` |
| VBA32 | `BScope.TrojanDownloader.Agent` |
| VIPRE | `Gen:Heur.Variadic.Prometei.A` |
| Varist | `W32/Trojan.VGFZ-0267` |
| VirIT | `Backdoor.Win32.GenusC.JAY` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.Agent!6YTdzWgL7mU` |
| ZoneAlarm | `Troj/Prometei-R` |
| huorong | `Trojan/Prometei.a` |

### [ba3fa558b99fa654f5d6…](https://bazaar.abuse.ch/sample/ba3fa558b99fa654f5d69fb167540836c0951cf224642738ce466fbbe243323f/)

- **Familie:** Prometei
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.6
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.6`

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.6` |
| AhnLab-V3 | `CoinMiner/Linux.Generic.XE253` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.6` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.6` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045451-0` |
| DrWeb | `Linux.Siggen.8940` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Trojan.Linux.Prometei.6 (B)` |
| GData | `Trojan.Linux.Prometei.6` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Jiangmin | `Backdoor.Linux.jhzw` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.6` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.6` |
| huorong | `Trojan/Prometei.c` |

### [39ca53514fe587c11e21…](https://bazaar.abuse.ch/sample/39ca53514fe587c11e2156b2480ad121f7c938cafa723bfb3512f72a8f3d3fae/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9806` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.DJ.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.ab` |

### [2f8422e3a352e22a07d3…](https://bazaar.abuse.ch/sample/2f8422e3a352e22a07d36e7b47ee491d1f77b129ddd0d570ba0a4b727ed93742/)

- **Familie:** Prometei
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.D
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.D`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.D` |
| AVG | `ELF:Prometei-A [Trj]` |
| AhnLab-V3 | `Trojan/Linux.Prometei.SE260` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.D` |
| Avast | `ELF:Prometei-A [Trj]` |
| Avira | `EXP/ELF.Agent.L.22` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.D` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-9992782-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Siggen.4460` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Trojan.Linux.Prometei.D (B)` |
| F-Secure | `Exploit.EXP/ELF.Agent.L.22` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Prometei.D` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Jiangmin | `Backdoor.Linux.hmdw` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.D` |
| Microsoft 🛡️ | `Trojan:Linux/Prometei!MTB` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Sophos | `Linux/Bdoor-BIT` |
| Tencent | `Backdoor.Linux.Prometei.ga` |
| VBA32 | `Trojan.Linux.Mirai` |
| VIPRE | `Trojan.Linux.Prometei.D` |
| Varist | `E64/PrometeiS.B` |
| Zillya | `Trojan.Prometei.Linux.26` |
| ZoneAlarm | `Linux/Bdoor-BIT` |
| alibabacloud | `Miner:Win/Prometei.35eca64e` |
| huorong | `Trojan/Prometei.f` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| Varist | `W64/ABTrojan.ANKV-0822` |


## Top Tags

- **elf** (36×)
- **honeypot** (32×)
- **exe** (26×)
- **Mirai** (19×)
- **jar** (16×)
- **java** (15×)
- **sh** (12×)
- **python** (10×)
- **silentnet** (10×)
- **Prometei** (8×)
- **stealer** (6×)
- **upx-dec** (6×)
- **upx** (6×)
- **msi** (5×)
- **dropped-by-Vidar** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +36 (22→58)
- ↑ **Mirai** +6 (15→21)
- neu: **Prometei** (8)
- neu: **RemusStealer** (2)
- neu: **Vidar** (2)
- neu: **Blackmoon** (2)
- neu: **Gafgyt** (2)
- neu: **RatonRAT** (1)
- weg: **ValleyRAT** (war 2)
- weg: **BlakcSeeStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +31 (27→58)
- ↓ **Mirai** -3 (24→21)
- neu: **Prometei** (8)
- ↑ **RemusStealer** +1 (1→2)
- ↑ **Vidar** +1 (1→2)
- neu: **Blackmoon** (2)
- ↑ **AMOS** +1 (1→2)
- neu: **Gafgyt** (2)
- ↓ **Formbook** -1 (2→1)
- neu: **RatonRAT** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.435 MB |
| σ Dateigröße | 8.023 MB |
| Ø Risiko-Score | 58.0/100 |
| Ø Klassifikations-Konfidenz | 58.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 31/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 24 (23.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:41 | [f2e8327e5d3e…](https://bazaar.abuse.ch/sample/f2e8327e5d3e7b1d22c524f4d2c884a9c8db374c082ef96b9c70aaf4170736a2/) | `elf` | unbekannt | 43.4 | – | – | 🇺🇸US |
| 19:35 | [1c42d0dcc75b…](https://bazaar.abuse.ch/sample/1c42d0dcc75b8e43749b4b9d243ab63eb2bda47597640349f5eabe99c47b9ebb/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 19:34 | [472585a29d62…](https://bazaar.abuse.ch/sample/472585a29d62e4c6affbe21a8877eb180e13a081bbce2340800c5b7782a82259/) | `jar` | unbekannt | 82.1 | – | – | 🌐DK |
| 19:33 | [fb354e81e831…](https://bazaar.abuse.ch/sample/fb354e81e8315c1c664b63320a691e1e050446939389066e2aae245b4ae8a407/) | `jar` | unbekannt | 82.1 | – | – | 🌐DK |
| 19:31 | [9ee13f622abc…](https://bazaar.abuse.ch/sample/9ee13f622abc1b57cd30d78db6a25d45b8bf76ce771133ea3f2e233c17917b9e/) | `elf` | unbekannt | 43.2 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.10.2026 19:43 UTC*