# MalwareBazaar – 01.11.2026 21:50 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **73** |
| Höchster Score | **92.5/100** – 41d9eb2f5418181c… |
| Häufigste Familie | **Mirai** (63x) |
| Häufigster Typ | **elf** (65x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 63 Samples |
| Ø Dateigröße | 4.40 MB (σ=13.65) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 65 | 64.4%  ████████████ |
| `msi` | 17 | 16.8%  ███ |
| `exe` | 14 | 13.9%  ██ |
| `sh` | 2 | 2.0%   |
| `ps1` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 63 | 62.4% |
| 2 | LegionLoader | 17 | 16.8% |
| 3 | unbekannt | 7 | 6.9% |
| 4 | ValleyRAT | 3 | 3.0% |
| 5 | SalatStealer | 2 | 2.0% |
| 6 | RemusStealer | 2 | 2.0% |
| 7 | CoinMiner | 2 | 2.0% |
| 8 | Gh0stRAT | 1 | 1.0% |
| 9 | RustyStealer | 1 | 1.0% |
| 10 | SilentNet | 1 | 1.0% |
| 11 | AokigaharaStealer | 1 | 1.0% |
| 12 | WARDENStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 63 | 62.4% | 95% |
| Loader | 20 | 19.8% | 75% |
| Infostealer | 7 | 6.9% | 74% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| RAT | 3 | 3.0% | 75% |
| Cryptominer | 2 | 2.0% | 75% |
| Backdoor | 1 | 1.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Linux-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 73 | 72.3% |
| 🟠 HOCH | 23 | 22.8% |
| 🟡 MITTEL | 2 | 2.0% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [41d9eb2f541818…](https://bazaar.abuse.ch/sample/41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa/) | Gh0stRAT | Backdoor | **92.5** | 🔴 KRITISCH | – | – | ? |
| [1e2e390e13f2ef…](https://bazaar.abuse.ch/sample/1e2e390e13f2efe7176c41ba20837b65001517961c26fcd076e02d77ab98d788/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | 4.0% | ⚠️ KAUM ERKANNT | ✗ |
| [45075a965b00a8…](https://bazaar.abuse.ch/sample/45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [a5373179735e55…](https://bazaar.abuse.ch/sample/a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [7653b9b8300f18…](https://bazaar.abuse.ch/sample/7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [c8b1f0e93528eb…](https://bazaar.abuse.ch/sample/c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [7d67647e69bc45…](https://bazaar.abuse.ch/sample/7d67647e69bc453a71eb396d90ee995548607c19784f8b063af8304ecc184ae0/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [14abfa8e5cbabc…](https://bazaar.abuse.ch/sample/14abfa8e5cbabc1dd53f633dddb91eef1aa5fa8f7ac744a1386bbfd41c899162/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [7f7444f52c9fa1…](https://bazaar.abuse.ch/sample/7f7444f52c9fa16a521756f295222587135f0ee73a5c07879c5905333356204f/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [986f8931120279…](https://bazaar.abuse.ch/sample/986f893112027921a3e40de213b6a5614ed746a9aeba285e1560474f10ba7828/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6302/7774 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6302/7774 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6006/7774 |
| 6 | Kaspersky | 75.5% | 5868/7773 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5533/7770 |
| 9 | Rising | 68.3% | 5307/7774 |
| 10 | Varist | 66.1% | 5139/7769 |
| 11 | AVG | 65.2% | 5062/7769 |
| 12 | Avast | 65.1% | 5062/7770 |
| 13 | Tencent | 64.9% | 4898/7548 |
| 14 | McAfeeD | 61.3% | 4764/7766 |
| 15 | huorong | 60.9% | 4727/7766 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 67 | 66.3% |
| 🪟 Windows | 33 | 32.7% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 78.2% |
| Trojanisierte Software | 17 | 16.8% |
| MaaS-Loader | 5 | 5.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 33 | 32.7% |
| 2 | 🇦🇹 AT | 28 | 27.7% |
| 3 | 🇫🇷 FR | 15 | 14.9% |
| 4 | 🇺🇸 US | 10 | 9.9% |
| 5 | 🇮🇳 IN | 10 | 9.9% |
| 6 | 🇳🇱 NL | 2 | 2.0% |
| 7 | 🇬🇧 GB | 1 | 1.0% |
| 8 | 🇷🇴 RO | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 63 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 63 |
| Lateral Movement | 63 |

<details><summary>1e2e390e13f2efe7176c… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>45075a965b00a8f0248d… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a5373179735e55f60f02… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7653b9b8300f1825d8dd… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [1e2e390e13f2efe7176c…](https://bazaar.abuse.ch/sample/1e2e390e13f2efe7176c41ba20837b65001517961c26fcd076e02d77ab98d788/)

- **Familie:** Mirai
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| Lionic | `Trojan.ELF.Mirai.4!c` |

### [f18a75c71bca5bbae675…](https://bazaar.abuse.ch/sample/f18a75c71bca5bbae6757958c6d9188ac71ffcc0ad9c7fe25d86f748acd26046/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Mirai-BXM [Trj]` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Mirai-BXM [Trj]` |
| Avast-Mobile | `ELF:Mirai-BXM [Trj]` |
| Avira | `TR/LINUX.Mirai.BXM` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9774` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BXM` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Gafgyt` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Script/Mirai.EFX` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| huorong | `Trojan/Linux.Mirai.q` |

### [7f7444f52c9fa16a5217…](https://bazaar.abuse.ch/sample/7f7444f52c9fa16a521756f295222587135f0ee73a5c07879c5905333356204f/)

- **Familie:** Mirai
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Mirai.EFZ
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| McAfeeD | `Trojan:Script/Mirai.EFZ` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Varist | `E64/Mirai.ER.gen!Camelot` |

### [bf3e3e4bad292415eb98…](https://bazaar.abuse.ch/sample/bf3e3e4bad292415eb9882481150bd23a7603efc221538cc4fc6938b99a7c19b/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Mirai-BXM [Trj]` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Mirai-BXM [Trj]` |
| Avast-Mobile | `ELF:Mirai-BXM [Trj]` |
| Avira | `TR/LINUX.Mirai.BXM` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9774` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BXM` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Script/Mirai.EFX` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| huorong | `Trojan/Linux.Mirai.q` |

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

- **Mirai** (61×)
- **elf** (37×)
- **Torii** (22×)
- **LegionLoader** (20×)
- **exe** (13×)
- **signed** (4×)
- **SilverFox** (4×)
- **ValleyRAT** (4×)
- **ClickFix** (3×)
- **CurlyGate** (3×)
- **loader** (3×)
- **Satacom** (3×)
- **upx-dec** (3×)
- **upx** (3×)
- **unpacked** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +55 (8→63)
- neu: **LegionLoader** (17)
- ↓ **unbekannt** -42 (49→7)
- neu: **ValleyRAT** (3)
- ↓ **SalatStealer** -2 (4→2)
- neu: **RemusStealer** (2)
- ↑ **CoinMiner** +1 (1→2)
- neu: **Gh0stRAT** (1)
- ↓ **SilentNet** -6 (7→1)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +40 (23→63)
- neu: **LegionLoader** (17)
- ↓ **unbekannt** -20 (27→7)
- neu: **ValleyRAT** (3)
- ↓ **SalatStealer** -14 (16→2)
- neu: **RemusStealer** (2)
- ↑ **CoinMiner** +1 (1→2)
- neu: **Gh0stRAT** (1)
- ↓ **SilentNet** -1 (2→1)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.400 MB |
| σ Dateigröße | 13.647 MB |
| Ø Risiko-Score | 76.7/100 |
| Ø Klassifikations-Konfidenz | 85.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 63/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:24 | [45075a965b00…](https://bazaar.abuse.ch/sample/45075a965b00a8f0248dd4f40ea3621d58cefad5329ac86bf42caacc95729090/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 21:17 | [a5373179735e…](https://bazaar.abuse.ch/sample/a5373179735e55f60f0213c1267e1d8a163357b542de3149e8750aa0c048e39d/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 21:11 | [41d9eb2f5418…](https://bazaar.abuse.ch/sample/41d9eb2f5418181cfe9a9955bdb1ec99692618759704b92f332d2d6e121fa4aa/) | `exe` | Gh0stRAT | 92.5 | – | – | 🇺🇸US |
| 21:00 | [7653b9b8300f…](https://bazaar.abuse.ch/sample/7653b9b8300f1825d8dd067f4f68882181ca67148268368cac430dd7b0b2b219/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 20:50 | [c8b1f0e93528…](https://bazaar.abuse.ch/sample/c8b1f0e93528ebabaeb3139f8d22b6ae905df91c85bb4f6052e46e3dd694e649/) | `elf` | Mirai | 83.7 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 01.11.2026 21:50 UTC*