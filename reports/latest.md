# MalwareBazaar – 29.10.2026 23:51 UTC

Dieser Run hat **34 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **35** |
| Kritisch (≥75) | **25** |
| Höchster Score | **97.3/100** – 2b524c3a5ec090c4… |
| Häufigste Familie | **unbekannt** (16x) |
| Häufigster Typ | **elf** (15x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 18 Samples |
| Ø Dateigröße | 3.25 MB (σ=4.17) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 15 | 42.9%  ████████ |
| `exe` | 11 | 31.4%  ██████ |
| `js` | 2 | 5.7%  █ |
| `jar` | 2 | 5.7%  █ |
| `bat` | 1 | 2.9%   |
| `vbs` | 1 | 2.9%   |
| `sh` | 1 | 2.9%   |
| `zip` | 1 | 2.9%   |
| `rar` | 1 | 2.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 16 | 45.7% |
| 2 | Mirai | 14 | 40.0% |
| 3 | WannaCry | 1 | 2.9% |
| 4 | Malware | 1 | 2.9% |
| 5 | njrat | 1 | 2.9% |
| 6 | AsyncRAT | 1 | 2.9% |
| 7 | SalatStealer | 1 | 2.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 14 | 40.0% | 95% |
| Infostealer | 8 | 22.9% | 74% |
| Andere / Unbekannt | 4 | 11.4% | 20% |
| Skript/Dropper | 3 | 8.6% | 35% |
| RAT | 3 | 8.6% | 88% |
| Ransomware | 1 | 2.9% | 95% |
| Linux-Malware | 1 | 2.9% | 45% |
| Windows-Malware | 1 | 2.9% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 25 | 71.4% |
| 🟠 HOCH | 1 | 2.9% |
| 🟡 MITTEL | 5 | 14.3% |
| 🟢 NIEDRIG | 4 | 11.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2b524c3a5ec090…](https://bazaar.abuse.ch/sample/2b524c3a5ec090c4102a759d2973e1f7d945d59c3c783266bf089c523024b169/) | WannaCry | Ransomware | **97.3** | 🔴 KRITISCH | – | – | ? |
| [4e0a33cb525d0d…](https://bazaar.abuse.ch/sample/4e0a33cb525d0de95c41c00177c3795c8ebeee6421e6ed3507bbe8d8223589b6/) | njrat | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [6a5da90c553bb0…](https://bazaar.abuse.ch/sample/6a5da90c553bb0da87e821a3bece34e1394825e845601993bd1df5cea70e29f1/) | AsyncRAT | RAT | **86.6** | 🔴 KRITISCH | – | – | ? |
| [e82f7ae662b29f…](https://bazaar.abuse.ch/sample/e82f7ae662b29fafd8ced61d8433bbb3f61414f569e02e115a3f126af7adf043/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [4beca6ff7e9437…](https://bazaar.abuse.ch/sample/4beca6ff7e9437eb40c3dfc1843553dd7f720379388add8406266c3a1037c664/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [65f241c68881b3…](https://bazaar.abuse.ch/sample/65f241c68881b33c85bff7786a43495627151898e8e36b74f2595aaf1944a438/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | 10.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [60b99e207f4585…](https://bazaar.abuse.ch/sample/60b99e207f458578694969eaa8c7427cb80f340612ee65c07ce51a80eb2f774a/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [2ef700becf0f96…](https://bazaar.abuse.ch/sample/2ef700becf0f9631000cd781c72b066d8d23ff1b3d1c74a1b5dcbe26ff3aed34/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [14016b652089d5…](https://bazaar.abuse.ch/sample/14016b652089d520ad529c788dc98bed6a2ac32d0ac7fb65f833e40f0ff0e274/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [1718554f358140…](https://bazaar.abuse.ch/sample/1718554f358140911cc2e010476de223007080bd22cd2cd000e68b1ae1bece5a/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6252/7715 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6252/7715 |
| 3 | ESET-NOD32 | 77.3% | 5960/7715 |
| 4 | Kaspersky | 75.6% | 5828/7714 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5489/7712 |
| 8 | Rising | 68.3% | 5270/7715 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5103/7711 |
| 11 | Avast | 65.2% | 5024/7711 |
| 12 | AVG | 65.2% | 5024/7710 |
| 13 | Tencent | 64.9% | 4861/7489 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4722/7708 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 16 | 45.7% |
| 🪟 Windows | 12 | 34.3% |
| ❓ Unbekannt | 4 | 11.4% |
| 📦 Archiv | 3 | 8.6% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 32 | 91.4% |
| Drive-By / Exploit-Kit | 2 | 5.7% |
| Exploit / N-Day | 1 | 2.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 7 | 20.0% |
| 2 | 🇳🇱 NL | 6 | 17.1% |
| 3 | 🇩🇪 DE | 5 | 14.3% |
| 4 | 🇫🇷 FR | 5 | 14.3% |
| 5 | 🇭🇺 HU | 5 | 14.3% |
| 6 | 🇨🇦 CA | 2 | 5.7% |
| 7 | 🇦🇹 AT | 2 | 5.7% |
| 8 | 🇨🇭 CH | 1 | 2.9% |
| 9 | 🌐 CO | 1 | 2.9% |
| 10 | 🌐 Unbekannt | 1 | 2.9% |

## MITRE ATT&CK

> 18 von 35 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Collection | 3 |
| Credential Access | 2 |
| Exfiltration | 2 |
| Command and Control | 2 |
| Execution | 1 |

<details><summary>4e0a33cb525d0de95c41… – njrat | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>6a5da90c553bb0da87e8… – AsyncRAT | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>e82f7ae662b29fafd8ce… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4beca6ff7e9437eb40c3… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4beca6ff7e9437eb40c3…](https://bazaar.abuse.ch/sample/4beca6ff7e9437eb40c3dfc1843553dd7f720379388add8406266c3a1037c664/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| DrWeb | `Linux.DDoS.3423` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.DDos.dt` |

### [65f241c68881b33c85bf…](https://bazaar.abuse.ch/sample/65f241c68881b33c85bff7786a43495627151898e8e36b74f2595aaf1944a438/)

- **Familie:** Mirai
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| DrWeb | `Linux.DDoS.3423` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Flooder` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| huorong | `Trojan/Linux.DDos.dt` |

### [e82f7ae662b29fafd8ce…](https://bazaar.abuse.ch/sample/e82f7ae662b29fafd8ced61d8433bbb3f61414f569e02e115a3f126af7adf043/)

- **Familie:** Mirai
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan/Linux.DDos.dt
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DDoS.3423` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| SentinelOne | `Static AI - Suspicious ELF` |
| huorong | `Trojan/Linux.DDos.dt` |

### [2fdd91ccd5fedb001d13…](https://bazaar.abuse.ch/sample/2fdd91ccd5fedb001d13ccbf881f08f45df8dae3b307f0ad71f384189f282971/)

- **Familie:** Malware
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.30DF02C9
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Avira | `TR/Crypt.EPACK.Gen2` |
| Bkav | `W32.Malware.30DF02C9` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Agent_AGen.SXL trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/Crypt.EPACK.Gen2` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Heur!.02212023` |
| Kingsoft | `malware.kb.a.981` |
| McAfeeD | `ti!2FDD91CCD5FE` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/AEi.C6557B05!Eldorado` |

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

- **elf** (15×)
- **exe** (10×)
- **Mirai** (9×)
- **upx-dec** (6×)
- **upx** (6×)
- **stealer** (4×)
- **wraith** (4×)
- **Warden** (3×)
- **WARDENStealer** (3×)
- **Stealer** (3×)
- **DIVINEX** (2×)
- **Prometei** (2×)
- **Vidar** (2×)
- **VidarStealer** (2×)
- **signed** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -12 (28→16)
- ↑ **Mirai** +1 (13→14)
- ↓ **WannaCry** -1 (2→1)
- neu: **Malware** (1)
- neu: **njrat** (1)
- neu: **AsyncRAT** (1)
- ↓ **SalatStealer** -23 (24→1)
- weg: **Formbook** (war 9)
- weg: **RemcosRAT** (war 6)
- weg: **AgentTesla** (war 3)
- weg: **XWorm** (war 2)
- weg: **MassLogger** (war 2)
- weg: **CoinMiner** (war 2)
- weg: **KATARU** (war 4)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -7 (23→16)
- ↓ **Mirai** -9 (23→14)
- neu: **WannaCry** (1)
- neu: **Malware** (1)
- neu: **njrat** (1)
- neu: **AsyncRAT** (1)
- ↓ **SalatStealer** -12 (13→1)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.250 MB |
| σ Dateigröße | 4.173 MB |
| Ø Risiko-Score | 69.9/100 |
| Ø Klassifikations-Konfidenz | 72.7% |
| Samples mit VT | 5/35 |
| Samples mit MITRE | 18/35 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 38 |
| Unbekannte Familien | 4 (11.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:29 | [f7a94508252e…](https://bazaar.abuse.ch/sample/f7a94508252e01cf555da011b19cb63f8ebb1259ecafd83a093a52a40ef2bd5a/) | `exe` | unbekannt | 81.9 | – | – | 🇺🇸US |
| 23:15 | [2b524c3a5ec0…](https://bazaar.abuse.ch/sample/2b524c3a5ec090c4102a759d2973e1f7d945d59c3c783266bf089c523024b169/) | `exe` | WannaCry | 97.3 | – | – | 🇺🇸US |
| 23:00 | [60b99e207f45…](https://bazaar.abuse.ch/sample/60b99e207f458578694969eaa8c7427cb80f340612ee65c07ce51a80eb2f774a/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 22:47 | [2ef700becf0f…](https://bazaar.abuse.ch/sample/2ef700becf0f9631000cd781c72b066d8d23ff1b3d1c74a1b5dcbe26ff3aed34/) | `elf` | Mirai | 83.6 | – | – | 🇳🇱NL |
| 22:46 | [14016b652089…](https://bazaar.abuse.ch/sample/14016b652089d520ad529c788dc98bed6a2ac32d0ac7fb65f833e40f0ff0e274/) | `elf` | Mirai | 83.6 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 29.10.2026 23:51 UTC*