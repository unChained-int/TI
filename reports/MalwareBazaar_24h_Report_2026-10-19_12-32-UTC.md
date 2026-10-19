# MalwareBazaar – 19.10.2026 12:32 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **56** |
| Höchster Score | **96.7/100** – dfaf761e4fc7ba49… |
| Häufigste Familie | **unbekannt** (40x) |
| Häufigster Typ | **exe** (36x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 36 Samples |
| Ø Dateigröße | 2.44 MB (σ=10.36) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 36 | 35.6%  ███████ |
| `elf` | 32 | 31.7%  ██████ |
| `sh` | 6 | 5.9%  █ |
| `xls` | 6 | 5.9%  █ |
| `macho` | 3 | 3.0%   |
| `iso` | 3 | 3.0%   |
| `msi` | 2 | 2.0%   |
| `dll` | 2 | 2.0%   |
| `wsf` | 2 | 2.0%   |
| `vbs` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 40 | 39.6% |
| 2 | Mirai | 24 | 23.8% |
| 3 | BlakcSeeStealer | 8 | 7.9% |
| 4 | ValleyRAT | 5 | 5.0% |
| 5 | Formbook | 4 | 4.0% |
| 6 | RedLineStealer | 3 | 3.0% |
| 7 | SVCStealer | 3 | 3.0% |
| 8 | WannaCry | 2 | 2.0% |
| 9 | AMOS | 2 | 2.0% |
| 10 | Tofsee | 1 | 1.0% |
| 11 | Prometei | 1 | 1.0% |
| 12 | MeshAgent | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 25 | 24.8% | 82% |
| Botnet/IoT | 24 | 23.8% | 95% |
| Windows-Malware | 10 | 9.9% | 35% |
| Linux-Malware | 9 | 8.9% | 45% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| Maldoc | 7 | 6.9% | 35% |
| Loader | 6 | 5.9% | 75% |
| RAT | 6 | 5.9% | 78% |
| Ransomware | 2 | 2.0% | 95% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Spyware | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 56 | 55.4% |
| 🟠 HOCH | 9 | 8.9% |
| 🟡 MITTEL | 28 | 27.7% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [dfaf761e4fc7ba…](https://bazaar.abuse.ch/sample/dfaf761e4fc7ba493df5e0d25d2aee2c2f000fd6c43df4acb3c9922fa94089d8/) | WannaCry | Ransomware | **96.7** | 🔴 KRITISCH | – | – | ? |
| [9c56c207ca461c…](https://bazaar.abuse.ch/sample/9c56c207ca461c9a8fd3942ac72decc0a83684c56b81d7cefdcb054919646efb/) | WannaCry | Ransomware | **94.5** | 🔴 KRITISCH | – | – | ? |
| [80db443e3ad1ce…](https://bazaar.abuse.ch/sample/80db443e3ad1ce509ef96b009e47b866611fee72da7dae9d8a70d81b010e6355/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [225f89ad501a71…](https://bazaar.abuse.ch/sample/225f89ad501a71af48f405b6c61309a6c0f041ad8add6625e75274c536954f1f/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [ab5b9b53b603bc…](https://bazaar.abuse.ch/sample/ab5b9b53b603bc5bc8abb0eb0aab014d82d20b603b40fdc69642b5b907fcea43/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [5431d932869413…](https://bazaar.abuse.ch/sample/5431d9328694139eb052492c1f891aea28d6eee2ceab442501efde5b50a8e20a/) | Formbook | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [7e6854f052cb97…](https://bazaar.abuse.ch/sample/7e6854f052cb97be92d9e7e902af27dadf63a1d89d97df856c6433e15b35b08d/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [18b6a5c94a4c3b…](https://bazaar.abuse.ch/sample/18b6a5c94a4c3bfba43a9265d8eb3edc75201fffb18a862ea58da864de0e3b34/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [f7856dc0d9a74e…](https://bazaar.abuse.ch/sample/f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d/) | RedLineStealer | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [4f1271f35cb5bf…](https://bazaar.abuse.ch/sample/4f1271f35cb5bfdb456481302e219e5b8e7341bf1e871bd5f4cdc6636da18929/) | RedLineStealer | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6060/7491 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6060/7491 |
| 3 | ESET-NOD32 | 77.4% | 5797/7491 |
| 4 | Kaspersky | 76.3% | 5713/7490 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5351/7488 |
| 8 | Rising | 68.7% | 5146/7491 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4961/7487 |
| 11 | Tencent | 65.2% | 4738/7265 |
| 12 | Avast | 65.2% | 4879/7487 |
| 13 | AVG | 65.2% | 4879/7486 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4584/7484 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 41 | 40.6% |
| 🪟 Windows | 41 | 40.6% |
| 📄 Dokument | 7 | 6.9% |
| 📦 Archiv | 5 | 5.0% |
| ❓ Unbekannt | 4 | 4.0% |
| 🍎 macOS | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 78.2% |
| Phishing / E-Mail-Anhang | 7 | 6.9% |
| MaaS-Loader | 5 | 5.0% |
| C2 / Nachladen | 3 | 3.0% |
| Drive-By / Exploit-Kit | 3 | 3.0% |
| Trojanisierte Software | 2 | 2.0% |
| Exploit / N-Day | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 36 | 35.6% |
| 2 | 🇭🇺 HU | 34 | 33.7% |
| 3 | 🇺🇸 US | 14 | 13.9% |
| 4 | 🇨🇭 CH | 4 | 4.0% |
| 5 | 🇮🇩 ID | 3 | 3.0% |
| 6 | 🇫🇷 FR | 3 | 3.0% |
| 7 | 🇬🇧 GB | 3 | 3.0% |
| 8 | 🇳🇱 NL | 1 | 1.0% |
| 9 | 🌐 LU | 1 | 1.0% |
| 10 | 🇨🇦 CA | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 36 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 10 |
| Credential Access | 9 |
| Exfiltration | 2 |
| Impact | 1 |
| Command and Control | 1 |

<details><summary>80db443e3ad1ce509ef9… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f300eb2ed96284817606…](https://bazaar.abuse.ch/sample/f300eb2ed9628481760661cfa21f0a678a7cdc935492047591f04b23cc854f3f/)

- **Familie:** Mirai
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Agent-AYQ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen3` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai.ba` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Agent-AYQ [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `TR/LINUX.Agent.AYQ` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135890-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.AX trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Trojan.TR/LINUX.Agent.AYQ` |
| Fortinet | `ELF/Mirai.AT!tr.botnet` |
| GData | `Linux.Trojan.Mirai.J` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ba` |
| Kingsoft | `Linux.Backdoor.Mirai.ba` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.BL!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai.k` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.was` |
| TrellixENS | `Linux/Mirai.k` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMNM4` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMNM4` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.CA.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Backdoor/Linux.Mirai.u` |

### [e1961d4b7acb3179aeb6…](https://bazaar.abuse.ch/sample/e1961d4b7acb3179aeb69ee692f6105c392b85ff2c8f18a5a920c70543305f77/)

- **Familie:** MalwareX-gen [Drp]
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.EE3FA392` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/TrojanDropper.Agent.AFO trojan` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `UDS:Trojan.Win32.Shellcode` |
| Kingsoft | `Win32.Trojan.Agent.gen` |
| Malwarebytes | `Malware.AI.1928920158` |
| McAfeeD | `ti!E1961D4B7ACB` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.82 (RDML:Dj789bO4mzd4/ghwOdJBCQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win64.Trojan-Dropper.Opper.Nsmw` |
| TrellixENS | `Artemis!6C7015E9390F` |
| alibabacloud | `Trojan[dropper]:Win/Donut.C9OKG` |

### [81304c9fb3c0ee18b3d2…](https://bazaar.abuse.ch/sample/81304c9fb3c0ee18b3d2e5941551195bdc6186900121e2c06c7d7bf5037dc9a1/)

- **Familie:** ValleyRAT
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.AE99812
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.AE99812` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| ESET-NOD32 | `Generik.CRNTXAL trojan` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Rising | `Trojan.Agent/PYC!1.14869 (CLOUD)` |
| Zillya | `Trojan.Blank.Script.2228` |

### [dcd78573fefcf1bbb119…](https://bazaar.abuse.ch/sample/dcd78573fefcf1bbb11978fc23821dba1331e354fd620ed86e1e7075388c025d/)

- **Familie:** SVCStealer
- **Erkannt von:** 52 von 75 Engines (69.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Lazy.731392
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Lazy.731392`

**Erkennende Engines (52/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Lazy.731392` |
| APEX | `Malicious` |
| AVG | `Win64:Agent-KP [Pws]` |
| AhnLab-V3 | `Trojan/Win.CryptBot.R787099` |
| Alibaba | `TrojanPSW:Win64/Stealer.75872149` |
| Antiy-AVL | `Trojan[Spy]/Win64.Agent` |
| Arcabit | `Trojan.Lazy.DB2900` |
| Avast | `Win64:Agent-KP [Pws]` |
| Avira | `TR/W64.Agent.LD` |
| BitDefender 🛡️ | `Gen:Variant.Lazy.731392` |
| Bkav | `W32.Malware.4608FED4` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Malware.Phil-10045361-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Spy.Agent.ML trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Lazy.731392 (B)` |
| F-Secure | `Trojan.TR/W64.Agent.LD` |
| Fortinet | `W64/Agent.ML!tr.spy` |
| GData | `Gen:Variant.Lazy.731392` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Heur!.0300602B` |
| K7AntiVirus | `Spyware ( 005d22721 )` |
| K7GW | `Spyware ( 005d22721 )` |
| Kaspersky | `Trojan-PSW.Win64.Stealer.awko` |
| Lionic | `Trojan.Win32.Stealer.12!c` |
| Malwarebytes | `Malware.AI.4088209889` |
| MaxSecure | `Trojan.Malware.697087689.susgen` |
| McAfeeD | `Trojan:Win/Hacktool.EAM` |
| MicroWorld-eScan | `Gen:Variant.Lazy.731392` |
| Microsoft 🛡️ | `PWS:MSIL/Polazert!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Stealer.OskiStealer!1.C41E (CLASSIC)` |
| Sangfor | `Virus.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan-PWS/W64.InfoStealer.2400296` |
| Tencent | `Malware.Win32.Gencirc.10c4a3a0` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!DC0E1FF65B8D` |
| TrendMicro | `TrojanSpy.Win32.STEALER.USBLH126` |
| TrendMicro-HouseCall | `TrojanSpy.Win32.STEALER.USBLH126` |
| VIPRE | `Gen:Variant.Lazy.731392` |
| Varist | `W64/ABApplication.UADL-3351` |
| Zillya | `Trojan.Agent.Win64.200424` |
| alibabacloud | `Hacktool:Multi/BrowserGhost` |
| huorong | `HackTool/W64.Chromelevator.b!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| Varist | `W64/ABTrojan.ANKV-0822` |


## Top Tags

- **exe** (36×)
- **elf** (32×)
- **Mirai** (25×)
- **APT28** (8×)
- **BlakcSeeStealer** (8×)
- **xls** (6×)
- **sh** (5×)
- **honeypot** (5×)
- **ValleyRAT** (5×)
- **Formbook** (4×)
- **stealer** (4×)
- **macho** (3×)
- **dropped-by-GCleaner** (3×)
- **iso** (3×)
- **signed** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +20 (20→40)
- ↑ **Mirai** +9 (15→24)
- neu: **BlakcSeeStealer** (8)
- ↑ **ValleyRAT** +4 (1→5)
- neu: **Formbook** (4)
- neu: **RedLineStealer** (3)
- neu: **SVCStealer** (3)
- neu: **WannaCry** (2)
- neu: **Tofsee** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +13 (27→40)
- ↓ **Mirai** -1 (25→24)
- neu: **BlakcSeeStealer** (8)
- ↑ **ValleyRAT** +4 (1→5)
- ↑ **Formbook** +2 (2→4)
- neu: **RedLineStealer** (3)
- neu: **SVCStealer** (3)
- neu: **WannaCry** (2)
- ↑ **AMOS** +1 (1→2)
- neu: **Tofsee** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.442 MB |
| σ Dateigröße | 10.358 MB |
| Ø Risiko-Score | 65.5/100 |
| Ø Klassifikations-Konfidenz | 67.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 36/101 |
| Eindeutige Familien | 19 |
| Eindeutige Tags | 75 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:31 | [074062fdc2db…](https://bazaar.abuse.ch/sample/074062fdc2db8eb38ff0b58a3e17bdcde4c004922e35938a71da8a57b9a9b71b/) | `macho` | unbekannt | 32.7 | – | – | 🌐HU |
| 12:25 | [05cebfa73485…](https://bazaar.abuse.ch/sample/05cebfa73485dadf802c473571183eda70aecd9766136c7c1af666987bcb6461/) | `sh` | unbekannt | 32.6 | – | – | 🇩🇪DE |
| 12:16 | [ddf1967721ba…](https://bazaar.abuse.ch/sample/ddf1967721baa3579812474e24d6bac823dd732399a5601bff34945fe1cf4858/) | `msi` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 12:15 | [9f222ca23d14…](https://bazaar.abuse.ch/sample/9f222ca23d14438eefeee9d6a31ee4243e54df8385fbd0dc5d0d3e8f9d7b4026/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 12:11 | [0ca1cdf2f7b0…](https://bazaar.abuse.ch/sample/0ca1cdf2f7b0adf4d0e3641016087852c9d96bb4686b3b0ab53399217ea2f2e0/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.10.2026 12:32 UTC*