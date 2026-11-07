# MalwareBazaar – 07.11.2026 18:31 UTC

Dieser Run hat **46 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **47** |
| Kritisch (≥75) | **25** |
| Höchster Score | **93.9/100** – 930ba0ab96e5cfd4… |
| Häufigste Familie | **unbekannt** (23x) |
| Häufigster Typ | **elf** (28x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 19 Samples |
| Ø Dateigröße | 3.19 MB (σ=8.34) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 28 | 59.6%  ███████████ |
| `exe` | 14 | 29.8%  █████ |
| `ps1` | 2 | 4.3%   |
| `sh` | 2 | 4.3%   |
| `jar` | 1 | 2.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 23 | 48.9% |
| 2 | Mirai | 11 | 23.4% |
| 3 | WARDENStealer | 5 | 10.6% |
| 4 | Vidar | 3 | 6.4% |
| 5 | WannaCry | 2 | 4.3% |
| 6 | B!ml | 1 | 2.1% |
| 7 | Silentnet | 1 | 2.1% |
| 8 | NanoCore | 1 | 2.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 13 | 27.7% | 45% |
| Botnet/IoT | 11 | 23.4% | 95% |
| Infostealer | 8 | 17.0% | 82% |
| RAT | 3 | 6.4% | 82% |
| Trojaner | 3 | 6.4% | 75% |
| Skript/Dropper | 2 | 4.3% | 35% |
| Cryptominer | 2 | 4.3% | 75% |
| Andere / Unbekannt | 2 | 4.3% | 20% |
| Ransomware | 2 | 4.3% | 95% |
| Loader | 1 | 2.1% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 25 | 53.2% |
| 🟠 HOCH | 5 | 10.6% |
| 🟡 MITTEL | 15 | 31.9% |
| 🟢 NIEDRIG | 2 | 4.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [930ba0ab96e5cf…](https://bazaar.abuse.ch/sample/930ba0ab96e5cfd4c3dc3cab78a3fa5514acd88c0ddcf32e73af7c2c31bd335c/) | WannaCry | Ransomware | **93.9** | 🔴 KRITISCH | – | – | ? |
| [6e8e30f07d7b32…](https://bazaar.abuse.ch/sample/6e8e30f07d7b320f716ca446d6121e90d0d5e77f3bb2da77de0f2a9c404fd9e7/) | Vidar | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [d9c4d2c9345c60…](https://bazaar.abuse.ch/sample/d9c4d2c9345c60752c4c517ef2e51c47cb4f672f963a0342f86e045210fa4575/) | Vidar | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [c6c20ea175d882…](https://bazaar.abuse.ch/sample/c6c20ea175d882477847c3f18d2f9fcf40c12cb83d049c1105f8f4f660586a40/) | Vidar | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [ae993224131ab8…](https://bazaar.abuse.ch/sample/ae993224131ab80bb7c9cc0e5b30125b37b31c5d07d4a84683c39e38bf2ba6c9/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [79827cd008c315…](https://bazaar.abuse.ch/sample/79827cd008c3158399ffda92e85bbbf2c5d79cf17ffc8496ffdce05f20df08a3/) | B!ml | Trojaner | **84.5** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [47a958a9db9cb8…](https://bazaar.abuse.ch/sample/47a958a9db9cb844e1a96f15f413f3b5471bde9cd1bd1a7136496dfae1759e10/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [07378564b4f1e6…](https://bazaar.abuse.ch/sample/07378564b4f1e66c5442ac8dfd1e8f97766e33c626b831c6c8f3985dc627153f/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [49ddb91ad5bf14…](https://bazaar.abuse.ch/sample/49ddb91ad5bf145b9c72a9eb666c202a90c715bbfeb0f5bcc5df02041de87545/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [69f6fb3ee34957…](https://bazaar.abuse.ch/sample/69f6fb3ee349579e5330e140c63f4fd20201d597ae0f0e1eebfa2a2e7b330e39/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6378/7872 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6378/7872 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6082/7872 |
| 6 | Kaspersky | 75.5% | 5939/7871 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5602/7868 |
| 9 | Rising | 68.3% | 5377/7872 |
| 10 | Varist | 66.1% | 5204/7867 |
| 11 | Avast | 65.1% | 5122/7868 |
| 12 | AVG | 65.1% | 5122/7867 |
| 13 | Tencent | 64.9% | 4963/7646 |
| 14 | McAfeeD | 61.4% | 4829/7864 |
| 15 | huorong | 60.9% | 4788/7864 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 30 | 63.8% |
| 🪟 Windows | 16 | 34.0% |
| ❓ Unbekannt | 1 | 2.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 43 | 91.5% |
| MaaS-Loader | 2 | 4.3% |
| Exploit / N-Day | 2 | 4.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 22 | 46.8% |
| 2 | 🇩🇪 DE | 10 | 21.3% |
| 3 | 🇫🇷 FR | 7 | 14.9% |
| 4 | 🇳🇱 NL | 4 | 8.5% |
| 5 | 🌐 PT | 1 | 2.1% |
| 6 | 🇦🇹 AT | 1 | 2.1% |
| 7 | 🇨🇭 CH | 1 | 2.1% |
| 8 | 🌐 Unbekannt | 1 | 2.1% |

## MITRE ATT&CK

> 19 von 47 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 11 |
| Lateral Movement | 11 |
| Collection | 6 |
| Credential Access | 4 |
| Exfiltration | 3 |
| Command and Control | 2 |
| Impact | 2 |

<details><summary>6e8e30f07d7b320f716c… – Vidar | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>d9c4d2c9345c60752c4c… – Vidar | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>c6c20ea175d882477847… – Vidar | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>ae993224131ab80bb7c9… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [72eb219ea890425f78d7…](https://bazaar.abuse.ch/sample/72eb219ea890425f78d7d90e72e1db40a4e51fee718dbaf193f755efae1ad29f/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| Kingsoft | `Linux.Backdoor.Mirai.mu` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [42856ec3246ea7b03a9f…](https://bazaar.abuse.ch/sample/42856ec3246ea7b03a9fc2d8c82d7dea79c3866ca81c466929561f364cc24309/)

- **Familie:** WARDENStealer
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Alibaba | `Trojan:Win64/ShellcodeRunner.8a559d94` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| Avast | `FileRepMalware [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| CTX | `dll.unknown.yogi` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| Fortinet | `W64/MALD2.DEDF!tr` |
| GData | `Gen:Variant.Yogi.85599` |
| K7AntiVirus | `Trojan ( 006e90e91 )` |
| K7GW | `Trojan ( 006e90e91 )` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| McAfeeD | `ti!42856EC3246E` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| Sangfor | `Trojan.Win64.Agent.Vcc0` |
| Skyhigh | `BehavesLike.Win64.Trojan.hc` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win64.Trojan.Shellcoderunner.Wmhl` |
| TrellixENS | `Artemis!C7873CEC834F` |
| VIPRE | `Gen:Variant.Yogi.85599` |
| alibabacloud | `Trojan:Win/ShellcodeRunner.CRY` |
| huorong | `Trojan/W64.ShellLoader.ea!crit` |

### [79827cd008c3158399ff…](https://bazaar.abuse.ch/sample/79827cd008c3158399ffda92e85bbbf2c5d79cf17ffc8496ffdce05f20df08a3/)

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

### [dbdf262ca964e3115e1e…](https://bazaar.abuse.ch/sample/dbdf262ca964e3115e1e07a0d5bbc12e8aafe17f71ce0621b9ba6b15aeb9777d/)

- **Familie:** WannaCry
- **Erkannt von:** 53 von 75 Engines (70.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0147`

**Erkennende Engines (53/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0147` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Alibaba | `Ransom:Win32/WannaCrypt.50a` |
| Antiy-AVL | `Trojan[Exploit]/Win64.CVE-2017-0147` |
| Arcabit | `Exploit.CVE-2017-0147` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `EXP/W32.CVE-2017-01.B` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0147` |
| Bkav | `W32.Malware.AF3781B2` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.cve-2017-0147` |
| ClamAV | `Win.Ransomware.Wanna-9769986-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cynet | `Malicious (score: 100)` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win64/Exploit.CVE-2017-0147.A trojan` |
| Emsisoft | `Exploit.CVE-2017-0147 (B)` |
| F-Secure | `Exploit.EXP/W32.CVE-2017-01.B` |
| Fortinet | `W64/Wanna.AK!tr` |
| GData | `Exploit.CVE-2017-0147` |
| Gridinsoft | `Trojan.Win64.Downloader.oa!s1` |
| Ikarus | `Exploit.CVE-2017-0147` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan-Ransom.Win32.Wanna.ak` |
| Kingsoft | `Win32.Trojan-Ransom.Wanna.ak` |
| Lionic | `Trojan.Win32.Wanna.ts4v` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| MaxSecure | `WannaCry.W32.040225.Ransomware.YR` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Ransom-WannaCry!94A0DD4E1E0E` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| Tencent | `Trojan.Win64.Wanna.a` |
| TrellixENS | `Ransom-WannaCry!94A0DD4E1E0E` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-3d3fcce2!Eldorado` |
| VirIT | `Ransom.Win64.GenX.IKBP` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `Exploit/EquationDrug.a` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (28×)
- **exe** (13×)
- **Mirai** (11×)
- **diicot** (11×)
- **upx** (8×)
- **upx-dec** (6×)
- **WARDENStealer** (5×)
- **honeypot** (5×)
- **signed** (3×)
- **Vidar** (3×)
- **Prometei** (3×)
- **ps1** (2×)
- **remcos** (2×)
- **cowrie** (2×)
- **SilverFox** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +1 (22→23)
- ↓ **Mirai** -21 (32→11)
- ↑ **WARDENStealer** +3 (2→5)
- ↑ **Vidar** +2 (1→3)
- ↑ **WannaCry** +1 (1→2)
- neu: **B!ml** (1)
- ↓ **Silentnet** -1 (2→1)
- weg: **RevStealer** (war 7)
- weg: **Formbook** (war 2)
- weg: **CoinMiner** (war 2)
- weg: **VShell** (war 4)
- weg: **Snowlight** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -12 (35→23)
- ↓ **Mirai** -7 (18→11)
- ↑ **WARDENStealer** +3 (2→5)
- neu: **Vidar** (3)
- neu: **WannaCry** (2)
- neu: **B!ml** (1)
- weg: **SalatStealer** (war 3)
- weg: **RemcosRAT** (war 2)
- weg: **VShell** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.190 MB |
| σ Dateigröße | 8.335 MB |
| Ø Risiko-Score | 65.2/100 |
| Ø Klassifikations-Konfidenz | 69.9% |
| Samples mit VT | 5/47 |
| Samples mit MITRE | 19/47 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 2 (4.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:28 | [ae993224131a…](https://bazaar.abuse.ch/sample/ae993224131ab80bb7c9cc0e5b30125b37b31c5d07d4a84683c39e38bf2ba6c9/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 18:27 | [a00c6f4a355d…](https://bazaar.abuse.ch/sample/a00c6f4a355ded5a846d690368cb17a414cab4c64e7dd1af725f0e03e67582d8/) | `ps1` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 18:27 | [3404ac2243b8…](https://bazaar.abuse.ch/sample/3404ac2243b8e4d9c81f7f8c3c1b00163bc48752437e47ca34ea076ea3437e4a/) | `ps1` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 18:17 | [07d4b1f763d1…](https://bazaar.abuse.ch/sample/07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca/) | `exe` | WARDENStealer | 82.0 | – | – | 🌐PT |
| 17:49 | [72eb219ea890…](https://bazaar.abuse.ch/sample/72eb219ea890425f78d7d90e72e1db40a4e51fee718dbaf193f755efae1ad29f/) | `elf` | Mirai | 80.4 | 30.7% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 07.11.2026 18:31 UTC*