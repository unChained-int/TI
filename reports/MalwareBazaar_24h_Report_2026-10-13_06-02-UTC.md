# MalwareBazaar – 13.10.2026 06:02 UTC

Dieser Run hat **99 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **83** |
| Höchster Score | **94.8/100** – c9f871fe3e4834d0… |
| Häufigste Familie | **Mirai** (52x) |
| Häufigster Typ | **elf** (65x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 63 Samples |
| Ø Dateigröße | 1.75 MB (σ=3.38) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 65 | 65.0%  █████████████ |
| `exe` | 25 | 25.0%  █████ |
| `sh` | 3 | 3.0%   |
| `macho` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |
| `js` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 52 | 52.0% |
| 2 | unbekannt | 16 | 16.0% |
| 3 | NanoCore | 4 | 4.0% |
| 4 | Formbook | 3 | 3.0% |
| 5 | Gafgyt | 3 | 3.0% |
| 6 | RemcosRAT | 3 | 3.0% |
| 7 | AMOS | 3 | 3.0% |
| 8 | Vidar | 2 | 2.0% |
| 9 | ValleyRAT | 2 | 2.0% |
| 10 | DCRat | 2 | 2.0% |
| 11 | SloppyRAT | 1 | 1.0% |
| 12 | Ngioweb | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 55 | 55.0% | 95% |
| RAT | 17 | 17.0% | 89% |
| Linux-Malware | 12 | 12.0% | 45% |
| Infostealer | 9 | 9.0% | 93% |
| Trojaner | 3 | 3.0% | 72% |
| Loader | 2 | 2.0% | 75% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 83 | 83.0% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 13 | 13.0% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c9f871fe3e4834…](https://bazaar.abuse.ch/sample/c9f871fe3e4834d05fba569ee47bd00a07273203382309fd994002c0e9ff6968/) | WannaCry | Ransomware | **94.8** | 🔴 KRITISCH | – | – | ? |
| [313fb55ebf3132…](https://bazaar.abuse.ch/sample/313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9/) | Vidar | Infostealer | **90.6** | 🔴 KRITISCH | – | – | ? |
| [b2a327241ee8fd…](https://bazaar.abuse.ch/sample/b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6/) | Formbook | Infostealer | **90.4** | 🔴 KRITISCH | – | – | ? |
| [a666c1bded48fe…](https://bazaar.abuse.ch/sample/a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5/) | Formbook | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [e07c5e686877ff…](https://bazaar.abuse.ch/sample/e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b/) | Vidar | Infostealer | **89.6** | 🔴 KRITISCH | – | – | ? |
| [9ddd60703a3f6a…](https://bazaar.abuse.ch/sample/9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee/) | Formbook | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |
| [05bdc12486c7b3…](https://bazaar.abuse.ch/sample/05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31/) | NetSupport | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [b028b2b4a6a39c…](https://bazaar.abuse.ch/sample/b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9/) | DCRat | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [c6ed1c7e207d9a…](https://bazaar.abuse.ch/sample/c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c/) | DCRat | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [e0e218a1ce45c5…](https://bazaar.abuse.ch/sample/e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2/) | RemcosRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5940/7342 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5940/7342 |
| 3 | ESET-NOD32 | 77.4% | 5683/7342 |
| 4 | Kaspersky | 76.3% | 5603/7341 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5254/7339 |
| 8 | Rising | 68.7% | 5045/7342 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4876/7338 |
| 11 | Tencent | 65.3% | 4644/7116 |
| 12 | AVG | 65.1% | 4773/7337 |
| 13 | Avast | 65.0% | 4773/7338 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4501/7335 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 68 | 68.0% |
| 🪟 Windows | 27 | 27.0% |
| 🍎 macOS | 3 | 3.0% |
| ❓ Unbekannt | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 90 | 90.0% |
| C2 / Nachladen | 4 | 4.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 68 | 68.0% |
| 2 | 🇺🇸 US | 13 | 13.0% |
| 3 | 🇳🇱 NL | 13 | 13.0% |
| 4 | 🇨🇭 CH | 3 | 3.0% |
| 5 | 🇸🇬 SG | 1 | 1.0% |
| 6 | 🇧🇷 BR | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 63 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 52 |
| Lateral Movement | 52 |
| Collection | 10 |
| Command and Control | 6 |
| Credential Access | 5 |
| Exfiltration | 2 |
| Execution | 1 |

<details><summary>313fb55ebf3132807935… – Vidar | 🔴 KRITISCH 90.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>b2a327241ee8fdf5f345… – Formbook | 🔴 KRITISCH 90.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a666c1bded48fe95e898… – Formbook | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e07c5e686877ffef93fd… – Vidar | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [063a716290fe030ad8fc…](https://bazaar.abuse.ch/sample/063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a/)

- **Familie:** NanoCore
- **Erkannt von:** 60 von 75 Engines (80.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (60/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C1321CAC` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
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
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!223D1C4D8FFB` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!223D1C4D8FFB` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!223D1C4D8FFB` |
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
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |

### [e306aaeb91b1b1cffb2b…](https://bazaar.abuse.ch/sample/e306aaeb91b1b1cffb2b1055963084fd68b9576310a8c11665c5fa1227182a4b/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.K!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| CTX | `elf.exploit-kit.mirai` |
| Cynet | `Malicious (score: 99)` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Ikarus | `Exploit.CVE-2026-43284` |
| Kingsoft | `Linux.Exploit.CVE-2026-432.a` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Exploit.Linux.CVE.Vzse` |
| SentinelOne | `Static AI - Malicious ELF` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Trojan.Linux.Mirai.Ntdra` |
| alibabacloud | `Exp:Linux/DirtyFrag` |
| huorong | `Exploit/Linux.DirtyFrag.a!crit` |

### [83f9a1de405b5b861c20…](https://bazaar.abuse.ch/sample/83f9a1de405b5b861c20012471b1f83c2f5af699d01ba407c60a37e8a9f0f837/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Suspicious.Linux.Save.a
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avira | `TR/LINUX.Mirai.DDE` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3199` |
| ESET-NOD32 | `Linux/Mirai.ETS trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DDE` |
| Fortinet | `ELF/Mirai.EOB!tr` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.kl` |
| McAfeeD | `Trojan:Linux/Mirai.ERC` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.144FE (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Tencent | `Backdoor.Linux.Mirai.ham` |
| VBA32 | `Trojan.Linux.Flylegit` |
| Varist | `E32/Mirai.AO.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.hf` |

### [704cb8bb6752a4df08fb…](https://bazaar.abuse.ch/sample/704cb8bb6752a4df08fb3885ada0a7edabe84bd822d6317cfda1dab9e4be1aa8/)

- **Familie:** ELF:Flooder-ADS [Trj]
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Flooder-ADS [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Flooder-ADS [Trj]` |
| Antiy-AVL | `Trojan[Miner]/Linux.CoinMiner` |
| Avast | `ELF:Flooder-ADS [Trj]` |
| DrWeb | `Linux.Siggen.12970` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.wo` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Tencent | `Trojan.Linux.Catstorm.Catra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/CoinMiner.dm` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
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
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (65×)
- **Mirai** (51×)
- **exe** (24×)
- **RAT** (11×)
- **Gafgyt** (6×)
- **dropped-by-GCleaner** (4×)
- **NanoCore** (4×)
- **trojan** (3×)
- **sh** (3×)
- **Formbook** (3×)
- **AMOS** (3×)
- **ClickFix** (3×)
- **Foxveil** (3×)
- **Mach-O** (3×)
- **macho** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +18 (34→52)
- ↓ **unbekannt** -18 (34→16)
- neu: **NanoCore** (4)
- ↑ **Formbook** +1 (2→3)
- neu: **Gafgyt** (3)
- ↓ **RemcosRAT** -1 (4→3)
- neu: **AMOS** (3)
- ↑ **Vidar** +1 (1→2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **DCRat** (2)
- weg: **SilentNet** (war 8)
- weg: **VIPKeylogger** (war 2)
- weg: **XWorm** (war 2)
- weg: **Blackmoon** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +15 (37→52)
- ↓ **unbekannt** -14 (30→16)
- neu: **NanoCore** (4)
- ↑ **Formbook** +1 (2→3)
- ↑ **Gafgyt** +2 (1→3)
- ↑ **RemcosRAT** +1 (2→3)
- neu: **AMOS** (3)
- ↑ **Vidar** +1 (1→2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **DCRat** (2)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.750 MB |
| σ Dateigröße | 3.385 MB |
| Ø Risiko-Score | 77.1/100 |
| Ø Klassifikations-Konfidenz | 86.1% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 63/100 |
| Eindeutige Familien | 20 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 06:00 | [06690169576f…](https://bazaar.abuse.ch/sample/06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 05:58 | [6662803a6481…](https://bazaar.abuse.ch/sample/6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19/) | `exe` | unbekannt | 83.6 | – | – | 🇩🇪DE |
| 05:57 | [4eab4e848a9e…](https://bazaar.abuse.ch/sample/4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad/) | `exe` | unbekannt | 82.2 | – | – | 🇩🇪DE |
| 05:55 | [313fb55ebf31…](https://bazaar.abuse.ch/sample/313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9/) | `exe` | Vidar | 90.6 | – | – | 🌐CH |
| 05:54 | [0ffa71364281…](https://bazaar.abuse.ch/sample/0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.10.2026 06:02 UTC*