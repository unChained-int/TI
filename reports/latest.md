# MalwareBazaar – 29.10.2026 12:31 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **61** |
| Höchster Score | **94.5/100** – 1abb43f7db0f6cf9… |
| Häufigste Familie | **Formbook** (27x) |
| Häufigster Typ | **js** (60x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 45 Samples |
| Ø Dateigröße | 3.79 MB (σ=13.95) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 60 | 59.4%  ███████████ |
| `exe` | 15 | 14.9%  ██ |
| `elf` | 8 | 7.9%  █ |
| `ps1` | 4 | 4.0%   |
| `sh` | 3 | 3.0%   |
| `bat` | 2 | 2.0%   |
| `vbs` | 2 | 2.0%   |
| `zsh` | 2 | 2.0%   |
| `msi` | 2 | 2.0%   |
| `zip` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Formbook | 27 | 26.7% |
| 2 | unbekannt | 19 | 18.8% |
| 3 | RemcosRAT | 14 | 13.9% |
| 4 | AgentTesla | 7 | 6.9% |
| 5 | XWorm | 4 | 4.0% |
| 6 | MassLogger | 4 | 4.0% |
| 7 | LxBaseRAT | 3 | 3.0% |
| 8 | Mirai | 3 | 3.0% |
| 9 | WannaCry | 2 | 2.0% |
| 10 | ConnectWise | 2 | 2.0% |
| 11 | VIPKeylogger | 2 | 2.0% |
| 12 | UmbraRAT | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 32 | 31.7% | 92% |
| RAT | 24 | 23.8% | 91% |
| Skript/Dropper | 18 | 17.8% | 35% |
| Windows-Malware | 8 | 7.9% | 35% |
| Linux-Malware | 4 | 4.0% | 45% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| Botnet/IoT | 3 | 3.0% | 95% |
| Loader | 2 | 2.0% | 85% |
| Ransomware | 2 | 2.0% | 95% |
| Spyware | 2 | 2.0% | 75% |
| Cryptominer | 2 | 2.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 61 | 60.4% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 30 | 29.7% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1abb43f7db0f6c…](https://bazaar.abuse.ch/sample/1abb43f7db0f6cf97f446d4b6d5b3290514f8981edd6d4e081556e629a8a855d/) | WannaCry | Ransomware | **94.5** | 🔴 KRITISCH | – | – | ? |
| [6bfffc25d79bff…](https://bazaar.abuse.ch/sample/6bfffc25d79bff45dfaa3417b63d31f097877109dc4bc2c57e66827babcc806b/) | Formbook | Infostealer | **90.3** | 🔴 KRITISCH | – | – | ? |
| [e39c8457e4eaaa…](https://bazaar.abuse.ch/sample/e39c8457e4eaaa1c0ca650dd2bb434d07118a34397180292ba6d05584f65d7c7/) | Formbook | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [4b6cb164891d6b…](https://bazaar.abuse.ch/sample/4b6cb164891d6b6fc7595dfa608f2f1a5634a70f7f6e41a3ca41cca4e9aa770b/) | Formbook | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [64b047c1e215c0…](https://bazaar.abuse.ch/sample/64b047c1e215c0ff15744ae2ac183bdbcd821e42a2408c7e53a6dddf8982dd66/) | Formbook | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [461f8ab06a9bd0…](https://bazaar.abuse.ch/sample/461f8ab06a9bd0a09ec335b81ac676e1b868c295592abe44edf5c5e1f693639e/) | AsyncRAT | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [8d2b845d9a2a0c…](https://bazaar.abuse.ch/sample/8d2b845d9a2a0c4bbd8ad440a8c7f00ac21fe8c97289f1c279a377abf024f5b3/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [55df08cbf2166e…](https://bazaar.abuse.ch/sample/55df08cbf2166ea1882ee70688482540adf15cda4eaf01af1db5f52695b69d72/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [3c6e84ce47f613…](https://bazaar.abuse.ch/sample/3c6e84ce47f6133e3a9902509f171e04642436de4117d3cf0ff2fae0168d743c/) | XWorm | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [721f2100c56f1f…](https://bazaar.abuse.ch/sample/721f2100c56f1f8ed2ae903f2c30521e0ca9b67db943fdab8f6dc071226eabe3/) | XWorm | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6248/7706 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6248/7706 |
| 3 | ESET-NOD32 | 77.2% | 5952/7706 |
| 4 | Kaspersky | 75.5% | 5820/7705 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5483/7703 |
| 8 | Rising | 68.3% | 5267/7706 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5099/7702 |
| 11 | Avast | 65.2% | 5018/7702 |
| 12 | AVG | 65.2% | 5018/7701 |
| 13 | Tencent | 64.9% | 4858/7480 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4719/7699 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 59 | 58.4% |
| 🪟 Windows | 23 | 22.8% |
| 🐧 Linux | 13 | 12.9% |
| 📦 Archiv | 4 | 4.0% |
| 🤖 Android | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Drive-By / Exploit-Kit | 60 | 59.4% |
| Unbekannt / nicht bestimmbar | 36 | 35.6% |
| Exploit / N-Day | 2 | 2.0% |
| Trojanisierte Software | 2 | 2.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 60 | 59.4% |
| 2 | 🇺🇸 US | 15 | 14.9% |
| 3 | 🇩🇪 DE | 9 | 8.9% |
| 4 | 🇭🇺 HU | 6 | 5.9% |
| 5 | 🇨🇭 CH | 3 | 3.0% |
| 6 | 🇳🇱 NL | 3 | 3.0% |
| 7 | 🇨🇦 CA | 2 | 2.0% |
| 8 | 🇨🇿 CZ | 1 | 1.0% |
| 9 | 🌐 TH | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 45 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 41 |
| Credential Access | 27 |
| Command and Control | 15 |
| Initial Access | 3 |
| Lateral Movement | 3 |
| Execution | 1 |

<details><summary>6bfffc25d79bff45dfaa… – Formbook | 🔴 KRITISCH 90.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e39c8457e4eaaa1c0ca6… – Formbook | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4b6cb164891d6b6fc759… – Formbook | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>64b047c1e215c0ff1574… – Formbook | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [361d59f3c4c3503eac70…](https://bazaar.abuse.ch/sample/361d59f3c4c3503eac7034992fc6a43b6d0150225a8a211d7ec8d46ad1faba4a/)

- **Familie:** Mirai
- **Erkannt von:** 38 von 75 Engines (50.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40659388
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40659388`

**Erkennende Engines (38/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40659388` |
| AVG | `ELF:Mirai-AM [Trj]` |
| AhnLab-V3 | `Linux/Miraidown.Gen` |
| Antiy-AVL | `Trojan[Downloader]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D26C69BC` |
| Avast | `ELF:Mirai-AM [Trj]` |
| Avast-Mobile | `ELF:MiraiDownloader-QG [Trj]` |
| Avira | `TR/LINUX.Mirai.AM` |
| BitDefender 🛡️ | `Trojan.Generic.40659388` |
| CTX | `elf.trojan.generic` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9779` |
| ESET-NOD32 | `Linux/TrojanDownloader.Mirai.A trojan` |
| Emsisoft | `Trojan.Generic.40659388 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AM` |
| Fortinet | `ELF/Mirai.A!tr.dldr` |
| GData | `Linux.Trojan.Agent.WXRUMB` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Mirai` |
| Kaspersky | `HEUR:Trojan-Downloader.Linux.Mirai.d` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!361D59F3C4C3` |
| MicroWorld-eScan | `Trojan.Generic.40659388` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HX!MTB` |
| Rising | `Downloader.Mirai/Linux!8.13556 (TFE:14:dBdUm02wosG)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Skyhigh | `GenericRXIA-WK!AD2D6F946475` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.MiraiDownload.ve` |
| TrellixENS | `GenericRXIA-WK!AD2D6F946475` |
| TrendMicro | `Possible_MIRAIDLOD.SMLBAT6` |
| TrendMicro-HouseCall | `Possible_MIRAIDLOD.SMLBAT6` |
| VIPRE | `Trojan.Generic.40659388` |
| Varist | `E32/ABDownloader.AYR` |
| VirIT | `Linux.DownLoader.UP` |
| alibabacloud | `DDoS:Linux/Mirai.QZ` |
| huorong | `Trojan/Linux.Agent.bn!crit` |

### [550f8a71333e34ac7937…](https://bazaar.abuse.ch/sample/550f8a71333e34ac7937e4cd35aa3bd8a6ba0ee01c25d5e102c3a5ac97c0d7c8/)

- **Familie:** WannaCry
- **Erkannt von:** 53 von 75 Engines (70.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0147`

**Erkennende Engines (53/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0147` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Antiy-AVL | `Trojan[Exploit]/Win64.CVE-2017-0147` |
| Arcabit | `Exploit.CVE-2017-0147` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `EXP/W32.CVE-2017-01.B` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0147` |
| Bkav | `W32.Malware.5EBFDF8F` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.generic` |
| ClamAV | `Win.Ransomware.Wanna-9769986-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win64/Exploit.CVE-2017-0147.A trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Exploit.CVE-2017-0147 (B)` |
| F-Secure | `Exploit.EXP/W32.CVE-2017-01.B` |
| Fortinet | `W64/Wanna.AK!tr` |
| GData | `Exploit.CVE-2017-0147` |
| Gridinsoft | `Trojan.Win64.Downloader.oa!s1` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan.Win32.Eb.s` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| McAfeeD | `ti!550F8A71333E` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Panda | `Trj/GdSda.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Ransom-WannaCry!4CF2B4FFC8B2` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5298176` |
| Tencent | `Trojan.Win64.Wanna.a` |
| TrellixENS | `Ransom-WannaCry!4CF2B4FFC8B2` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-e4f863f0!Eldorado` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| Zillya | `Trojan.Wanna.Win32.27` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `Exploit/EquationDrug.a` |

### [c96f81d0ddbc29f0315c…](https://bazaar.abuse.ch/sample/c96f81d0ddbc29f0315c4b0809d97e280051a016b6a6852e5bd88e1a6ec235bc/)

- **Familie:** 44CaliberStealer
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Application.FCA.5731
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.FCA.5731`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.FCA.5731` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Bd]` |
| AhnLab-V3 | `Trojan/Win32.Ruftar.R30190` |
| Antiy-AVL | `Trojan[Dropper]/Win32.Delf` |
| Arcabit | `Trojan.Application.FCA.D1663` |
| Avast | `Win32:MalwareX-gen [Bd]` |
| Avira | `DR/Delphi.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Application.FCA.5731` |
| Bkav | `W32.Malware.2E0248E8` |
| CAT-QuickHeal | `Worm.GenericFC.S32598663` |
| CTX | `exe.unknown.generic` |
| ClamAV | `Win.Packed.Datastealer-9856291-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.44779` |
| ESET-NOD32 | `Win32/TrojanDropper.Delf.OEF trojan` |
| Elastic | `Windows.Generic.Threat` |
| Emsisoft | `Gen:Variant.Application.FCA.5731 (B)` |
| F-Secure | `Dropper.DR/Delphi.Gen` |
| Fortinet | `W32/Generic.AC.3D983!tr` |
| GData | `Gen:Variant.Application.FCA.5731` |
| Gridinsoft | `Backdoor.Win32.Gen.zv!s1` |
| Ikarus | `Trojan.MSIL.Bladabindi` |
| Jiangmin | `Trojan/Genome.bawa` |
| K7AntiVirus | `Trojan ( 005d24611 )` |
| K7GW | `Trojan ( 005d24611 )` |
| Kaspersky | `Trojan-Dropper.Win32.Delf.eimp` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Rbot.llQF` |
| Malwarebytes | `Backdoor.XWorm` |
| MaxSecure | `Dropper.Delf.EFNZ` |
| McAfeeD | `Real Protect-LS!C7371D1FB21B` |
| MicroWorld-eScan | `Gen:Variant.Application.FCA.5731` |
| Microsoft 🛡️ | `Trojan:MSIL/Jalapeno.AT!MTB` |
| NANO-Antivirus | `Trojan.Win32.Dropper.flagce` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Dropper.Delf!1.C7FF (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/XWorm-A` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Trojan-Dropper.Win32.Delf.waa` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `GenericRXDR-OQ!C7371D1FB21B` |
| TrendMicro | `TROJ_BINDER.SMBD` |
| TrendMicro-HouseCall | `TROJ_BINDER.SMBD` |
| VBA32 | `TrojanDropper.Delf` |
| VIPRE | `Gen:Variant.Application.FCA.5731` |
| Varist | `W32/Trojan.VVWT-8174` |
| ViRobot | `Trojan.Win32.A.Scar.451584.A` |
| VirIT | `Trojan.Win32.Generic.CKWZ` |
| Webroot | `W32.Trojan.Gen` |
| Xcitium | `TrojWare.Win32.TrojanDropper.Delf.SOC@572vwy` |
| Yandex | `Trojan.GenAsa!mL69tvFKrYE` |
| ZoneAlarm | `Mal/XWorm-A` |
| alibabacloud | `Rat:Win/AsyncRAT.Stub` |
| huorong | `Backdoor/DarkKomet.a` |

### [4238ad79148a3af8926a…](https://bazaar.abuse.ch/sample/4238ad79148a3af8926ac7d6fc41da3effb7895a93fe33307b5b55d4ec3b3cba/)

- **Familie:** SalatStealer
- **Erkannt von:** 47 von 75 Engines (62.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (47/75):**

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
| Bkav | `W32.Malware.A2C6619E` |
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
| Gridinsoft | `Trojan.Win32.Agent.oa!s1` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| McAfeeD | `Real Protect-LS!B13DD26ED784` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!B13DD26ED784` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570909` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!B13DD26ED784` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

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

- **js** (60×)
- **Formbook** (27×)
- **exe** (14×)
- **RemcosRAT** (14×)
- **elf** (8×)
- **RAT** (8×)
- **AgentTesla** (7×)
- **geo** (5×)
- **ps1** (4×)
- **XWorm** (4×)
- **TUR** (4×)
- **MassLogger** (4×)
- **dionaea** (3×)
- **LxBaseRAT** (3×)
- **Mirai** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Formbook** +26 (1→27)
- ↓ **unbekannt** -3 (22→19)
- ↑ **RemcosRAT** +12 (2→14)
- ↑ **AgentTesla** +6 (1→7)
- ↑ **XWorm** +2 (2→4)
- neu: **MassLogger** (4)
- neu: **LxBaseRAT** (3)
- ↓ **Mirai** -38 (41→3)
- neu: **WannaCry** (2)
- ↑ **ConnectWise** +1 (1→2)

## Änderungen – 7d-Vergleich

- ↑ **Formbook** +26 (1→27)
- ↓ **unbekannt** -5 (24→19)
- ↑ **RemcosRAT** +13 (1→14)
- neu: **AgentTesla** (7)
- ↑ **XWorm** +3 (1→4)
- neu: **MassLogger** (4)
- neu: **LxBaseRAT** (3)
- ↓ **Mirai** -20 (23→3)
- neu: **WannaCry** (2)
- ↑ **ConnectWise** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.794 MB |
| σ Dateigröße | 13.949 MB |
| Ø Risiko-Score | 68.3/100 |
| Ø Klassifikations-Konfidenz | 71.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 45/101 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 53 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:23 | [90a479239030…](https://bazaar.abuse.ch/sample/90a4792390309c8097c54a910999864f96df9b00cdc2d5f21f14e4ef2dc0338f/) | `bat` | unbekannt | 39.0 | – | – | 🌐HU |
| 12:17 | [e169bd066b45…](https://bazaar.abuse.ch/sample/e169bd066b4532515844045497fe9d42ed26a15bf236d1f1a2b64573f5717b7d/) | `bat` | unbekannt | 38.9 | – | – | 🌐HU |
| 12:15 | [62c2770a1b4b…](https://bazaar.abuse.ch/sample/62c2770a1b4b676ad92fead8fc4bf874251c0c185ed47a5bab1ca65caff9147f/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 12:12 | [4e6489e9161e…](https://bazaar.abuse.ch/sample/4e6489e9161e0abff2f2bc40a4fcc3489cc69371b099fd0f2756fc6a607cfcc0/) | `js` | unbekannt | 38.8 | – | – | 🌐HU |
| 12:10 | [65f7b9d663b9…](https://bazaar.abuse.ch/sample/65f7b9d663b9adc3ad6d0dc4d72f4dafd9c04b837a3e255f9a435dcc3512598f/) | `ps1` | unbekannt | 38.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 29.10.2026 12:31 UTC*