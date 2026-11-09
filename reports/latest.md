# MalwareBazaar – 09.11.2026 05:18 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **45** |
| Höchster Score | **84.4/100** – 3a7baa9951ba3ed4… |
| Häufigste Familie | **Mirai** (44x) |
| Häufigster Typ | **elf** (95x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 44 Samples |
| Ø Dateigröße | 0.10 MB (σ=0.68) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 95 | 94.1%  ██████████████████ |
| `exe` | 4 | 4.0%   |
| `sh` | 1 | 1.0%   |
| `vbs` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 44 | 43.6% |
| 2 | Snowlight | 29 | 28.7% |
| 3 | unbekannt | 24 | 23.8% |
| 4 | Gafgyt | 1 | 1.0% |
| 5 | VShell | 1 | 1.0% |
| 6 | ELF:Downloader-BR [Drp] | 1 | 1.0% |
| 7 | NanoCore | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 47 | 46.5% | 45% |
| Botnet/IoT | 45 | 44.6% | 95% |
| Windows-Malware | 3 | 3.0% | 35% |
| Loader | 3 | 3.0% | 65% |
| Andere / Unbekannt | 1 | 1.0% | 20% |
| Skript/Dropper | 1 | 1.0% | 35% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 44.6% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 51 | 50.5% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3a7baa9951ba3e…](https://bazaar.abuse.ch/sample/3a7baa9951ba3ed4336cb4854df1cdacf32f9a936680f39baaab773bfc02fc17/) | Gafgyt | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [367c190e18c768…](https://bazaar.abuse.ch/sample/367c190e18c768821ca6230a40469f045ccb38ffe61b5e6facc7137ea4e1642c/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [87081defed2a5f…](https://bazaar.abuse.ch/sample/87081defed2a5fc33ae0afc4ecbcc58cae46b4932fdf7db109c9fbfb723b3819/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [9ee5f59cb5edcc…](https://bazaar.abuse.ch/sample/9ee5f59cb5edcc718170c927dc0b9ca2d755a9a243b998dd14695c7e055e54bc/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [1aeed0362c452c…](https://bazaar.abuse.ch/sample/1aeed0362c452cb4788657c5189e44bb8497f33d65bac5df8227cfc458b0f99e/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [5ee886f9a3ac7d…](https://bazaar.abuse.ch/sample/5ee886f9a3ac7d073f54a6fcecb2684ca97a6ac41c776a5fe6c1c49dcc500dd1/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [83e9310db1f4cf…](https://bazaar.abuse.ch/sample/83e9310db1f4cfeb0a512f0565c8fdb68abf69270cb97c887e7fca024d832d6d/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [c0ed298ff8e875…](https://bazaar.abuse.ch/sample/c0ed298ff8e875074aa48a1483235974290cf36b3f14ad69743b5f09d8b4e67e/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [fa918aa9b92d86…](https://bazaar.abuse.ch/sample/fa918aa9b92d863fa91b55a392218c6930be1ee3f79d70a331cd2e86dd306abc/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [da24ff7cb249b6…](https://bazaar.abuse.ch/sample/da24ff7cb249b6a983ffeba042f88d66b68a9b2ca2d7edd515aa9e03b4f902a4/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6405/7901 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6405/7901 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6105/7901 |
| 6 | Kaspersky | 75.5% | 5962/7900 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5622/7897 |
| 9 | Rising | 68.4% | 5402/7901 |
| 10 | Varist | 66.1% | 5221/7896 |
| 11 | Avast | 65.2% | 5148/7897 |
| 12 | AVG | 65.2% | 5148/7896 |
| 13 | Tencent | 65.0% | 4986/7675 |
| 14 | McAfeeD | 61.4% | 4845/7893 |
| 15 | huorong | 61.0% | 4811/7893 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 97 | 96.0% |
| 🪟 Windows | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 74 | 73.3% |
| 2 | 🇫🇷 FR | 17 | 16.8% |
| 3 | 🇩🇪 DE | 6 | 5.9% |
| 4 | 🇳🇱 NL | 2 | 2.0% |
| 5 | 🇨🇭 CH | 1 | 1.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 44 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 44 |
| Lateral Movement | 44 |

<details><summary>367c190e18c768821ca6… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>87081defed2a5fc33ae0… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9ee5f59cb5edcc718170… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1aeed0362c452cb47886… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [82b8b37c4869a03e4362…](https://bazaar.abuse.ch/sample/82b8b37c4869a03e43624481ef69ff7a761e0f1e6bdcaca4dce8d52179c6a876/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2270` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF64/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.emw` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.S!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!7835DEB824C3` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| VBA32 | `Trojan.Elf64.Agent` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [517685bd342dc09c4bbf…](https://bazaar.abuse.ch/sample/517685bd342dc09c4bbf55fc6f5e66996ceef2d18d96440ee4857ad54f606ad0/)

- **Familie:** Snowlight
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!1CF53F3B3630
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.dws` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!1CF53F3B3630` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!1CF53F3B3630` |
| Varist | `E32/Agent.BE.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.ab!crit` |

### [94db44dd02356ecd82dc…](https://bazaar.abuse.ch/sample/94db44dd02356ecd82dce8495efa97f491c99a895dc69dcbda88df321f8807ef/)

- **Familie:** Snowlight
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!721EC36D460D
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.dws` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!721EC36D460D` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!721EC36D460D` |
| Varist | `E32/Agent.BE.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.ab!crit` |

### [4eed978bffdb456a9ffa…](https://bazaar.abuse.ch/sample/4eed978bffdb456a9ffa263cc97a37907e0f2406663cf67fbc3bf0b3a16ee4e2/)

- **Familie:** ELF:Downloader-BR [Drp]
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BR [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BR [Drp]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BR [Drp]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `DR/LINUX.Downloade.BR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Dropper.DR/LINUX.Downloade.BR` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Downloader.Agent/Linux!8.13C9D (TFE:14:7f7dlmYAy1C)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| Varist | `E32/Agent.DB.gen!Eldorado` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.7a308702` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

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

- **elf** (95×)
- **Mirai** (44×)
- **Snowlight** (30×)
- **Torii** (3×)
- **exe** (3×)
- **upx-dec** (2×)
- **upx** (2×)
- **Gafgyt** (1×)
- **Prometei** (1×)
- **sh** (1×)
- **VShell** (1×)
- **vbs** (1×)
- **cowrie** (1×)
- **honeypot** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +18 (26→44)
- neu: **Snowlight** (29)
- ↓ **unbekannt** -3 (27→24)
- neu: **Gafgyt** (1)
- ↓ **VShell** -1 (2→1)
- neu: **ELF:Downloader-BR [Drp]** (1)
- weg: **EchoBot** (war 3)
- weg: **WARDENStealer** (war 5)
- weg: **SalatStealer** (war 2)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +23 (21→44)
- ↑ **Snowlight** +28 (1→29)
- ↓ **unbekannt** -9 (33→24)
- neu: **Gafgyt** (1)
- ↓ **VShell** -1 (2→1)
- neu: **ELF:Downloader-BR [Drp]** (1)
- weg: **RemcosRAT** (war 2)
- weg: **SalatStealer** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)
- weg: **WARDENStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.103 MB |
| σ Dateigröße | 0.676 MB |
| Ø Risiko-Score | 61.6/100 |
| Ø Klassifikations-Konfidenz | 67.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 44/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 14 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:09 | [3a7baa9951ba…](https://bazaar.abuse.ch/sample/3a7baa9951ba3ed4336cb4854df1cdacf32f9a936680f39baaab773bfc02fc17/) | `elf` | Gafgyt | 84.4 | – | – | 🇩🇪DE |
| 05:01 | [49c507577ab6…](https://bazaar.abuse.ch/sample/49c507577ab6da5b7210db6eb565116e879f2bc5e9108389840a42a189678166/) | `elf` | unbekannt | 43.1 | – | – | 🇺🇸US |
| 05:00 | [c9c94586d37e…](https://bazaar.abuse.ch/sample/c9c94586d37ed1e18500da884988a6868cda9aab5b0ec4d83c387cb9599905f8/) | `elf` | Snowlight | 43.1 | – | – | 🇺🇸US |
| 05:00 | [82b8b37c4869…](https://bazaar.abuse.ch/sample/82b8b37c4869a03e43624481ef69ff7a761e0f1e6bdcaca4dce8d52179c6a876/) | `elf` | Mirai | 79.4 | 36.0% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 05:00 | [367c190e18c7…](https://bazaar.abuse.ch/sample/367c190e18c768821ca6230a40469f045ccb38ffe61b5e6facc7137ea4e1642c/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 09.11.2026 05:18 UTC*