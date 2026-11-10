# MalwareBazaar – 10.11.2026 07:05 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **50** |
| Höchster Score | **83.7/100** – 4a64138c242b044f… |
| Häufigste Familie | **unbekannt** (30x) |
| Häufigster Typ | **elf** (58x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 28 Samples |
| Ø Dateigröße | 2.66 MB (σ=4.59) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 58 | 57.4%  ███████████ |
| `exe` | 33 | 32.7%  ██████ |
| `js` | 6 | 5.9%  █ |
| `docx` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 30 | 29.7% |
| 2 | Mirai | 27 | 26.7% |
| 3 | SalatStealer | 22 | 21.8% |
| 4 | Snowlight | 14 | 13.9% |
| 5 | AgentTesla | 2 | 2.0% |
| 6 | CoinMiner | 2 | 2.0% |
| 7 | RevStealer | 2 | 2.0% |
| 8 | RudeDevil | 1 | 1.0% |
| 9 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 30 | 29.7% | 45% |
| Botnet/IoT | 27 | 26.7% | 95% |
| Infostealer | 24 | 23.8% | 75% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Windows-Malware | 6 | 5.9% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Loader | 2 | 2.0% | 75% |
| Maldoc | 1 | 1.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |
| Android-Malware | 1 | 1.0% | 45% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 50 | 49.5% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 44 | 43.6% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [4a64138c242b04…](https://bazaar.abuse.ch/sample/4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [43d1a98eb1f031…](https://bazaar.abuse.ch/sample/43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [810b14a04ffbf6…](https://bazaar.abuse.ch/sample/810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [af2cff1c6787f3…](https://bazaar.abuse.ch/sample/af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [aa56c8dd587df3…](https://bazaar.abuse.ch/sample/aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [dd17dea02b2040…](https://bazaar.abuse.ch/sample/dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [92ae676dc54633…](https://bazaar.abuse.ch/sample/92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [c29adb640900be…](https://bazaar.abuse.ch/sample/c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [5581413a198a4b…](https://bazaar.abuse.ch/sample/5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [0e8e773ff96909…](https://bazaar.abuse.ch/sample/0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6420/7916 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6420/7916 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6119/7916 |
| 6 | Kaspersky | 75.5% | 5976/7915 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5636/7912 |
| 9 | Rising | 68.4% | 5414/7916 |
| 10 | Varist | 66.2% | 5234/7911 |
| 11 | Avast | 65.2% | 5160/7912 |
| 12 | AVG | 65.2% | 5160/7911 |
| 13 | Tencent | 65.0% | 4997/7690 |
| 14 | McAfeeD | 61.4% | 4855/7908 |
| 15 | huorong | 61.0% | 4821/7908 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 58 | 57.4% |
| 🪟 Windows | 33 | 32.7% |
| ❓ Unbekannt | 7 | 6.9% |
| 📄 Dokument | 1 | 1.0% |
| 📦 Archiv | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 91 | 90.1% |
| Drive-By / Exploit-Kit | 6 | 5.9% |
| MaaS-Loader | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 35 | 34.7% |
| 2 | 🇺🇸 US | 34 | 33.7% |
| 3 | 🇩🇪 DE | 15 | 14.9% |
| 4 | 🇳🇱 NL | 11 | 10.9% |
| 5 | 🌐 PT | 2 | 2.0% |
| 6 | 🇮🇳 IN | 1 | 1.0% |
| 7 | 🇮🇩 ID | 1 | 1.0% |
| 8 | 🇯🇵 JP | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 28 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 27 |
| Lateral Movement | 27 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>4a64138c242b044fb7fd… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>43d1a98eb1f0314e6f9b… – Mirai | 🔴 KRITISCH 83.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>810b14a04ffbf6e0ccf6… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>af2cff1c6787f3fa75f1… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>aa56c8dd587df31e42ae… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a92f2d3dc8ca44a3aa1b…](https://bazaar.abuse.ch/sample/a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af/)

- **Familie:** CoinMiner
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** IL:Trojan.Downloader.4973
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `IL:Trojan.Downloader.4973`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `IL:Trojan.Downloader.4973` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Malware/Win.Generic.C4478643` |
| Antiy-AVL | `Trojan/MSIL.Mokes` |
| Arcabit | `IL:Trojan.Downloader.D136D` |
| Avast | `Win32:MalwareX-gen [Cryp]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `IL:Trojan.Downloader.4973` |
| Bkav | `W32.Malware.976A67E0` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Packed.Msilzilla-10018301-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDropNET.43` |
| ESET-NOD32 | `MSIL/Agent.UZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `IL:Trojan.Downloader.4973 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `MSIL/GenKryptik.FFMZ!tr` |
| GData | `IL:Trojan.Downloader.4973` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Krypt` |
| K7AntiVirus | `Ransomware ( 005a8b921 )` |
| K7GW | `Ransomware ( 005a8b921 )` |
| Kaspersky | `HEUR:Trojan-Downloader.MSIL.ShortLoader.gen` |
| Malwarebytes | `Trojan.Crypt.MSIL.Generic` |
| McAfeeD | `Real Protect-LS!14013E5F8CE2` |
| MicroWorld-eScan | `IL:Trojan.Downloader.4973` |
| Microsoft 🛡️ | `Trojan:MSIL/Mokes.B!MTB` |
| Rising | `Trojan.AntiVM!1.CF63 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXOO-YN!14013E5F8CE2` |
| Sophos | `Troj/ILAgent-I` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16002975` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `GenericRXOO-YN!14013E5F8CE2` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Injector.gen` |
| VIPRE | `IL:Trojan.Downloader.4973` |
| Varist | `W32/MSIL_Kryptik.FFY.gen!Eldorado` |
| ZoneAlarm | `Troj/ILAgent-I` |
| huorong | `VirTool/MSIL.Obfuscator.su` |

### [e50d206d484b8d1681e3…](https://bazaar.abuse.ch/sample/e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524/)

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
| Bkav | `W32.Malware.A859E5BF` |
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
| McAfeeD | `Real Protect-LS!C5366430A3D5` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!C5366430A3D5` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570817` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!C5366430A3D5` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [217b3a2ff0d10801141c…](https://bazaar.abuse.ch/sample/217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da/)

- **Familie:** Snowlight
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
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
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!A95190CA9386` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [96679534563c125293b2…](https://bazaar.abuse.ch/sample/96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!2A5AFB05B2A8
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Gafgyt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Siggen.900` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Gafgyt.BJ!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!2A5AFB05B2A8` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!2A5AFB05B2A8` |
| Varist | `E32/Agent.DC.gen!Eldorado` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vefl` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (58×)
- **exe** (32×)
- **Mirai** (27×)
- **Snowlight** (14×)
- **SalatStealer** (11×)
- **upx-dec** (11×)
- **salatstealer** (11×)
- **upx** (11×)
- **js** (6×)
- **Prometei** (3×)
- **AgentTesla** (2×)
- **CoinMiner** (2×)
- **dropped-by-OffLoader** (2×)
- **RevStealer** (2×)
- **docx** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +2 (28→30)
- ↑ **Mirai** +11 (16→27)
- neu: **SalatStealer** (22)
- neu: **Snowlight** (14)
- ↓ **AgentTesla** -6 (8→2)
- neu: **CoinMiner** (2)
- neu: **RevStealer** (2)
- neu: **RudeDevil** (1)
- ↓ **RemcosRAT** -9 (10→1)
- weg: **Formbook** (war 4)
- weg: **AsyncRAT** (war 2)
- weg: **LxBaseRAT** (war 2)
- weg: **WARDENStealer** (war 7)
- weg: **Vidar** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -2 (32→30)
- ↑ **Mirai** +5 (22→27)
- ↑ **SalatStealer** +20 (2→22)
- ↑ **Snowlight** +12 (2→14)
- ↓ **AgentTesla** -1 (3→2)
- ↑ **CoinMiner** +1 (1→2)
- ↑ **RevStealer** +1 (1→2)
- neu: **RudeDevil** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)
- weg: **WARDENStealer** (war 3)
- weg: **VShell** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.659 MB |
| σ Dateigröße | 4.587 MB |
| Ø Risiko-Score | 62.1/100 |
| Ø Klassifikations-Konfidenz | 65.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 28/101 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 22 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 06:57 | [53917de940b5…](https://bazaar.abuse.ch/sample/53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e/) | `js` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 06:56 | [94b597e300b6…](https://bazaar.abuse.ch/sample/94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29/) | `docx` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 06:56 | [264e109751bb…](https://bazaar.abuse.ch/sample/264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3/) | `js` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 06:55 | [6f4facc2fa66…](https://bazaar.abuse.ch/sample/6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282/) | `exe` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 06:55 | [bc00e9d8bb62…](https://bazaar.abuse.ch/sample/bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e/) | `exe` | AgentTesla | 39.0 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 10.11.2026 07:05 UTC*