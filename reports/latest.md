# MalwareBazaar – 07.11.2026 00:00 UTC

Dieser Run hat **59 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **60** |
| Kritisch (≥75) | **33** |
| Höchster Score | **88.3/100** – cc15b5db6eb77fd0… |
| Häufigste Familie | **Mirai** (26x) |
| Häufigster Typ | **elf** (30x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 27 Samples |
| Ø Dateigröße | 4.66 MB (σ=10.22) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 30 | 50.0%  ██████████ |
| `exe` | 25 | 41.7%  ████████ |
| `jar` | 2 | 3.3%   |
| `ps1` | 1 | 1.7%   |
| `msi` | 1 | 1.7%   |
| `sh` | 1 | 1.7%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 26 | 43.3% |
| 2 | VShell | 11 | 18.3% |
| 3 | unbekannt | 11 | 18.3% |
| 4 | WARDENStealer | 6 | 10.0% |
| 5 | Silentnet | 2 | 3.3% |
| 6 | SilentNet | 1 | 1.7% |
| 7 | Vidar | 1 | 1.7% |
| 8 | Gorat | 1 | 1.7% |
| 9 | NanoCore | 1 | 1.7% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 26 | 43.3% | 95% |
| Windows-Malware | 16 | 26.7% | 35% |
| Infostealer | 7 | 11.7% | 78% |
| Linux-Malware | 4 | 6.7% | 45% |
| Andere / Unbekannt | 3 | 5.0% | 20% |
| RAT | 2 | 3.3% | 80% |
| Skript/Dropper | 1 | 1.7% | 35% |
| Trojaner | 1 | 1.7% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 33 | 55.0% |
| 🟠 HOCH | 3 | 5.0% |
| 🟡 MITTEL | 21 | 35.0% |
| 🟢 NIEDRIG | 3 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [cc15b5db6eb77f…](https://bazaar.abuse.ch/sample/cc15b5db6eb77fd0b3720e709c4a1c05b4bb156bcc36fde59817705c55d7504e/) | Vidar | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [dc0319acd1efff…](https://bazaar.abuse.ch/sample/dc0319acd1efffd248ce27b476c1c9e712cdef84fe4db0419bfa517ae09052e8/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [4ac60577d94b0a…](https://bazaar.abuse.ch/sample/4ac60577d94b0a1104484d07605942b05bc2764601cb8d59cb5b0bf8ceb31aaf/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [942fa5f406ab3c…](https://bazaar.abuse.ch/sample/942fa5f406ab3cf520632b84f5573f65caf412eaaacc2344d0916c5c5a672bdb/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [a94dc1b2f69847…](https://bazaar.abuse.ch/sample/a94dc1b2f69847597e0ab38bfee2b02b7a945e042b48ce536658b07dfe0c7fa7/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [c81edf8b6f9d66…](https://bazaar.abuse.ch/sample/c81edf8b6f9d6691f29a3ba56f4be2a7b6aa661c93a4913e8e5d7085fc81e7b9/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [cfb03e874e3861…](https://bazaar.abuse.ch/sample/cfb03e874e3861a59177c94f5f55219ef2e7bb27a05f5840388ee1356bad8924/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [add3a24af01e12…](https://bazaar.abuse.ch/sample/add3a24af01e12693ff8afe21713f9b784e9fb741d6c03587783f6fa3348ec02/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [2b7e8ac60ace15…](https://bazaar.abuse.ch/sample/2b7e8ac60ace152cadc7da94bf1401a290f942923735db061af41bd50cb501d4/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [840b953a4da855…](https://bazaar.abuse.ch/sample/840b953a4da8557b6ac82b5a3ed63a1fedc5328e5681a48c8e20465bd3e8712d/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6364/7857 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6364/7857 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6070/7857 |
| 6 | Kaspersky | 75.4% | 5927/7856 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5591/7853 |
| 9 | Rising | 68.3% | 5366/7857 |
| 10 | Varist | 66.1% | 5194/7852 |
| 11 | Avast | 65.1% | 5109/7853 |
| 12 | AVG | 65.1% | 5109/7852 |
| 13 | Tencent | 64.9% | 4953/7631 |
| 14 | McAfeeD | 61.4% | 4820/7849 |
| 15 | huorong | 60.8% | 4776/7849 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 42 | 70.0% |
| 🪟 Windows | 16 | 26.7% |
| ❓ Unbekannt | 2 | 3.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 59 | 98.3% |
| Trojanisierte Software | 1 | 1.7% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇳🇱 NL | 28 | 46.7% |
| 2 | 🇫🇷 FR | 12 | 20.0% |
| 3 | 🇩🇪 DE | 9 | 15.0% |
| 4 | 🇺🇸 US | 7 | 11.7% |
| 5 | 🌐 Unbekannt | 2 | 3.3% |
| 6 | 🇮🇩 ID | 2 | 3.3% |

## MITRE ATT&CK

> 27 von 60 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 26 |
| Lateral Movement | 26 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |

<details><summary>cc15b5db6eb77fd0b372… – Vidar | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>dc0319acd1efffd248ce… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4ac60577d94b0a110448… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>942fa5f406ab3cf52063… – Mirai | 🔴 KRITISCH 83.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a94dc1b2f69847597e0a… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [8b261fda299fecdf5850…](https://bazaar.abuse.ch/sample/8b261fda299fecdf58507945690b7f3aff58b410490e91ea66299ffb49eae060/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Application.Generic.37119494
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37119494`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37119494` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D2366606` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37119494` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37119494 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37119494` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37119494` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37119494` |
| huorong | `Trojan/Prometei.c` |

### [4de4621f66780e1400bf…](https://bazaar.abuse.ch/sample/4de4621f66780e1400bf3c55f146f84f6d77bbdd3a401451f3b7f16d674e3804/)

- **Familie:** Gorat
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.Gorat.H.48292B95
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Generic.Gorat.H.48292B95`

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Gorat.H.48292B95` |
| Arcabit | `Generic.Gorat.H.48292B95` |
| BitDefender 🛡️ | `Generic.Gorat.H.48292B95` |
| Bkav | `W32.Malware.8107FC39` |
| CTX | `exe.unknown.gorat` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Flooder.Agent.I trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Generic.Gorat.H.48292B95 (B)` |
| GData | `Generic.Gorat.H.48292B95` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Agent` |
| Lionic | `Trojan.UKP.Generic.4!c` |
| MicroWorld-eScan | `Generic.Gorat.H.48292B95` |
| Microsoft 🛡️ | `Trojan:Win64/Flooder.AA!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14326 (CLASSIC)` |
| Tencent | `Trojan.Win64.GoratFlooder.16006104` |
| VIPRE | `Generic.Gorat.H.48292B95` |
| huorong | `HackTool/W64.Flooder.a!crit` |

### [9e6da804ae9ca0a07348…](https://bazaar.abuse.ch/sample/9e6da804ae9ca0a07348e92d99416bcf3fc650ccbdf4a9b4db34f6d546ddfb10/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:DDOSAgent-GJ [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:DDOSAgent-GJ [Expl]` |
| Antiy-AVL | `Trojan[DDoS]/Linux.Agent` |
| Avast | `ELF:DDOSAgent-GJ [Expl]` |
| DrWeb | `Linux.DDoS.2850` |
| ESET-NOD32 | `Linux/Flooder.Agent.JS trojan` |
| Fortinet | `ELF/Flooder.JS!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.DDoS` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.vd` |
| Rising | `Backdoor.Mirai/Linux!1.14326 (CLASSIC)` |
| Tencent | `Trojan-DDoS.Linux.Agent.hb` |
| alibabacloud | `Trojan:Linux/Flooder.Akgpp` |
| huorong | `Trojan/Linux.Mirai.bv!crit` |

### [151754ec3454ca923e15…](https://bazaar.abuse.ch/sample/151754ec3454ca923e1534780d92322a7c34f07f6ea182b8badfa702684fa52b/)

- **Familie:** VShell
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Rozena.60
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Rozena.60`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Rozena.60` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R706966` |
| Antiy-AVL | `Trojan/Win32.Mikey` |
| Arcabit | `Trojan.Rozena.60` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Rozena.60` |
| Bkav | `W32.Malware.B936D804` |
| CTX | `exe.unknown.rozena` |
| ClamAV | `Win.Malware.Mikey-10044490-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.DownLoader48.12277` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Rozena.60 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/HelloKitty.PNG!tr.ransom` |
| GData | `Gen:Variant.Rozena.60` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Shelm` |
| Jiangmin | `Trojan.Generic.hscxe` |
| K7AntiVirus | `Trojan ( 005c2d751 )` |
| K7GW | `Trojan ( 005c2d751 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Malwarebytes | `Trojan.ShellCode.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!151754EC3454` |
| MicroWorld-eScan | `Gen:Variant.Rozena.60` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Trojan.Win64.NetworkShellcodeLoader.lkdmtv` |
| Rising | `Backdoor.VShell/x64!1.13127 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Mikey` |
| Skyhigh | `Trojan-JAED!0B7616336D70` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Rozena.cbq` |
| TrellixENS | `Trojan-JAED!0B7616336D70` |
| VIPRE | `Gen:Variant.Rozena.60` |
| Varist | `W64/Rozena.IC.gen!Eldorado` |
| VirIT | `Trojan.Win64.Genus.GAI` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Trojan:Win/Rozena.7352d04f` |
| huorong | `TrojanDownloader/Small.hr` |

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

- **elf** (30×)
- **Mirai** (26×)
- **exe** (24×)
- **VShell** (11×)
- **Ladvix** (5×)
- **upx** (4×)
- **WARDENStealer** (4×)
- **Warden** (4×)
- **Prometei** (3×)
- **cowrie** (3×)
- **honeypot** (3×)
- **upx-dec** (3×)
- **Stealer** (3×)
- **WardenStealer** (2×)
- **stealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +18 (8→26)
- ↑ **VShell** +8 (3→11)
- ↓ **unbekannt** -36 (47→11)
- ↑ **WARDENStealer** +4 (2→6)
- ↓ **Silentnet** -1 (3→2)
- neu: **Gorat** (1)
- neu: **NanoCore** (1)
- weg: **FunStealer** (war 5)
- weg: **RemcosRAT** (war 3)
- weg: **XWorm** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 2)
- weg: **RevStealer** (war 8)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +8 (18→26)
- ↑ **VShell** +10 (1→11)
- ↓ **unbekannt** -24 (35→11)
- ↑ **WARDENStealer** +4 (2→6)
- ↑ **Silentnet** +1 (1→2)
- neu: **Vidar** (1)
- neu: **Gorat** (1)
- weg: **SalatStealer** (war 5)
- weg: **Formbook** (war 3)
- weg: **RemcosRAT** (war 2)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.657 MB |
| σ Dateigröße | 10.222 MB |
| Ø Risiko-Score | 63.0/100 |
| Ø Klassifikations-Konfidenz | 67.9% |
| Samples mit VT | 5/60 |
| Samples mit MITRE | 27/60 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 3 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:55 | [a2be7c598232…](https://bazaar.abuse.ch/sample/a2be7c598232fd904c4cae52a3d6c4882e4215058c877e5eb457dbdcd6ac7565/) | `exe` | VShell | 39.1 | – | – | 🇳🇱NL |
| 23:46 | [f9061f7b36d5…](https://bazaar.abuse.ch/sample/f9061f7b36d532aed8903b3cf0da34a9e86d5b6d1afe9473d0b56421a7a7b694/) | `ps1` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 23:44 | [dc0319acd1ef…](https://bazaar.abuse.ch/sample/dc0319acd1efffd248ce27b476c1c9e712cdef84fe4db0419bfa517ae09052e8/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 23:40 | [05b9093b0904…](https://bazaar.abuse.ch/sample/05b9093b090410fe33d1026a36af12a7c546c523d801a5de854c5a961e15a0f3/) | `exe` | VShell | 38.8 | – | – | 🇳🇱NL |
| 23:35 | [a931d0024e78…](https://bazaar.abuse.ch/sample/a931d0024e785f0059df3a0f81efc3e5f0a6d5b3a9438401c756c8beda489523/) | `exe` | VShell | 38.7 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 07.11.2026 00:00 UTC*