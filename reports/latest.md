# MalwareBazaar – 24.11.2026 04:42 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **45** |
| Höchster Score | **84.1/100** – 568fb54ea0cb1c12… |
| Häufigste Familie | **unbekannt** (54x) |
| Häufigster Typ | **elf** (58x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 16 Samples |
| Ø Dateigröße | 2.49 MB (σ=3.92) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 58 | 58.0%  ███████████ |
| `exe` | 25 | 25.0%  █████ |
| `macho` | 14 | 14.0%  ██ |
| `vbs` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 54 | 54.0% |
| 2 | Snowlight | 19 | 19.0% |
| 3 | Mirai | 11 | 11.0% |
| 4 | ConnectWise | 7 | 7.0% |
| 5 | VShell | 4 | 4.0% |
| 6 | WARDENStealer | 3 | 3.0% |
| 7 | Adware.OfferCore | 1 | 1.0% |
| 8 | RemusStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 30 | 30.0% | 75% |
| Windows-Malware | 21 | 21.0% | 35% |
| Linux-Malware | 20 | 20.0% | 45% |
| Botnet/IoT | 16 | 16.0% | 89% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Infostealer | 4 | 4.0% | 75% |
| Trojaner | 2 | 2.0% | 65% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Android-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 45.0% |
| 🟠 HOCH | 7 | 7.0% |
| 🟡 MITTEL | 43 | 43.0% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [568fb54ea0cb1c…](https://bazaar.abuse.ch/sample/568fb54ea0cb1c12b4c715aafb2c9f70578d75566f8f5aa4836e303e5281bac8/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [8fe49621b41edc…](https://bazaar.abuse.ch/sample/8fe49621b41edccde2410fc98fae074fc19aacb5bae2a13ffcca027729a150f7/) | Mirai | Botnet/IoT | **81.6** | 🔴 KRITISCH | – | – | ? |
| [15567428d31120…](https://bazaar.abuse.ch/sample/15567428d311200e40e7ab177057c175b4e2a6ee8d1988d6e0b48e7616957ed7/) | Mirai | Botnet/IoT | **81.5** | 🔴 KRITISCH | – | – | ? |
| [899393290e2cd7…](https://bazaar.abuse.ch/sample/899393290e2cd788738eedcc60a5daffbce33ce663de5a1d33d8ae7ecdd31ae8/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [92a7b768621553…](https://bazaar.abuse.ch/sample/92a7b7686215536194376d0bd9e13048838bfe5c6520e4ab1032083b75631809/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [b2cef7e99d9eca…](https://bazaar.abuse.ch/sample/b2cef7e99d9ecac752f9349b05176db590c0cebe9e9bd661c0c09bc8fa6cb3b9/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [59d1d9200ca05c…](https://bazaar.abuse.ch/sample/59d1d9200ca05c65cb886acb09e0a3db90680ac0578b2eff8cbdd1b07cfa1266/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |
| [e6287b4eb9367d…](https://bazaar.abuse.ch/sample/e6287b4eb9367dcd6c22c288633694dc01684cb10576a5335b6e2b107facba88/) | unbekannt | RAT | **81.2** | 🔴 KRITISCH | – | – | ? |
| [c82fefc1415785…](https://bazaar.abuse.ch/sample/c82fefc141578588963773e3c182c1c26acd149b240c5a5fe0d994beaa924152/) | Mirai | Botnet/IoT | **81.2** | 🔴 KRITISCH | – | – | ? |
| [4467f0bf8f96ee…](https://bazaar.abuse.ch/sample/4467f0bf8f96ee978722e4ca9308088d65eee1ffc6ee45b6b1b1a3bf9eec37ef/) | Mirai | Botnet/IoT | **81.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6593/8120 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6593/8120 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6288/8120 |
| 6 | Kaspersky | 75.6% | 6142/8119 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5787/8116 |
| 9 | Rising | 68.6% | 5570/8120 |
| 10 | Varist | 66.1% | 5366/8115 |
| 11 | Tencent | 65.2% | 5148/7894 |
| 12 | Avast | 65.2% | 5295/8116 |
| 13 | AVG | 65.2% | 5295/8115 |
| 14 | McAfeeD | 61.5% | 4987/8112 |
| 15 | huorong | 61.0% | 4951/8112 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 71 | 71.0% |
| 🪟 Windows | 23 | 23.0% |
| 🍎 macOS | 5 | 5.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 98.0% |
| APK-Sideloading | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 54 | 54.0% |
| 2 | 🇫🇷 FR | 43 | 43.0% |
| 3 | 🇳🇱 NL | 1 | 1.0% |
| 4 | 🌐 TH | 1 | 1.0% |
| 5 | 🇯🇵 JP | 1 | 1.0% |

## MITRE ATT&CK

> 16 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 16 |
| Lateral Movement | 16 |

<details><summary>568fb54ea0cb1c12b4c7… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>8fe49621b41edccde241… – Mirai | 🔴 KRITISCH 81.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>15567428d311200e40e7… – Mirai | 🔴 KRITISCH 81.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>899393290e2cd788738e… – Mirai | 🔴 KRITISCH 81.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>92a7b768621553619437… – Mirai | 🔴 KRITISCH 81.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 34 von 74 Engines (46.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (34/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Alibaba | `RiskWare:MSIL/ConnectWise.1db56782` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop31.17564` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kaspersky | `not-a-virus:RemoteAdmin.MSIL.ConnectWise.b` |
| Lionic | `Riskware.Win32.ConnectWise.1!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| MaxSecure | `RemoteAdmin.W32.181224.CWise.gen.YR` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win32.ScreenConnect.tc` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrellixENS | `PUP-IPR` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |

### [dffa6d4603b3e7926da0…](https://bazaar.abuse.ch/sample/dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644/)

- **Familie:** VShell
- **Erkannt von:** 48 von 73 Engines (65.8%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Rozena.85
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Rozena.85`

**Erkennende Engines (48/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Rozena.85` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R706966` |
| Antiy-AVL | `Trojan[Downloader]/Win64.Small` |
| Arcabit | `Trojan.Rozena.85` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Rozena.85` |
| Bkav | `W32.Malware.6952AD0B` |
| CTX | `exe.unknown.rozena` |
| ClamAV | `Win.Malware.Mikey-10044490-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.DownLoader48.12277` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Rozena.85 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/HelloKitty.PNG!tr.ransom` |
| GData | `Gen:Variant.Rozena.85` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Shelm` |
| Jiangmin | `Trojan.Generic.hsgtv` |
| K7AntiVirus | `Trojan ( 005c2d751 )` |
| K7GW | `Trojan ( 005c2d751 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Malwarebytes | `Trojan.ShellCode.Generic` |
| MaxSecure | `Trojan.W64.040826.Cerbu.Rozena.YR` |
| McAfeeD | `ti!DFFA6D4603B3` |
| MicroWorld-eScan | `Gen:Variant.Rozena.85` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Trojan.Win64.NetworkShellcodeLoader.lkdmtv` |
| Rising | `Backdoor.VShell/x64!1.13127 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Mikey` |
| Skyhigh | `Trojan-JAED!7F0439FBD368` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Rozena.cbq` |
| TrellixENS | `Trojan-JAED!7F0439FBD368` |
| VIPRE | `Gen:Variant.Rozena.85` |
| Varist | `W64/Rozena.IC.gen!Eldorado` |
| VirIT | `Trojan.Win64.Genus.GAI` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Trojan:Win/Rozena.7352d04f` |
| huorong | `TrojanDownloader/Small.hr` |

### [9b0df0e5780d90b5bf93…](https://bazaar.abuse.ch/sample/9b0df0e5780d90b5bf93a01dd2d405c5293a81fa20a45f3a842181a0c15dad7b/)

- **Familie:** Snowlight
- **Erkannt von:** 28 von 73 Engines (38.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/73):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!B05EE61BF478` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [3ed9331395f682afa485…](https://bazaar.abuse.ch/sample/3ed9331395f682afa48574702b4f0474981bd0e6d1283bf61e95966c1d673e05/)

- **Familie:** RemusStealer
- **Erkannt von:** 13 von 73 Engines (17.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/73):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `MalwareX-gen [Pws]` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.A9731CD2` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (moderate confidence)` |
| Kaspersky | `UDS:Trojan.Win32.Dizemp` |
| Kingsoft | `malware.kb.a.972` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| huorong | `Trojan/ShellLoader.axp` |

### [0149ed565f55195e2a61…](https://bazaar.abuse.ch/sample/0149ed565f55195e2a611d5b3576b01b8f5a8b6acb7162e71cd659034f45b105/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 73 Engines (30.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!C3618F7B0AB0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/73):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Gafgyt` |
| Avast | `ELF:Downloader-BP [Trj]` |
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
| Microsoft 🛡️ | `Trojan:Linux/Mirai.AT!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!C3618F7B0AB0` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!C3618F7B0AB0` |
| Varist | `E32/Agent.DC.gen!Eldorado` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |


## Top Tags

- **elf** (57×)
- **EasyShell** (30×)
- **RAT** (30×)
- **Rust** (30×)
- **SnoopyTriage** (30×)
- **exe** (25×)
- **Snowlight** (19×)
- **Mirai** (16×)
- **macho** (14×)
- **ConnectWise** (7×)
- **rmm-abuse** (7×)
- **ScreenConnect** (7×)
- **signed** (7×)
- **VShell** (4×)
- **WARDENStealer** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +25 (29→54)
- neu: **Snowlight** (19)
- ↓ **Mirai** -19 (30→11)
- neu: **ConnectWise** (7)
- neu: **VShell** (4)
- ↓ **WARDENStealer** -1 (4→3)
- neu: **Adware.OfferCore** (1)
- ↓ **RemusStealer** -1 (2→1)
- weg: **Prometei** (war 6)
- weg: **RemcosRAT** (war 2)
- weg: **njrat** (war 2)
- weg: **EasyShell** (war 18)
- weg: **SalatStealer** (war 2)
- weg: **WSHRat** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +21 (33→54)
- ↑ **Snowlight** +17 (2→19)
- ↓ **Mirai** -20 (31→11)
- ↑ **ConnectWise** +6 (1→7)
- neu: **VShell** (4)
- ↓ **WARDENStealer** -2 (5→3)
- neu: **Adware.OfferCore** (1)
- neu: **RemusStealer** (1)
- weg: **RemcosRAT** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Prometei** (war 5)
- weg: **njrat** (war 2)
- weg: **FantasyHub** (war 2)
- weg: **EasyShell** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.494 MB |
| σ Dateigröße | 3.919 MB |
| Ø Risiko-Score | 59.1/100 |
| Ø Klassifikations-Konfidenz | 59.2% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 16/100 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 20 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:36 | [e6287b4eb936…](https://bazaar.abuse.ch/sample/e6287b4eb9367dcd6c22c288633694dc01684cb10576a5335b6e2b107facba88/) | `macho` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 04:10 | [568fb54ea0cb…](https://bazaar.abuse.ch/sample/568fb54ea0cb1c12b4c715aafb2c9f70578d75566f8f5aa4836e303e5281bac8/) | `elf` | Mirai | 84.1 | – | – | 🇳🇱NL |
| 04:09 | [9f326bf52b4a…](https://bazaar.abuse.ch/sample/9f326bf52b4ab535018c5199876e93913f33a9e472423e635c2248ebf43e8ad1/) | `elf` | Snowlight | 42.9 | – | – | 🇺🇸US |
| 04:08 | [b055c8859a55…](https://bazaar.abuse.ch/sample/b055c8859a55e8683cec80bb4b721d10e0e6821637f2dafdb35c8bab29874eb7/) | `elf` | unbekannt | 42.9 | – | – | 🇫🇷FR |
| 04:06 | [bc51b59a1f8e…](https://bazaar.abuse.ch/sample/bc51b59a1f8e740b54209fe896c8d7c52b3109002c685f22b05af989b96a320a/) | `elf` | unbekannt | 80.8 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.11.2026 04:42 UTC*