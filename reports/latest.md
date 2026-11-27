# MalwareBazaar – 27.11.2026 07:23 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **41** |
| Höchster Score | **96.1/100** – 4cb6ed1cec23d867… |
| Häufigste Familie | **unbekannt** (24x) |
| Häufigster Typ | **elf** (43x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 25 Samples |
| Ø Dateigröße | 4.64 MB (σ=9.41) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 43 | 42.6%  ████████ |
| `exe` | 37 | 36.6%  ███████ |
| `sh` | 4 | 4.0%   |
| `vbs` | 4 | 4.0%   |
| `zip` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `jar` | 2 | 2.0%   |
| `dll` | 2 | 2.0%   |
| `7z` | 2 | 2.0%   |
| `iso` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 24 | 23.8% |
| 2 | Snowlight | 16 | 15.8% |
| 3 | Prometei | 15 | 14.9% |
| 4 | Mirai | 10 | 9.9% |
| 5 | WARDENStealer | 9 | 8.9% |
| 6 | RemusStealer | 6 | 5.9% |
| 7 | njrat | 4 | 4.0% |
| 8 | GuLoader | 3 | 3.0% |
| 9 | FleetDeck | 2 | 2.0% |
| 10 | WannaCry | 2 | 2.0% |
| 11 | CNBackdoor | 2 | 2.0% |
| 12 | ACRStealer | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 30 | 29.7% | 45% |
| Infostealer | 19 | 18.8% | 76% |
| Botnet/IoT | 12 | 11.9% | 91% |
| Windows-Malware | 10 | 9.9% | 35% |
| Loader | 10 | 9.9% | 80% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| RAT | 5 | 5.0% | 95% |
| Android-Malware | 2 | 2.0% | 45% |
| Ransomware | 2 | 2.0% | 95% |
| Backdoor | 2 | 2.0% | 75% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 41 | 40.6% |
| 🟠 HOCH | 10 | 9.9% |
| 🟡 MITTEL | 42 | 41.6% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [4cb6ed1cec23d8…](https://bazaar.abuse.ch/sample/4cb6ed1cec23d867519052a90c1518f96bffa6ce1a7dd2f418dd90e51de615e0/) | WannaCry | Ransomware | **96.1** | 🔴 KRITISCH | – | – | ? |
| [568457a3f7f574…](https://bazaar.abuse.ch/sample/568457a3f7f57435846704179136e37112f51ef842c3c5c5dc50126ef4f662a2/) | WannaCry | Ransomware | **95.9** | 🔴 KRITISCH | – | – | ? |
| [47a3deaa3a039f…](https://bazaar.abuse.ch/sample/47a3deaa3a039fda2355766ae50168d3c2f09b9e162a12a91d011bdd1ee19140/) | RemcosRAT | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |
| [3ee24d18474191…](https://bazaar.abuse.ch/sample/3ee24d184741913dcd4830c8f96d83893cb8600f6595ef1d36d4c56d2874bfc0/) | njrat | RAT | **86.7** | 🔴 KRITISCH | – | – | ? |
| [4cafe1c3bf6941…](https://bazaar.abuse.ch/sample/4cafe1c3bf694177f9354bc6111a3b010ee2c3e46e2d1310d8f703f7297af19a/) | njrat | RAT | **86.6** | 🔴 KRITISCH | – | – | ? |
| [99d5d5cac2d1da…](https://bazaar.abuse.ch/sample/99d5d5cac2d1dae784d40c8d65e5bd763c4fb3ecba4e6b0126f1717a31532d0a/) | Formbook | Infostealer | **86.6** | 🔴 KRITISCH | – | – | ? |
| [f38e079d9b9407…](https://bazaar.abuse.ch/sample/f38e079d9b940722bcd2a26d1d2a2e1323026dcf5f21f2023de8d3b4712706d4/) | njrat | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [a3c7ee3195dcd8…](https://bazaar.abuse.ch/sample/a3c7ee3195dcd84f4d006b027ac0c02f0b13050bd7faa09227c8af3621e3bb1b/) | njrat | RAT | **85.4** | 🔴 KRITISCH | – | – | ? |
| [a26c16372d3982…](https://bazaar.abuse.ch/sample/a26c16372d3982be4f5280110463196090413023696866211cdb4be259a3cb35/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [74e9182a82476c…](https://bazaar.abuse.ch/sample/74e9182a82476cc14e6900f6488acd02bd5bcb8abd4c3fed7605009ce9bc1ca1/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6623/8158 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6623/8158 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6322/8158 |
| 6 | Kaspersky | 75.5% | 6161/8157 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5813/8154 |
| 9 | Rising | 68.6% | 5600/8158 |
| 10 | Varist | 66.1% | 5391/8153 |
| 11 | Tencent | 65.3% | 5178/7932 |
| 12 | Avast | 65.1% | 5311/8154 |
| 13 | AVG | 65.1% | 5311/8153 |
| 14 | McAfeeD | 61.3% | 5000/8150 |
| 15 | huorong | 61.0% | 4974/8150 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 48 | 47.5% |
| 🪟 Windows | 42 | 41.6% |
| 📦 Archiv | 6 | 5.9% |
| ❓ Unbekannt | 3 | 3.0% |
| 🤖 Android | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 84.2% |
| C2 / Nachladen | 5 | 5.0% |
| Drive-By / Exploit-Kit | 4 | 4.0% |
| MaaS-Loader | 3 | 3.0% |
| APK-Sideloading | 2 | 2.0% |
| Exploit / N-Day | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 28 | 27.7% |
| 2 | 🇩🇪 DE | 26 | 25.7% |
| 3 | 🇪🇸 ES | 22 | 21.8% |
| 4 | 🇫🇷 FR | 12 | 11.9% |
| 5 | 🇨🇭 CH | 5 | 5.0% |
| 6 | 🇳🇱 NL | 5 | 5.0% |
| 7 | 🇯🇵 JP | 2 | 2.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 25 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 11 |
| Lateral Movement | 11 |
| Execution | 8 |
| Collection | 6 |
| Command and Control | 5 |
| Persistence | 5 |
| Defense Evasion | 3 |
| Credential Access | 1 |

<details><summary>47a3deaa3a039fda2355… – RemcosRAT | 🔴 KRITISCH 87.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>3ee24d184741913dcd48… – njrat | 🔴 KRITISCH 86.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>4cafe1c3bf694177f935… – njrat | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [8fb6b91efeb4ab7cde2f…](https://bazaar.abuse.ch/sample/8fb6b91efeb4ab7cde2f3e1eeb13554fdcac9af10876a0b055738b34103bf974/)

- **Familie:** Prometei
- **Erkannt von:** 31 von 74 Engines (41.9%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39504221
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39504221`

**Erkennende Engines (31/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39504221` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC95D` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39504221` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39504221 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39504221` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39504221` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Prometei!CB6C04651F16` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39504221` |
| Varist | `E64/PrometeiS.C` |
| huorong | `Trojan/Prometei.c` |

### [1baf3cc8000f03eff249…](https://bazaar.abuse.ch/sample/1baf3cc8000f03eff249d02bce841785bb18e843e56cf865868b7b3e6a52d0e9/)

- **Familie:** Malware
- **Erkannt von:** 15 von 74 Engines (20.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.59521AC8
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.59521AC8` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [e3e75de320d4d391d0df…](https://bazaar.abuse.ch/sample/e3e75de320d4d391d0df8d341dc65d1d7fb985524bf0fdb0cd67c593be4fa9d0/)

- **Familie:** WARDENStealer
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.93C08E2
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R808447` |
| Bkav | `W32.Malware.93C08E2` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kaspersky | `VHO:Trojan.Win32.Agent.gen` |
| Kingsoft | `malware.kb.a.970` |
| Malwarebytes | `Trojan.Injector.RND.Generic` |
| MaxSecure | `Trojan.W32.251126.WardenStealer.a.swat.YR` |
| McAfeeD | `Trojan:Win/RavenStealer.NE` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Rising | `Trojan.Kryptik@AI.93 (RDML:zFLWybku3pvQ6A5pwLjKYA)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `W32.Trojan.Gen` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [fa9e77fab0c6495bdb2b…](https://bazaar.abuse.ch/sample/fa9e77fab0c6495bdb2b3a8cd3dabcebaa572e4c31bcd282811d6d5e8da0dd02/)

- **Familie:** ELF:Downloader-BR [Drp]
- **Erkannt von:** 21 von 74 Engines (28.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BR [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/74):**

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
| Fortinet | `ELF/Agent.IT!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Downloader.Agent/Linux!8.13C9D (TFE:14:7f7dlmYAy1C)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| Varist | `E32/Agent.DB.gen!Eldorado` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.7a308702` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **elf** (43×)
- **exe** (38×)
- **Snowlight** (16×)
- **Prometei** (15×)
- **WARDENStealer** (12×)
- **Mirai** (11×)
- **signed** (9×)
- **RemusStealer** (6×)
- **Torii** (5×)
- **71a55f** (5×)
- **sh** (4×)
- **vbs** (4×)
- **njrat** (4×)
- **RAT** (4×)
- **GuLoader** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -8 (32→24)
- neu: **Snowlight** (16)
- ↑ **Prometei** +7 (8→15)
- ↓ **Mirai** -27 (37→10)
- neu: **WARDENStealer** (9)
- neu: **RemusStealer** (6)
- ↑ **njrat** +3 (1→4)
- neu: **GuLoader** (3)
- neu: **FleetDeck** (2)
- neu: **WannaCry** (2)
- weg: **AgentTesla** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **CatStorm** (war 8)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -15 (39→24)
- ↑ **Snowlight** +13 (3→16)
- ↑ **Prometei** +10 (5→15)
- ↓ **Mirai** -11 (21→10)
- ↑ **WARDENStealer** +6 (3→9)
- neu: **RemusStealer** (6)
- ↑ **njrat** +2 (2→4)
- neu: **GuLoader** (3)
- neu: **FleetDeck** (2)
- neu: **WannaCry** (2)
- weg: **CatStorm** (war 2)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.636 MB |
| σ Dateigröße | 9.407 MB |
| Ø Risiko-Score | 58.9/100 |
| Ø Klassifikations-Konfidenz | 61.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 25/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 07:19 | [3db8beda6ffe…](https://bazaar.abuse.ch/sample/3db8beda6ffed5244ea4c3343c0f7dfbe153421085d20c446c2d8adb4e2f5c30/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 07:18 | [c563c85b9ef3…](https://bazaar.abuse.ch/sample/c563c85b9ef3688a049f29df7424eda621f86e7310159f3065f00d4ca5093759/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 07:12 | [a26c16372d39…](https://bazaar.abuse.ch/sample/a26c16372d3982be4f5280110463196090413023696866211cdb4be259a3cb35/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 07:12 | [8a0220a06604…](https://bazaar.abuse.ch/sample/8a0220a06604d08a75adb50f2c75bcd5c44457c39effce59e7c07dbd93fc2341/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 07:09 | [79e7e2035513…](https://bazaar.abuse.ch/sample/79e7e203551314bd53577efa71e6119666e2c6302fb9c9922d7850f7241f5b2b/) | `exe` | FleetDeck | 38.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 27.11.2026 07:23 UTC*