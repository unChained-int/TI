# MalwareBazaar – 26.11.2026 22:53 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **45** |
| Höchster Score | **91.0/100** – 8a7e85ac6f02a2d3… |
| Häufigste Familie | **unbekannt** (41x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 26 Samples |
| Ø Dateigröße | 8.34 MB (σ=19.23) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 52.5%  ██████████ |
| `exe` | 20 | 19.8%  ███ |
| `apk` | 10 | 9.9%  █ |
| `sh` | 7 | 6.9%  █ |
| `jar` | 4 | 4.0%   |
| `zip` | 2 | 2.0%   |
| `vbs` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 41 | 40.6% |
| 2 | Mirai | 18 | 17.8% |
| 3 | CatStorm | 16 | 15.8% |
| 4 | Prometei | 7 | 6.9% |
| 5 | CoinMiner | 3 | 3.0% |
| 6 | ValleyRAT | 3 | 3.0% |
| 7 | njrat | 2 | 2.0% |
| 8 | Vidar | 2 | 2.0% |
| 9 | Bombay | 2 | 2.0% |
| 10 | GuLoader | 1 | 1.0% |
| 11 | Gh0stRAT | 1 | 1.0% |
| 12 | OverlordRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 28 | 27.7% | 45% |
| Botnet/IoT | 18 | 17.8% | 95% |
| RAT | 11 | 10.9% | 79% |
| Andere / Unbekannt | 11 | 10.9% | 20% |
| Trojaner | 11 | 10.9% | 73% |
| Windows-Malware | 7 | 6.9% | 35% |
| Cryptominer | 6 | 5.9% | 75% |
| Infostealer | 4 | 4.0% | 85% |
| Loader | 3 | 3.0% | 82% |
| Backdoor | 1 | 1.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 44.6% |
| 🟠 HOCH | 9 | 8.9% |
| 🟡 MITTEL | 35 | 34.7% |
| 🟢 NIEDRIG | 12 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8a7e85ac6f02a2…](https://bazaar.abuse.ch/sample/8a7e85ac6f02a2d3cf8a4a0ba83a905c2cec0d2b23c8b4122183fc9b9398c6f6/) | Gh0stRAT | Backdoor | **91.0** | 🔴 KRITISCH | – | – | ? |
| [220b6483799c8a…](https://bazaar.abuse.ch/sample/220b6483799c8aaf4a0f6361e2e3dc9d65b229b545f266ba152549968be0355d/) | njrat | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [6951beb6805767…](https://bazaar.abuse.ch/sample/6951beb68057674e29203c00042cf30d8d61933090a301c29e8ed0b153017f53/) | njrat | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [3f76ea65d0cf64…](https://bazaar.abuse.ch/sample/3f76ea65d0cf641176a2062eb3bab342f95b3e7916cee14985b19585866e73d3/) | Vidar | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [2f77c5d0a03676…](https://bazaar.abuse.ch/sample/2f77c5d0a0367682299901db001e36a7b75033093a9fcbb85b7e96288988bb9a/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [c33175d6d7f33f…](https://bazaar.abuse.ch/sample/c33175d6d7f33fcc3c067f22d349c5233168714950c4c16e86daa8e1a6858459/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [cd195ba1bc8aa6…](https://bazaar.abuse.ch/sample/cd195ba1bc8aa690a37a0321ad46776a5321d79a1ba1a03b60313e5c79ff7d2d/) | GuLoader | Loader | **83.4** | 🔴 KRITISCH | – | – | ? |
| [669e6059475fcf…](https://bazaar.abuse.ch/sample/669e6059475fcfc115bc8f49b0d53a8111448491970956763af85c24b576b5e9/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [2d758e27e51558…](https://bazaar.abuse.ch/sample/2d758e27e5155806074011cc0371d85570f3dcb06ca632e41d93a5b54e9ad5d3/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [fa4526351ddd5b…](https://bazaar.abuse.ch/sample/fa4526351ddd5bdf5e592cc15f42d2d2ff13efcb645fee808d5facecc26fe0f1/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6619/8153 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6619/8153 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6317/8153 |
| 6 | Kaspersky | 75.5% | 6158/8152 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5808/8149 |
| 9 | Rising | 68.6% | 5596/8153 |
| 10 | Varist | 66.1% | 5386/8148 |
| 11 | Tencent | 65.3% | 5173/7927 |
| 12 | AVG | 65.2% | 5309/8148 |
| 13 | Avast | 65.1% | 5309/8149 |
| 14 | McAfeeD | 61.4% | 4998/8145 |
| 15 | huorong | 61.0% | 4970/8145 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 61 | 60.4% |
| 🪟 Windows | 23 | 22.8% |
| 🤖 Android | 10 | 9.9% |
| ❓ Unbekannt | 5 | 5.0% |
| 📦 Archiv | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 84 | 83.2% |
| APK-Sideloading | 10 | 9.9% |
| MaaS-Loader | 3 | 3.0% |
| Drive-By / Exploit-Kit | 3 | 3.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 43 | 42.6% |
| 2 | 🇳🇱 NL | 13 | 12.9% |
| 3 | 🇭🇺 HU | 10 | 9.9% |
| 4 | 🌐 UZ | 10 | 9.9% |
| 5 | 🇺🇸 US | 8 | 7.9% |
| 6 | 🇫🇷 FR | 7 | 6.9% |
| 7 | 🇨🇭 CH | 4 | 4.0% |
| 8 | 🇺🇦 UA | 3 | 3.0% |
| 9 | 🌐 DZ | 2 | 2.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 26 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Collection | 4 |
| Impact | 3 |
| Command and Control | 2 |
| Credential Access | 2 |
| Exfiltration | 2 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>220b6483799c8aaf4a0f… – njrat | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>6951beb68057674e2920… – njrat | 🔴 KRITISCH 87.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>3f76ea65d0cf641176a2… – Vidar | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2f77c5d0a03676822999… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f026ecd3b21d03ed3010…](https://bazaar.abuse.ch/sample/f026ecd3b21d03ed3010e7dd86257e5046d49213e6d4f445a6af6389544efc78/)

- **Familie:** CoinMiner
- **Erkannt von:** 3 von 74 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTK trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Miner]/JS.CoinMiner.xmr` |
| ESET-NOD32 | `Linux/Agent.BTK trojan` |
| Google | `Detected` |

### [fa92bbe8f2e095e151d2…](https://bazaar.abuse.ch/sample/fa92bbe8f2e095e151d2c0dedef47fe1d1358f668f0c55c986b5e14438ff3334/)

- **Familie:** CatStorm
- **Erkannt von:** 7 von 74 Engines (9.5%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/CoinMiner.ASV trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/74):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DDoS.3446` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.yn` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Tencent | `Trojan.Linux.Catstorm.qzvra` |
| huorong | `Trojan/CoinMiner.dm` |

### [a963c6f3ff6551defe81…](https://bazaar.abuse.ch/sample/a963c6f3ff6551defe81bfb153df22d5d6636a821eb66cc73baf22bd9d1d4e52/)

- **Familie:** WARDENStealer
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Pws]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Pws]` |
| Avast | `FileRepMalware [Pws]` |
| Bkav | `W32.Malware.838247DD` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/GenKryptik.HYAZ trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kingsoft | `malware.kb.a.994` |
| McAfeeD | `Trojan:Win/RavenStealer.NE` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.98 (RDML:tMv3mUlJV6ZkP9dup5/cgw)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Generic ML PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [30f2e8b95eeabd8ca20c…](https://bazaar.abuse.ch/sample/30f2e8b95eeabd8ca20c727563110140a4ea2ff40a884ae32e2c159b4639d8b1/)

- **Familie:** Vidar
- **Erkannt von:** 25 von 74 Engines (33.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:Evo-gen [Trj]` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.EBD269F6` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/GenKryptik.HYIU trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| GData | `Win64.Trojan.Agent.JP5QGP` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| Kaspersky | `UDS:Trojan-PSW.Win32.Vidar` |
| Kingsoft | `Win32.Troj.Unknown.a` |
| Lionic | `Trojan.Win32.WinGo.4!c` |
| McAfeeD | `ti!30F2E8B95EEA` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik!8.8 (CLOUD)` |
| Sangfor | `Trojan.Win32.Evo.V7bb` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.FalseSign.Ychl` |
| Varist | `W64/WinGo.J.gen!Eldorado` |
| alibabacloud | `Trojan:Multi/Wacatac.B9nj` |

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

- **elf** (51×)
- **exe** (19×)
- **Mirai** (18×)
- **Torii** (14×)
- **signed** (10×)
- **apk** (10×)
- **Banker** (9×)
- **RAT** (8×)
- **CatStorm** (8×)
- **upx-dec** (8×)
- **upx** (8×)
- **Prometei** (7×)
- **Android** (7×)
- **sh** (5×)
- **cowrie** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +15 (26→41)
- ↓ **Mirai** -11 (29→18)
- neu: **CatStorm** (16)
- ↓ **Prometei** -1 (8→7)
- neu: **CoinMiner** (3)
- ↑ **ValleyRAT** +2 (1→3)
- ↑ **njrat** +1 (1→2)
- neu: **Vidar** (2)
- neu: **Bombay** (2)
- neu: **GuLoader** (1)
- weg: **GoDDoSAgent** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +4 (37→41)
- ↓ **Mirai** -4 (22→18)
- ↑ **CatStorm** +15 (1→16)
- ↑ **Prometei** +2 (5→7)
- ↑ **CoinMiner** +2 (1→3)
- ↑ **ValleyRAT** +2 (1→3)
- neu: **Vidar** (2)
- neu: **Bombay** (2)
- neu: **GuLoader** (1)
- weg: **RemcosRAT** (war 2)
- weg: **Snowlight** (war 3)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.336 MB |
| σ Dateigröße | 19.231 MB |
| Ø Risiko-Score | 59.1/100 |
| Ø Klassifikations-Konfidenz | 62.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 26/101 |
| Eindeutige Familien | 16 |
| Eindeutige Tags | 74 |
| Unbekannte Familien | 11 (10.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:52 | [16835df442d8…](https://bazaar.abuse.ch/sample/16835df442d800533171d281780659582d60fec5d727abd999a6155c2fb58092/) | `exe` | unbekannt | 81.3 | – | – | 🇺🇦UA |
| 22:40 | [cd195ba1bc8a…](https://bazaar.abuse.ch/sample/cd195ba1bc8aa690a37a0321ad46776a5321d79a1ba1a03b60313e5c79ff7d2d/) | `vbs` | GuLoader | 83.4 | – | – | 🌐CH |
| 22:24 | [9553ac741529…](https://bazaar.abuse.ch/sample/9553ac7415296384f0c2a0effe42f963f95e1d858bd11a23d5359b0dfa6c2dae/) | `zip` | unbekannt | 32.3 | – | – | 🌐HU |
| 22:20 | [2f77c5d0a036…](https://bazaar.abuse.ch/sample/2f77c5d0a0367682299901db001e36a7b75033093a9fcbb85b7e96288988bb9a/) | `elf` | Mirai | 84.1 | – | – | 🇳🇱NL |
| 22:20 | [c33175d6d7f3…](https://bazaar.abuse.ch/sample/c33175d6d7f33fcc3c067f22d349c5233168714950c4c16e86daa8e1a6858459/) | `elf` | Mirai | 84.1 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.11.2026 22:53 UTC*