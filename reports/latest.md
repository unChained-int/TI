# MalwareBazaar – 10.11.2026 00:00 UTC

Dieser Run hat **78 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **79** |
| Kritisch (≥75) | **48** |
| Höchster Score | **89.7/100** – fb191ab486dc6dd3… |
| Häufigste Familie | **Mirai** (27x) |
| Häufigster Typ | **elf** (32x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 34 Samples |
| Ø Dateigröße | 3.55 MB (σ=14.11) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 32 | 40.5%  ████████ |
| `exe` | 28 | 35.4%  ███████ |
| `ps1` | 6 | 7.6%  █ |
| `js` | 3 | 3.8%   |
| `msi` | 2 | 2.5%   |
| `jar` | 2 | 2.5%   |
| `sh` | 2 | 2.5%   |
| `apk` | 1 | 1.3%   |
| `lnk` | 1 | 1.3%   |
| `gz` | 1 | 1.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 27 | 34.2% |
| 2 | unbekannt | 26 | 32.9% |
| 3 | WARDENStealer | 14 | 17.7% |
| 4 | Vidar | 4 | 5.1% |
| 5 | Prometei | 1 | 1.3% |
| 6 | Linux | 1 | 1.3% |
| 7 | Win64:Evo-gen [Trj] | 1 | 1.3% |
| 8 | Trojan | 1 | 1.3% |
| 9 | CoinMiner | 1 | 1.3% |
| 10 | SilentNet | 1 | 1.3% |
| 11 | Gh0stRAT | 1 | 1.3% |
| 12 | RemcosRAT | 1 | 1.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 27 | 34.2% | 95% |
| Infostealer | 20 | 25.3% | 79% |
| Skript/Dropper | 8 | 10.1% | 35% |
| Windows-Malware | 7 | 8.9% | 35% |
| Andere / Unbekannt | 6 | 7.6% | 20% |
| Linux-Malware | 4 | 5.1% | 45% |
| Loader | 2 | 2.5% | 75% |
| Android-Malware | 1 | 1.3% | 45% |
| Cryptominer | 1 | 1.3% | 65% |
| Trojaner | 1 | 1.3% | 65% |
| Backdoor | 1 | 1.3% | 95% |
| RAT | 1 | 1.3% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 48 | 60.8% |
| 🟠 HOCH | 5 | 6.3% |
| 🟡 MITTEL | 12 | 15.2% |
| 🟢 NIEDRIG | 14 | 17.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [fb191ab486dc6d…](https://bazaar.abuse.ch/sample/fb191ab486dc6dd30b1b701a96bc5efe1103be9b8c47bba5a965895e81e693a6/) | Vidar | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [01086b20dff3c4…](https://bazaar.abuse.ch/sample/01086b20dff3c40f58c7ac4451aa8aa92425408b1f703d7a3294eaab60c91a4b/) | Vidar | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [e089ef9158fab0…](https://bazaar.abuse.ch/sample/e089ef9158fab0eaa1afbab6f34fb94aabdb91854539c3cbe63fe18ae872dc81/) | Vidar | Infostealer | **89.6** | 🔴 KRITISCH | – | – | ? |
| [ed7e8837436f31…](https://bazaar.abuse.ch/sample/ed7e8837436f3117ddd4bf1ba74959a7dcf3abb0ad6ec9c63c47e122d433fd2c/) | Gh0stRAT | Backdoor | **87.7** | 🔴 KRITISCH | – | – | ? |
| [957991aa93aa4b…](https://bazaar.abuse.ch/sample/957991aa93aa4b9cb7113daaee044326f97e21e0dd725ae59123ffae7513bb4a/) | Vidar | Infostealer | **86.3** | 🔴 KRITISCH | – | – | ? |
| [3b3ee6153cde57…](https://bazaar.abuse.ch/sample/3b3ee6153cde57050d03983b713d4f2e9a2dd4837a4b1edde1cef320114bf5e7/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [6736ba2865a42d…](https://bazaar.abuse.ch/sample/6736ba2865a42dd0d6f75055d27cb0cd0e57193c4f4d5a3446ff653675c4039c/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [4cdd2e04da5268…](https://bazaar.abuse.ch/sample/4cdd2e04da52682a1cee682f091ecedf64990d3c5a6f37fdfc31b703fcbfa7ae/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [561b1f5b62c3e5…](https://bazaar.abuse.ch/sample/561b1f5b62c3e55b2abf0d13ae513a1c70afb60ed9fa4797415c58f308bfaf96/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [9dc52ed67d1f8b…](https://bazaar.abuse.ch/sample/9dc52ed67d1f8bbdb1e452da4381efd7479cd7fa309ea2bd5a07926735e9563f/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6415/7911 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6415/7911 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6114/7911 |
| 6 | Kaspersky | 75.5% | 5972/7910 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5632/7907 |
| 9 | Rising | 68.4% | 5409/7911 |
| 10 | Varist | 66.1% | 5229/7906 |
| 11 | Avast | 65.2% | 5155/7907 |
| 12 | AVG | 65.2% | 5155/7906 |
| 13 | Tencent | 65.0% | 4992/7685 |
| 14 | McAfeeD | 61.4% | 4852/7903 |
| 15 | huorong | 61.0% | 4817/7903 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 37 | 46.8% |
| 🐧 Linux | 34 | 43.0% |
| ❓ Unbekannt | 6 | 7.6% |
| 🤖 Android | 1 | 1.3% |
| 📦 Archiv | 1 | 1.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 70 | 88.6% |
| Trojanisierte Software | 3 | 3.8% |
| Drive-By / Exploit-Kit | 3 | 3.8% |
| MaaS-Loader | 2 | 2.5% |
| APK-Sideloading | 1 | 1.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 31.6% |
| 2 | 🇫🇷 FR | 23 | 29.1% |
| 3 | 🇺🇸 US | 8 | 10.1% |
| 4 | 🇳🇱 NL | 8 | 10.1% |
| 5 | 🌐 CO | 3 | 3.8% |
| 6 | 🇨🇭 CH | 3 | 3.8% |
| 7 | 🇭🇺 HU | 2 | 2.5% |
| 8 | 🌐 MY | 2 | 2.5% |
| 9 | 🇯🇵 JP | 1 | 1.3% |
| 10 | 🇧🇷 BR | 1 | 1.3% |
| 11 | 🌐 PT | 1 | 1.3% |
| 12 | 🇦🇹 AT | 1 | 1.3% |
| 13 | 🌐 Unbekannt | 1 | 1.3% |

## MITRE ATT&CK

> 34 von 79 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 27 |
| Lateral Movement | 27 |
| Collection | 7 |
| Credential Access | 6 |
| Exfiltration | 6 |
| Command and Control | 1 |

<details><summary>fb191ab486dc6dd30b1b… – Vidar | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>01086b20dff3c40f58c7… – Vidar | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>e089ef9158fab0eaa1af… – Vidar | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>957991aa93aa4b9cb711… – Vidar | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5bd073b69ff53215f593…](https://bazaar.abuse.ch/sample/5bd073b69ff53215f593f7d225c75257b419beb5069574c66b8411953a4a33c0/)

- **Familie:** Linux
- **Erkannt von:** 39 von 75 Engines (52.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Application.Linux.Miner.68
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Linux.Miner.68`

**Erkennende Engines (39/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Linux.Miner.68` |
| AVG | `ELF:Agent-CXA [Trj]` |
| AhnLab-V3 | `CoinMiner/Linux.Agent.30304472` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Arcabit | `Application.Linux.Miner.68` |
| Avast | `ELF:Agent-CXA [Trj]` |
| Avira | `EXP/ELF.Coinminer.A` |
| BitDefender 🛡️ | `Application.Linux.Miner.68` |
| CTX | `elf.miner.generic` |
| ClamAV | `Unix.Trojan.Coinminer-10007719-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Siggen.8622` |
| ESET-NOD32 | `Linux/CoinMiner.ABF trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Application.Linux.Miner.68 (B)` |
| F-Secure | `Exploit.EXP/ELF.Coinminer.A` |
| Fortinet | `Adware/Miner` |
| GData | `Application.Linux.Miner.68` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Generic` |
| Jiangmin | `Trojan.Linux.dsm` |
| K7GW | `Trojan ( 0040f1571 )` |
| Kaspersky | `HEUR:Trojan.Linux.Miner.gen` |
| Kingsoft | `Linux.Trojan.Miner.gen` |
| Lionic | `Trojan.Linux.Miner.4!c` |
| McAfeeD | `Trojan:Linux/Multiverze.EAB` |
| MicroWorld-eScan | `Application.Linux.Miner.68` |
| Microsoft 🛡️ | `Trojan:Linux/Multiverze!rfn` |
| Rising | `HackTool.NBMiner/Linux!1.E357 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Risktool.Linux.Miner.ck` |
| VBA32 | `Trojan.Linux.Agent` |
| VIPRE | `Application.Linux.Miner.68` |
| Varist | `E64/ABRisk.KUKE-8` |
| Zillya | `Trojan.252279.Linux.1` |
| alibabacloud | `Miner:Linux/CoinMiner.JUO` |
| huorong | `Trojan/Linux.CoinMiner.ao` |

### [529c122e2f93c1a0169e…](https://bazaar.abuse.ch/sample/529c122e2f93c1a0169e13178a2b5c0da6d26e61ff6bd93eaf09acb174dfe9cb/)

- **Familie:** Win64:Evo-gen [Trj]
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:Evo-gen [Trj]` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.49D5BD1D` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Kryptik.AGA trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/Vidar.YI!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Krypt` |
| Kaspersky | `VHO:Trojan-PSW.Win32.Vidar.gen` |
| Malwarebytes | `Spyware.Remus` |
| McAfeeD | `ti!529C122E2F93` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Vidar!8.11173 (TFE:29:OzwFnBYZQnG)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |
| huorong | `Trojan/W64.Agent.cx!crit` |

### [def9ab1eb56c0b2ef1ec…](https://bazaar.abuse.ch/sample/def9ab1eb56c0b2ef1ec7acd65590388b75718ed533787c39e0aa126a785f85b/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Hajime-Q [Trj]` |
| AhnLab-V3 | `Linux/Mirai14.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Hajime-Q [Trj]` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Gafgyt-7641309-0` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.ASV trojan` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2014-8361.a` |
| MaxSecure | `Backdoor.W32.300821.Linux.Mirai.b.YR` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.DCB1 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Gafgyt.LO` |
| huorong | `Trojan/Linux.Mirai.f` |

### [9ed57182ce0ca60bd50b…](https://bazaar.abuse.ch/sample/9ed57182ce0ca60bd50bbac4afa46a8cf62b2b315527e5c80b4747673ecfc85a/)

- **Familie:** Trojan
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.Trojan.ChrExt.4.C41B5FBC
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Generic.Trojan.ChrExt.4.C41B5FBC`

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| Arcabit | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| BitDefender 🛡️ | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| CTX | `script.trojan.chrext` |
| ESET-NOD32 | `PowerShell/Agent.ELS trojan` |
| Emsisoft | `Generic.Trojan.ChrExt.4.C41B5FBC (B)` |
| Fortinet | `PowerShell/Agent.EKF!tr` |
| GData | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| Google | `Detected` |
| Ikarus | `Trojan.PowerShell.Agent` |
| Kaspersky | `HEUR:Trojan.PowerShell.AmsiBypass.gen` |
| MicroWorld-eScan | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Agent/JS!1.13E87 (CLASSIC)` |
| VIPRE | `Generic.Trojan.ChrExt.4.C41B5FBC` |
| huorong | `Trojan/PS.Obfuscator.r` |

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
| Sangfor | `Trojan.Win32.Autoit.Vdnf` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (32×)
- **Mirai** (27×)
- **exe** (25×)
- **WARDENStealer** (14×)
- **upx-dec** (13×)
- **upx** (13×)
- **stealer** (12×)
- **Warden** (8×)
- **ps1** (6×)
- **Vidar** (5×)
- **signed** (5×)
- **Torii** (5×)
- **ClickFix** (4×)
- **DIVINEX** (4×)
- **msi** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +2 (25→27)
- neu: **WARDENStealer** (14)
- neu: **Vidar** (4)
- neu: **Prometei** (1)
- neu: **Linux** (1)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Trojan** (1)
- neu: **CoinMiner** (1)
- neu: **SilentNet** (1)
- weg: **Snowlight** (war 14)
- weg: **AgentTesla** (war 8)
- weg: **Formbook** (war 4)
- weg: **AsyncRAT** (war 2)
- weg: **LxBaseRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +6 (21→27)
- ↓ **unbekannt** -7 (33→26)
- ↑ **WARDENStealer** +11 (3→14)
- neu: **Vidar** (4)
- neu: **Prometei** (1)
- neu: **Linux** (1)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Trojan** (1)
- weg: **SalatStealer** (war 2)
- weg: **VShell** (war 2)
- weg: **AgentTesla** (war 3)
- weg: **Formbook** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.553 MB |
| σ Dateigröße | 14.113 MB |
| Ø Risiko-Score | 65.4/100 |
| Ø Klassifikations-Konfidenz | 69.4% |
| Samples mit VT | 5/79 |
| Samples mit MITRE | 34/79 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 46 |
| Unbekannte Familien | 6 (7.6%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:48 | [73c0f45d7d10…](https://bazaar.abuse.ch/sample/73c0f45d7d10d3184f0fe17dfc1c855e264bd995c771d90aea5fbeb8dddd07bd/) | `apk` | unbekannt | 43.2 | – | – | 🌐JP |
| 23:43 | [399cc61557f4…](https://bazaar.abuse.ch/sample/399cc61557f427e3e2712b5a2207dd4aadba90914f56563edc6dec61248cb15b/) | `lnk` | unbekannt | 32.5 | – | – | 🌐HU |
| 23:40 | [4f2dcdbdaafc…](https://bazaar.abuse.ch/sample/4f2dcdbdaafc83be8afb38e7a95e8c68ff41dc859ec2638a83e8031436fd256c/) | `exe` | unbekannt | 38.8 | – | – | 🌐MY |
| 23:39 | [19be4e68616c…](https://bazaar.abuse.ch/sample/19be4e68616ce49bf5299614b3ca3a3d9d1627c1dbfed27d9c60371c46450fbf/) | `msi` | unbekannt | 38.8 | – | – | 🌐MY |
| 23:19 | [e07a760ada60…](https://bazaar.abuse.ch/sample/e07a760ada60e2e4c629ec60664ea449504b19391bd75a097ba1142dccede213/) | `elf` | Prometei | 42.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 10.11.2026 00:00 UTC*