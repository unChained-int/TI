# MalwareBazaar – 16.10.2026 22:40 UTC

Dieser Run hat **50 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **51** |
| Kritisch (≥75) | **32** |
| Höchster Score | **87.3/100** – 165619e61ebf6feb… |
| Häufigste Familie | **Mirai** (21x) |
| Häufigster Typ | **elf** (24x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 27 Samples |
| Ø Dateigröße | 3.77 MB (σ=8.13) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 24 | 47.1%  █████████ |
| `exe` | 14 | 27.5%  █████ |
| `jar` | 4 | 7.8%  █ |
| `sh` | 2 | 3.9%   |
| `apk` | 2 | 3.9%   |
| `js` | 1 | 2.0%   |
| `zip` | 1 | 2.0%   |
| `bat` | 1 | 2.0%   |
| `macho` | 1 | 2.0%   |
| `zsh` | 1 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 21 | 41.2% |
| 2 | unbekannt | 18 | 35.3% |
| 3 | ConnectWise | 1 | 2.0% |
| 4 | RemusStealer | 1 | 2.0% |
| 5 | Linux | 1 | 2.0% |
| 6 | Amadey | 1 | 2.0% |
| 7 | Trojan ( 005faeab1 ) | 1 | 2.0% |
| 8 | SalatStealer | 1 | 2.0% |
| 9 | GCleaner | 1 | 2.0% |
| 10 | NetSupport | 1 | 2.0% |
| 11 | njrat | 1 | 2.0% |
| 12 | SilentNet | 1 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 21 | 41.2% | 95% |
| Andere / Unbekannt | 7 | 13.7% | 20% |
| Loader | 6 | 11.8% | 78% |
| Infostealer | 5 | 9.8% | 79% |
| RAT | 4 | 7.8% | 90% |
| Skript/Dropper | 2 | 3.9% | 35% |
| Linux-Malware | 2 | 3.9% | 45% |
| Android-Malware | 2 | 3.9% | 45% |
| Exploit | 1 | 2.0% | 65% |
| Trojaner | 1 | 2.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 32 | 62.7% |
| 🟠 HOCH | 6 | 11.8% |
| 🟡 MITTEL | 6 | 11.8% |
| 🟢 NIEDRIG | 7 | 13.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [165619e61ebf6f…](https://bazaar.abuse.ch/sample/165619e61ebf6feb78b2b78f1fa407540e71712e6fe8185bb810c8dffd54eaff/) | njrat | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [dbc032fe60b321…](https://bazaar.abuse.ch/sample/dbc032fe60b321173186600c4ef7461a0df8f3eb44d6f414c876988d98e9563e/) | AMOS | Infostealer | **86.2** | 🔴 KRITISCH | – | – | ? |
| [2e2b253c3cc9b6…](https://bazaar.abuse.ch/sample/2e2b253c3cc9b64cec1d49793f41aba524d7cb766f614ad2647b18aaa6515248/) | NetSupport | RAT | **86.1** | 🔴 KRITISCH | 16.0% | 🟡 SCHWACH ERKANNT | ✗ |
| [9896ae46927893…](https://bazaar.abuse.ch/sample/9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [1442f715afabfb…](https://bazaar.abuse.ch/sample/1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [c9f7fada2b226e…](https://bazaar.abuse.ch/sample/c9f7fada2b226ef942e7ffd5eb5a63c8ac741b53dd3328cd6c907cea135849e0/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [8182fdf5fffca2…](https://bazaar.abuse.ch/sample/8182fdf5fffca2a35ea0c59210fe6e47c6eb670a794bad8f10e0c33d9896741c/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [f7fefce08a47ca…](https://bazaar.abuse.ch/sample/f7fefce08a47ca10b350aee0da7b26c55213204371116e476fc635be17dff105/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b77381dddb9c39…](https://bazaar.abuse.ch/sample/b77381dddb9c39d4380f0206435f462af7295206eb06f0d30e174aacd46b2d41/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [c7f02f9b77f12f…](https://bazaar.abuse.ch/sample/c7f02f9b77f12f9ce12f281eaa2d409237cab14881b52fe4420ef512540ea544/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6005/7425 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6005/7425 |
| 3 | ESET-NOD32 | 77.4% | 5747/7425 |
| 4 | Kaspersky | 76.3% | 5667/7424 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5309/7422 |
| 8 | Rising | 68.7% | 5102/7425 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4931/7421 |
| 11 | Tencent | 65.3% | 4701/7199 |
| 12 | Avast | 65.1% | 4832/7421 |
| 13 | AVG | 65.1% | 4832/7420 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4549/7418 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 27 | 52.9% |
| 🪟 Windows | 15 | 29.4% |
| ❓ Unbekannt | 5 | 9.8% |
| 🤖 Android | 2 | 3.9% |
| 📦 Archiv | 1 | 2.0% |
| 🍎 macOS | 1 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 40 | 78.4% |
| C2 / Nachladen | 6 | 11.8% |
| MaaS-Loader | 2 | 3.9% |
| APK-Sideloading | 2 | 3.9% |
| Drive-By / Exploit-Kit | 1 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 26 | 51.0% |
| 2 | 🇩🇪 DE | 6 | 11.8% |
| 3 | 🇭🇺 HU | 5 | 9.8% |
| 4 | 🇬🇧 GB | 4 | 7.8% |
| 5 | 🇫🇷 FR | 2 | 3.9% |
| 6 | 🇲🇽 MX | 2 | 3.9% |
| 7 | 🇧🇷 BR | 2 | 3.9% |
| 8 | 🇦🇹 AT | 1 | 2.0% |
| 9 | 🌐 PT | 1 | 2.0% |
| 10 | 🇳🇱 NL | 1 | 2.0% |
| 11 | 🌐 Unbekannt | 1 | 2.0% |

## MITRE ATT&CK

> 27 von 51 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 21 |
| Lateral Movement | 21 |
| Execution | 3 |
| Persistence | 3 |
| Command and Control | 3 |
| Collection | 3 |

<details><summary>165619e61ebf6feb78b2… – njrat | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>2e2b253c3cc9b64cec1d… – NetSupport | 🔴 KRITISCH 86.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Collection | [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture |

</details>
<details><summary>9896ae46927893323395… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1442f715afabfbbb9c1a… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5e04ffbc4d8322f21603…](https://bazaar.abuse.ch/sample/5e04ffbc4d8322f216036037621eb0b32b82060a043901431003ef5ebe7dd35b/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14331 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Linux.Trojan.Linux.Jajl` |
| Varist | `E32/Mirai.EN.gen!Camelot` |

### [d286b0b622b93aa7f8a6…](https://bazaar.abuse.ch/sample/d286b0b622b93aa7f8a6877ad09ce1be8c543c9319114ffd505c064cfe53d441/)

- **Familie:** Linux
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** HEUR:Exploit.Linux.CVE-2014-8361.a
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2014-8361.a` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.Mirai.f` |

### [d5e4db7daf438660a065…](https://bazaar.abuse.ch/sample/d5e4db7daf438660a0659b8eb31f5c4c2fb7c47f56440aef79d30bd1c78cf328/)

- **Familie:** Trojan ( 005faeab1 )
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 005faeab1 )
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win32:MalwareX-gen [Drp]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5585999` |
| Avast | `Win32:MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| CTX | `exe.trojan.malwarex` |
| CrowdStrike | `win/grayware_confidence_60% (D)` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| Fortinet | `W32/PossibleThreat` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 005faeab1 )` |
| K7GW | `Trojan ( 005faeab1 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| MaxSecure | `Trojan.Malware.325365696.susgen` |
| McAfeeD | `ti!D5E4DB7DAF43` |
| Paloalto | `generic.ml` |
| Sangfor | `Trojan.Win32.Agent.Vfs1` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| TrellixENS | `Artemis!B5C117E1F341` |
| TrendMicro | `Trojan.Win32.ZYX.USBLG626` |
| TrendMicro-HouseCall | `Trojan.Win32.ZYX.USBLG626` |
| Varist | `W32/ABApplication.MLEH-8635` |

### [2e2b253c3cc9b64cec1d…](https://bazaar.abuse.ch/sample/2e2b253c3cc9b64cec1d49793f41aba524d7cb766f614ad2647b18aaa6515248/)

- **Familie:** NetSupport
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Malware/Win.AGEN.C5954884` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.699D4C9` |
| ClamAV | `Win.Malware.Ulise-9789134-0` |
| DrWeb | `Program.RemoteAdmin.837` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `VHO:Backdoor.Win32.RABased.gen` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Webroot | `W32.Malware.gen` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
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
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (24×)
- **Mirai** (21×)
- **exe** (15×)
- **honeypot** (6×)
- **dropped-by-GCleaner** (4×)
- **jar** (3×)
- **arm** (3×)
- **d52f85** (2×)
- **dropped-by-Amadey** (2×)
- **cowrie** (2×)
- **java** (2×)
- **Stealer** (2×)
- **sh** (2×)
- **apk** (2×)
- **B** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +10 (11→21)
- ↓ **unbekannt** -14 (32→18)
- neu: **Linux** (1)
- neu: **Amadey** (1)
- neu: **Trojan ( 005faeab1 )** (1)
- neu: **GCleaner** (1)
- neu: **NetSupport** (1)
- weg: **Formbook** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -10 (31→21)
- ↓ **unbekannt** -11 (29→18)
- neu: **Linux** (1)
- neu: **Amadey** (1)
- neu: **Trojan ( 005faeab1 )** (1)
- neu: **SalatStealer** (1)
- neu: **GCleaner** (1)
- neu: **NetSupport** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.770 MB |
| σ Dateigröße | 8.128 MB |
| Ø Risiko-Score | 69.1/100 |
| Ø Klassifikations-Konfidenz | 73.3% |
| Samples mit VT | 5/51 |
| Samples mit MITRE | 27/51 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 46 |
| Unbekannte Familien | 7 (13.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:23 | [9d2519c26fc9…](https://bazaar.abuse.ch/sample/9d2519c26fc99039bf0d22af806baac93048dedbd557a275cb19478e886d63ff/) | `exe` | unbekannt | 74.9 | – | – | 🇺🇸US |
| 22:19 | [ee735503a6d7…](https://bazaar.abuse.ch/sample/ee735503a6d76a9eb6a0b7b511eb430aed0e8325c4ebdece5ea4c8c61e551c95/) | `exe` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 22:16 | [9896ae469278…](https://bazaar.abuse.ch/sample/9896ae46927893323395f9ef5a12a54808486aab9e04fac7b442a6e5ec67a129/) | `elf` | Mirai | 84.2 | – | – | 🇺🇸US |
| 22:07 | [1442f715afab…](https://bazaar.abuse.ch/sample/1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 22:05 | [e050ddccbdac…](https://bazaar.abuse.ch/sample/e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5/) | `js` | ConnectWise | 38.6 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.10.2026 22:40 UTC*