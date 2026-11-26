# MalwareBazaar – 26.11.2026 13:47 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **68** |
| Höchster Score | **89.4/100** – 5ce53eeac3aedcfa… |
| Häufigste Familie | **Mirai** (56x) |
| Häufigster Typ | **elf** (72x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 61 Samples |
| Ø Dateigröße | 2.69 MB (σ=9.83) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 72 | 71.3%  ██████████████ |
| `exe` | 9 | 8.9%  █ |
| `sh` | 8 | 7.9%  █ |
| `msi` | 2 | 2.0%   |
| `js` | 2 | 2.0%   |
| `zip` | 2 | 2.0%   |
| `wsf` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 56 | 55.4% |
| 2 | unbekannt | 24 | 23.8% |
| 3 | Prometei | 8 | 7.9% |
| 4 | AgentTesla | 2 | 2.0% |
| 5 | Emotet | 2 | 2.0% |
| 6 | ValleyRAT | 2 | 2.0% |
| 7 | B!ml | 1 | 1.0% |
| 8 | Formbook | 1 | 1.0% |
| 9 | RemcosRAT | 1 | 1.0% |
| 10 | QuasarRAT | 1 | 1.0% |
| 11 | SparkRAT | 1 | 1.0% |
| 12 | Panchan | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 57 | 56.4% | 94% |
| Linux-Malware | 15 | 14.9% | 45% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| RAT | 5 | 5.0% | 83% |
| Trojaner | 4 | 4.0% | 80% |
| Infostealer | 4 | 4.0% | 80% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Cryptominer | 2 | 2.0% | 75% |
| Windows-Malware | 2 | 2.0% | 35% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 68 | 67.3% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5ce53eeac3aedc…](https://bazaar.abuse.ch/sample/5ce53eeac3aedcfaf5b593b53a53f59217f880331413f3da30b6966b25f1e4df/) | Emotet | Trojaner | **89.4** | 🔴 KRITISCH | – | – | ? |
| [707e89148589be…](https://bazaar.abuse.ch/sample/707e89148589beeb0d1602cc080ae609bc4203b0fd074e80bf8f23159588c0ee/) | Emotet | Trojaner | **89.4** | 🔴 KRITISCH | – | – | ? |
| [d8911e00ee875a…](https://bazaar.abuse.ch/sample/d8911e00ee875acf893d83b7d54c5212fc04d0aeb36a58bbe0aa6e8132b176dd/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [80471f058c53e1…](https://bazaar.abuse.ch/sample/80471f058c53e11aa44ebdcd1dfe9c91d946bac64cac2091d7b81bb6e1332ed1/) | RemcosRAT | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [bb0abcb462379d…](https://bazaar.abuse.ch/sample/bb0abcb462379d5f89cbdad87573bd609bf90603c5de8fde6a548189aa8f77c5/) | QuasarRAT | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [835e644ea7034a…](https://bazaar.abuse.ch/sample/835e644ea7034a7e45db2d8089363b582e49eb99707776e5fc1a920f049b30e2/) | B!ml | Trojaner | **84.7** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [4bcf4f98b05a1d…](https://bazaar.abuse.ch/sample/4bcf4f98b05a1d73bc58ea28c00d9a9ae5e122bcfbe953c041d3fdfe571d702f/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [3610234fabf37a…](https://bazaar.abuse.ch/sample/3610234fabf37a83b4634d6d7fcfc29e40ee472edcb3fe969a2bb16af244fd21/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [9ba243514b9f6c…](https://bazaar.abuse.ch/sample/9ba243514b9f6c5c1a414ae03b6ad1f687c7a908e11928ba21e770b7d83749e7/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [a1676bb77f6820…](https://bazaar.abuse.ch/sample/a1676bb77f6820e644cf6794774bd021dbd16c1d734cded73ec03bdbff211201/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6615/8148 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6615/8148 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6312/8148 |
| 6 | Kaspersky | 75.6% | 6156/8147 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5804/8144 |
| 9 | Rising | 68.6% | 5592/8148 |
| 10 | Varist | 66.1% | 5383/8143 |
| 11 | Tencent | 65.2% | 5169/7922 |
| 12 | Avast | 65.2% | 5307/8144 |
| 13 | AVG | 65.2% | 5307/8143 |
| 14 | McAfeeD | 61.4% | 4996/8140 |
| 15 | huorong | 61.0% | 4967/8140 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 80 | 79.2% |
| 🪟 Windows | 14 | 13.9% |
| ❓ Unbekannt | 4 | 4.0% |
| 📦 Archiv | 2 | 2.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 94 | 93.1% |
| Trojanisierte Software | 2 | 2.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 68 | 67.3% |
| 2 | 🌐 GR | 5 | 5.0% |
| 3 | 🇭🇺 HU | 5 | 5.0% |
| 4 | 🇺🇸 US | 4 | 4.0% |
| 5 | 🇸🇬 SG | 4 | 4.0% |
| 6 | 🌐 IL | 4 | 4.0% |
| 7 | 🇫🇷 FR | 3 | 3.0% |
| 8 | 🇨🇿 CZ | 2 | 2.0% |
| 9 | 🇨🇭 CH | 2 | 2.0% |
| 10 | 🇮🇳 IN | 1 | 1.0% |
| 11 | 🌐 BD | 1 | 1.0% |
| 12 | 🇺🇦 UA | 1 | 1.0% |
| 13 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 61 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 58 |
| Lateral Movement | 58 |
| Collection | 2 |
| Command and Control | 2 |
| Execution | 2 |
| Credential Access | 1 |
| Exfiltration | 1 |

<details><summary>5ce53eeac3aedcfaf5b5… – Emotet | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing |
| Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>707e89148589beeb0d16… – Emotet | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing |
| Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>d8911e00ee875acf893d… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>80471f058c53e11aa44e… – RemcosRAT | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>bb0abcb462379d5f89cb… – QuasarRAT | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [835e644ea7034a7e45db…](https://bazaar.abuse.ch/sample/835e644ea7034a7e45db2d8089363b582e49eb99707776e5fc1a920f049b30e2/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [d29db09ec9d0a2f504ae…](https://bazaar.abuse.ch/sample/d29db09ec9d0a2f504aed61489cc0cfb6a9d25c089fe3122d37697795960adde/)

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
| Skyhigh | `Prometei!5BCA3AEF6F71` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39504221` |
| Varist | `E64/PrometeiS.C` |
| huorong | `Trojan/Prometei.c` |

### [d97a15cbd70197f40b59…](https://bazaar.abuse.ch/sample/d97a15cbd70197f40b597ec25914d7abde71de21c9d217701a3fe75377a94488/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [fabb72ff2bda87a164a3…](https://bazaar.abuse.ch/sample/fabb72ff2bda87a164a32d3f554ea4398fa529e66d954c00a7249c76cc67e0a8/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.cerra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

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

- **elf** (72×)
- **Mirai** (56×)
- **Torii** (56×)
- **sh** (8×)
- **exe** (8×)
- **Prometei** (8×)
- **honeypot** (6×)
- **RedOps** (5×)
- **STRU** (5×)
- **WeaveLotus** (5×)
- **cowrie** (4×)
- **mips** (4×)
- **Beretta** (4×)
- **clipper** (4×)
- **mcp** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +53 (3→56)
- ↓ **unbekannt** -9 (33→24)
- ↑ **AgentTesla** +1 (1→2)
- neu: **Emotet** (2)
- neu: **ValleyRAT** (2)
- neu: **B!ml** (1)
- ↓ **Formbook** -1 (2→1)
- ↓ **RemcosRAT** -3 (4→1)
- neu: **QuasarRAT** (1)
- weg: **EasyShell** (war 7)
- weg: **WARDENStealer** (war 6)
- weg: **AsyncRAT** (war 2)
- weg: **SilentNet** (war 2)
- weg: **GoDDoSAgent** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +34 (22→56)
- ↓ **unbekannt** -13 (37→24)
- ↑ **Prometei** +3 (5→8)
- ↑ **AgentTesla** +1 (1→2)
- neu: **Emotet** (2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **B!ml** (1)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **QuasarRAT** (1)
- weg: **WARDENStealer** (war 4)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 3)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.687 MB |
| σ Dateigröße | 9.825 MB |
| Ø Risiko-Score | 69.7/100 |
| Ø Klassifikations-Konfidenz | 76.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 61/101 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 59 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:44 | [223086b6ecfa…](https://bazaar.abuse.ch/sample/223086b6ecfa2f89513fb0635ebf3abf21a55319a3dff56ba0c45a0bf79b8634/) | `sh` | unbekannt | 68.0 | – | – | 🇺🇸US |
| 13:41 | [5d8336cff2c2…](https://bazaar.abuse.ch/sample/5d8336cff2c20c90b37cf8d87daa3f902a7663f83314abe860fe3592f7d1fccb/) | `exe` | unbekannt | 39.0 | – | – | 🌐CZ |
| 13:28 | [9ea20d46bb99…](https://bazaar.abuse.ch/sample/9ea20d46bb9939382c6c63548890239d0285b0c60b2f63f59f9a667373d5aef9/) | `sh` | unbekannt | 32.4 | – | – | 🌐GR |
| 13:28 | [835e644ea703…](https://bazaar.abuse.ch/sample/835e644ea7034a7e45db2d8089363b582e49eb99707776e5fc1a920f049b30e2/) | `sh` | B!ml | 84.7 | 1.4% | ⚠️ KAUM ERKANNT | 🌐GR |
| 13:27 | [97630da7a0d1…](https://bazaar.abuse.ch/sample/97630da7a0d17e94ab5db44c1fe6ddd52ac975d8df0d160bfca6102bdb4be265/) | `sh` | unbekannt | 32.4 | – | – | 🌐GR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.11.2026 13:47 UTC*