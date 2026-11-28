# MalwareBazaar – 28.11.2026 01:15 UTC

Dieser Run hat **84 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **85** |
| Kritisch (≥75) | **50** |
| Höchster Score | **87.0/100** – b8715f98732aed99… |
| Häufigste Familie | **Mirai** (33x) |
| Häufigster Typ | **elf** (54x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 42 Samples |
| Ø Dateigröße | 5.51 MB (σ=18.27) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 54 | 63.5%  ████████████ |
| `exe` | 17 | 20.0%  ████ |
| `jar` | 4 | 4.7%   |
| `rar` | 3 | 3.5%   |
| `js` | 2 | 2.4%   |
| `apk` | 1 | 1.2%   |
| `msi` | 1 | 1.2%   |
| `7z` | 1 | 1.2%   |
| `zip` | 1 | 1.2%   |
| `lnk` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 33 | 38.8% |
| 2 | unbekannt | 23 | 27.1% |
| 3 | Prometei | 13 | 15.3% |
| 4 | CatStorm | 5 | 5.9% |
| 5 | AsyncRAT | 3 | 3.5% |
| 6 | njrat | 3 | 3.5% |
| 7 | ConnectWise | 2 | 2.4% |
| 8 | LummaStealer | 2 | 2.4% |
| 9 | MalwareX-gen [Pws] | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 33 | 38.8% | 95% |
| Linux-Malware | 20 | 23.5% | 45% |
| RAT | 9 | 10.6% | 88% |
| Infostealer | 7 | 8.2% | 81% |
| Windows-Malware | 6 | 7.1% | 35% |
| Andere / Unbekannt | 5 | 5.9% | 20% |
| Trojaner | 3 | 3.5% | 65% |
| Skript/Dropper | 1 | 1.2% | 35% |
| Loader | 1 | 1.2% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 50 | 58.8% |
| 🟠 HOCH | 3 | 3.5% |
| 🟡 MITTEL | 25 | 29.4% |
| 🟢 NIEDRIG | 7 | 8.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b8715f98732aed…](https://bazaar.abuse.ch/sample/b8715f98732aed990b5bb61e87065548035d38426f34c0146da6f8e5ec57123a/) | LummaStealer | Infostealer | **87.0** | 🔴 KRITISCH | – | – | ? |
| [6afa4283b21642…](https://bazaar.abuse.ch/sample/6afa4283b2164247b05668c063698157f5af9a6449d7f2736758f3fd4d720152/) | LummaStealer | Infostealer | **86.6** | 🔴 KRITISCH | – | – | ? |
| [64fe92d83db4cb…](https://bazaar.abuse.ch/sample/64fe92d83db4cbcc914c6406d802a082bdd48a174a702e1bea1a3b0d5c295bbf/) | AsyncRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [1ba6f169a3da4e…](https://bazaar.abuse.ch/sample/1ba6f169a3da4e80369ba75c6adc8a25c152bace7bddf55d2c67cd4d566e36e9/) | AsyncRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [e04612fed47e2f…](https://bazaar.abuse.ch/sample/e04612fed47e2f78f8b13c6a24682983ff8007a975432207e6b56b61d7467ce1/) | AsyncRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [b0d479a8888297…](https://bazaar.abuse.ch/sample/b0d479a8888297276a839540fa3e9cf803336e5d65ee42edfb3202efa3470808/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [190ef6c6cc7716…](https://bazaar.abuse.ch/sample/190ef6c6cc7716c61834b22a46a636685b5db7be2712587502b2e9707feb9dac/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [fdb8a3b6a8b565…](https://bazaar.abuse.ch/sample/fdb8a3b6a8b5657f32fc662de7d3f30bfd2a568324266e00e07bdfb1a60a22db/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [59a02a87159c31…](https://bazaar.abuse.ch/sample/59a02a87159c319ea56258b119be0893b49e24276b7268665e1362004327519b/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [75b67b86930148…](https://bazaar.abuse.ch/sample/75b67b86930148544cb1e934d2186cd94d54c8a91e1ebde89f1cb5493ffd28a0/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6631/8168 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6631/8168 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6330/8168 |
| 6 | Kaspersky | 75.5% | 6167/8167 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5820/8164 |
| 9 | Rising | 68.7% | 5608/8168 |
| 10 | Varist | 66.1% | 5398/8163 |
| 11 | Tencent | 65.3% | 5186/7942 |
| 12 | Avast | 65.1% | 5316/8164 |
| 13 | AVG | 65.1% | 5316/8163 |
| 14 | McAfeeD | 61.3% | 5005/8160 |
| 15 | huorong | 61.1% | 4982/8160 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 54 | 63.5% |
| 🪟 Windows | 17 | 20.0% |
| ❓ Unbekannt | 6 | 7.1% |
| 📦 Archiv | 5 | 5.9% |
| 📄 Dokument | 2 | 2.4% |
| 🤖 Android | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 92.9% |
| Drive-By / Exploit-Kit | 2 | 2.4% |
| Phishing / E-Mail-Anhang | 2 | 2.4% |
| APK-Sideloading | 1 | 1.2% |
| Trojanisierte Software | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 54 | 63.5% |
| 2 | 🇺🇸 US | 10 | 11.8% |
| 3 | 🇫🇷 FR | 6 | 7.1% |
| 4 | 🇭🇺 HU | 5 | 5.9% |
| 5 | 🇨🇦 CA | 3 | 3.5% |
| 6 | 🇳🇱 NL | 3 | 3.5% |
| 7 | 🇨🇭 CH | 1 | 1.2% |
| 8 | 🌐 CO | 1 | 1.2% |
| 9 | 🇯🇵 JP | 1 | 1.2% |
| 10 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 42 von 85 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 33 |
| Lateral Movement | 33 |
| Command and Control | 6 |
| Collection | 4 |
| Credential Access | 3 |
| Exfiltration | 3 |
| Execution | 3 |

<details><summary>b8715f98732aed990b5b… – LummaStealer | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>6afa4283b2164247b056… – LummaStealer | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>64fe92d83db4cbcc914c… – AsyncRAT | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>1ba6f169a3da4e80369b… – AsyncRAT | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>e04612fed47e2f78f8b1… – AsyncRAT | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [dfb39f55c165f80e80fc…](https://bazaar.abuse.ch/sample/dfb39f55c165f80e80fca15b1de2a35e0ec23a65395e977e3df97e56a9b75651/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 72 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/72):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-CVH [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [933027e84e44f124ac11…](https://bazaar.abuse.ch/sample/933027e84e44f124ac11a286d51dc52fe30d05633347222dbd8eaf3729579dcb/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 72 Engines (37.5%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/72):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| Kingsoft | `Linux.Backdoor.Mirai.oc` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [7998bf3808c42f53d95e…](https://bazaar.abuse.ch/sample/7998bf3808c42f53d95e7244ec3533dacc1adc1c50b3f3b9b60d631dcb105ab1/)

- **Familie:** MalwareX-gen [Pws]
- **Erkannt von:** 32 von 72 Engines (44.4%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (32/72):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.4D76B955` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Injector.AOW!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kaspersky | `VHO:Trojan.Win32.Agent.gen` |
| Kingsoft | `malware.kb.a.988` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.W32.251126.WardenStealer.a.swat.YR` |
| McAfeeD | `Trojan:Win/RavenStealer.NE` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik@AI.84 (RDML:FnDyj3423xazL4RDDfHDJQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| TrellixENS | `Artemis!C19ED619C3D1` |
| Varist | `W64/Agent.NRC.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [89a25a908fa6d0df1fe4…](https://bazaar.abuse.ch/sample/89a25a908fa6d0df1fe4b3c089686fd4fdbf6f124e26fb4cb73ce2fcfe418a09/)

- **Familie:** CatStorm
- **Erkannt von:** 15 von 72 Engines (20.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Gen.NPE
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/72):**

| Engine | Erkannter Name |
|--------|----------------|
| Avast-Mobile | `FileRepMalware [Trj]` |
| DrWeb | `Linux.DDoS.3446` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Google | `Detected` |
| McAfeeD | `ti!89A25A908FA6` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner!rfn` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Trojan.Linux.Catstorm.qzvra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| Varist | `E64/ABTrojan.LGTC-` |
| alibabacloud | `Miner:Linux/Miner.gyf` |
| huorong | `Trojan/CoinMiner.dm` |

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

- **elf** (53×)
- **Mirai** (33×)
- **Torii** (33×)
- **exe** (16×)
- **Prometei** (13×)
- **stealer** (5×)
- **RAT** (5×)
- **CatStorm** (5×)
- **jar** (4×)
- **rar** (3×)
- **signed** (3×)
- **java** (3×)
- **AsyncRAT** (3×)
- **njrat** (3×)
- **clipper** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +21 (12→33)
- ↓ **unbekannt** -22 (45→23)
- ↑ **Prometei** +5 (8→13)
- ↑ **CatStorm** +3 (2→5)
- neu: **AsyncRAT** (3)
- ↑ **njrat** +1 (2→3)
- ↑ **ConnectWise** +1 (1→2)
- neu: **LummaStealer** (2)
- neu: **MalwareX-gen [Pws]** (1)
- weg: **Snowlight** (war 8)
- weg: **WARDENStealer** (war 6)
- weg: **RemusStealer** (war 3)
- weg: **GuLoader** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +14 (19→33)
- ↓ **unbekannt** -17 (40→23)
- ↑ **Prometei** +8 (5→13)
- ↑ **CatStorm** +3 (2→5)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **njrat** +1 (2→3)
- neu: **LummaStealer** (2)
- neu: **MalwareX-gen [Pws]** (1)
- weg: **WARDENStealer** (war 3)
- weg: **Snowlight** (war 4)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.513 MB |
| σ Dateigröße | 18.273 MB |
| Ø Risiko-Score | 65.2/100 |
| Ø Klassifikations-Konfidenz | 70.7% |
| Samples mit VT | 5/85 |
| Samples mit MITRE | 42/85 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 54 |
| Unbekannte Familien | 5 (5.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 01:08 | [c1710cbb4e3c…](https://bazaar.abuse.ch/sample/c1710cbb4e3cf1ada9964abd58694b8595d1f9e42aa0e576923ef45d99b1b600/) | `exe` | unbekannt | 39.0 | – | – | 🌐CA |
| 01:08 | [1fd6951418c4…](https://bazaar.abuse.ch/sample/1fd6951418c4651bb19b3948c76ce8c0f9fb8be3e6b87f9754c1e6b87f6c020a/) | `exe` | unbekannt | 39.0 | – | – | 🌐CA |
| 00:36 | [5d93eb1287ea…](https://bazaar.abuse.ch/sample/5d93eb1287ea996f3e807b6495133c24e9677fa7e700aa1180dc21aa0eff8c4d/) | `elf` | Prometei | 42.8 | – | – | 🇩🇪DE |
| 00:29 | [6e36d5277a8f…](https://bazaar.abuse.ch/sample/6e36d5277a8f0fbd321964b68185506db73c7383d59890407aa5d4387c3aa386/) | `elf` | Prometei | 42.7 | – | – | 🇩🇪DE |
| 00:25 | [59a02a87159c…](https://bazaar.abuse.ch/sample/59a02a87159c319ea56258b119be0893b49e24276b7268665e1362004327519b/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.11.2026 01:15 UTC*