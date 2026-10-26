# MalwareBazaar – 26.10.2026 19:47 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **47** |
| Höchster Score | **88.3/100** – f59012e49f2e8fd6… |
| Häufigste Familie | **Mirai** (27x) |
| Häufigster Typ | **elf** (37x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 33 Samples |
| Ø Dateigröße | 3.68 MB (σ=8.65) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 37 | 36.6%  ███████ |
| `jar` | 19 | 18.8%  ███ |
| `exe` | 13 | 12.9%  ██ |
| `js` | 9 | 8.9%  █ |
| `zip` | 7 | 6.9%  █ |
| `apk` | 3 | 3.0%   |
| `vbs` | 2 | 2.0%   |
| `hta` | 2 | 2.0%   |
| `zsh` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 27 | 26.7% |
| 2 | SilentNet | 26 | 25.7% |
| 3 | unbekannt | 19 | 18.8% |
| 4 | SalatStealer | 5 | 5.0% |
| 5 | XWorm | 5 | 5.0% |
| 6 | RemcosRAT | 4 | 4.0% |
| 7 | AgentTesla | 2 | 2.0% |
| 8 | PhantomStealer | 2 | 2.0% |
| 9 | ValleyRAT | 2 | 2.0% |
| 10 | ELF:Mirai-AQY [Trj] | 1 | 1.0% |
| 11 | GoToResolve | 1 | 1.0% |
| 12 | RustDesk | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 29 | 28.7% | 93% |
| Andere / Unbekannt | 28 | 27.7% | 20% |
| RAT | 11 | 10.9% | 91% |
| Infostealer | 9 | 8.9% | 78% |
| Linux-Malware | 8 | 7.9% | 45% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Loader | 3 | 3.0% | 75% |
| Windows-Malware | 3 | 3.0% | 35% |
| Trojaner | 2 | 2.0% | 70% |
| Android-Malware | 2 | 2.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 47 | 46.5% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 19 | 18.8% |
| 🟢 NIEDRIG | 28 | 27.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f59012e49f2e8f…](https://bazaar.abuse.ch/sample/f59012e49f2e8fd657a11cf2008fe74ca289d189552e29cdc3d1078956ad0d31/) | Stealc | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [49bcc0a6fa25f1…](https://bazaar.abuse.ch/sample/49bcc0a6fa25f1d01ff245484042523430a1341b16417f343520f06a43a7f238/) | RemcosRAT | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [affae61bc8ca3c…](https://bazaar.abuse.ch/sample/affae61bc8ca3c1e089ae6a3220fb7c633f9e5af791c6d70c6c1c4191f230684/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [62bce207b46b94…](https://bazaar.abuse.ch/sample/62bce207b46b94fe534a613d5e42de57aa867cdfce983f03f7350f880b0439e8/) | RemcosRAT | RAT | **86.9** | 🔴 KRITISCH | – | – | ? |
| [286ae740278234…](https://bazaar.abuse.ch/sample/286ae740278234a35e85eb0c2931824f4df807b0840de2675c66e3ca2d892a17/) | RemcosRAT | RAT | **86.9** | 🔴 KRITISCH | – | – | ? |
| [4990213133c26f…](https://bazaar.abuse.ch/sample/4990213133c26f6a0652e72e819dbadf0b02d217684004b81d9e27242179412a/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [ff2839b99f338f…](https://bazaar.abuse.ch/sample/ff2839b99f338ff35883f57cefa6d21ef66718500d1f1ae4746e9878fc75255a/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [dffa283eb54f9d…](https://bazaar.abuse.ch/sample/dffa283eb54f9df2783f31aca2758141868cd4ea478f612a641a5dbbf25737a0/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [34ee8610bdeb9e…](https://bazaar.abuse.ch/sample/34ee8610bdeb9e57569fd9ea3e1366072048aa1afc7de6cd16ba5b93092ed7b7/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [c352d38dac9987…](https://bazaar.abuse.ch/sample/c352d38dac998755f0674bd2089def16d59fca0f9693eaa29eb4410cbf102587/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6203/7653 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6203/7653 |
| 3 | ESET-NOD32 | 77.2% | 5906/7653 |
| 4 | Kaspersky | 75.7% | 5794/7652 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5440/7650 |
| 8 | Rising | 68.3% | 5227/7653 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5061/7649 |
| 11 | Avast | 65.1% | 4980/7649 |
| 12 | AVG | 65.1% | 4980/7648 |
| 13 | Tencent | 64.8% | 4816/7427 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4684/7646 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 40 | 39.6% |
| ❓ Unbekannt | 25 | 24.8% |
| 🪟 Windows | 20 | 19.8% |
| 📦 Archiv | 12 | 11.9% |
| 🤖 Android | 3 | 3.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 84 | 83.2% |
| Drive-By / Exploit-Kit | 9 | 8.9% |
| MaaS-Loader | 3 | 3.0% |
| APK-Sideloading | 3 | 3.0% |
| Trojanisierte Software | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 26 | 25.7% |
| 2 | 🇩🇪 DE | 24 | 23.8% |
| 3 | 🇨🇭 CH | 10 | 9.9% |
| 4 | 🇸🇪 SE | 10 | 9.9% |
| 5 | 🇪🇸 ES | 6 | 5.9% |
| 6 | 🇫🇷 FR | 6 | 5.9% |
| 7 | 🇳🇱 NL | 4 | 4.0% |
| 8 | 🇭🇺 HU | 4 | 4.0% |
| 9 | 🇦🇹 AT | 3 | 3.0% |
| 10 | 🇬🇧 GB | 2 | 2.0% |
| 11 | 🇨🇦 CA | 1 | 1.0% |
| 12 | 🇸🇬 SG | 1 | 1.0% |
| 13 | 🇧🇷 BR | 1 | 1.0% |
| 14 | 🌐 CO | 1 | 1.0% |
| 15 | 🌐 IQ | 1 | 1.0% |

## MITRE ATT&CK

> 33 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 27 |
| Lateral Movement | 27 |
| Collection | 6 |
| Command and Control | 4 |
| Credential Access | 2 |

<details><summary>f59012e49f2e8fd657a1… – Stealc | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>49bcc0a6fa25f1d01ff2… – RemcosRAT | 🔴 KRITISCH 87.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>affae61bc8ca3c1e089a… – Formbook | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>62bce207b46b94fe534a… – RemcosRAT | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>286ae740278234a35e85… – RemcosRAT | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [01bbf841bc97e59fb87a…](https://bazaar.abuse.ch/sample/01bbf841bc97e59fb87ac7a74f02d80ac65d16741b3fd690dccdfd508cde6aa4/)

- **Familie:** ELF:Mirai-AQY [Trj]
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-AQY [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AQY [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-AQY [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.AQY` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Fgt.6308` |
| ESET-NOD32 | `Linux/Mirai.ATK trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AQY` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-BIX` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| TrellixENS | `Linux/Mirai.cx` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-BIX` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [f4c91ae15bb4b0d39b8d…](https://bazaar.abuse.ch/sample/f4c91ae15bb4b0d39b8d3bd2c69a51366ac2379738b35618dc5c7773b899c0d0/)

- **Familie:** Linux
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.Linux.GenericKD.60061969
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan:Script/Wacatac.C!ml`

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| GData | `Trojan.Linux.GenericKD.60061969` |
| MicroWorld-eScan | `Trojan.Linux.GenericKD.60061969` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Tencent | `Linux.Trojan.Coinminer.Mcnw` |

### [14a0a30d3976f58ac0ff…](https://bazaar.abuse.ch/sample/14a0a30d3976f58ac0ff1146840c8284bed6bebf60dd85342a9ad473457825f8/)

- **Familie:** RemcosRAT
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40652964
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40652964`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40652964` |
| AVG | `Script:SNH-gen [Trj]` |
| AhnLab-V3 | `Trojan/JS.AGENT.SC316972` |
| Arcabit | `Trojan.Generic.D26C50A4` |
| Avast | `Script:SNH-gen [Trj]` |
| Avira | `TR/SNH` |
| BitDefender 🛡️ | `Trojan.Generic.40652964` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `JS.Muldrop.1368` |
| ESET-NOD32 | `JS/Agent.VMP trojan` |
| Emsisoft | `Trojan.Generic.40652964 (B)` |
| F-Secure | `Trojan.TR/SNH` |
| Fortinet | `JS/Agent.VMP!tr` |
| GData | `Trojan.Generic.40652964` |
| Ikarus | `Trojan.JS.Agent` |
| Kaspersky | `HEUR:Trojan.Script.Generic` |
| Kingsoft | `Script.Trojan.Generic.a` |
| Lionic | `Trojan.HTML.Generic.4!c` |
| McAfeeD | `Trojan:Script/JSDownloader.FD` |
| MicroWorld-eScan | `Trojan.Generic.40652964` |
| NANO-Antivirus | `Trojan.Script.Heuristic-js.iacgm` |
| Rising | `Trojan.Obfus/JS!1.1490C (CLASSIC)` |
| Skyhigh | `BehavesLike.HTML.Exploit.mr` |
| Symantec | `ISB.Dropper!gen1` |
| Tencent | `Script.Trojan.Generic.Kjgl` |
| VIPRE | `Trojan.Generic.40652964` |
| Varist | `HTML/Agent.IU` |
| VirIT | `Trojan.HTA.Agent.DSS` |
| alibabacloud | `Trojan:Javascript/Generic.Gen` |
| huorong | `Trojan/JS.Obfuscated.op!crit` |

### [cea94badd85daaa9af8e…](https://bazaar.abuse.ch/sample/cea94badd85daaa9af8e2fae9011f7560fc4395a914a53cef0fa1f76ad3663d2/)

- **Familie:** Mirai
- **Erkannt von:** 37 von 75 Engines (49.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40676918
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40676918`

**Erkennende Engines (37/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40676918` |
| AVG | `ELF:Mirai-AM [Trj]` |
| AhnLab-V3 | `Linux/Miraidown.Gen` |
| Antiy-AVL | `Trojan[Downloader]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D26CAE36` |
| Avast | `ELF:Mirai-AM [Trj]` |
| Avast-Mobile | `ELF:MiraiDownloader-QG [Trj]` |
| Avira | `TR/LINUX.Mirai.AM` |
| BitDefender 🛡️ | `Trojan.Generic.40676918` |
| CAT-QuickHeal | `Elf.Backdoor.A28787189` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9779` |
| ESET-NOD32 | `Linux/TrojanDownloader.Mirai.A trojan` |
| Emsisoft | `Trojan.Generic.40676918 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AM` |
| Fortinet | `ELF/Mirai.A!tr.dldr` |
| GData | `Trojan.Generic.40676918` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Mirai` |
| Kaspersky | `HEUR:Trojan-Downloader.Linux.Mirai.d` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!CEA94BADD85D` |
| MicroWorld-eScan | `Trojan.Generic.40676918` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HX!MTB` |
| Rising | `Downloader.Mirai/Linux!8.13556 (TFE:14:dBdUm02wosG)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Skyhigh | `GenericRXIA-WK!F713314E3505` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.MiraiDownload.ve` |
| TrellixENS | `GenericRXIA-WK!F713314E3505` |
| TrendMicro | `Possible_MIRAIDLOD.SMLBAT6` |
| TrendMicro-HouseCall | `Possible_MIRAIDLOD.SMLBAT6` |
| Varist | `E32/ABDownloader.LXZ` |
| VirIT | `Linux.DownLoader.UP` |
| alibabacloud | `DDoS:Linux/Mirai.QZ` |
| huorong | `Trojan/Linux.Agent.bn!crit` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (44/75):**

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
| Bkav | `W32.Malware.62046A21` |
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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!9E7BE912AC3C` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **elf** (37×)
- **Mirai** (27×)
- **jar** (26×)
- **SilentNet** (24×)
- **exe** (12×)
- **zip** (12×)
- **js** (9×)
- **ddos** (7×)
- **jkl** (6×)
- **cowrie** (5×)
- **honeypot** (5×)
- **signed** (5×)
- **XWorm** (5×)
- **SalatStealer** (4×)
- **arm** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +9 (18→27)
- neu: **SilentNet** (26)
- ↑ **unbekannt** +2 (17→19)
- ↓ **SalatStealer** -24 (29→5)
- ↑ **XWorm** +4 (1→5)
- ↑ **RemcosRAT** +1 (3→4)
- neu: **AgentTesla** (2)
- neu: **PhantomStealer** (2)
- neu: **ValleyRAT** (2)
- neu: **ELF:Mirai-AQY [Trj]** (1)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +8 (19→27)
- neu: **SilentNet** (26)
- ↓ **unbekannt** -16 (35→19)
- ↓ **SalatStealer** -1 (6→5)
- neu: **XWorm** (5)
- ↑ **RemcosRAT** +2 (2→4)
- ↑ **AgentTesla** +1 (1→2)
- neu: **PhantomStealer** (2)
- neu: **ValleyRAT** (2)
- neu: **ELF:Mirai-AQY [Trj]** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.685 MB |
| σ Dateigröße | 8.653 MB |
| Ø Risiko-Score | 58.9/100 |
| Ø Klassifikations-Konfidenz | 60.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 33/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 69 |
| Unbekannte Familien | 28 (27.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:44 | [1394bd1d2264…](https://bazaar.abuse.ch/sample/1394bd1d22647bc1ff776506f62fd46ad59d49e64b37dac9812228a49f3017e9/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 19:42 | [0df9702efed7…](https://bazaar.abuse.ch/sample/0df9702efed752e824e600287187540fd1cbc50e52eb3b1c4cc06126446a27d1/) | `elf` | Mirai | 84.5 | – | – | 🌐ES |
| 19:42 | [5fbe2d464ee5…](https://bazaar.abuse.ch/sample/5fbe2d464ee5f0391f98907cf43a4e37fd37aaace7e3a24e898c7945bdfcb0e7/) | `elf` | Mirai | 84.5 | – | – | 🌐ES |
| 19:42 | [87717b022f21…](https://bazaar.abuse.ch/sample/87717b022f21e66c4467beda7d640736b386e23ecf5ef900d4587b6467bfd145/) | `elf` | Mirai | 84.5 | – | – | 🌐ES |
| 19:42 | [b5fcabc415d2…](https://bazaar.abuse.ch/sample/b5fcabc415d29d82f33c62bf760ea0ae63ff062e9c2b18f82435750831493623/) | `elf` | Mirai | 84.5 | – | – | 🌐ES |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.10.2026 19:47 UTC*