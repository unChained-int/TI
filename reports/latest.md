# MalwareBazaar – 15.11.2026 05:30 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **73** |
| Höchster Score | **97.5/100** – 34e22edd2350543f… |
| Häufigste Familie | **Mirai** (46x) |
| Häufigster Typ | **elf** (47x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 52 Samples |
| Ø Dateigröße | 2.82 MB (σ=7.93) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 47 | 46.5%  █████████ |
| `exe` | 40 | 39.6%  ███████ |
| `msi` | 5 | 5.0%   |
| `js` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |
| `sh` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |
| `php` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 46 | 45.5% |
| 2 | unbekannt | 22 | 21.8% |
| 3 | WARDENStealer | 5 | 5.0% |
| 4 | RevStealer | 5 | 5.0% |
| 5 | ConnectWise | 5 | 5.0% |
| 6 | RemusStealer | 3 | 3.0% |
| 7 | SalatStealer | 3 | 3.0% |
| 8 | njrat | 3 | 3.0% |
| 9 | WannaCry | 2 | 2.0% |
| 10 | Downloader!gen446 | 1 | 1.0% |
| 11 | Babadeda | 1 | 1.0% |
| 12 | XWorm | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 46 | 45.5% | 95% |
| Infostealer | 18 | 17.8% | 75% |
| Windows-Malware | 16 | 15.8% | 35% |
| Loader | 6 | 5.9% | 77% |
| RAT | 6 | 5.9% | 92% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Ransomware | 2 | 2.0% | 95% |
| Android-Malware | 1 | 1.0% | 45% |
| Post-Exploitation | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 73 | 72.3% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [34e22edd235054…](https://bazaar.abuse.ch/sample/34e22edd2350543f4b621924eb1bff7bffdd2ab7f7ddd30f57b01e7afb78b69c/) | WannaCry | Ransomware | **97.5** | 🔴 KRITISCH | – | – | ? |
| [107bde91266112…](https://bazaar.abuse.ch/sample/107bde9126611222a6c6622985635e3c5bcf8cc11a080a1a1431facc19897eee/) | WannaCry | Ransomware | **94.5** | 🔴 KRITISCH | – | – | ? |
| [db962f875ae97c…](https://bazaar.abuse.ch/sample/db962f875ae97c88644c7def3d9da0b0aa8d2926cf988283c398b88a942853a7/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [e2947958360816…](https://bazaar.abuse.ch/sample/e29479583608163b5b1d4ff415f7100b007bf03ddd6b4dda774ebcff39bedc9c/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [dc75bef4fdc1b0…](https://bazaar.abuse.ch/sample/dc75bef4fdc1b0cc2a54a6c3fbbe1ffeebe7257f9e4cf43ac2d8c9dd2fd1709a/) | njrat | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [4669d8bd80b1af…](https://bazaar.abuse.ch/sample/4669d8bd80b1af16ddaa16a9c9c5aa3faccb8c7188f2eb7dc9fb7de487b77e4f/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [3d142729813c74…](https://bazaar.abuse.ch/sample/3d142729813c74f5a28964144eb07f226555129d31084fe0c166f6a1da8995c2/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [0f46c1fd38b978…](https://bazaar.abuse.ch/sample/0f46c1fd38b978bb082bb8163a8daac097730f0fee8c3439cc8f44430f05c90d/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [35777f8686a70e…](https://bazaar.abuse.ch/sample/35777f8686a70e614f84a34a1a045b40c401f559fc2626a91f0a9d95f013c7d1/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [36d54277bec12d…](https://bazaar.abuse.ch/sample/36d54277bec12d3b1f0ff399a8eaa8642fbc1c99b268e55ce23aef496dd15708/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6487/7994 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6487/7994 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6179/7994 |
| 6 | Kaspersky | 75.5% | 6033/7993 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5692/7990 |
| 9 | Rising | 68.4% | 5468/7994 |
| 10 | Varist | 66.0% | 5276/7989 |
| 11 | Avast | 65.1% | 5204/7990 |
| 12 | AVG | 65.1% | 5204/7989 |
| 13 | Tencent | 65.0% | 5049/7768 |
| 14 | McAfeeD | 61.4% | 4905/7986 |
| 15 | huorong | 60.8% | 4856/7986 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 48 | 47.5% |
| 🪟 Windows | 48 | 47.5% |
| ❓ Unbekannt | 3 | 3.0% |
| 🤖 Android | 1 | 1.0% |
| 🌐 Web | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 84.2% |
| Trojanisierte Software | 5 | 5.0% |
| MaaS-Loader | 4 | 4.0% |
| Drive-By / Exploit-Kit | 3 | 3.0% |
| Exploit / N-Day | 2 | 2.0% |
| APK-Sideloading | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 43 | 42.6% |
| 2 | 🇺🇸 US | 31 | 30.7% |
| 3 | 🇨🇿 CZ | 9 | 8.9% |
| 4 | 🇫🇷 FR | 8 | 7.9% |
| 5 | 🇳🇱 NL | 8 | 7.9% |
| 6 | 🇯🇵 JP | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 52 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 46 |
| Lateral Movement | 46 |
| Collection | 5 |
| Command and Control | 4 |
| Credential Access | 1 |
| Exfiltration | 1 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>db962f875ae97c88644c… – njrat | 🔴 KRITISCH 85.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>e29479583608163b5b1d… – njrat | 🔴 KRITISCH 85.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>dc75bef4fdc1b0cc2a54… – njrat | 🔴 KRITISCH 85.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [fa4387cbb847d8d36450…](https://bazaar.abuse.ch/sample/fa4387cbb847d8d36450642b024be7e7af480925cc557770a4174084e1ca4833/)

- **Familie:** Downloader!gen446
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ISB.Downloader!gen446
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/Kryptik.PK trojan` |
| Microsoft 🛡️ | `Trojan:PowerShell/Obfuse.FW!MTB` |
| Symantec | `ISB.Downloader!gen446` |

### [add68e988346756c2aa0…](https://bazaar.abuse.ch/sample/add68e988346756c2aa0aba09458c2e00415d35a318c2392ad76290907702834/)

- **Familie:** XWorm
- **Erkannt von:** 52 von 75 Engines (69.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** IL:Trojan.XWorm.53
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `IL:Trojan.XWorm.53`

**Erkennende Engines (52/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `IL:Trojan.XWorm.53` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| Alibaba | `Trojan:MSIL/InjectorX.fcb08c70` |
| Antiy-AVL | `Trojan/MSIL.Vimditator` |
| Arcabit | `IL:Trojan.XWorm.53` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `TR/Spy.Gen` |
| BitDefender 🛡️ | `IL:Trojan.XWorm.53` |
| Bkav | `W32.Malware.5ECB1F0C` |
| CTX | `exe.trojan.xworm` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.StealerNET.203` |
| ESET-NOD32 | `MSIL/XWorm.N trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `IL:Trojan.XWorm.53 (B)` |
| F-Secure | `Trojan.TR/Spy.Gen` |
| Fortinet | `MSIL/XWorm.ECL!tr` |
| GData | `IL:Trojan.XWorm.53` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Bladabindi` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan.MSIL.Vimditator.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.XWorm.4!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!1BC9158BC04C` |
| MicroWorld-eScan | `IL:Trojan.XWorm.53` |
| Microsoft 🛡️ | `Trojan:MSIL/InjectorX.RDA!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Malware.Obfus/MSIL@AI.80 (RDM.MSIL2:H3OjZStCRPdduGRIffuANw)` |
| Sangfor | `Virus.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `ACL/Generic.RJGR` |
| Sophos | `Troj/XWorm-F` |
| Symantec | `MSIL.XWorm!gen2` |
| Tencent | `Malware.Win32.Gencirc.14b714a7` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `ACL/Generic.RJGR` |
| VBA32 | `Malware-Cryptor.MSIL.AgentTesla.Heur` |
| VIPRE | `IL:Trojan.XWorm.53` |
| Varist | `W32/MSIL_Kryptik.NDA.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Xworm_F.138240` |
| Webroot | `W32.Malware.gen` |
| ZoneAlarm | `Troj/XWorm-F` |
| alibabacloud | `Backdoor:MSIL/Fynloski.A` |
| huorong | `Trojan/MSIL.Injector.nq` |

### [4bbcf635ecbbca9db3bf…](https://bazaar.abuse.ch/sample/4bbcf635ecbbca9db3bf09653a150c4324e80f19c3e8c89bb07a00fb16c87e2c/)

- **Familie:** Linux
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Sliver.1
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Sliver.1`

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Sliver.1` |
| Arcabit | `Trojan.Linux.Sliver.1` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Sliver.1` |
| CTX | `elf.unknown.sliver` |
| Emsisoft | `Gen:Variant.Linux.Sliver.1 (B)` |
| GData | `Gen:Variant.Linux.Sliver.1` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.Linux.Vilers.b` |
| Lionic | `Trojan.Linux.Vilers.4!c` |
| McAfeeD | `ti!4BBCF635ECBB` |
| MicroWorld-eScan | `Gen:Variant.Linux.Sliver.1` |
| Microsoft 🛡️ | `VirTool:Linux/Sliver.A!MTB` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `ATK/Sliver-Z` |
| VIPRE | `Gen:Variant.Linux.Sliver.1` |
| ZoneAlarm | `ATK/Sliver-Z` |
| alibabacloud | `Trojan:Linux/Sliver.A9OKG` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

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
| CAT-QuickHeal | `Trojan.Injector` |
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
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
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

- **elf** (47×)
- **Mirai** (46×)
- **exe** (39×)
- **Torii** (27×)
- **upx-dec** (6×)
- **signed** (6×)
- **Prometei** (5×)
- **upx** (5×)
- **WARDENStealer** (5×)
- **stealer** (5×)
- **RevStealer** (5×)
- **ConnectWise** (5×)
- **msi** (5×)
- **SalatStealer** (4×)
- **loader** (4×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -9 (55→46)
- ↓ **unbekannt** -9 (31→22)
- ↑ **WARDENStealer** +1 (4→5)
- neu: **RevStealer** (5)
- neu: **ConnectWise** (5)
- ↑ **RemusStealer** +2 (1→3)
- ↑ **SalatStealer** +1 (2→3)
- ↑ **njrat** +2 (1→3)
- neu: **WannaCry** (2)
- neu: **Downloader!gen446** (1)
- weg: **ValleyRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +13 (33→46)
- ↓ **unbekannt** -5 (27→22)
- ↑ **WARDENStealer** +1 (4→5)
- ↑ **RevStealer** +3 (2→5)
- ↑ **ConnectWise** +4 (1→5)
- neu: **RemusStealer** (3)
- ↓ **SalatStealer** -3 (6→3)
- ↑ **njrat** +2 (1→3)
- neu: **WannaCry** (2)
- neu: **Downloader!gen446** (1)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.819 MB |
| σ Dateigröße | 7.930 MB |
| Ø Risiko-Score | 70.8/100 |
| Ø Klassifikations-Konfidenz | 76.7% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 52/101 |
| Eindeutige Familien | 16 |
| Eindeutige Tags | 43 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:28 | [4669d8bd80b1…](https://bazaar.abuse.ch/sample/4669d8bd80b1af16ddaa16a9c9c5aa3faccb8c7188f2eb7dc9fb7de487b77e4f/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 05:27 | [3d142729813c…](https://bazaar.abuse.ch/sample/3d142729813c74f5a28964144eb07f226555129d31084fe0c166f6a1da8995c2/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 05:25 | [0f46c1fd38b9…](https://bazaar.abuse.ch/sample/0f46c1fd38b978bb082bb8163a8daac097730f0fee8c3439cc8f44430f05c90d/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 05:25 | [35777f8686a7…](https://bazaar.abuse.ch/sample/35777f8686a70e614f84a34a1a045b40c401f559fc2626a91f0a9d95f013c7d1/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 05:25 | [36d54277bec1…](https://bazaar.abuse.ch/sample/36d54277bec12d3b1f0ff399a8eaa8642fbc1c99b268e55ce23aef496dd15708/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.11.2026 05:30 UTC*