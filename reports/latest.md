# MalwareBazaar – 13.10.2026 15:41 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **48** |
| Höchster Score | **89.6/100** – 275700b41f499d80… |
| Häufigste Familie | **unbekannt** (44x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 47 Samples |
| Ø Dateigröße | 3.35 MB (σ=8.86) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 52.5%  ██████████ |
| `exe` | 22 | 21.8%  ████ |
| `sh` | 7 | 6.9%  █ |
| `js` | 5 | 5.0%   |
| `jar` | 3 | 3.0%   |
| `macho` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `zip` | 2 | 2.0%   |
| `vbs` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 44 | 43.6% |
| 2 | Mirai | 37 | 36.6% |
| 3 | Formbook | 5 | 5.0% |
| 4 | CoinMiner | 3 | 3.0% |
| 5 | AsyncRAT | 2 | 2.0% |
| 6 | DCRat | 1 | 1.0% |
| 7 | RemusStealer | 1 | 1.0% |
| 8 | GCleaner | 1 | 1.0% |
| 9 | Prometei | 1 | 1.0% |
| 10 | Koadic | 1 | 1.0% |
| 11 | XWorm | 1 | 1.0% |
| 12 | FleetDeck | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 37 | 36.6% | 95% |
| Linux-Malware | 18 | 17.8% | 45% |
| Andere / Unbekannt | 15 | 14.9% | 20% |
| Windows-Malware | 11 | 10.9% | 35% |
| RAT | 6 | 5.9% | 95% |
| Infostealer | 6 | 5.9% | 92% |
| Cryptominer | 3 | 3.0% | 75% |
| Loader | 3 | 3.0% | 75% |
| Skript/Dropper | 2 | 2.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 48 | 47.5% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 31 | 30.7% |
| 🟢 NIEDRIG | 15 | 14.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [275700b41f499d…](https://bazaar.abuse.ch/sample/275700b41f499d80822ed756aea03fe2b83317b5cba4d04d01413d01e50df66d/) | DCRat | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [6e6b35831c2dd3…](https://bazaar.abuse.ch/sample/6e6b35831c2dd3b9a5d9c3edf9d15ee6a9ec3ff6266446cfe6615fc9b4e0b3f3/) | Formbook | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |
| [d44a531a8618b4…](https://bazaar.abuse.ch/sample/d44a531a8618b44e33bd9aafaccf2272495b0a3d580cd72fbd89db698f231015/) | Formbook | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [2c5841111f1eb3…](https://bazaar.abuse.ch/sample/2c5841111f1eb3ebaccf966e8ce6fbcc8d99f5f2958017ebfa1c12c62afa13c1/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [e38c67895ad921…](https://bazaar.abuse.ch/sample/e38c67895ad921cc238ec9b59ebe38bc21ad43dfb3875116ed05dfb38d168abc/) | XWorm | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [36fe14010dff2e…](https://bazaar.abuse.ch/sample/36fe14010dff2ef4a80737f0f99cdb2017aaf1f860e2cf4a34f3e21da2ac4e55/) | Formbook | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [4e6fe5635c33a9…](https://bazaar.abuse.ch/sample/4e6fe5635c33a92261ebbdf22cfecae08d71d6705f54f943ef6ca089a978bebb/) | AsyncRAT | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [3461b395a20846…](https://bazaar.abuse.ch/sample/3461b395a20846cefef84d6f7ddcbd7aff2209423eaaf74925ab70b0038e160a/) | QuasarRAT | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [abc19d78d94158…](https://bazaar.abuse.ch/sample/abc19d78d94158d057220187860ce7781187c9a74667e34689b46637f86684d7/) | AsyncRAT | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [36c1dd7e4ff963…](https://bazaar.abuse.ch/sample/36c1dd7e4ff963177ed67d5779b36c44ad4a25bd8673b4cf333ec9b221309f1e/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5944/7347 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5944/7347 |
| 3 | ESET-NOD32 | 77.4% | 5688/7347 |
| 4 | Kaspersky | 76.3% | 5608/7346 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5259/7344 |
| 8 | Rising | 68.7% | 5049/7347 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4881/7343 |
| 11 | Tencent | 65.3% | 4649/7121 |
| 12 | AVG | 65.1% | 4776/7342 |
| 13 | Avast | 65.0% | 4776/7343 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4505/7340 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 60 | 59.4% |
| 🪟 Windows | 26 | 25.7% |
| ❓ Unbekannt | 10 | 9.9% |
| 📦 Archiv | 3 | 3.0% |
| 🍎 macOS | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 92 | 91.1% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| MaaS-Loader | 2 | 2.0% |
| C2 / Nachladen | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 39 | 38.6% |
| 2 | 🇺🇸 US | 25 | 24.8% |
| 3 | 🇫🇷 FR | 8 | 7.9% |
| 4 | 🇭🇺 HU | 7 | 6.9% |
| 5 | 🇨🇿 CZ | 6 | 5.9% |
| 6 | 🇳🇱 NL | 5 | 5.0% |
| 7 | 🇬🇧 GB | 3 | 3.0% |
| 8 | 🇵🇱 PL | 3 | 3.0% |
| 9 | 🇨🇭 CH | 2 | 2.0% |
| 10 | 🇪🇸 ES | 1 | 1.0% |
| 11 | 🇧🇷 BR | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 47 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 37 |
| Lateral Movement | 37 |
| Collection | 6 |
| Credential Access | 5 |
| Command and Control | 4 |
| Execution | 3 |
| Persistence | 1 |
| Exfiltration | 1 |

<details><summary>6e6b35831c2dd3b9a5d9… – Formbook | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>d44a531a8618b44e33bd… – Formbook | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2c5841111f1eb3ebaccf… – Formbook | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [37182e1662c902727b8e…](https://bazaar.abuse.ch/sample/37182e1662c902727b8e0e988f24e84c40405cfb4d98a2f78be2d7467a0d1569/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!F3470902AB45
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.ATK trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.BO!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ki` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.EN!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!F3470902AB45` |
| Sophos | `Linux/DDoS-BIX` |
| Tencent | `Backdoor.Linux.Mirai.PPCra` |
| TrellixENS | `LINUX/Mirai-FQU!F3470902AB45` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-BIX` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [e51fb04c6063d255d9e8…](https://bazaar.abuse.ch/sample/e51fb04c6063d255d9e82fb983642aeb044004ad4af0a1b7a0cf4c9e908c69fc/)

- **Familie:** Mirai
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Crypt` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Linux.Backdoor.Gafgyt.Rsmw` |
| Varist | `E64/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.l` |

### [5c62a78d342e98c2b1b6…](https://bazaar.abuse.ch/sample/5c62a78d342e98c2b1b6722433c766441523ef04d9659b7f00286d9f3283166b/)

- **Familie:** Formbook
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Alibaba | `Trojan:MSIL/Taskun.3414edaf` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.2AD8A74A` |
| CTX | `exe.trojan.msil` |
| ClamAV | `Win.Dropper.Nanocore-10025638-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.ARCM trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `MSIL/Masslogger.PBZX!tr` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.MSIL.Taskun.vho` |
| Kingsoft | `malware.kb.c.933` |
| Lionic | `Trojan.Win32.Taskun.4!c` |
| Malwarebytes | `Trojan.MalPack.PNG.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!2D7077C6484E` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Malware.Obfus/MSIL@AI.88 (RDM.MSIL2:VxtijpbA6EfM4h3PovPleQ)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Msil.Trojan.Taskun.Hajl` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!2D7077C6484E` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| Varist | `W32/MSIL_Kryptik.MUC2.ge!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Wacatac.B9nj` |

### [80b75788ef444d40a485…](https://bazaar.abuse.ch/sample/80b75788ef444d40a485023337bb73e943e0622f00eb7c08400558892db6ef67/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-AQY [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AQY [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-AQY [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.AQY` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AQY` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gp` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| TrellixENS | `LINUX/Mirai-FQU!BF0B203C61FB` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.f` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
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
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **Mirai** (37×)
- **elf** (36×)
- **exe** (20×)
- **sh** (5×)
- **Formbook** (5×)
- **js** (5×)
- **cowrie** (4×)
- **honeypot** (4×)
- **signed** (3×)
- **CoinMiner** (3×)
- **Steam** (3×)
- **jar** (3×)
- **AMOS** (2×)
- **ClickFix** (2×)
- **Foxveil** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +18 (26→44)
- ↑ **Mirai** +3 (34→37)
- ↑ **Formbook** +1 (4→5)
- neu: **CoinMiner** (3)
- neu: **RemusStealer** (1)
- neu: **GCleaner** (1)
- neu: **Prometei** (1)
- neu: **Koadic** (1)
- weg: **SilentNet** (war 8)
- weg: **VIPKeylogger** (war 2)
- weg: **Blackmoon** (war 2)
- weg: **WannaCry** (war 2)
- weg: **AMOS** (war 2)
- weg: **NanoCore** (war 2)
- weg: **Gafgyt** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +17 (27→44)
- ↓ **Mirai** -2 (39→37)
- ↑ **Formbook** +3 (2→5)
- neu: **CoinMiner** (3)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **DCRat** (1)
- neu: **RemusStealer** (1)
- neu: **GCleaner** (1)
- neu: **Prometei** (1)
- neu: **Koadic** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.353 MB |
| σ Dateigröße | 8.865 MB |
| Ø Risiko-Score | 61.4/100 |
| Ø Klassifikations-Konfidenz | 65.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 47/101 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 15 (14.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 15:39 | [88b28c9ef950…](https://bazaar.abuse.ch/sample/88b28c9ef950652f73525452bf01a98c74d4c6b16e71b5d096b0ecc51be5edfa/) | `elf` | unbekannt | 43.3 | – | – | 🌐CZ |
| 15:39 | [7261b7040c03…](https://bazaar.abuse.ch/sample/7261b7040c03d65049babe825f24429a450b2efc88904e4904d627e9cf239a36/) | `elf` | unbekannt | 43.3 | – | – | 🌐CZ |
| 15:39 | [1fd54a75d19f…](https://bazaar.abuse.ch/sample/1fd54a75d19f3ef8f42caa8aceb1c1b19740d66b1349c58eb9307429850fe6b4/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 15:39 | [3a8d21a3a9ef…](https://bazaar.abuse.ch/sample/3a8d21a3a9ef78276173782093290f0a82a48b9d437c43d5815cf255af18adf5/) | `elf` | unbekannt | 43.3 | – | – | 🌐CZ |
| 15:39 | [0463c43339da…](https://bazaar.abuse.ch/sample/0463c43339dab19c4065f7511277256484b7edf67fe4459b99bae4247a3b9ff6/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.10.2026 15:41 UTC*