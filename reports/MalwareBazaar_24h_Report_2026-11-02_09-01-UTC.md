# MalwareBazaar – 02.11.2026 09:01 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **67** |
| Höchster Score | **94.1/100** – b1022d3e58a0318b… |
| Häufigste Familie | **Mirai** (34x) |
| Häufigster Typ | **elf** (36x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 49 Samples |
| Ø Dateigröße | 2.37 MB (σ=6.13) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 36 | 36.0%  ███████ |
| `exe` | 35 | 35.0%  ███████ |
| `js` | 12 | 12.0%  ██ |
| `vbs` | 4 | 4.0%   |
| `ps1` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |
| `dll` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 34 | 34.0% |
| 2 | unbekannt | 18 | 18.0% |
| 3 | RemcosRAT | 8 | 8.0% |
| 4 | VShell | 6 | 6.0% |
| 5 | SalatStealer | 6 | 6.0% |
| 6 | Formbook | 5 | 5.0% |
| 7 | AgentTesla | 5 | 5.0% |
| 8 | ValleyRAT | 2 | 2.0% |
| 9 | PhantomStealer | 2 | 2.0% |
| 10 | NanoCore | 2 | 2.0% |
| 11 | ConnectWise | 2 | 2.0% |
| 12 | CoinMiner | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 36 | 36.0% | 94% |
| Windows-Malware | 19 | 19.0% | 35% |
| Infostealer | 16 | 16.0% | 81% |
| RAT | 14 | 14.0% | 92% |
| Skript/Dropper | 5 | 5.0% | 35% |
| Linux-Malware | 2 | 2.0% | 45% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Loader | 2 | 2.0% | 85% |
| Cryptominer | 2 | 2.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 67 | 67.0% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 22 | 22.0% |
| 🟢 NIEDRIG | 6 | 6.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b1022d3e58a031…](https://bazaar.abuse.ch/sample/b1022d3e58a0318b52feb8aa8048376113ca7596830cb0da750c08f2c8ece583/) | Sliver | Post-Exploitat | **94.1** | 🔴 KRITISCH | – | – | ? |
| [1c390ca00731fe…](https://bazaar.abuse.ch/sample/1c390ca00731fe9c5632ef7e8b30d776b4955ddf4a2c1adeb0981733461466e6/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [2d792a60273e0b…](https://bazaar.abuse.ch/sample/2d792a60273e0b756e5efe2ef9275df360eb55faa365fdb2dffeb4a6ba431846/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [ad3c80ea943027…](https://bazaar.abuse.ch/sample/ad3c80ea9430278dae35e4c5fd8656e1dc577f6d53c6ea4242b72f6a1f42c5c8/) | RemcosRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [c8ef25d664803c…](https://bazaar.abuse.ch/sample/c8ef25d664803cd43b5a877f059b699021215c1226383fb39279f37119434079/) | RemcosRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [1167be18640e28…](https://bazaar.abuse.ch/sample/1167be18640e28a0c1ee3d200549125a6ab40b79fcc998e7be6ccfe9ffc0a242/) | njrat | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [c30c0eb893e8db…](https://bazaar.abuse.ch/sample/c30c0eb893e8db7de821c2f02dca74aa4c1f2573cbebf447a091dbe8851a6f90/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [353ba612671006…](https://bazaar.abuse.ch/sample/353ba612671006ee7ab30660ab36b68364a5b1407f784238946b9e7539378bd0/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [fb6ac4c4d225bc…](https://bazaar.abuse.ch/sample/fb6ac4c4d225bc2fd05325500aa94a4bbbcac2e61ebe14d8141dff0429f5fff4/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [d89653faf40894…](https://bazaar.abuse.ch/sample/d89653faf40894917cf9e6c5af92f4c6ccea72b2ed3e90938f0ec247cb4f1429/) | RemcosRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6310/7784 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6310/7784 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.2% | 6013/7784 |
| 6 | Kaspersky | 75.5% | 5875/7783 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5541/7780 |
| 9 | Rising | 68.3% | 5315/7784 |
| 10 | Varist | 66.2% | 5146/7779 |
| 11 | Avast | 65.2% | 5070/7780 |
| 12 | AVG | 65.2% | 5070/7779 |
| 13 | Tencent | 64.9% | 4905/7558 |
| 14 | McAfeeD | 61.3% | 4770/7776 |
| 15 | huorong | 60.9% | 4734/7776 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 47 | 47.0% |
| 🪟 Windows | 41 | 41.0% |
| ❓ Unbekannt | 9 | 9.0% |
| 🤖 Android | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 82 | 82.0% |
| Drive-By / Exploit-Kit | 13 | 13.0% |
| APK-Sideloading | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 25.0% |
| 2 | 🇺🇸 US | 22 | 22.0% |
| 3 | 🇮🇹 IT | 15 | 15.0% |
| 4 | 🇦🇹 AT | 14 | 14.0% |
| 5 | 🇳🇱 NL | 13 | 13.0% |
| 6 | 🇫🇷 FR | 5 | 5.0% |
| 7 | 🇭🇺 HU | 2 | 2.0% |
| 8 | 🇨🇦 CA | 1 | 1.0% |
| 9 | 🇨🇭 CH | 1 | 1.0% |
| 10 | 🌐 MY | 1 | 1.0% |
| 11 | 🌐 EE | 1 | 1.0% |

## MITRE ATT&CK

> 49 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 34 |
| Lateral Movement | 34 |
| Collection | 14 |
| Command and Control | 9 |
| Credential Access | 5 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>1c390ca00731fe9c5632… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2d792a60273e0b756e5e… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ad3c80ea9430278dae35… – RemcosRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c8ef25d664803cd43b5a… – RemcosRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 58 von 74 Engines (78.4%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (58/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |

### [1f1007ec859f46e109c8…](https://bazaar.abuse.ch/sample/1f1007ec859f46e109c8a1a0aa8ecac0718cf12dde897d3b2e8ec30fe2036ef2/)

- **Familie:** AgentTesla
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 005d5f371 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `MalwareX-gen [Drp]` |
| Alibaba | `Trojan:MSIL/Kryptik.dd7a891a` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.40E28E90` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.AREP trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `MSIL/AgentTesla.ALLB!tr` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 005d5f371 )` |
| K7GW | `Trojan ( 005d5f371 )` |
| Kaspersky | `VHO:Trojan-PSW.MSIL.Agensla.gen` |
| Malwarebytes | `Trojan.MalPack.PNG.Generic` |
| McAfeeD | `Trojan:Win/GenericPack.BMP` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Malware.Obfus/MSIL@AI.98 (RDM.MSIL2:IGqy+TKTH3Cu4/lqc/0hIg)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `MSIL.Packed.19` |
| TrendMicro | `TrojanSpy.MSIL.NEGASTEAL.SMG` |
| TrendMicro-HouseCall | `TrojanSpy.MSIL.NEGASTEAL.SMG` |
| Varist | `W32/MSIL_Agent.JXW.gen!Eldorado` |

### [d35456005f057f63188f…](https://bazaar.abuse.ch/sample/d35456005f057f63188fefe395033af02deb1a600aa2b6cbe33f248ceab6791b/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Agent-AYQ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Agent-AYQ [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Agent.J.8` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7136013-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Agent.J.8` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.icqg` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.E!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FROZ!79887A27254A` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wao` |
| TrellixENS | `Linux/Mirai-FROZ!79887A27254A` |
| TrendMicro | `Possible_MIRAI.SMLBO14` |
| TrendMicro-HouseCall | `Possible_MIRAI.SMLBO14` |
| VBA32 | `Trojan.Linux.Agent` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai.a3a340fc` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [8456ad953d7cf20d539b…](https://bazaar.abuse.ch/sample/8456ad953d7cf20d539b97597c5545cdf5c98b52d2c80285b90281871ed3731e/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.282
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.282`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.282` |
| AVG | `ELF:Agent-AYQ [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.XE228` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.282` |
| Avast | `ELF:Agent-AYQ [Trj]` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.282` |
| CTX | `elf.trojan.mirai` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Emsisoft | `Trojan.Linux.Mirai.282 (B)` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Trojan.Linux.Mirai.282` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.aont` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.h` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.282` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| TrellixENS | `GenericRXTP-FK!54C633A2144F` |
| VIPRE | `Trojan.Linux.Mirai.282` |
| Varist | `E32/Mirai.BOF` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai.6624ba2d` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [37319900a72afee46018…](https://bazaar.abuse.ch/sample/37319900a72afee460184d5af3b4486248efcc470e260962b338ebcd90d81de9/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BIJ [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BIJ [Trj]` |
| AhnLab-V3 | `Trojan/Linux.Mirai.SE306` |
| Avast | `ELF:Mirai-BIJ [Trj]` |
| Avast-Mobile | `ELF:Mirai-BIK [Trj]` |
| Avira | `TR/LINUX.Mirai.BIJ` |
| ClamAV | `Unix.Trojan.Mirai-9907086-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BIJ` |
| Fortinet | `ELF/UNSTABLE.REAL!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.GV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.1056B (CLASSIC)` |
| Tencent | `Trojan.Linux.Mirai.zbtra` |
| huorong | `Backdoor/Linux.Mirai.de` |


## Top Tags

- **exe** (42×)
- **elf** (36×)
- **Mirai** (33×)
- **Torii** (16×)
- **ddos** (15×)
- **js** (12×)
- **dht** (10×)
- **midbot** (10×)
- **proxy** (10×)
- **sixsayven** (10×)
- **unknown** (10×)
- **RemcosRAT** (8×)
- **RAT** (7×)
- **upx-dec** (6×)
- **upx** (6×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +11 (23→34)
- ↓ **unbekannt** -18 (36→18)
- neu: **RemcosRAT** (8)
- neu: **VShell** (6)
- ↑ **SalatStealer** +3 (3→6)
- neu: **Formbook** (5)
- neu: **AgentTesla** (5)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **PhantomStealer** (2)
- neu: **NanoCore** (2)
- weg: **SilentNet** (war 7)
- weg: **LegionLoader** (war 6)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +9 (25→34)
- ↓ **unbekannt** -9 (27→18)
- ↑ **RemcosRAT** +6 (2→8)
- neu: **VShell** (6)
- ↓ **SalatStealer** -7 (13→6)
- ↑ **Formbook** +3 (2→5)
- ↑ **AgentTesla** +4 (1→5)
- neu: **ValleyRAT** (2)
- neu: **PhantomStealer** (2)
- neu: **NanoCore** (2)
- weg: **SilentNet** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.375 MB |
| σ Dateigröße | 6.129 MB |
| Ø Risiko-Score | 69.6/100 |
| Ø Klassifikations-Konfidenz | 74.2% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 49/100 |
| Eindeutige Familien | 20 |
| Eindeutige Tags | 67 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 09:00 | [84fac1d9c9d8…](https://bazaar.abuse.ch/sample/84fac1d9c9d83182fa6428365907f7fbeb4c621eb7eb2b2a0140fdcd245b20e9/) | `elf` | unbekannt | 43.4 | – | – | 🌐CA |
| 08:57 | [d7c37383870d…](https://bazaar.abuse.ch/sample/d7c37383870dfc0df21ab05739f426ff452eac860a7286601244861468bc9e15/) | `exe` | unbekannt | 39.1 | – | – | 🌐CH |
| 08:50 | [ad3c80ea9430…](https://bazaar.abuse.ch/sample/ad3c80ea9430278dae35e4c5fd8656e1dc577f6d53c6ea4242b72f6a1f42c5c8/) | `js` | RemcosRAT | 89.6 | – | – | 🇳🇱NL |
| 08:47 | [a9859c49d20b…](https://bazaar.abuse.ch/sample/a9859c49d20baf131d1e9253acb0118fac412acaa97938d87c7c8daa7554cd54/) | `apk` | unbekannt | 75.9 | – | – | 🌐IT |
| 08:47 | [f1d4de01de1e…](https://bazaar.abuse.ch/sample/f1d4de01de1e6de618539e9bb2e149374924cadd33554ec18f2c68e7e2c632f2/) | `sh` | unbekannt | 75.9 | – | – | 🌐IT |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 02.11.2026 09:01 UTC*