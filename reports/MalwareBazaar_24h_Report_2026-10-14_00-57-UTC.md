# MalwareBazaar – 14.10.2026 00:57 UTC

Dieser Run hat **42 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **43** |
| Kritisch (≥75) | **25** |
| Höchster Score | **88.8/100** – a1efcf4e1c2ee9a4… |
| Häufigste Familie | **Mirai** (19x) |
| Häufigster Typ | **elf** (22x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 4.65 MB (σ=11.57) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 22 | 51.2%  ██████████ |
| `exe` | 14 | 32.6%  ██████ |
| `macho` | 4 | 9.3%  █ |
| `js` | 2 | 4.7%   |
| `vbs` | 1 | 2.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 19 | 44.2% |
| 2 | unbekannt | 16 | 37.2% |
| 3 | AMOS | 2 | 4.7% |
| 4 | ValleyRAT | 1 | 2.3% |
| 5 | SalatStealer | 1 | 2.3% |
| 6 | CoinMiner | 1 | 2.3% |
| 7 | Prometei | 1 | 2.3% |
| 8 | ConnectWise | 1 | 2.3% |
| 9 | RemcosRAT | 1 | 2.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 19 | 44.2% | 95% |
| Windows-Malware | 6 | 14.0% | 35% |
| Loader | 5 | 11.6% | 75% |
| Skript/Dropper | 3 | 7.0% | 35% |
| Linux-Malware | 3 | 7.0% | 45% |
| Infostealer | 3 | 7.0% | 88% |
| RAT | 2 | 4.7% | 85% |
| Andere / Unbekannt | 1 | 2.3% | 20% |
| Trojaner | 1 | 2.3% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 25 | 58.1% |
| 🟠 HOCH | 5 | 11.6% |
| 🟡 MITTEL | 12 | 27.9% |
| 🟢 NIEDRIG | 1 | 2.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a1efcf4e1c2ee9…](https://bazaar.abuse.ch/sample/a1efcf4e1c2ee9a4a887ec9208a7f69c0bc360677db147161cad1e54520780fd/) | AMOS | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [d1ddc006dd617b…](https://bazaar.abuse.ch/sample/d1ddc006dd617bbbde3900096129eb1544aaeeb43e6618023d7bab4c8c125a9d/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [790a894bb0f999…](https://bazaar.abuse.ch/sample/790a894bb0f9991f03c6a28c0a7edbdf87e3fcd1d799dc008831ceaf28356401/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [a492874bc7c116…](https://bazaar.abuse.ch/sample/a492874bc7c1168420e2b05b3551cfd688b237746fc5a17e42cdfb6996ffe19c/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [c4354c0820ad6f…](https://bazaar.abuse.ch/sample/c4354c0820ad6fa70541c1ad9ad80eceecd363dbde86ab8a05d295fa97618306/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [d28ca3a85b535c…](https://bazaar.abuse.ch/sample/d28ca3a85b535cb6dd70fe2c1d4931c3b74ee06bc4aef03cbd65169e234492d2/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [7b77fb4e603b09…](https://bazaar.abuse.ch/sample/7b77fb4e603b09807d59473897d7ca8880697a31bc93b702fae63324077cb798/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [a1e934b757fed4…](https://bazaar.abuse.ch/sample/a1e934b757fed45fd8375307543385366f53ad33d36aa3f29cc684a87077d941/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [8c862ddc08f540…](https://bazaar.abuse.ch/sample/8c862ddc08f5409694f0f474dcfb97cc7a5c08cf2b298220224cd9de02b324e7/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [132667205ebc62…](https://bazaar.abuse.ch/sample/132667205ebc62af108648fcf4df97efc56960fdc71ac5485bc6ccd546260c99/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5950/7356 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5950/7356 |
| 3 | ESET-NOD32 | 77.4% | 5695/7356 |
| 4 | Kaspersky | 76.4% | 5616/7355 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5264/7353 |
| 8 | Rising | 68.7% | 5056/7356 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4885/7352 |
| 11 | Tencent | 65.3% | 4655/7130 |
| 12 | Avast | 65.0% | 4781/7352 |
| 13 | AVG | 65.0% | 4781/7351 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4508/7349 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 22 | 51.2% |
| 🪟 Windows | 15 | 34.9% |
| 🍎 macOS | 4 | 9.3% |
| ❓ Unbekannt | 2 | 4.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 34 | 79.1% |
| C2 / Nachladen | 5 | 11.6% |
| Drive-By / Exploit-Kit | 2 | 4.7% |
| MaaS-Loader | 2 | 4.7% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 22 | 51.2% |
| 2 | 🇳🇱 NL | 11 | 25.6% |
| 3 | 🇩🇪 DE | 5 | 11.6% |
| 4 | 🇨🇭 CH | 3 | 7.0% |
| 5 | 🇫🇷 FR | 1 | 2.3% |
| 6 | 🌐 Unbekannt | 1 | 2.3% |

## MITRE ATT&CK

> 21 von 43 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 19 |
| Lateral Movement | 19 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>790a894bb0f9991f03c6… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a492874bc7c1168420e2… – Mirai | 🔴 KRITISCH 82.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c4354c0820ad6fa70541… – Mirai | 🔴 KRITISCH 82.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ac04d6f242b026ee7be4…](https://bazaar.abuse.ch/sample/ac04d6f242b026ee7be404dd99a0d09564b1c74eb7e453401dc2c15b680bad05/)

- **Familie:** CoinMiner
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.CoinMiner.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (moderate confidence)` |
| Ikarus | `PUA.CoinMiner` |
| Kaspersky | `HEUR:Trojan.Win64.Generic` |
| Kingsoft | `Win64.Trojan.Generic.a` |
| Lionic | `Trojan.Win32.CoinMiner.4!c` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Paloalto | `generic.ml` |
| huorong | `HackTool/CoinMiner.w` |

### [9dd4010135c9569e93c8…](https://bazaar.abuse.ch/sample/9dd4010135c9569e93c8936761b574c40b99832182657709fe0e6097d0cf549b/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BDU [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BDU [Trj]` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-BDU [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.BDU` |
| ClamAV | `Unix.Trojan.Mirai-7100807-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9770` |
| ESET-NOD32 | `Linux/Mirai.WJ trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BDU` |
| Fortinet | `ELF/Moobot.A!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| Varist | `E32/Mirai.J.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.kz` |

### [4bf406172374a1ee8a9b…](https://bazaar.abuse.ch/sample/4bf406172374a1ee8a9b3feb09edabf2e7db056d599c33fbc690eace66f0a9a8/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2021-36260-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2021-36260-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2021-36260-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2021-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10760` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2021-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Trojan/Linux.Mirai.f` |

### [6fb97a2c7104a0da9524…](https://bazaar.abuse.ch/sample/6fb97a2c7104a0da95241868e4bf190162f91d444c070520555e52accde27c9f/)

- **Familie:** ConnectWise
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** RemoteTool ( 005d29b61 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Alibaba | `RiskWare:Win32/Screcwon.43dd1224` |
| Cylance | `Unsafe` |
| DrWeb | `Program.RemoteAdmin.975` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.Q potentially unsafe application` |
| Google | `Detected` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `RemoteTool ( 005d29b61 )` |
| K7GW | `RemoteTool ( 005d29b61 )` |
| Kaspersky | `not-a-virus:HEUR:RemoteAdmin.Win32.ConnectWise.gen` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Riskware.Win32.ConnectWise.1!c` |
| MaxSecure | `Trojan.Malware.331091061.susgen` |
| NANO-Antivirus | `Riskware.Win32.RemoteAdmin.ljylbz` |
| Rising | `Hacktool.ConnectWiseControl!8.17790 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.AB.gen!Eldorado` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| huorong | `HackTool/ConnectWiseControl.i` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (63/75):**

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
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| Zillya | `Trojan.Rescoms.Win32.2903` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (20×)
- **Mirai** (19×)
- **exe** (13×)
- **upx-dec** (7×)
- **upx** (7×)
- **ClickFix** (4×)
- **Foxveil** (4×)
- **macho** (4×)
- **macOS** (4×)
- **dropped-by-GCleaner** (4×)
- **AMOS** (3×)
- **Mach-O** (3×)
- **js** (2×)
- **loader** (2×)
- **A** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -23 (42→19)
- ↓ **unbekannt** -17 (33→16)
- ↓ **ValleyRAT** -1 (2→1)
- ↓ **SalatStealer** -1 (2→1)
- ↓ **CoinMiner** -1 (2→1)
- neu: **Prometei** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -21 (40→19)
- ↓ **unbekannt** -13 (29→16)
- neu: **AMOS** (2)
- neu: **SalatStealer** (1)
- neu: **Prometei** (1)
- ↓ **ConnectWise** -1 (2→1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.648 MB |
| σ Dateigröße | 11.570 MB |
| Ø Risiko-Score | 67.4/100 |
| Ø Klassifikations-Konfidenz | 73.3% |
| Samples mit VT | 5/43 |
| Samples mit MITRE | 21/43 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 31 |
| Unbekannte Familien | 1 (2.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:53 | [790a894bb0f9…](https://bazaar.abuse.ch/sample/790a894bb0f9991f03c6a28c0a7edbdf87e3fcd1d799dc008831ceaf28356401/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 00:51 | [ffe464e18a80…](https://bazaar.abuse.ch/sample/ffe464e18a80c72f24ef569f838052cea48eaf98ce383b603aadf55ce59be858/) | `vbs` | unbekannt | 39.0 | – | – | 🌐CH |
| 00:48 | [fe797609cfa7…](https://bazaar.abuse.ch/sample/fe797609cfa79302b8bc937b2cf996510fcee26146c54b59614daef3ed59aeef/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 00:39 | [c09eae9edbc7…](https://bazaar.abuse.ch/sample/c09eae9edbc74e13ad4613ccad95330959b48d54d768dbad6f35507d1beb9ea6/) | `elf` | unbekannt | 43.1 | – | – | 🇩🇪DE |
| 00:31 | [3bfd259546c9…](https://bazaar.abuse.ch/sample/3bfd259546c9746ae49fbf47a478a231d0f96dc6aadc2cdfd7f24753a1c54d92/) | `macho` | unbekannt | 32.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.10.2026 00:57 UTC*