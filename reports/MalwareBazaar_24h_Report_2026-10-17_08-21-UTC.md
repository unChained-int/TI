# MalwareBazaar – 17.10.2026 08:21 UTC

Dieser Run hat **83 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **84** |
| Kritisch (≥75) | **59** |
| Höchster Score | **88.4/100** – 7f98634c81ada016… |
| Häufigste Familie | **Mirai** (49x) |
| Häufigster Typ | **elf** (62x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 51 Samples |
| Ø Dateigröße | 0.98 MB (σ=2.79) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 62 | 73.8%  ██████████████ |
| `exe` | 15 | 17.9%  ███ |
| `jar` | 2 | 2.4%   |
| `sh` | 2 | 2.4%   |
| `dll` | 2 | 2.4%   |
| `msi` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 49 | 58.3% |
| 2 | unbekannt | 26 | 31.0% |
| 3 | ConnectWise | 3 | 3.6% |
| 4 | RemcosRAT | 2 | 2.4% |
| 5 | Application | 1 | 1.2% |
| 6 | NanoCore | 1 | 1.2% |
| 7 | Adware.Generic | 1 | 1.2% |
| 8 | Trojan ( 006e7d7c1 ) | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 49 | 58.3% | 95% |
| Linux-Malware | 12 | 14.3% | 45% |
| Infostealer | 8 | 9.5% | 75% |
| Windows-Malware | 7 | 8.3% | 35% |
| Andere / Unbekannt | 4 | 4.8% | 20% |
| RAT | 3 | 3.6% | 95% |
| Cryptominer | 1 | 1.2% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 70.2% |
| 🟠 HOCH | 2 | 2.4% |
| 🟡 MITTEL | 19 | 22.6% |
| 🟢 NIEDRIG | 4 | 4.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7f98634c81ada0…](https://bazaar.abuse.ch/sample/7f98634c81ada016093032eec6aca74bc1c72be595a660b2a54a8528934afa2d/) | RemcosRAT | RAT | **88.4** | 🔴 KRITISCH | – | – | ? |
| [f9ec15f5b5115f…](https://bazaar.abuse.ch/sample/f9ec15f5b5115f2c81426e36f82f155bd174493d12cf535eec06613d62e9ec94/) | NanoCore | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [35f673c8c63948…](https://bazaar.abuse.ch/sample/35f673c8c639480ff5826e699b0e8b1be5265b036070e69037547cade40f746d/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [80b1b417dd06b5…](https://bazaar.abuse.ch/sample/80b1b417dd06b5903373ae4e328fe4087c439d03356033d06145207f6e274ba3/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [28ed14b299fae3…](https://bazaar.abuse.ch/sample/28ed14b299fae35342512a842aef6c5f892e230f216a90332b3adeb1242c9606/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [a78f71a0b7e820…](https://bazaar.abuse.ch/sample/a78f71a0b7e820cf410576f16b77f601020813a416b6ac5f805d62fd5f56d6fd/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [d70a253f0142cb…](https://bazaar.abuse.ch/sample/d70a253f0142cb957b33698f84ff4f7b3ff11239aeb7063aee8853a17347e129/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [550f69bbb009c7…](https://bazaar.abuse.ch/sample/550f69bbb009c7259fbe33e76f002343787cf86c9631380545feafff6ec8bc28/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [3d538238f57dae…](https://bazaar.abuse.ch/sample/3d538238f57dae3a0592ab63f39d9ae61b6b70c8488b80e9e877d46d24e5f7aa/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [c6a3f36b19a89f…](https://bazaar.abuse.ch/sample/c6a3f36b19a89f245c55c5350464854e549b9a699248c80ec402a50d75a1fea8/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6013/7435 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6013/7435 |
| 3 | ESET-NOD32 | 77.4% | 5755/7435 |
| 4 | Kaspersky | 76.4% | 5676/7434 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5313/7432 |
| 8 | Rising | 68.7% | 5109/7435 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4934/7431 |
| 11 | Tencent | 65.3% | 4707/7209 |
| 12 | Avast | 65.1% | 4839/7431 |
| 13 | AVG | 65.1% | 4839/7430 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4553/7428 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 64 | 76.2% |
| 🪟 Windows | 18 | 21.4% |
| ❓ Unbekannt | 2 | 2.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 94.0% |
| MaaS-Loader | 4 | 4.8% |
| Trojanisierte Software | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 39 | 46.4% |
| 2 | 🇺🇸 US | 20 | 23.8% |
| 3 | 🇦🇹 AT | 10 | 11.9% |
| 4 | 🇷🇴 RO | 7 | 8.3% |
| 5 | 🇳🇱 NL | 7 | 8.3% |
| 6 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 51 von 84 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 49 |
| Lateral Movement | 49 |
| Command and Control | 2 |
| Collection | 2 |

<details><summary>7f98634c81ada0160930… – RemcosRAT | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>35f673c8c639480ff582… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>80b1b417dd06b5903373… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>28ed14b299fae3534251… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [eac9effad47b9fdb65ff…](https://bazaar.abuse.ch/sample/eac9effad47b9fdb65ff2bc500d68a97ebfd90b68423faa674fe5e4114bac6f3/)

- **Familie:** Application
- **Erkannt von:** 32 von 75 Engines (42.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Application.Linux.Miner.3
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.Linux.Miner.3`

**Erkennende Engines (32/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Linux.Miner.3` |
| AVG | `ELF:BitCoinMiner-HF [Trj]` |
| AhnLab-V3 | `Linux/CoinMiner.Gen2` |
| Antiy-AVL | `Trojan[Miner]/Linux.CoinMiner.k` |
| Arcabit | `Trojan.Application.Linux.Miner.3` |
| Avast | `ELF:BitCoinMiner-HF [Trj]` |
| Avast-Mobile | `ELF:Miner-RD [PUP]` |
| Avira | `TR/LINUX.BitCoinMi.HF` |
| BitDefender 🛡️ | `Gen:Variant.Application.Linux.Miner.3` |
| CTX | `elf.miner.generic` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Tool.Linux.BtcMine.4897` |
| ESET-NOD32 | `Linux/CoinMiner.BK potentially unwanted application` |
| Elastic | `Linux.Cryptominer.Camelot` |
| Emsisoft | `Gen:Variant.Application.Linux.Miner.3 (B)` |
| F-Secure | `Trojan.TR/LINUX.BitCoinMi.HF` |
| Fortinet | `ELF/BitCoinMiner.HF!tr` |
| GData | `Gen:Variant.Application.Linux.Miner.3` |
| Kaspersky | `not-a-virus:HEUR:RiskTool.Linux.Miner.gen` |
| Kingsoft | `Win32.HACKTOOL.Miner.v` |
| MicroWorld-eScan | `Gen:Variant.Application.Linux.Miner.3` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner.C12` |
| Rising | `HackTool.XMRMiner!1.FD0F (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Risktool.Linux.Miner.nf` |
| TrendMicro | `Coinminer.Linux.MALXMR.SMDSL32` |
| TrendMicro-HouseCall | `Coinminer.Linux.MALXMR.SMDSL32` |
| VIPRE | `Gen:Variant.Application.Linux.Miner.3` |
| alibabacloud | `Miner:Multi/XMRig` |
| huorong | `HackTool/Linux.CoinMiner.a!crit` |

### [c795068c16610acaabba…](https://bazaar.abuse.ch/sample/c795068c16610acaabba8520b457d364b353e50fae29dc2080d0f27aaeae6539/)

- **Familie:** Mirai
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| GData | `Linux.Trojan-DDoS.Lightaidra.A` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B2 (CLASSIC)` |
| huorong | `Trojan/Linux.Mirai.l` |

### [67c3e1ac1213b0b3caff…](https://bazaar.abuse.ch/sample/67c3e1ac1213b0b3caff36b55e5042bbf450f850ac0025e1475763afeee5a01d/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Arcabit | `Trojan.Linux.Cling.1` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.trojan.cling` |
| ClamAV | `Unix.Trojan.Mirai-10056451-0` |
| DrWeb | `Linux.Siggen.14629` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mt` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| alibabacloud | `DDoS:Linux/Mirai.mn` |

### [7aa8a13432f1999f3780…](https://bazaar.abuse.ch/sample/7aa8a13432f1999f37809e8576ea7e442d57e1902e991d11dedbfbdfc156a3de/)

- **Familie:** Trojan ( 006e7d7c1 )
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 006e7d7c1 )
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R801231` |
| Antiy-AVL | `Trojan/Win64.Kryptik` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.1050F761` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/Kryptik_AGen.AUA trojan` |
| Elastic | `malicious (moderate confidence)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| K7AntiVirus | `Trojan ( 006e7d7c1 )` |
| K7GW | `Trojan ( 006e7d7c1 )` |
| Kaspersky | `Trojan.Win64.Agentb.lmvp` |
| Trapmine | `malicious.high.ml.score` |

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

- **elf** (48×)
- **Mirai** (47×)
- **exe** (13×)
- **stealer** (8×)
- **unpacked** (8×)
- **WardenStealer** (8×)
- **YapStealer** (8×)
- **upx-dec** (5×)
- **upx** (5×)
- **Gafgyt** (5×)
- **dropped-by-OffLoader** (4×)
- **ConnectWise** (3×)
- **signed** (3×)
- **jar** (2×)
- **java** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +31 (18→49)
- ↓ **unbekannt** -5 (31→26)
- ↑ **ConnectWise** +2 (1→3)
- neu: **Application** (1)
- neu: **NanoCore** (1)
- neu: **Adware.Generic** (1)
- neu: **Trojan ( 006e7d7c1 )** (1)
- weg: **Formbook** (war 2)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +19 (30→49)
- ↓ **unbekannt** -1 (27→26)
- ↑ **ConnectWise** +2 (1→3)
- neu: **Application** (1)
- neu: **NanoCore** (1)
- neu: **Adware.Generic** (1)
- neu: **Trojan ( 006e7d7c1 )** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.976 MB |
| σ Dateigröße | 2.788 MB |
| Ø Risiko-Score | 70.2/100 |
| Ø Klassifikations-Konfidenz | 77.0% |
| Samples mit VT | 5/84 |
| Samples mit MITRE | 51/84 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 27 |
| Unbekannte Familien | 4 (4.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:14 | [ebc670c78771…](https://bazaar.abuse.ch/sample/ebc670c78771f5d01e4ad2fbe072027db9dab1f87968c2ef5e195f409ee6ed4f/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 08:13 | [b8a45651efea…](https://bazaar.abuse.ch/sample/b8a45651efea3e24d4e9c1ba578927feea4606072f819845ed7748c095735e50/) | `exe` | unbekannt | 39.0 | – | – | 🌐RO |
| 08:12 | [c07b77aa52aa…](https://bazaar.abuse.ch/sample/c07b77aa52aafd8c5f7b186757c54cf02053a8d7f7b7cb0e09239ea1c72697fb/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 08:10 | [525f28b2105f…](https://bazaar.abuse.ch/sample/525f28b2105f8c1cd58f3c869baa983e1ad74a1cbcf19df2e3b7c4f9972e91f8/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 08:04 | [35f673c8c639…](https://bazaar.abuse.ch/sample/35f673c8c639480ff5826e699b0e8b1be5265b036070e69037547cade40f746d/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 08:21 UTC*