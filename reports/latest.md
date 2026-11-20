# MalwareBazaar – 20.11.2026 12:37 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **66** |
| Höchster Score | **89.9/100** – 8aa30c2a1ac9efb9… |
| Häufigste Familie | **Mirai** (45x) |
| Häufigster Typ | **elf** (51x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 57 Samples |
| Ø Dateigröße | 1.29 MB (σ=4.77) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 51 | 50.5%  ██████████ |
| `js` | 24 | 23.8%  ████ |
| `vbs` | 18 | 17.8%  ███ |
| `apk` | 5 | 5.0%   |
| `zip` | 1 | 1.0%   |
| `vbe` | 1 | 1.0%   |
| `exe` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 45 | 44.6% |
| 2 | unbekannt | 29 | 28.7% |
| 3 | Prometei | 6 | 5.9% |
| 4 | AsyncRAT | 6 | 5.9% |
| 5 | AgentTesla | 4 | 4.0% |
| 6 | RemcosRAT | 3 | 3.0% |
| 7 | Formbook | 1 | 1.0% |
| 8 | F04IE00KK26 | 1 | 1.0% |
| 9 | VBS | 1 | 1.0% |
| 10 | Artemis!Trojan | 1 | 1.0% |
| 11 | XWorm | 1 | 1.0% |
| 12 | AveMariaRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 45 | 44.6% | 95% |
| Skript/Dropper | 27 | 26.7% | 35% |
| RAT | 12 | 11.9% | 93% |
| Trojaner | 7 | 6.9% | 71% |
| Linux-Malware | 6 | 5.9% | 45% |
| Infostealer | 3 | 3.0% | 88% |
| Android-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 66 | 65.3% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 34 | 33.7% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8aa30c2a1ac9ef…](https://bazaar.abuse.ch/sample/8aa30c2a1ac9efb951410643ef3164e0bc76bf15c80649969343d2c1b9b53a9b/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [5022ffb94ae19c…](https://bazaar.abuse.ch/sample/5022ffb94ae19cd33032856267b46d2bc90933c5dad82a1cb19c2a45817f8691/) | FormBook | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [cbf2bfed7ac956…](https://bazaar.abuse.ch/sample/cbf2bfed7ac956648512d56836545f07dabe3e3794ef114516d4148b137f5de8/) | XWorm | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [4a10ce086908c0…](https://bazaar.abuse.ch/sample/4a10ce086908c05ddfe51bde268b29badd8e840a00283401a1118a67f5787d72/) | AsyncRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [30ff48b30a0d5b…](https://bazaar.abuse.ch/sample/30ff48b30a0d5bc52f97aa596ee346d5d851642fdc7fcead9ffa7c56cfdbf489/) | RemcosRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [117e1398748fb7…](https://bazaar.abuse.ch/sample/117e1398748fb7bebd1c8b0ae382d03e200653f08921789263a20ee7fc84f8b5/) | AsyncRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [21fce2ad2a7f95…](https://bazaar.abuse.ch/sample/21fce2ad2a7f956bfbc76c26fd3cbe8d830a6eec0044f234f3b73cc247bdf717/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [28f5352fd55689…](https://bazaar.abuse.ch/sample/28f5352fd556897652f11a392b1eb29ae6d8bf33071caa95f369c5639636caa7/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [ab30e3627d1a78…](https://bazaar.abuse.ch/sample/ab30e3627d1a786ee152810114dd8b2e5ed583cb114ed003924edd4212b1ed3d/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [fc2f01b3de460c…](https://bazaar.abuse.ch/sample/fc2f01b3de460c6d9d0c99fdcedf5af5582606289798bbdffaff802317ceb18f/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6548/8070 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6548/8070 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6246/8070 |
| 6 | Kaspersky | 75.6% | 6099/8069 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5753/8066 |
| 9 | Rising | 68.5% | 5531/8070 |
| 10 | Varist | 66.1% | 5333/8065 |
| 11 | Tencent | 65.2% | 5112/7844 |
| 12 | Avast | 65.2% | 5262/8066 |
| 13 | AVG | 65.2% | 5262/8065 |
| 14 | McAfeeD | 61.5% | 4962/8062 |
| 15 | huorong | 61.0% | 4914/8062 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 51 | 50.5% |
| ❓ Unbekannt | 25 | 24.8% |
| 🪟 Windows | 19 | 18.8% |
| 🤖 Android | 5 | 5.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 72 | 71.3% |
| Drive-By / Exploit-Kit | 24 | 23.8% |
| APK-Sideloading | 5 | 5.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 51 | 50.5% |
| 2 | 🇫🇷 FR | 43 | 42.6% |
| 3 | 🌐 UZ | 4 | 4.0% |
| 4 | 🇺🇸 US | 1 | 1.0% |
| 5 | 🇯🇵 JP | 1 | 1.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 57 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 45 |
| Lateral Movement | 45 |
| Command and Control | 10 |
| Collection | 6 |
| Execution | 6 |
| Credential Access | 2 |

<details><summary>8aa30c2a1ac9efb95141… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>5022ffb94ae19cd33032… – FormBook | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4a10ce086908c05ddfe5… – AsyncRAT | 🔴 KRITISCH 88.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>30ff48b30a0d5bc52f97… – RemcosRAT | 🔴 KRITISCH 88.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [1094a8458e976f5719b6…](https://bazaar.abuse.ch/sample/1094a8458e976f5719b667f3bd22eaa605fa96488401560520a4843af059e22a/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 73 Engines (30.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/73):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [c663630c869213533b75…](https://bazaar.abuse.ch/sample/c663630c869213533b7518d908cf1d0a63141e6f40c0077b37960c883635dcf3/)

- **Familie:** F04IE00KK26
- **Erkannt von:** 8 von 73 Engines (11.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** TROJ_GEN.F04IE00KK26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/CloudEye.RE trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `UDS:Trojan.VBS.SAgent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| TrendMicro | `TROJ_GEN.F04IE00KK26` |
| TrendMicro-HouseCall | `TROJ_GEN.F04IE00KK26` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

### [d358892ee93cb6101cdb…](https://bazaar.abuse.ch/sample/d358892ee93cb6101cdbd04b9310b054a3466ed4a73fcca2d12aa930d9e418f0/)

- **Familie:** VBS
- **Erkannt von:** 3 von 74 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** UDS:Trojan.VBS.SAgent.gen
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `UDS:Trojan.VBS.SAgent.gen` |

### [233b42590ffdc66b07a0…](https://bazaar.abuse.ch/sample/233b42590ffdc66b07a0c711d158050a0e2935eab8d07231d7c5353f4220ba92/)

- **Familie:** Artemis!Trojan
- **Erkannt von:** 8 von 73 Engines (11.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Artemis!Trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/CloudEye.RE trojan` |
| GData | `Script.Trojan.Agent.NIA365` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `UDS:Trojan.VBS.SAgent.gen` |
| Skyhigh | `Artemis!Trojan` |
| Symantec | `Trojan.Gen.NPE` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **elf** (51×)
- **Mirai** (45×)
- **Torii** (41×)
- **js** (24×)
- **vbs** (18×)
- **RAT** (8×)
- **Prometei** (6×)
- **AsyncRAT** (6×)
- **apk** (5×)
- **AgentTesla** (4×)
- **Banker** (4×)
- **EVANGELION** (4×)
- **signed** (4×)
- **Uzbekistan** (4×)
- **wretchedcat** (4×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -6 (51→45)
- ↑ **unbekannt** +7 (22→29)
- ↑ **Prometei** +1 (5→6)
- ↑ **AsyncRAT** +5 (1→6)
- neu: **AgentTesla** (4)
- ↑ **RemcosRAT** +2 (1→3)
- neu: **Formbook** (1)
- neu: **F04IE00KK26** (1)
- neu: **VBS** (1)
- neu: **Artemis!Trojan** (1)
- weg: **WARDENStealer** (war 6)
- weg: **SalatStealer** (war 5)
- weg: **VShell** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +6 (39→45)
- ↑ **unbekannt** +6 (23→29)
- ↑ **Prometei** +3 (3→6)
- ↑ **AsyncRAT** +5 (1→6)
- ↑ **AgentTesla** +2 (2→4)
- neu: **F04IE00KK26** (1)
- neu: **VBS** (1)
- neu: **Artemis!Trojan** (1)
- weg: **WARDENStealer** (war 5)
- weg: **SalatStealer** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.285 MB |
| σ Dateigröße | 4.769 MB |
| Ø Risiko-Score | 69.0/100 |
| Ø Klassifikations-Konfidenz | 73.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 57/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 29 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:35 | [edabf4110316…](https://bazaar.abuse.ch/sample/edabf41103164ae85fabd5f4d60959583e2a61343b88e2dc64a68677d57030ce/) | `zip` | unbekannt | 82.2 | – | – | 🇺🇸US |
| 12:10 | [2f0804a35b95…](https://bazaar.abuse.ch/sample/2f0804a35b954e3015e41de2e4b5aa18f06cacb7f7bb8f2999956608a4b358fc/) | `apk` | unbekannt | 43.0 | – | – | 🌐JP |
| 12:05 | [fe7a4db4805e…](https://bazaar.abuse.ch/sample/fe7a4db4805e2ac2b88b96c0d76a1147c8991509a176183db0b7341cd5bde359/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 12:04 | [f47e46d88682…](https://bazaar.abuse.ch/sample/f47e46d88682d43f62b6bb03eb87afd875b4d8eb037352aa3dc14344ff49ea72/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 12:03 | [834aa98da770…](https://bazaar.abuse.ch/sample/834aa98da77013151fce63d96afdb9387aa2acc285d2888e01ecbe310621a09e/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.11.2026 12:37 UTC*