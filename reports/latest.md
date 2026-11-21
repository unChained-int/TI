# MalwareBazaar – 21.11.2026 20:25 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **78** |
| Höchster Score | **88.5/100** – dedfde9e078a7ce4… |
| Häufigste Familie | **Mirai** (53x) |
| Häufigster Typ | **elf** (82x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 56 Samples |
| Ø Dateigröße | 2.82 MB (σ=11.38) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 82 | 81.2%  ████████████████ |
| `exe` | 9 | 8.9%  █ |
| `macho` | 6 | 5.9%  █ |
| `jar` | 2 | 2.0%   |
| `ps1` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 53 | 52.5% |
| 2 | unbekannt | 32 | 31.7% |
| 3 | Prometei | 6 | 5.9% |
| 4 | SilentNet | 2 | 2.0% |
| 5 | njrat | 2 | 2.0% |
| 6 | CatStorm | 2 | 2.0% |
| 7 | Trojan.GenericKD.82216314 | 1 | 1.0% |
| 8 | RustyStealer | 1 | 1.0% |
| 9 | RemcosRAT | 1 | 1.0% |
| 10 | SMLBR4 | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 54 | 53.5% | 94% |
| RAT | 24 | 23.8% | 78% |
| Linux-Malware | 13 | 12.9% | 45% |
| Windows-Malware | 4 | 4.0% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Trojaner | 1 | 1.0% | 65% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Infostealer | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 78 | 77.2% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 18 | 17.8% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [dedfde9e078a7c…](https://bazaar.abuse.ch/sample/dedfde9e078a7ce495aae711fb71c1c1eb1cb01c96bf1b29e1dc62b78b7a3d53/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [f5b4aeedf5abe3…](https://bazaar.abuse.ch/sample/f5b4aeedf5abe38673a221b65a5d0b1c1db9a3a5a4518efbfb4e539539f4a6ef/) | njrat | RAT | **88.4** | 🔴 KRITISCH | – | – | ? |
| [47e8f5413ce9d9…](https://bazaar.abuse.ch/sample/47e8f5413ce9d9b072da198e8eb5d2a9bcb5c7bc80b0058aeef9f32051d39276/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [4781d91f14c43c…](https://bazaar.abuse.ch/sample/4781d91f14c43cee9663eff5f80cd4bc00bdd7dbea0486aa7773a0bfecbf9bea/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [fd822189b15793…](https://bazaar.abuse.ch/sample/fd822189b1579331813294572335bfc1619fcbaa26a08614ddbc872d7074cf39/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [11b8a87847eb99…](https://bazaar.abuse.ch/sample/11b8a87847eb99b358a8d2eef712167a277396a1da251e91147d67d3c75482df/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [c083531e41575c…](https://bazaar.abuse.ch/sample/c083531e41575c9ee3a92f519b3ae61d932e9b68a7c84ff67d16ab270cd54718/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [22179c5cdce92d…](https://bazaar.abuse.ch/sample/22179c5cdce92d71fb1e9d522ac53212600359d71174d6753f1a4b57697b7eee/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [fefaca1dfa42ab…](https://bazaar.abuse.ch/sample/fefaca1dfa42ab57916670b739a2e6faa16f14a05ce97d04b50235bdcae9f858/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [ff70b432b683eb…](https://bazaar.abuse.ch/sample/ff70b432b683ebdb6b43b582cda8912a61002a02c6cd778a65e6baff296fac63/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6563/8088 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6563/8088 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6259/8088 |
| 6 | Kaspersky | 75.6% | 6112/8087 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5764/8084 |
| 9 | Rising | 68.5% | 5543/8088 |
| 10 | Varist | 66.1% | 5343/8083 |
| 11 | Tencent | 65.2% | 5125/7862 |
| 12 | Avast | 65.2% | 5272/8084 |
| 13 | AVG | 65.2% | 5272/8083 |
| 14 | McAfeeD | 61.5% | 4972/8080 |
| 15 | huorong | 61.0% | 4925/8080 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 90 | 89.1% |
| 🪟 Windows | 9 | 8.9% |
| ❓ Unbekannt | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 52 | 51.5% |
| 2 | 🇺🇸 US | 24 | 23.8% |
| 3 | 🇸🇬 SG | 15 | 14.9% |
| 4 | 🇫🇷 FR | 5 | 5.0% |
| 5 | 🇷🇴 RO | 2 | 2.0% |
| 6 | 🇨🇭 CH | 1 | 1.0% |
| 7 | 🇳🇱 NL | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 56 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 53 |
| Lateral Movement | 53 |
| Command and Control | 3 |
| Collection | 3 |

<details><summary>dedfde9e078a7ce495aa… – RemcosRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>f5b4aeedf5abe38673a2… – njrat | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>47e8f5413ce9d9b072da… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4781d91f14c43cee9663… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>fd822189b15793318132… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [776ba1cf1aa94fb8d93e…](https://bazaar.abuse.ch/sample/776ba1cf1aa94fb8d93ef8a2bdda79c08124998f80e021a26a50ca46ef26b4fd/)

- **Familie:** Trojan.GenericKD.82216314
- **Erkannt von:** 39 von 74 Engines (52.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82216314
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82216314`

**Erkennende Engines (39/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82216314` |
| AVG | `Other:Malware-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R808482` |
| Arcabit | `Trojan.Generic.D4E6857A` |
| Avast | `Other:Malware-gen [Trj]` |
| Avira | `TR/Malware` |
| BitDefender 🛡️ | `Trojan.GenericKD.82216314` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Packed.CAB.BZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.82216314 (B)` |
| F-Secure | `Trojan.TR/Malware` |
| GData | `Win64.Trojan.Agent.A62P1A` |
| Google | `Detected` |
| Ikarus | `Trojan.Malware` |
| Kaspersky | `Trojan.Win32.Autoit.adilu` |
| Kingsoft | `Win32.Trojan.Autoit.adilu` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| McAfeeD | `Trojan:Win/SuspiciousAutoit.A` |
| MicroWorld-eScan | `Trojan.GenericKD.82216314` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Autoit!8.150 (CLOUD)` |
| Sangfor | `Trojan.Win32.Autoit.Vtwm` |
| Skyhigh | `BehavesLike.Win64.Dropper.wz` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.Autoit.Pqil` |
| TrellixENS | `Artemis!04FFA4FBAB96` |
| TrendMicro | `TrojanSpy.Win64.ACRSTEALER.YXGKRZ` |
| TrendMicro-HouseCall | `TrojanSpy.Win64.ACRSTEALER.YXGKRZ` |
| VIPRE | `Trojan.GenericKD.82216314` |
| Varist | `W64/ABTrojan.EGEV-1213` |
| Zillya | `Backdoor.Agent.Win32.102378` |
| alibabacloud | `VirTool:Win/Wacatac.B9nj` |

### [7114558e776ed34023fa…](https://bazaar.abuse.ch/sample/7114558e776ed34023fa7566c26be2f34f153a738b4b60a4d3d74a824a9db5b5/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.EKB trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| McAfeeD | `Trojan:Linux/Mirai.ERC` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FO!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Trojan.Linux.Mirai.nn` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.l` |

### [05537a14c9a6d520352a…](https://bazaar.abuse.ch/sample/05537a14c9a6d520352af7f289934b9a61216656b98504d1af6deaeb61104fe6/)

- **Familie:** SMLBR4
- **Erkannt von:** 4 von 74 Engines (5.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Possible_MIRAIDLOD.SMLBR4
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Trojan-Downloader.Linux.Mirai.d` |
| Sangfor | `Suspicious.Linux.Save.a` |
| TrendMicro | `Possible_MIRAIDLOD.SMLBR4` |
| TrendMicro-HouseCall | `Possible_MIRAIDLOD.SMLBR4` |

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

- **elf** (82×)
- **Mirai** (53×)
- **Torii** (49×)
- **RAT** (22×)
- **EasyShell** (21×)
- **Rust** (21×)
- **SnoopyTriage** (21×)
- **cowrie** (15×)
- **honeypot** (15×)
- **exe** (8×)
- **macho** (6×)
- **Prometei** (6×)
- **arm** (4×)
- **jar** (2×)
- **java** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +38 (15→53)
- ↓ **unbekannt** -18 (50→32)
- ↓ **Prometei** -1 (7→6)
- neu: **SilentNet** (2)
- ↑ **njrat** +1 (1→2)
- ↓ **CatStorm** -1 (3→2)
- neu: **Trojan.GenericKD.82216314** (1)
- neu: **RustyStealer** (1)
- neu: **RemcosRAT** (1)
- neu: **SMLBR4** (1)
- weg: **WARDENStealer** (war 5)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +19 (34→53)
- ↑ **unbekannt** +4 (28→32)
- ↑ **Prometei** +2 (4→6)
- ↑ **SilentNet** +1 (1→2)
- ↑ **njrat** +1 (1→2)
- neu: **CatStorm** (2)
- neu: **Trojan.GenericKD.82216314** (1)
- neu: **RustyStealer** (1)
- ↓ **RemcosRAT** -2 (3→1)
- neu: **SMLBR4** (1)
- weg: **WARDENStealer** (war 5)
- weg: **SalatStealer** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.821 MB |
| σ Dateigröße | 11.381 MB |
| Ø Risiko-Score | 73.2/100 |
| Ø Klassifikations-Konfidenz | 79.0% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 56/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 38 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:06 | [df5f364a5733…](https://bazaar.abuse.ch/sample/df5f364a573312665ebe4b10d344ac7572ad7146c8a7095c5bf25c55cbd9d5de/) | `elf` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 20:06 | [c0cde708b4e0…](https://bazaar.abuse.ch/sample/c0cde708b4e05bbd741dc96bf9a4593731a6a3d06175d2ebeea2b061af2e1525/) | `elf` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 20:06 | [cfcc27972cb4…](https://bazaar.abuse.ch/sample/cfcc27972cb4599acd3e761d50117243ca716b7a0d40aceefbe0deaef2652736/) | `elf` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 20:06 | [8934326c5af7…](https://bazaar.abuse.ch/sample/8934326c5af7663597a4c19a81a58f6b0d23a2af97616343b3c25a52d5b12b19/) | `macho` | unbekannt | 81.0 | – | – | 🇺🇸US |
| 20:06 | [e123bfd4b2eb…](https://bazaar.abuse.ch/sample/e123bfd4b2eb837e02c0a1efc06a34ac982d197bd3fa65bd545765d0a220fea6/) | `macho` | unbekannt | 81.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.11.2026 20:25 UTC*