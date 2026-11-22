# MalwareBazaar – 22.11.2026 09:38 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **84** |
| Höchster Score | **86.0/100** – 65278002c1474ae3… |
| Häufigste Familie | **unbekannt** (60x) |
| Häufigster Typ | **elf** (62x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 24 Samples |
| Ø Dateigröße | 2.49 MB (σ=3.42) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 62 | 61.4%  ████████████ |
| `exe` | 16 | 15.8%  ███ |
| `macho` | 14 | 13.9%  ██ |
| `dll` | 5 | 5.0%   |
| `sh` | 3 | 3.0%   |
| `zsh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 60 | 59.4% |
| 2 | Mirai | 21 | 20.8% |
| 3 | Prometei | 6 | 5.9% |
| 4 | CoinMiner | 4 | 4.0% |
| 5 | Gafgyt | 2 | 2.0% |
| 6 | BTN trojan | 2 | 2.0% |
| 7 | SheetRAT | 2 | 2.0% |
| 8 | njrat | 2 | 2.0% |
| 9 | YQU trojan | 1 | 1.0% |
| 10 | WARDENStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 47 | 46.5% | 76% |
| Botnet/IoT | 23 | 22.8% | 95% |
| Infostealer | 14 | 13.9% | 75% |
| Linux-Malware | 8 | 7.9% | 45% |
| Cryptominer | 4 | 4.0% | 75% |
| Loader | 2 | 2.0% | 75% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Windows-Malware | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 84 | 83.2% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 9 | 8.9% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [65278002c1474a…](https://bazaar.abuse.ch/sample/65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5/) | njrat | RAT | **86.0** | 🔴 KRITISCH | – | – | ? |
| [1e16d65d0f2088…](https://bazaar.abuse.ch/sample/1e16d65d0f2088278c41ab3be380140d00c2f6417c1dea7af8ce7ae0dea005be/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [ff06964ad799ef…](https://bazaar.abuse.ch/sample/ff06964ad799ef24748af9de0eb47a2ccb72b126255ccbefa068c070f864ec5d/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [ad46b84535afa8…](https://bazaar.abuse.ch/sample/ad46b84535afa896a979ddb95ed5437186525e385abb739c4a259260e502221e/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [ea63ae7168af9d…](https://bazaar.abuse.ch/sample/ea63ae7168af9d8616ad5e622f78a6bec5a18a46d3d9b2dfdeb8451bb3d129a0/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [6c07b64055df22…](https://bazaar.abuse.ch/sample/6c07b64055df22ad04cd6d12654f0c1c0a97164f489f8d0191d1efd68dc29ab8/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [57e493cada3a87…](https://bazaar.abuse.ch/sample/57e493cada3a87218fc4e15cc15bf81905ac0eeccba5d0bc8ef7206ab935ecc6/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [4ca2b0bb582404…](https://bazaar.abuse.ch/sample/4ca2b0bb582404745f8db023ace08695f9806a482c64cf3b54f9e844769103bc/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [f13fade7d302f3…](https://bazaar.abuse.ch/sample/f13fade7d302f315a25c92168e61a4bd31ae8c924c09816aea5dc04a93be4b41/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [082f55d6f63b6e…](https://bazaar.abuse.ch/sample/082f55d6f63b6e58965b896c4aa824b828251320e2950df0ac7b7a44a758c81a/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6571/8097 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6571/8097 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6268/8097 |
| 6 | Kaspersky | 75.6% | 6120/8096 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5770/8093 |
| 9 | Rising | 68.6% | 5551/8097 |
| 10 | Varist | 66.1% | 5347/8092 |
| 11 | Tencent | 65.2% | 5131/7871 |
| 12 | Avast | 65.2% | 5278/8093 |
| 13 | AVG | 65.2% | 5278/8092 |
| 14 | McAfeeD | 61.5% | 4974/8089 |
| 15 | huorong | 61.0% | 4931/8089 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 81 | 80.2% |
| 🪟 Windows | 19 | 18.8% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 48 | 47.5% |
| 2 | 🇩🇪 DE | 30 | 29.7% |
| 3 | 🇪🇸 ES | 13 | 12.9% |
| 4 | 🇫🇷 FR | 5 | 5.0% |
| 5 | 🇳🇱 NL | 2 | 2.0% |
| 6 | 🇨🇭 CH | 1 | 1.0% |
| 7 | 🇯🇵 JP | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 24 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 21 |
| Lateral Movement | 21 |
| Command and Control | 2 |
| Collection | 2 |
| Impact | 1 |

<details><summary>65278002c1474ae35c8a… – njrat | 🔴 KRITISCH 86.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>1e16d65d0f2088278c41… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ff06964ad799ef24748a… – Mirai | 🔴 KRITISCH 83.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ad46b84535afa896a979… – Mirai | 🔴 KRITISCH 83.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ea63ae7168af9d8616ad… – Mirai | 🔴 KRITISCH 82.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d5b6c533464791de05d0…](https://bazaar.abuse.ch/sample/d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9/)

- **Familie:** YQU trojan
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** MSIL/Agent.YQU trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `MSIL/Agent.YQU trojan` |

### [6e237da8c748e4afc14f…](https://bazaar.abuse.ch/sample/6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6/)

- **Familie:** BTN trojan
- **Erkannt von:** 4 von 74 Engines (5.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:3KiNDdNqclO)` |

### [dba9625fec97eb3bac3f…](https://bazaar.abuse.ch/sample/dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb/)

- **Familie:** BTN trojan
- **Erkannt von:** 4 von 74 Engines (5.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Backdoor.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Agent/Linux!8.133D0 (TFE:14:3Ol2Hl59JIN)` |

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

- **elf** (62×)
- **RAT** (46×)
- **EasyShell** (43×)
- **Rust** (43×)
- **SnoopyTriage** (43×)
- **Mirai** (20×)
- **exe** (15×)
- **macho** (14×)
- **stealer** (13×)
- **Torii** (13×)
- **go-crypter-payload** (12×)
- **x64** (12×)
- **Prometei** (6×)
- **dll** (5×)
- **dotnet** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +16 (44→60)
- ↓ **Mirai** -13 (34→21)
- ↑ **Prometei** +2 (4→6)
- neu: **CoinMiner** (4)
- neu: **Gafgyt** (2)
- neu: **BTN trojan** (2)
- neu: **SheetRAT** (2)
- ↑ **njrat** +1 (1→2)
- neu: **YQU trojan** (1)
- weg: **CatStorm** (war 3)
- weg: **Snowlight** (war 9)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +33 (27→60)
- ↓ **Mirai** -13 (34→21)
- ↑ **Prometei** +1 (5→6)
- neu: **CoinMiner** (4)
- neu: **Gafgyt** (2)
- neu: **BTN trojan** (2)
- neu: **SheetRAT** (2)
- ↑ **njrat** +1 (1→2)
- neu: **YQU trojan** (1)
- ↓ **WARDENStealer** -4 (5→1)
- weg: **SalatStealer** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Snowlight** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.495 MB |
| σ Dateigröße | 3.418 MB |
| Ø Risiko-Score | 75.2/100 |
| Ø Klassifikations-Konfidenz | 76.1% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 24/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 09:37 | [6c687c24cd80…](https://bazaar.abuse.ch/sample/6c687c24cd807035794063edace443f31590e6f75e2a045612cdbf4d7d91b405/) | `exe` | unbekannt | 82.2 | – | – | 🌐ES |
| 09:37 | [6276b87c1afe…](https://bazaar.abuse.ch/sample/6276b87c1afed5cdd81b055019ba451603cda15b7a6bd36c6e93b8c7924a4da8/) | `exe` | unbekannt | 82.2 | – | – | 🌐ES |
| 09:36 | [5a2cedc7746e…](https://bazaar.abuse.ch/sample/5a2cedc7746ead418b24830ab6eda67241c5acd115cdd2ace9ff1eb177dafff8/) | `exe` | unbekannt | 82.2 | – | – | 🌐ES |
| 09:36 | [302a330c3c6b…](https://bazaar.abuse.ch/sample/302a330c3c6b95a7b57ddb56b3c6c053043ca4f77f4a2fca925691814548e1c2/) | `exe` | unbekannt | 82.2 | – | – | 🌐ES |
| 09:36 | [3e3f9121dd8a…](https://bazaar.abuse.ch/sample/3e3f9121dd8af97780ed5c709129def9a6df2acdab33465045b4e5d015e509e9/) | `elf` | unbekannt | 81.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.11.2026 09:38 UTC*