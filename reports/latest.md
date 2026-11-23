# MalwareBazaar – 23.11.2026 19:57 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **76** |
| Höchster Score | **96.4/100** – 7926adcc75f56fe4… |
| Häufigste Familie | **EasyShell** (37x) |
| Häufigster Typ | **elf** (43x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 11 Samples |
| Ø Dateigröße | 2.66 MB (σ=3.18) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 43 | 42.6%  ████████ |
| `exe` | 29 | 28.7%  █████ |
| `macho` | 11 | 10.9%  ██ |
| `js` | 7 | 6.9%  █ |
| `sh` | 6 | 5.9%  █ |
| `dll` | 2 | 2.0%   |
| `vbs` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |
| `xml` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | EasyShell | 37 | 36.6% |
| 2 | unbekannt | 18 | 17.8% |
| 3 | Prometei | 7 | 6.9% |
| 4 | Mirai | 7 | 6.9% |
| 5 | WARDENStealer | 7 | 6.9% |
| 6 | SalatStealer | 4 | 4.0% |
| 7 | WSHRat | 4 | 4.0% |
| 8 | njrat | 3 | 3.0% |
| 9 | RemusStealer | 3 | 3.0% |
| 10 | PureLogsStealer | 2 | 2.0% |
| 11 | EvolutionRAT | 2 | 2.0% |
| 12 | WannaCry | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 47 | 46.5% | 77% |
| Infostealer | 20 | 19.8% | 75% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| Linux-Malware | 7 | 6.9% | 45% |
| Botnet/IoT | 7 | 6.9% | 95% |
| Windows-Malware | 6 | 5.9% | 35% |
| Trojaner | 2 | 2.0% | 65% |
| Ransomware | 2 | 2.0% | 95% |
| Cryptominer | 1 | 1.0% | 75% |
| Skript/Dropper | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 76 | 75.2% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 14 | 13.9% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7926adcc75f56f…](https://bazaar.abuse.ch/sample/7926adcc75f56fe4aed40216d46c5e4b8a6726656afae59897a62f9e93c9b5e2/) | WannaCry | Ransomware | **96.4** | 🔴 KRITISCH | – | – | ? |
| [751496bf4b0db6…](https://bazaar.abuse.ch/sample/751496bf4b0db608dd759ed5a9ce6976c68b0f3952ccbbf63bfb0c5418524ffb/) | WannaCry | Ransomware | **95.6** | 🔴 KRITISCH | – | – | ? |
| [22cff4193ae806…](https://bazaar.abuse.ch/sample/22cff4193ae8068f429394232b84b08588fab449490256cabd6ab797c1550e7f/) | njrat | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [12292dbdeedd35…](https://bazaar.abuse.ch/sample/12292dbdeedd35e5af3ae42ef63ec9499920f312d975831d3e0202ea03c9947f/) | njrat | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [c59661c80e3075…](https://bazaar.abuse.ch/sample/c59661c80e30752bdb10dbe1165b86c916ed2aa0c683a502fb79b209bd9817db/) | RemcosRAT | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [f33285dee0d1a0…](https://bazaar.abuse.ch/sample/f33285dee0d1a0a31090bee4054a5f64836cb87dabb714fd58ac43b56afc55ec/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [e9cc23ac282767…](https://bazaar.abuse.ch/sample/e9cc23ac282767d6a10231191ed16637d66e114b4a647a85e2cb3a6523da9984/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [a92df6a57d324b…](https://bazaar.abuse.ch/sample/a92df6a57d324bcea6871aa23747b3c5876e5fc44155630c9a42ce9a880db4aa/) | B!ml | Trojaner | **83.9** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [d1480d70856ae4…](https://bazaar.abuse.ch/sample/d1480d70856ae48b9f4044087da6aeb76d4b88bd6e4c5bee84d140f73593e784/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [63243a9c64713c…](https://bazaar.abuse.ch/sample/63243a9c64713c6f8827a7877cff7892ba10cb3f214d4573701d2cd4cd7719fb/) | EasyShell | RAT | **82.8** | 🔴 KRITISCH | 6.9% | ⚠️ KAUM ERKANNT | ✗ |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6588/8115 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6588/8115 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6284/8115 |
| 6 | Kaspersky | 75.6% | 6137/8114 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5783/8111 |
| 9 | Rising | 68.6% | 5566/8115 |
| 10 | Varist | 66.1% | 5362/8110 |
| 11 | Tencent | 65.2% | 5144/7889 |
| 12 | Avast | 65.2% | 5291/8111 |
| 13 | AVG | 65.2% | 5291/8110 |
| 14 | McAfeeD | 61.5% | 4986/8107 |
| 15 | huorong | 61.0% | 4946/8107 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 64 | 63.4% |
| 🪟 Windows | 32 | 31.7% |
| ❓ Unbekannt | 4 | 4.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 91 | 90.1% |
| Drive-By / Exploit-Kit | 7 | 6.9% |
| Exploit / N-Day | 2 | 2.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 38 | 37.6% |
| 2 | 🇫🇷 FR | 31 | 30.7% |
| 3 | 🇩🇪 DE | 10 | 9.9% |
| 4 | 🇳🇱 NL | 6 | 5.9% |
| 5 | 🇨🇦 CA | 5 | 5.0% |
| 6 | 🌐 CL | 5 | 5.0% |
| 7 | 🇧🇷 BR | 2 | 2.0% |
| 8 | 🇨🇭 CH | 2 | 2.0% |
| 9 | 🇷🇺 RU | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 11 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 7 |
| Lateral Movement | 7 |
| Command and Control | 4 |
| Collection | 4 |

<details><summary>22cff4193ae8068f4293… – njrat | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>12292dbdeedd35e5af3a… – njrat | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c59661c80e30752bdb10… – RemcosRAT | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a92df6a57d324bcea687…](https://bazaar.abuse.ch/sample/a92df6a57d324bcea6871aa23747b3c5876e5fc44155630c9a42ce9a880db4aa/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 73 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/73):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [1955c0324a747f56d91b…](https://bazaar.abuse.ch/sample/1955c0324a747f56d91b1526c66f06d0d2e14489b37c9b5996db015daf272197/)

- **Familie:** Prometei
- **Erkannt von:** 29 von 73 Engines (39.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Application.Generic.37937637
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37937637`

**Erkennende Engines (29/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39503691` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D242E1E5` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37937637` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37937637 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37937637` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37937637` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37937637` |
| Varist | `E64/PrometeiS.C` |
| huorong | `Trojan/Prometei.c` |

### [63243a9c64713c6f8827…](https://bazaar.abuse.ch/sample/63243a9c64713c6f8827a7877cff7892ba10cb3f214d4573701d2cd4cd7719fb/)

- **Familie:** EasyShell
- **Erkannt von:** 5 von 73 Engines (6.9%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:3KiNDdNqclO)` |
| Tencent | `Malware.Linux.Generic.1c0cccc5` |

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

- **elf** (43×)
- **RAT** (40×)
- **EasyShell** (37×)
- **Rust** (37×)
- **SnoopyTriage** (37×)
- **exe** (28×)
- **macho** (11×)
- **WARDENStealer** (9×)
- **js** (7×)
- **Prometei** (7×)
- **cowrie** (7×)
- **honeypot** (7×)
- **Mirai** (6×)
- **sh** (6×)
- **stealer** (6×)

## Änderungen – 24h-Vergleich

- ↑ **EasyShell** +33 (4→37)
- ↓ **unbekannt** -24 (42→18)
- ↑ **Prometei** +2 (5→7)
- ↓ **Mirai** -33 (40→7)
- ↑ **WARDENStealer** +5 (2→7)
- neu: **SalatStealer** (4)
- neu: **WSHRat** (4)
- ↑ **njrat** +1 (2→3)
- neu: **RemusStealer** (3)
- neu: **PureLogsStealer** (2)
- weg: **ValleyRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **EasyShell** +36 (1→37)
- ↓ **unbekannt** -15 (33→18)
- ↑ **Prometei** +2 (5→7)
- ↓ **Mirai** -25 (32→7)
- ↑ **WARDENStealer** +2 (5→7)
- ↑ **SalatStealer** +3 (1→4)
- neu: **WSHRat** (4)
- ↑ **njrat** +1 (2→3)
- neu: **RemusStealer** (3)
- neu: **PureLogsStealer** (2)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.661 MB |
| σ Dateigröße | 3.180 MB |
| Ø Risiko-Score | 70.6/100 |
| Ø Klassifikations-Konfidenz | 68.2% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 11/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 57 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:45 | [32af770680bd…](https://bazaar.abuse.ch/sample/32af770680bdeec67bb4e427b15dcadd1957d28a40228c8ac4f76314af2ba400/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |
| 19:44 | [89649ab108f8…](https://bazaar.abuse.ch/sample/89649ab108f8f5e611b72151b12563378bac75a10d9824796659476f49efb2db/) | `js` | PureLogsStealer | 82.0 | – | – | 🇫🇷FR |
| 19:44 | [037edfcf6623…](https://bazaar.abuse.ch/sample/037edfcf662364acb3dca409032c2f70dc56c1479a2adfd54cd91a24a7d469da/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |
| 19:44 | [7cfe4aaf1703…](https://bazaar.abuse.ch/sample/7cfe4aaf17035fcf173b395811e5071c60357c1600b322a0f1d46ce646b0dff4/) | `js` | PureLogsStealer | 82.0 | – | – | 🇫🇷FR |
| 19:39 | [f39f23641be4…](https://bazaar.abuse.ch/sample/f39f23641be4186353ef72d3b3e0db42ed9355655ca17d3b9dc78b1409850006/) | `elf` | Prometei | 43.1 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.11.2026 19:57 UTC*