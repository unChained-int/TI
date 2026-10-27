# MalwareBazaar – 27.10.2026 11:48 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **56** |
| Höchster Score | **84.5/100** – e77bf89ea8f9c233… |
| Häufigste Familie | **Mirai** (46x) |
| Häufigster Typ | **elf** (83x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 46 Samples |
| Ø Dateigröße | 1.64 MB (σ=4.89) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 83 | 82.2%  ████████████████ |
| `exe` | 11 | 10.9%  ██ |
| `sh` | 5 | 5.0%   |
| `msi` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 46 | 45.5% |
| 2 | unbekannt | 36 | 35.6% |
| 3 | SalatStealer | 7 | 6.9% |
| 4 | ConnectWise | 5 | 5.0% |
| 5 | CatStorm | 3 | 3.0% |
| 6 | BPZ trojan | 2 | 2.0% |
| 7 | Linux | 1 | 1.0% |
| 8 | Prometei | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 48 | 47.5% | 94% |
| Linux-Malware | 33 | 32.7% | 45% |
| Infostealer | 7 | 6.9% | 74% |
| Windows-Malware | 6 | 5.9% | 35% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Trojaner | 2 | 2.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 56 | 55.4% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 39 | 38.6% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [e77bf89ea8f9c2…](https://bazaar.abuse.ch/sample/e77bf89ea8f9c233aad8f56e752fab4894f86a395580c12bc8d4d8a016456f60/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [4613efca07b6f4…](https://bazaar.abuse.ch/sample/4613efca07b6f4f7251d47f85ded5a24dbf3c5da45bd20d6ffb1a2634377af79/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [f4c8d6295c9701…](https://bazaar.abuse.ch/sample/f4c8d6295c9701b99f0d796887317c3daf1157787efd36976ff704fb17ac6d61/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [6a6d88708db360…](https://bazaar.abuse.ch/sample/6a6d88708db36048c255428b5ae500a54ba176e383f5d03731f7c247d8b4b771/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [ec839751e147da…](https://bazaar.abuse.ch/sample/ec839751e147daf30ecb5033ac19771cac39152fc26a6cb9c7784b8d81852435/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [07fc89008020d1…](https://bazaar.abuse.ch/sample/07fc89008020d1ae4ac2b99566a5baf81e08b63573ad3e94b26d40c9cfc8e20e/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [bb004bfced2f05…](https://bazaar.abuse.ch/sample/bb004bfced2f05f827df56aa96da6145d4a549ab51ec1b615caa11f538b66172/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [3bed123a2c7e2c…](https://bazaar.abuse.ch/sample/3bed123a2c7e2c1aee74f16ca9536062d1adddf7860dcb1b7d8423e848deff5a/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [0be548304c0661…](https://bazaar.abuse.ch/sample/0be548304c06613c02502f14196e1f981b8c4d42e18e1684bfa669fcd200bfc0/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [13edf966f53de5…](https://bazaar.abuse.ch/sample/13edf966f53de5f04b2b9ffc9b7a0eb2e486edbba642ec8acf123a2af8761567/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6214/7667 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6214/7667 |
| 3 | ESET-NOD32 | 77.2% | 5918/7667 |
| 4 | Kaspersky | 75.6% | 5796/7666 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5451/7664 |
| 8 | Rising | 68.3% | 5236/7667 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5072/7663 |
| 11 | Avast | 65.1% | 4989/7663 |
| 12 | AVG | 65.1% | 4989/7662 |
| 13 | Tencent | 64.9% | 4827/7441 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4691/7660 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 88 | 87.1% |
| 🪟 Windows | 13 | 12.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Trojanisierte Software | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 33 | 32.7% |
| 2 | 🇦🇹 AT | 26 | 25.7% |
| 3 | 🇳🇱 NL | 21 | 20.8% |
| 4 | 🇪🇸 ES | 7 | 6.9% |
| 5 | 🇩🇪 DE | 4 | 4.0% |
| 6 | 🇫🇷 FR | 4 | 4.0% |
| 7 | 🇨🇭 CH | 4 | 4.0% |
| 8 | 🇭🇺 HU | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 46 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 46 |
| Lateral Movement | 46 |

<details><summary>e77bf89ea8f9c233aad8… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4613efca07b6f4f7251d… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>f4c8d6295c9701b99f0d… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6a6d88708db36048c255… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ec839751e147daf30ecb… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [32461e7f070f54877faa…](https://bazaar.abuse.ch/sample/32461e7f070f54877faa5c5367765eb312044e537148536dfc024c942bb70c39/)

- **Familie:** BPZ trojan
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BPZ trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.Siggen.15884` |
| ESET-NOD32 | `Linux/Agent.BPZ trojan` |

### [5ccc3e27d069f4fba530…](https://bazaar.abuse.ch/sample/5ccc3e27d069f4fba530d739a8af153532a1ae8ad57bf85c5e18271943dd2c43/)

- **Familie:** BPZ trojan
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BPZ trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.Siggen.15884` |
| ESET-NOD32 | `Linux/Agent.BPZ trojan` |

### [95ac614aa2dabb5ea0b2…](https://bazaar.abuse.ch/sample/95ac614aa2dabb5ea0b2416462d69eef49116563f99f877dd977317178174ceb/)

- **Familie:** Linux
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Backdoor.Linux.MIRAI.SMQB
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMQB` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMQB` |
| Varist | `E32/Mirai.OA2.gen!Eldorado` |

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

- **Mirai** (40×)
- **elf** (36×)
- **upx-dec** (14×)
- **upx** (14×)
- **cowrie** (8×)
- **honeypot** (8×)
- **ddos** (7×)
- **jkl** (7×)
- **exe** (6×)
- **ConnectWise** (5×)
- **arm** (4×)
- **SalatStealer** (3×)
- **salatstealer** (3×)
- **CatStorm** (3×)
- **signed** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +25 (21→46)
- ↑ **unbekannt** +10 (26→36)
- ↓ **SalatStealer** -11 (18→7)
- neu: **ConnectWise** (5)
- neu: **CatStorm** (3)
- neu: **BPZ trojan** (2)
- neu: **Linux** (1)
- neu: **Prometei** (1)
- weg: **RemcosRAT** (war 4)
- weg: **CoinMiner** (war 2)
- weg: **XWorm** (war 2)
- weg: **SilentNet** (war 6)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +27 (19→46)
- ↑ **unbekannt** +4 (32→36)
- ↓ **SalatStealer** -1 (8→7)
- neu: **ConnectWise** (5)
- neu: **CatStorm** (3)
- neu: **BPZ trojan** (2)
- neu: **Linux** (1)
- neu: **Prometei** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.642 MB |
| σ Dateigröße | 4.892 MB |
| Ø Risiko-Score | 64.6/100 |
| Ø Klassifikations-Konfidenz | 68.8% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 46/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 20 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:40 | [e77bf89ea8f9…](https://bazaar.abuse.ch/sample/e77bf89ea8f9c233aad8f56e752fab4894f86a395580c12bc8d4d8a016456f60/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 11:40 | [04f6b7bb9a29…](https://bazaar.abuse.ch/sample/04f6b7bb9a29b8ea586fff7d75af46eabdb82ac08578481c2d0848994297bbeb/) | `elf` | unbekannt | 43.2 | – | – | 🇺🇸US |
| 11:39 | [aac5a8c1cc53…](https://bazaar.abuse.ch/sample/aac5a8c1cc531e652e9862e001f9e11bed81a4eb6966633a2700132dc06f0ba1/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 11:35 | [4613efca07b6…](https://bazaar.abuse.ch/sample/4613efca07b6f4f7251d47f85ded5a24dbf3c5da45bd20d6ffb1a2634377af79/) | `elf` | Mirai | 84.4 | – | – | 🌐ES |
| 11:35 | [f4c8d6295c97…](https://bazaar.abuse.ch/sample/f4c8d6295c9701b99f0d796887317c3daf1157787efd36976ff704fb17ac6d61/) | `elf` | Mirai | 84.4 | – | – | 🌐ES |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 27.10.2026 11:48 UTC*