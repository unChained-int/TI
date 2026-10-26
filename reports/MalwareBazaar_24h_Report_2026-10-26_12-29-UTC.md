# MalwareBazaar – 26.10.2026 12:29 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **59** |
| Höchster Score | **88.9/100** – 7aa96e6f115552e6… |
| Häufigste Familie | **unbekannt** (27x) |
| Häufigster Typ | **elf** (34x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 36 Samples |
| Ø Dateigröße | 1.75 MB (σ=3.36) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 34 | 33.7%  ██████ |
| `exe` | 31 | 30.7%  ██████ |
| `vbs` | 14 | 13.9%  ██ |
| `py` | 8 | 7.9%  █ |
| `macho` | 5 | 5.0%   |
| `zip` | 4 | 4.0%   |
| `js` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 27 | 26.7% |
| 2 | Mirai | 18 | 17.8% |
| 3 | RemcosRAT | 11 | 10.9% |
| 4 | CoinMiner | 7 | 6.9% |
| 5 | RevStealer | 4 | 4.0% |
| 6 | GuLoader | 3 | 3.0% |
| 7 | WARDENStealer | 3 | 3.0% |
| 8 | AMOS | 3 | 3.0% |
| 9 | XWorm | 3 | 3.0% |
| 10 | Formbook | 3 | 3.0% |
| 11 | Gafgyt | 3 | 3.0% |
| 12 | AgentTesla | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 22 | 21.8% | 94% |
| Infostealer | 19 | 18.8% | 82% |
| RAT | 16 | 15.8% | 92% |
| Andere / Unbekannt | 12 | 11.9% | 20% |
| Windows-Malware | 12 | 11.9% | 35% |
| Linux-Malware | 8 | 7.9% | 45% |
| Cryptominer | 7 | 6.9% | 75% |
| Loader | 3 | 3.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |
| Skript/Dropper | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 58.4% |
| 🟠 HOCH | 9 | 8.9% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 12 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7aa96e6f115552…](https://bazaar.abuse.ch/sample/7aa96e6f115552e6cc2ecff9f0d481a50978c41aabcac921e2225e0a24b465c1/) | AMOS | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [cc30e4d19f6c79…](https://bazaar.abuse.ch/sample/cc30e4d19f6c7975ba027b58b79bb58794c0baa7007350e4db5e15408b566f0c/) | AMOS | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [53348cdd623399…](https://bazaar.abuse.ch/sample/53348cdd623399a974a1254b25588de33b8fdfbaa0aa2a7c1aa4668d77944df7/) | RemcosRAT | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [c4889a8f6355fc…](https://bazaar.abuse.ch/sample/c4889a8f6355fc4172907cf72ec72c102221fcd82ec41be0882a0458b6916a32/) | RemcosRAT | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [3c217eeecaa616…](https://bazaar.abuse.ch/sample/3c217eeecaa616ad300b86fe00f2ddebeb05cba3dfb4c33f3c716f0f162c282c/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [fdc398f55cc3c5…](https://bazaar.abuse.ch/sample/fdc398f55cc3c5cd02bf4f31f0cf287f96fde32aa370117dd40aa9017c4cc3f5/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [48855cab734337…](https://bazaar.abuse.ch/sample/48855cab73433732c13c75330290b0f690e4c76d1740c8de691bef2138a6f213/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [039f9d8c2121b5…](https://bazaar.abuse.ch/sample/039f9d8c2121b55e8321c4490678f11322ffedf063c28a97a40ba8c543ddc6a7/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [32ce7696a243d7…](https://bazaar.abuse.ch/sample/32ce7696a243d77a4ee9d927e306e93629651d251a697ff58dc28f8c3dfdede0/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [93c3de8bfbaff0…](https://bazaar.abuse.ch/sample/93c3de8bfbaff071374ed32f128a405df30eebae99c218bf9f390c0e592d75b1/) | AMOS | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6199/7648 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6199/7648 |
| 3 | ESET-NOD32 | 77.2% | 5902/7648 |
| 4 | Kaspersky | 75.7% | 5791/7647 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5437/7645 |
| 8 | Rising | 68.3% | 5223/7648 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5057/7644 |
| 11 | Avast | 65.1% | 4976/7644 |
| 12 | AVG | 65.1% | 4976/7643 |
| 13 | Tencent | 64.8% | 4811/7422 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4681/7641 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 45 | 44.6% |
| 🐧 Linux | 36 | 35.6% |
| ❓ Unbekannt | 11 | 10.9% |
| 🍎 macOS | 5 | 5.0% |
| 📡 IoT/OT | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 92 | 91.1% |
| Drive-By / Exploit-Kit | 6 | 5.9% |
| USB / Wechselmedium | 3 | 3.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 26 | 25.7% |
| 2 | 🇺🇸 US | 20 | 19.8% |
| 3 | 🇫🇷 FR | 20 | 19.8% |
| 4 | 🇸🇪 SE | 13 | 12.9% |
| 5 | 🌐 EG | 8 | 7.9% |
| 6 | 🇳🇱 NL | 6 | 5.9% |
| 7 | 🇨🇭 CH | 3 | 3.0% |
| 8 | 🇭🇺 HU | 3 | 3.0% |
| 9 | 🇨🇦 CA | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 36 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Collection | 15 |
| Command and Control | 11 |
| Credential Access | 4 |
| Defense Evasion | 3 |
| Execution | 3 |
| Exfiltration | 1 |

<details><summary>53348cdd623399a974a1… – RemcosRAT | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c4889a8f6355fc417290… – RemcosRAT | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>3c217eeecaa616ad300b… – Formbook | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [22c92b30936cdba7e83f…](https://bazaar.abuse.ch/sample/22c92b30936cdba7e83f88030f3142923c12a60e05cdcacc2f20d7d0b91521b3/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQR!7B42D7029D3A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CFR [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE290` |
| Antiy-AVL | `Trojan/Linux.Mirai.a` |
| Avast | `ELF:Mirai-CFR [Trj]` |
| Avast-Mobile | `ELF:Mirai-CQP [Trj]` |
| Avira | `TR/LINUX.Mirai.CFR` |
| ClamAV | `Unix.Trojan.Gafgyt-9939811-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9810` |
| ESET-NOD32 | `Linux/Mirai.CGG trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CFR` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.JK!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11723 (CLASSIC)` |
| Sangfor | `Backdoor.Linux.Mirai.V0cg` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQR!7B42D7029D3A` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.kntra` |
| TrellixENS | `LINUX/Mirai-FQR!7B42D7029D3A` |
| huorong | `Backdoor/Linux.Mirai.ev` |

### [accc4a37b2c284cc3571…](https://bazaar.abuse.ch/sample/accc4a37b2c284cc357171cd4a11ba004211acf694e5587698955cb5c87bcfe3/)

- **Familie:** malicious (moderate confidence
- **Erkannt von:** 5 von 74 Engines (6.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** malicious (moderate confidence)
- **VT-Reputation:** -1
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ClamAV | `Win.Trojan.Agent-192767` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (moderate confidence)` |
| VirIT | `Trojan.Win32.Generic.PBM` |

### [209ee7bde47de5b4a7e6…](https://bazaar.abuse.ch/sample/209ee7bde47de5b4a7e6aee8ffc38f21dfb586900a801747af5037e71be21a25/)

- **Familie:** CatStorm
- **Erkannt von:** 15 von 74 Engines (20.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Avast | `ELF:Agent-ETO [Trj]` |
| DrWeb | `Linux.Siggen.12970` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.wo` |
| Kingsoft | `Linux.Trojan.Agent.wo` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner!rfn` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Trojan.Linux.Catstorm.Cbtra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/CoinMiner.dm` |

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

- **elf** (31×)
- **exe** (30×)
- **Mirai** (18×)
- **vbs** (14×)
- **RemcosRAT** (11×)
- **wraith** (8×)
- **py** (8×)
- **CoinMiner** (7×)
- **AMOS** (5×)
- **ClickFix** (5×)
- **Foxveil** (5×)
- **Mach-O** (5×)
- **macho** (5×)
- **macOS** (5×)
- **Gafgyt** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +12 (15→27)
- neu: **RemcosRAT** (11)
- ↑ **CoinMiner** +6 (1→7)
- neu: **RevStealer** (4)
- neu: **GuLoader** (3)
- neu: **WARDENStealer** (3)
- neu: **AMOS** (3)
- neu: **XWorm** (3)
- neu: **Formbook** (3)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -9 (36→27)
- ↓ **Mirai** -1 (19→18)
- ↑ **RemcosRAT** +10 (1→11)
- ↑ **CoinMiner** +4 (3→7)
- neu: **RevStealer** (4)
- neu: **GuLoader** (3)
- neu: **WARDENStealer** (3)
- ↑ **AMOS** +2 (1→3)
- neu: **XWorm** (3)
- ↑ **Formbook** +2 (1→3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.747 MB |
| σ Dateigröße | 3.359 MB |
| Ø Risiko-Score | 66.4/100 |
| Ø Klassifikations-Konfidenz | 69.6% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 36/101 |
| Eindeutige Familien | 24 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 12 (11.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:24 | [533fdbf6b547…](https://bazaar.abuse.ch/sample/533fdbf6b54775472b63e8e67a29d1647c207273b3cb32971f8647c42c6066a7/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 12:24 | [b6481b7215c6…](https://bazaar.abuse.ch/sample/b6481b7215c6147d72fc83e21fd99de8cd7d166b8245e3b86949ab56cb5ee996/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 12:21 | [ff727e01b90d…](https://bazaar.abuse.ch/sample/ff727e01b90dab5bd1ff00d9aa67a1a634a61462dec4a6b82b13f02eb5949c64/) | `elf` | CoinMiner | 67.9 | – | – | 🇺🇸US |
| 12:20 | [3d9818d6bd89…](https://bazaar.abuse.ch/sample/3d9818d6bd896bb4131f9f4fe021cfb9672b5fd737432ffc554581fe96678fe3/) | `elf` | CoinMiner | 67.9 | – | – | 🇺🇸US |
| 12:18 | [86f0d9e69171…](https://bazaar.abuse.ch/sample/86f0d9e69171fdf591af6df81030e4debb2710a2b8e59807862f50f27d79531b/) | `exe` | AgentTesla | 38.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.10.2026 12:29 UTC*