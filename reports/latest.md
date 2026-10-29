# MalwareBazaar – 29.10.2026 19:27 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **41** |
| Höchster Score | **97.7/100** – ccedb14d2f41bce2… |
| Häufigste Familie | **unbekannt** (41x) |
| Häufigster Typ | **elf** (63x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 40 Samples |
| Ø Dateigröße | 4.22 MB (σ=13.60) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 63 | 62.4%  ████████████ |
| `exe` | 14 | 13.9%  ██ |
| `vbs` | 5 | 5.0%   |
| `jar` | 4 | 4.0%   |
| `sh` | 3 | 3.0%   |
| `js` | 2 | 2.0%   |
| `apk` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `macho` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 41 | 40.6% |
| 2 | Mirai | 26 | 25.7% |
| 3 | KATARU | 12 | 11.9% |
| 4 | WannaCry | 4 | 4.0% |
| 5 | CoinMiner | 4 | 4.0% |
| 6 | MassLogger | 3 | 3.0% |
| 7 | RemcosRAT | 3 | 3.0% |
| 8 | RustyStealer | 2 | 2.0% |
| 9 | XWorm | 1 | 1.0% |
| 10 | Action1RMM | 1 | 1.0% |
| 11 | Grandoreiro | 1 | 1.0% |
| 12 | ELF:Agent-EDB [Trj] | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 61 | 60.4% | 84% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| Infostealer | 6 | 5.9% | 73% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Ransomware | 4 | 4.0% | 95% |
| Windows-Malware | 4 | 4.0% | 35% |
| RAT | 4 | 4.0% | 95% |
| Cryptominer | 4 | 4.0% | 75% |
| Loader | 2 | 2.0% | 75% |
| Linux-Malware | 1 | 1.0% | 45% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 41 | 40.6% |
| 🟠 HOCH | 41 | 40.6% |
| 🟡 MITTEL | 11 | 10.9% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ccedb14d2f41bc…](https://bazaar.abuse.ch/sample/ccedb14d2f41bce238a40dc24127b32e2ffbbb332da1c8ff579ad1094e60fff3/) | WannaCry | Ransomware | **97.7** | 🔴 KRITISCH | – | – | ? |
| [89b7ccbbe88a68…](https://bazaar.abuse.ch/sample/89b7ccbbe88a68556a160fd0f331e054d033fb4f10cab6ecb455866b5c56f8c6/) | WannaCry | Ransomware | **96.8** | 🔴 KRITISCH | – | – | ? |
| [e053402c2411b3…](https://bazaar.abuse.ch/sample/e053402c2411b3862ec6e3f2195e5fc4c96cd37e9f7b3869cf13901f6ffece1e/) | WannaCry | Ransomware | **95.2** | 🔴 KRITISCH | – | – | ? |
| [c386092022f380…](https://bazaar.abuse.ch/sample/c386092022f380ac92dc91e1b2f07a18b77ec9b5caeb7d77834185929dd27554/) | WannaCry | Ransomware | **94.6** | 🔴 KRITISCH | – | – | ? |
| [bd6ade8faebe97…](https://bazaar.abuse.ch/sample/bd6ade8faebe97345778611cc411c158e0f22106a46e792d1ab03eed873dc768/) | XWorm | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [94c6837f74fa77…](https://bazaar.abuse.ch/sample/94c6837f74fa7787f8d87956f22155b01b2f88c3c782011aedba57885f313406/) | RemcosRAT | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [221b4c28740ec8…](https://bazaar.abuse.ch/sample/221b4c28740ec85f9309bf22cf7f09722bf088acae869262a1da0b6e2396052b/) | RemcosRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [6f5db8c06d5b9e…](https://bazaar.abuse.ch/sample/6f5db8c06d5b9e5fde3fc53c42957134f14f2b39320166d0cfc699e99c943b43/) | RemcosRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [b7eaf8f9e4bd4f…](https://bazaar.abuse.ch/sample/b7eaf8f9e4bd4f69eb69494a3d7124bab061df80c585cfe23d101756153fd299/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [cf095f33cde5cb…](https://bazaar.abuse.ch/sample/cf095f33cde5cb97b30908fddde82a88b55744d055a14d1b99a0a1e0c6d9fd73/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6249/7710 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6249/7710 |
| 3 | ESET-NOD32 | 77.2% | 5955/7710 |
| 4 | Kaspersky | 75.5% | 5824/7709 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5486/7707 |
| 8 | Rising | 68.3% | 5269/7710 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5101/7706 |
| 11 | Avast | 65.2% | 5021/7706 |
| 12 | AVG | 65.2% | 5021/7705 |
| 13 | Tencent | 64.9% | 4860/7484 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4720/7703 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 67 | 66.3% |
| 🪟 Windows | 23 | 22.8% |
| ❓ Unbekannt | 6 | 5.9% |
| 🤖 Android | 3 | 3.0% |
| 🍎 macOS | 1 | 1.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 89 | 88.1% |
| Exploit / N-Day | 4 | 4.0% |
| Trojanisierte Software | 2 | 2.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| APK-Sideloading | 2 | 2.0% |
| MaaS-Loader | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 62 | 61.4% |
| 2 | 🇩🇪 DE | 9 | 8.9% |
| 3 | 🇺🇸 US | 6 | 5.9% |
| 4 | 🇦🇹 AT | 6 | 5.9% |
| 5 | 🇳🇱 NL | 6 | 5.9% |
| 6 | 🇸🇪 SE | 6 | 5.9% |
| 7 | 🇨🇭 CH | 3 | 3.0% |
| 8 | 🇭🇺 HU | 1 | 1.0% |
| 9 | 🇮🇳 IN | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 40 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 37 |
| Lateral Movement | 37 |
| Command and Control | 3 |
| Collection | 3 |


## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [91754c45753e86b26f14…](https://bazaar.abuse.ch/sample/91754c45753e86b26f145128ce65319216ca638db94cbbc99d6bf687e459f5e9/)

- **Familie:** MassLogger
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** VB:Trojan.Valyria.11904
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `VB:Trojan.Valyria.11904`

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `VB:Trojan.Valyria.11904` |
| Arcabit | `VB:Trojan.Valyria.D2E80` |
| BitDefender 🛡️ | `VB:Trojan.Valyria.11904` |
| CTX | `script.trojan.valyria` |
| Emsisoft | `VB:Trojan.Valyria.11904 (B)` |
| GData | `VB:Trojan.Valyria.11904` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-PSW.VBS.Disco.gen` |
| MicroWorld-eScan | `VB:Trojan.Valyria.11904` |
| Skyhigh | `BehavesLike.VBS.Dropper.dj` |
| Symantec | `ISB.Houdini!gen7` |
| VIPRE | `VB:Trojan.Valyria.11904` |
| Varist | `VBS/Agent.DDB` |

### [cf095f33cde5cb97b309…](https://bazaar.abuse.ch/sample/cf095f33cde5cb97b30908fddde82a88b55744d055a14d1b99a0a1e0c6d9fd73/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| DrWeb | `Linux.DDoS.3423` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Ikarus | `PUA.Linux.Obfuscated` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| huorong | `Trojan/Linux.DDos.dt` |

### [0dde34ec889d47b070d8…](https://bazaar.abuse.ch/sample/0dde34ec889d47b070d81e3aace459b9fb7d47aa20f007b52dbd22a77fde67ec/)

- **Familie:** ELF:Agent-EDB [Trj]
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-EDB [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-EDB [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Agent-EDB [Trj]` |
| DrWeb | `Linux.BackDoor.Vision.3` |
| ESET-NOD32 | `Linux/DDoS.Agent.JR trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.DDoS` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xl` |
| Rising | `Trojan.DDOS/Linux!1.145A1 (CLASSIC)` |
| Tencent | `Trojan.Linux.Botnet.pt` |
| huorong | `Trojan/Linux.Mirai.hx` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

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
| CTX | `exe.trojan.lummastealer` |
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
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **elf** (63×)
- **ddos** (57×)
- **unknown** (56×)
- **Mirai** (36×)
- **cosplay** (22×)
- **golang** (22×)
- **vision** (22×)
- **exe** (17×)
- **dht** (13×)
- **sixsayven** (13×)
- **Torii** (13×)
- **kataru** (12×)
- **upx** (10×)
- **boatnet** (10×)
- **miner** (10×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +17 (24→41)
- neu: **KATARU** (12)
- ↑ **WannaCry** +3 (1→4)
- ↑ **CoinMiner** +3 (1→4)
- ↑ **MassLogger** +2 (1→3)
- ↓ **RemcosRAT** -2 (5→3)
- neu: **RustyStealer** (2)
- neu: **Action1RMM** (1)
- weg: **Formbook** (war 9)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +18 (23→41)
- ↑ **Mirai** +3 (23→26)
- neu: **KATARU** (12)
- neu: **WannaCry** (4)
- ↑ **CoinMiner** +3 (1→4)
- neu: **MassLogger** (3)
- ↑ **RemcosRAT** +1 (2→3)
- neu: **RustyStealer** (2)
- neu: **Action1RMM** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.220 MB |
| σ Dateigröße | 13.599 MB |
| Ø Risiko-Score | 69.0/100 |
| Ø Klassifikations-Konfidenz | 72.9% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 40/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:26 | [0c6dc7c70dd1…](https://bazaar.abuse.ch/sample/0c6dc7c70dd1f121245c5eb743c18fc8a9532024e137535070d6c8479e7ccd9a/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 19:15 | [ccedb14d2f41…](https://bazaar.abuse.ch/sample/ccedb14d2f41bce238a40dc24127b32e2ffbbb332da1c8ff579ad1094e60fff3/) | `exe` | WannaCry | 97.7 | – | – | 🇺🇸US |
| 18:51 | [04e379318f3d…](https://bazaar.abuse.ch/sample/04e379318f3d36ee1a3014741820b347ece155e1ed3cb4d95468955dee6c252a/) | `jar` | unbekannt | 81.7 | – | – | 🇫🇷FR |
| 18:38 | [a6ecbf30583c…](https://bazaar.abuse.ch/sample/a6ecbf30583cf4e81c67d13d1f8917e18ab75a149191a3e8628f522d45312be0/) | `msi` | unbekannt | 38.4 | – | – | 🌐HU |
| 18:27 | [c3e3bdc3477e…](https://bazaar.abuse.ch/sample/c3e3bdc3477e5cbda369bef24acf8d562f1a585cdc29346a624edc27f04f2a7b/) | `sh` | unbekannt | 31.8 | – | – | 🌐CH |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 29.10.2026 19:27 UTC*