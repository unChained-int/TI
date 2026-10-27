# MalwareBazaar – 27.10.2026 21:57 UTC

Dieser Run hat **26 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **27** |
| Kritisch (≥75) | **15** |
| Höchster Score | **83.9/100** – 72769e3630c5defa… |
| Häufigste Familie | **unbekannt** (14x) |
| Häufigster Typ | **elf** (11x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 7 Samples |
| Ø Dateigröße | 6.89 MB (σ=17.48) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 11 | 40.7%  ████████ |
| `exe` | 7 | 25.9%  █████ |
| `zip` | 2 | 7.4%  █ |
| `macho` | 1 | 3.7%   |
| `zsh` | 1 | 3.7%   |
| `vbs` | 1 | 3.7%   |
| `dmg` | 1 | 3.7%   |
| `msi` | 1 | 3.7%   |
| `ps1` | 1 | 3.7%   |
| `sh` | 1 | 3.7%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 14 | 51.9% |
| 2 | Mirai | 7 | 25.9% |
| 3 | SalatStealer | 3 | 11.1% |
| 4 | AVR trojan | 1 | 3.7% |
| 5 | RustyStealer | 1 | 3.7% |
| 6 | Prometei | 1 | 3.7% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 7 | 25.9% | 95% |
| Andere / Unbekannt | 5 | 18.5% | 20% |
| Infostealer | 4 | 14.8% | 72% |
| RAT | 3 | 11.1% | 75% |
| Trojaner | 2 | 7.4% | 65% |
| Windows-Malware | 2 | 7.4% | 35% |
| Linux-Malware | 1 | 3.7% | 45% |
| Loader | 1 | 3.7% | 75% |
| Skript/Dropper | 1 | 3.7% | 35% |
| Cryptominer | 1 | 3.7% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 15 | 55.6% |
| 🟠 HOCH | 3 | 11.1% |
| 🟡 MITTEL | 4 | 14.8% |
| 🟢 NIEDRIG | 5 | 18.5% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [72769e3630c5de…](https://bazaar.abuse.ch/sample/72769e3630c5defaffa878c5e178ba2722ca2ca0aa181bd088c185b6534b9943/) | AVR trojan | Trojaner | **83.9** | 🔴 KRITISCH | 4.0% | ⚠️ KAUM ERKANNT | ✗ |
| [8fdf86dc457c55…](https://bazaar.abuse.ch/sample/8fdf86dc457c554f6637b51e51700eb39d5533c72390ce6e12b513105cd8b3ff/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [fb4d0f15ce071b…](https://bazaar.abuse.ch/sample/fb4d0f15ce071bcb263655c859d1e93ef3ff038292bd20c46165768de59623d4/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [c8cbeb5b2d878b…](https://bazaar.abuse.ch/sample/c8cbeb5b2d878b7ef58147a77db1a982841f0d54946a93cc5ed9251fabd37ef1/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [a6593d5bf995f4…](https://bazaar.abuse.ch/sample/a6593d5bf995f411994c152e376104af31f92d59b6280af0e2cf405f0d442633/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [f96b58c803989f…](https://bazaar.abuse.ch/sample/f96b58c803989f17d951864737a491c19737312fc1d013d677771e1e33c7db44/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |
| [6f50a26febc9f0…](https://bazaar.abuse.ch/sample/6f50a26febc9f01a4d6301596b73faa9f8ba17f248a18a9791ecc9145373c3b4/) | Mirai | Botnet/IoT | **80.4** | 🔴 KRITISCH | 26.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [f7161024d74ed8…](https://bazaar.abuse.ch/sample/f7161024d74ed8d6dd568b8d76d662a49d698e95c9c684046ad21ac0d09110a2/) | RustyStealer | Infostealer | **80.3** | 🔴 KRITISCH | – | – | ? |
| [bc51f4479eed58…](https://bazaar.abuse.ch/sample/bc51f4479eed583c1af96a82048128c53e421f1684e984cdc1315fce71a2d04a/) | Mirai | Botnet/IoT | **79.7** | 🔴 KRITISCH | 29.3% | 🟡 SCHWACH ERKANNT | ✗ |
| [742c930108de89…](https://bazaar.abuse.ch/sample/742c930108de8954897c7f0e7b8d0b70464cd290a944a8257f4b8e78e368cdd3/) | SalatStealer | Infostealer | **79.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6222/7677 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6222/7677 |
| 3 | ESET-NOD32 | 77.2% | 5927/7677 |
| 4 | Kaspersky | 75.6% | 5801/7676 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5459/7674 |
| 8 | Rising | 68.3% | 5243/7677 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5076/7673 |
| 11 | Avast | 65.1% | 4995/7673 |
| 12 | AVG | 65.1% | 4995/7672 |
| 13 | Tencent | 64.9% | 4835/7451 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4695/7670 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 13 | 48.1% |
| 🪟 Windows | 10 | 37.0% |
| 📦 Archiv | 2 | 7.4% |
| 🍎 macOS | 2 | 7.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 26 | 96.3% |
| Trojanisierte Software | 1 | 3.7% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 9 | 33.3% |
| 2 | 🇫🇷 FR | 5 | 18.5% |
| 3 | 🇺🇸 US | 4 | 14.8% |
| 4 | 🇭🇺 HU | 3 | 11.1% |
| 5 | 🇨🇭 CH | 2 | 7.4% |
| 6 | 🇨🇦 CA | 1 | 3.7% |
| 7 | 🇬🇧 GB | 1 | 3.7% |
| 8 | 🇳🇱 NL | 1 | 3.7% |
| 9 | 🌐 Unbekannt | 1 | 3.7% |

## MITRE ATT&CK

> 7 von 27 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 7 |
| Lateral Movement | 7 |

<details><summary>8fdf86dc457c554f6637… – Mirai | 🔴 KRITISCH 82.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>fb4d0f15ce071bcb2636… – Mirai | 🔴 KRITISCH 82.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c8cbeb5b2d878b7ef581… – Mirai | 🔴 KRITISCH 82.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a6593d5bf995f411994c… – Mirai | 🔴 KRITISCH 82.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [72769e3630c5defaffa8…](https://bazaar.abuse.ch/sample/72769e3630c5defaffa878c5e178ba2722ca2ca0aa181bd088c185b6534b9943/)

- **Familie:** AVR trojan
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/CoinMiner.AVR trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/CoinMiner.AVR trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |

### [6f50a26febc9f01a4d63…](https://bazaar.abuse.ch/sample/6f50a26febc9f01a4d6301596b73faa9f8ba17f248a18a9791ecc9145373c3b4/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai/Linux!1.DAAB (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [bc51f4479eed583c1af9…](https://bazaar.abuse.ch/sample/bc51f4479eed583c1af96a82048128c53e421f1684e984cdc1315fce71a2d04a/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| Kingsoft | `Linux.Backdoor.Mirai.mu` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai/Linux!1.DAAB (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [058df4e80179bd59af41…](https://bazaar.abuse.ch/sample/058df4e80179bd59af41fff29844382c27b826e2b991dea9af3e075e74e89e86/)

- **Familie:** Prometei
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Application.Generic.37110862
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37110862`

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37110862` |
| Arcabit | `Application.Generic.D236444E` |
| Avira | `EXP/ELF.Agent.L.22` |
| BitDefender 🛡️ | `Application.Generic.37110862` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045451-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Application.Generic.37110862 (B)` |
| F-Secure | `Exploit.EXP/ELF.Agent.L.22` |
| GData | `Application.Generic.37110862` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Application.Generic.37110862` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37110862` |
| huorong | `Trojan/Prometei.c` |

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

- **elf** (11×)
- **Mirai** (7×)
- **exe** (6×)
- **rat** (3×)
- **zip** (2×)
- **upx** (2×)
- **AMOS** (2×)
- **ClickFix** (2×)
- **Foxveil** (2×)
- **macOS** (2×)
- **salatstealer** (2×)
- **Prometei** (2×)
- **enthec** (1×)
- **Mach-O** (1×)
- **macho** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -13 (27→14)
- ↓ **Mirai** -31 (38→7)
- ↓ **SalatStealer** -16 (19→3)
- neu: **AVR trojan** (1)
- neu: **RustyStealer** (1)
- neu: **Prometei** (1)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -17 (31→14)
- ↓ **Mirai** -14 (21→7)
- ↓ **SalatStealer** -5 (8→3)
- neu: **AVR trojan** (1)
- neu: **Prometei** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.889 MB |
| σ Dateigröße | 17.481 MB |
| Ø Risiko-Score | 63.4/100 |
| Ø Klassifikations-Konfidenz | 63.3% |
| Samples mit VT | 5/27 |
| Samples mit MITRE | 7/27 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 29 |
| Unbekannte Familien | 5 (18.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:37 | [35b63d41888e…](https://bazaar.abuse.ch/sample/35b63d41888e44520c4c3078261e1946f6b4811ad640cec6bbdd74620afb0ddd/) | `zip` | unbekannt | 32.4 | – | – | 🌐HU |
| 21:30 | [3d04c183d179…](https://bazaar.abuse.ch/sample/3d04c183d179b06f0a0e7b20fbefeef0406db487bb28f947a9cb865b8217d7af/) | `elf` | unbekannt | 43.0 | – | – | 🌐CA |
| 21:29 | [72769e3630c5…](https://bazaar.abuse.ch/sample/72769e3630c5defaffa878c5e178ba2722ca2ca0aa181bd088c185b6534b9943/) | `elf` | AVR trojan | 83.9 | 4.0% | ⚠️ KAUM ERKANNT | 🇩🇪DE |
| 20:24 | [7d969f25af3d…](https://bazaar.abuse.ch/sample/7d969f25af3d016f00dd2858f28c5f2ff166f13b85072eaa8d736885ee956068/) | `macho` | unbekannt | 31.4 | – | – | 🇺🇸US |
| 20:09 | [e84d9461947e…](https://bazaar.abuse.ch/sample/e84d9461947ee432901dbaf5e1cf2fb61c84cd53ef62a11e30a9c56ea9b50228/) | `exe` | unbekannt | 37.5 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 27.10.2026 21:57 UTC*