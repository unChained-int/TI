# MalwareBazaar – 24.10.2026 17:16 UTC

Dieser Run hat **25 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **26** |
| Kritisch (≥75) | **18** |
| Höchster Score | **88.6/100** – fe9c5fe06b7ec8e8… |
| Häufigste Familie | **Mirai** (11x) |
| Häufigster Typ | **elf** (12x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 14 Samples |
| Ø Dateigröße | 3.78 MB (σ=5.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 12 | 46.2%  █████████ |
| `exe` | 10 | 38.5%  ███████ |
| `jar` | 2 | 7.7%  █ |
| `ps1` | 1 | 3.8%   |
| `sh` | 1 | 3.8%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 11 | 42.3% |
| 2 | unbekannt | 10 | 38.5% |
| 3 | Win64:Evo-gen [Trj] | 1 | 3.8% |
| 4 | Stealc | 1 | 3.8% |
| 5 | AsyncRAT | 1 | 3.8% |
| 6 | SalatStealer | 1 | 3.8% |
| 7 | PythonStealer | 1 | 3.8% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 11 | 42.3% | 95% |
| Infostealer | 5 | 19.2% | 79% |
| Windows-Malware | 3 | 11.5% | 35% |
| Trojaner | 2 | 7.7% | 65% |
| Cryptominer | 2 | 7.7% | 75% |
| Skript/Dropper | 1 | 3.8% | 35% |
| RAT | 1 | 3.8% | 95% |
| Andere / Unbekannt | 1 | 3.8% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 18 | 69.2% |
| 🟠 HOCH | 3 | 11.5% |
| 🟡 MITTEL | 4 | 15.4% |
| 🟢 NIEDRIG | 1 | 3.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [fe9c5fe06b7ec8…](https://bazaar.abuse.ch/sample/fe9c5fe06b7ec8e829adc6624f9e5bc1472e4e002bccb00dd0f0172e1526e5d5/) | AsyncRAT | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [c1512ef000b9ea…](https://bazaar.abuse.ch/sample/c1512ef000b9eae519fb8e7faac4e941ef07327c927b42aaa6556020b1ff940d/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [3bc8f5abac7902…](https://bazaar.abuse.ch/sample/3bc8f5abac7902afc33890e63375ab4b0e964bbb34c5d90f62f4684c267a9a81/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [74fec4a8c642ea…](https://bazaar.abuse.ch/sample/74fec4a8c642eaa88b425fd531660e8522a5b789c26a2bf3fc75fef1031d63d9/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [5f7153d8aed32a…](https://bazaar.abuse.ch/sample/5f7153d8aed32a5f40279a229a189cd44a8a9dbb900c0dd850ceb5066ee640b4/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [691700cf605aab…](https://bazaar.abuse.ch/sample/691700cf605aab9ea038f916297067d921ef9a4d9ee7e78fc15c1d31cb1a026f/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [35dcbbd2c5315d…](https://bazaar.abuse.ch/sample/35dcbbd2c5315df0e276733792bf49c0aa44ba1a4f38e12db96662ae86c9af68/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [e9dab84cf82a21…](https://bazaar.abuse.ch/sample/e9dab84cf82a215f7e236c924f270e175bf32d0ce025eed1a7207fc07d4c3245/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [e27e963b2b49cc…](https://bazaar.abuse.ch/sample/e27e963b2b49cc758ddd65456d335d0183ca9ddc54349494d6a9f49d7c0603f4/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [5108df9e7c1bd7…](https://bazaar.abuse.ch/sample/5108df9e7c1bd7e2e252c1ea7b11d6e1e2159f70a0d8d56b0cbc1cad5a351151/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6160/7606 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6160/7606 |
| 3 | ESET-NOD32 | 77.2% | 5870/7606 |
| 4 | Kaspersky | 75.9% | 5772/7605 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5407/7603 |
| 8 | Rising | 68.3% | 5196/7606 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5033/7602 |
| 11 | Avast | 65.1% | 4947/7602 |
| 12 | AVG | 65.1% | 4947/7601 |
| 13 | Tencent | 64.9% | 4786/7380 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4654/7599 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 13 | 50.0% |
| 🪟 Windows | 11 | 42.3% |
| ❓ Unbekannt | 2 | 7.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 26 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 11 | 42.3% |
| 2 | 🇺🇸 US | 10 | 38.5% |
| 3 | 🇳🇱 NL | 3 | 11.5% |
| 4 | 🇵🇱 PL | 1 | 3.8% |
| 5 | 🌐 Unbekannt | 1 | 3.8% |

## MITRE ATT&CK

> 14 von 26 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 11 |
| Lateral Movement | 11 |
| Credential Access | 1 |
| Collection | 1 |
| Command and Control | 1 |
| Execution | 1 |
| Impact | 1 |

<details><summary>fe9c5fe06b7ec8e829ad… – AsyncRAT | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>c1512ef000b9eae519fb… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3bc8f5abac7902afc338… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>74fec4a8c642eaa88b42… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5f7153d8aed32a5f4027… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [2f8d04858dcd75554f00…](https://bazaar.abuse.ch/sample/2f8d04858dcd75554f00bb5fd9011126665f90b91428222c29897275662f6619/)

- **Familie:** Win64:Evo-gen [Trj]
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:Evo-gen [Trj]` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.8561C1E7` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Kryptik.AEJ trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/Vidar.YI!tr` |
| Google | `Detected` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| McAfeeD | `ti!2F8D04858DCD` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [63ba3a7317f12efb1090…](https://bazaar.abuse.ch/sample/63ba3a7317f12efb1090152c900234cbe86477b81ceefac2987055d289d8fe1d/)

- **Familie:** Stealc
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Stealer.1032
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Stealer.1032`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Stealer.1032` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Trojan/Win.Kryptik.C5959798` |
| Antiy-AVL | `Trojan/Win32.GenKryptik` |
| Arcabit | `Trojan.Stealer.D408` |
| Avast | `Win32:MalwareX-gen [Misc]` |
| Avira | `TR/W32.Agent` |
| BitDefender 🛡️ | `Gen:Variant.Stealer.1032` |
| Bkav | `W32.Malware.B1A67C2F` |
| CTX | `exe.unknown.stealer` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DrWeb | `Trojan.Siggen36.25818` |
| ESET-NOD32 | `Win32/GenKryptik.HSDL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Stealer.1032 (B)` |
| F-Secure | `Trojan.TR/W32.Agent` |
| Fortinet | `W32/Injector.ETZT!tr` |
| GData | `Gen:Variant.Stealer.1032` |
| Google | `Detected` |
| Ikarus | `Backdoor.Win32.Yobdam` |
| K7AntiVirus | `Trojan ( 005690671 )` |
| K7GW | `Trojan ( 005690671 )` |
| Kaspersky | `Trojan.Win32.Evilch.ap` |
| Kingsoft | `malware.kb.a.710` |
| Malwarebytes | `Malware.AI.3067252631` |
| McAfeeD | `ti!63BA3A7317F1` |
| MicroWorld-eScan | `Gen:Variant.Stealer.1032` |
| Microsoft 🛡️ | `Trojan:Win32/GCleaner.PG!MTB` |
| Rising | `Trojan.Kryptik@AI.97 (RDML:ajAlToGpyIZOi2+3qqC8ZA)` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.10c4d285` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TScope.Trojan.Delf` |
| VIPRE | `Gen:Variant.Stealer.1032` |
| Varist | `W32/Agent.MND.gen!Eldorado` |
| VirIT | `Trojan.Win32.DelphGen.IXK` |

### [4d4b4e09d271be91c568…](https://bazaar.abuse.ch/sample/4d4b4e09d271be91c5682672f9b3a1133aa8500e838d5746e87ea67e67b6132b/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Backdoor.Linux.GAFGYT.SMMR1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-AYQ [Trj]` |
| AhnLab-V3 | `Linux/Mirai07.Exp` |
| Antiy-AVL | `Trojan/Linux.Ngioweb` |
| Avast | `ELF:Agent-AYQ [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.CXJ trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.E!xp` |
| Rising | `Backdoor.Mirai/Linux!1.E816 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-ICV!93AB0DC17B79` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.le` |
| TrendMicro | `Backdoor.Linux.GAFGYT.SMMR1` |
| TrendMicro-HouseCall | `Backdoor.Linux.GAFGYT.SMMR1` |
| Varist | `E64/Agent.S.gen!Eldorado` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (12×)
- **Mirai** (11×)
- **exe** (9×)
- **stealer** (3×)
- **signed** (2×)
- **jar** (2×)
- **CoinMiner** (2×)
- **honeypot** (2×)
- **DvnX** (1×)
- **Warden** (1×)
- **WARDENStealer** (1×)
- **Yap** (1×)
- **YapStealer** (1×)
- **Stealc** (1×)
- **ps1** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -7 (18→11)
- ↓ **unbekannt** -15 (25→10)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Stealc** (1)
- neu: **AsyncRAT** (1)
- ↓ **SalatStealer** -3 (4→1)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -9 (20→11)
- ↓ **unbekannt** -29 (39→10)
- neu: **Win64:Evo-gen [Trj]** (1)
- neu: **Stealc** (1)
- neu: **AsyncRAT** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.782 MB |
| σ Dateigröße | 5.072 MB |
| Ø Risiko-Score | 71.4/100 |
| Ø Klassifikations-Konfidenz | 76.0% |
| Samples mit VT | 4/26 |
| Samples mit MITRE | 14/26 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 33 |
| Unbekannte Familien | 1 (3.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:02 | [c1512ef000b9…](https://bazaar.abuse.ch/sample/c1512ef000b9eae519fb8e7faac4e941ef07327c927b42aaa6556020b1ff940d/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 16:54 | [3bc8f5abac79…](https://bazaar.abuse.ch/sample/3bc8f5abac7902afc33890e63375ab4b0e964bbb34c5d90f62f4684c267a9a81/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 16:42 | [74fec4a8c642…](https://bazaar.abuse.ch/sample/74fec4a8c642eaa88b425fd531660e8522a5b789c26a2bf3fc75fef1031d63d9/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 16:35 | [f1f746717376…](https://bazaar.abuse.ch/sample/f1f746717376e41575fec18ad5b87b2afce1b685372b2c467880c74f324b8665/) | `exe` | unbekannt | 38.5 | – | – | 🇺🇸US |
| 16:34 | [2f8d04858dcd…](https://bazaar.abuse.ch/sample/2f8d04858dcd75554f00bb5fd9011126665f90b91428222c29897275662f6619/) | `exe` | Win64:Evo-gen [Trj] | 79.6 | 20.0% | 🟡 SCHWACH ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.10.2026 17:16 UTC*