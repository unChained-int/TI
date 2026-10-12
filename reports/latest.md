# MalwareBazaar – 12.10.2026 22:48 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **51** |
| Höchster Score | **97.4/100** – 23bcf6f348b1e171… |
| Häufigste Familie | **unbekannt** (35x) |
| Häufigster Typ | **elf** (26x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 2 Samples |
| MITRE gemappt | 29 Samples |
| Ø Dateigröße | 3.79 MB (σ=10.51) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 26 | 25.7%  █████ |
| `jar` | 20 | 19.8%  ███ |
| `exe` | 16 | 15.8%  ███ |
| `js` | 16 | 15.8%  ███ |
| `dll` | 4 | 4.0%   |
| `vbs` | 4 | 4.0%   |
| `ps1` | 4 | 4.0%   |
| `zip` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `lnk` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 35 | 34.7% |
| 2 | Mirai | 17 | 16.8% |
| 3 | SilentNet | 15 | 14.9% |
| 4 | RemcosRAT | 6 | 5.9% |
| 5 | VIPKeylogger | 4 | 4.0% |
| 6 | XWorm | 4 | 4.0% |
| 7 | Formbook | 4 | 4.0% |
| 8 | Blackmoon | 3 | 3.0% |
| 9 | WannaCry | 2 | 2.0% |
| 10 | YoungLotus | 2 | 2.0% |
| 11 | AsyncRAT | 2 | 2.0% |
| 12 | PrintSpoofer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 22 | 21.8% | 20% |
| Botnet/IoT | 17 | 16.8% | 95% |
| RAT | 16 | 15.8% | 90% |
| Windows-Malware | 14 | 13.9% | 35% |
| Infostealer | 12 | 11.9% | 83% |
| Linux-Malware | 9 | 8.9% | 45% |
| Spyware | 4 | 4.0% | 75% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Ransomware | 2 | 2.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 51 | 50.5% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 27 | 26.7% |
| 🟢 NIEDRIG | 22 | 21.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [23bcf6f348b1e1…](https://bazaar.abuse.ch/sample/23bcf6f348b1e1713df5169efd393ec2049f0b618a593e281060c86a8785bd7e/) | WannaCry | Ransomware | **97.4** | 🔴 KRITISCH | – | – | ? |
| [b09fadd94d8416…](https://bazaar.abuse.ch/sample/b09fadd94d841637d7866f587280cfb6bfb6337d94e35c393ed5c38f5f9d5075/) | WannaCry | Ransomware | **96.5** | 🔴 KRITISCH | – | – | ? |
| [15e82adda5caf3…](https://bazaar.abuse.ch/sample/15e82adda5caf3e75a3a5e023ce8bb6e34684e519f7d0d689eae5d88e089f3e1/) | Gh0stRAT | Backdoor | **91.0** | 🔴 KRITISCH | – | – | ? |
| [ed77297087d416…](https://bazaar.abuse.ch/sample/ed77297087d4162a416fbc8c0be8359271c817798149402ce77c066b860d28a1/) | AMOS | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [8feedb12ef5da8…](https://bazaar.abuse.ch/sample/8feedb12ef5da8fb0edcfa94e86ca88b734f94bf71c9f5e68fd8244184899aff/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [a27ccdd396b465…](https://bazaar.abuse.ch/sample/a27ccdd396b4650450d0123ab4d88395301980dac4b90bfa313d99b175cd6c40/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [74d82db8de8837…](https://bazaar.abuse.ch/sample/74d82db8de883724b21017ad054b8563eca5dd2488f303d9f8a531051ec8fa5e/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [47dda33a6e37df…](https://bazaar.abuse.ch/sample/47dda33a6e37dfad19af8ea2f8734e1ac9f98cf37d3c60ced6b92a5a558129ea/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [9f3b55a3f92151…](https://bazaar.abuse.ch/sample/9f3b55a3f9215155fabe664b4ef46e3d9daacc47f401afa0b20817b64b7b2dea/) | XWorm | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [756fb4a226515d…](https://bazaar.abuse.ch/sample/756fb4a226515d1c7ffe9b6e989686c04a2a8100bab57d8d4be7e03941eabd42/) | RemcosRAT | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5936/7337 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5936/7337 |
| 3 | ESET-NOD32 | 77.4% | 5679/7337 |
| 4 | Kaspersky | 76.3% | 5599/7336 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5252/7334 |
| 8 | Rising | 68.7% | 5041/7337 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4873/7333 |
| 11 | Tencent | 65.2% | 4639/7111 |
| 12 | Avast | 65.1% | 4771/7333 |
| 13 | AVG | 65.1% | 4771/7332 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4497/7330 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 34 | 33.7% |
| 🐧 Linux | 33 | 32.7% |
| 🪟 Windows | 30 | 29.7% |
| 📦 Archiv | 3 | 3.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 76 | 75.2% |
| Drive-By / Exploit-Kit | 20 | 19.8% |
| Exploit / N-Day | 2 | 2.0% |
| USB / Wechselmedium | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 26 | 25.7% |
| 2 | 🇸🇪 SE | 24 | 23.8% |
| 3 | 🇩🇪 DE | 20 | 19.8% |
| 4 | 🇦🇹 AT | 13 | 12.9% |
| 5 | 🇳🇱 NL | 6 | 5.9% |
| 6 | 🇭🇺 HU | 6 | 5.9% |
| 7 | 🇧🇷 BR | 3 | 3.0% |
| 8 | 🇵🇱 PL | 2 | 2.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 29 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 17 |
| Lateral Movement | 17 |
| Collection | 10 |
| Command and Control | 8 |
| Credential Access | 4 |
| Execution | 2 |

<details><summary>8feedb12ef5da8fb0edc… – Formbook | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [fd793ca50146040d60bb…](https://bazaar.abuse.ch/sample/fd793ca50146040d60bbc34bf292cf579646ad811de22835a1e17b5ccd14e83a/)

- **Familie:** PrintSpoofer
- **Erkannt von:** 46 von 76 Engines (60.5%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.PrintSpoofer.1.5AA256BC
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Generic.PrintSpoofer.1.5AA256BC`

**Erkennende Engines (46/76):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.PrintSpoofer.1.5AA256BC` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Malware/Win.Generic.R537003` |
| Alibaba | `HackTool:Win32/PrintSpoofer.7ca2c03f` |
| Arcabit | `Generic.PrintSpoofer.1.5AA256BC` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/Agent.jcguh` |
| BitDefender 🛡️ | `Generic.PrintSpoofer.1.5AA256BC` |
| Bkav | `W64.AIDetectMalware` |
| CAT-QuickHeal | `Trojan.Ghanarava.171324734829a79a` |
| CTX | `exe.trojan.printspoofer` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/HackTool.Agent.X trojan` |
| Elastic | `Windows.Exploit.FakePipe` |
| Emsisoft | `Generic.PrintSpoofer.1.5AA256BC (B)` |
| F-Secure | `Trojan.TR/Agent.jcguh` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Generic.PrintSpoofer.1.5AA256BC` |
| Jiangmin | `HackTool.PrintSpoofer.bv` |
| K7AntiVirus | `Hacktool ( 005ce16d1 )` |
| K7GW | `Hacktool ( 005ce16d1 )` |
| Kaspersky | `HEUR:Exploit.Multi.Printer.gen` |
| Lionic | `Trojan.Win32.PrintSpoofer.3!c` |
| Malwarebytes | `Generic.Trojan.HackTool.DDS` |
| MaxSecure | `Trojan.Malware.119272633.susgen` |
| McAfeeD | `ti!FD793CA50146` |
| MicroWorld-eScan | `Generic.PrintSpoofer.1.5AA256BC` |
| Microsoft 🛡️ | `Exploit:Win64/CVE-2021-1675.B` |
| NANO-Antivirus | `Trojan.Win64.PrintSpoofer.kdqvdy` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Exploit.Printer!8.12946 (CLOUD)` |
| Sangfor | `Exploit.Win64.Printspoofer.V421` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `PUP-ILE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.13ad38f0` |
| TrellixENS | `PUP-ILE` |
| VIPRE | `Generic.PrintSpoofer.1.5AA256BC` |
| Zillya | `Tool.Agent.Win64.879` |
| alibabacloud | `HackTool:Win/Printspoofer` |
| huorong | `HackTool/PrintSpoofer.b` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
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
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (21×)
- **jar** (21×)
- **Mirai** (17×)
- **js** (16×)
- **exe** (14×)
- **java** (13×)
- **python** (12×)
- **silentnet** (12×)
- **RAT** (7×)
- **stealer** (7×)
- **Blackmoon** (6×)
- **dll** (6×)
- **persistence** (5×)
- **unpacked** (5×)
- **kurdishmyth** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +10 (25→35)
- ↓ **Mirai** -23 (40→17)
- neu: **SilentNet** (15)
- ↑ **RemcosRAT** +5 (1→6)
- neu: **VIPKeylogger** (4)
- neu: **XWorm** (4)
- ↑ **Formbook** +3 (1→4)
- neu: **Blackmoon** (3)
- ↑ **WannaCry** +1 (1→2)
- neu: **YoungLotus** (2)
- weg: **Gafgyt** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +5 (30→35)
- ↓ **Mirai** -22 (39→17)
- neu: **SilentNet** (15)
- ↑ **RemcosRAT** +5 (1→6)
- neu: **VIPKeylogger** (4)
- ↑ **XWorm** +3 (1→4)
- ↑ **Formbook** +3 (1→4)
- neu: **Blackmoon** (3)
- ↑ **WannaCry** +1 (1→2)
- neu: **YoungLotus** (2)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.786 MB |
| σ Dateigröße | 10.507 MB |
| Ø Risiko-Score | 59.6/100 |
| Ø Klassifikations-Konfidenz | 60.5% |
| Samples mit VT | 2/101 |
| Samples mit MITRE | 29/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 22 (21.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:43 | [16b3fd991a09…](https://bazaar.abuse.ch/sample/16b3fd991a093ceffdc966b2ef67e34e47042af7f27d9096c9ce0d64679820e5/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 22:43 | [3ed5197e70da…](https://bazaar.abuse.ch/sample/3ed5197e70da4d9867e9cf5e1fb414024b46c4c280e540b16214457022045edf/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 22:38 | [80d351949d6a…](https://bazaar.abuse.ch/sample/80d351949d6aaa4ab99ce149d7a757616df4124399e503ec6473b8331ce37fde/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 22:33 | [e33747bc8c4c…](https://bazaar.abuse.ch/sample/e33747bc8c4c2a09846c4bd73fe9cd67eff2cef9a9be1a1f3fade6964d644b18/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 22:33 | [1bad5a9a770c…](https://bazaar.abuse.ch/sample/1bad5a9a770ce72f976b551baac0e9c43153bb5b66ff35639abdb00462dd722d/) | `dll` | unbekannt | 38.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.10.2026 22:48 UTC*