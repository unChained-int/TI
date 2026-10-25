# MalwareBazaar – 25.10.2026 13:02 UTC

Dieser Run hat **73 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **74** |
| Kritisch (≥75) | **44** |
| Höchster Score | **89.6/100** – aa5ce2bb4008ae02… |
| Häufigste Familie | **Mirai** (17x) |
| Häufigster Typ | **exe** (33x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 27 Samples |
| Ø Dateigröße | 6.85 MB (σ=16.45) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 33 | 44.6%  ████████ |
| `elf` | 20 | 27.0%  █████ |
| `sh` | 8 | 10.8%  ██ |
| `js` | 5 | 6.8%  █ |
| `gz` | 3 | 4.1%   |
| `macho` | 1 | 1.4%   |
| `zip` | 1 | 1.4%   |
| `vbs` | 1 | 1.4%   |
| `xls` | 1 | 1.4%   |
| `jar` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 17 | 23.0% |
| 2 | SalatStealer | 17 | 23.0% |
| 3 | unbekannt | 14 | 18.9% |
| 4 | CoinMiner | 5 | 6.8% |
| 5 | GCleaner | 2 | 2.7% |
| 6 | Formbook | 2 | 2.7% |
| 7 | AveMariaRAT | 2 | 2.7% |
| 8 | AsyncRAT | 1 | 1.4% |
| 9 | njrat | 1 | 1.4% |
| 10 | DCRat | 1 | 1.4% |
| 11 | Prometei | 1 | 1.4% |
| 12 | AMOS | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 22 | 29.7% | 78% |
| Botnet/IoT | 17 | 23.0% | 95% |
| Cryptominer | 9 | 12.2% | 75% |
| RAT | 8 | 10.8% | 88% |
| Windows-Malware | 8 | 10.8% | 35% |
| Linux-Malware | 4 | 5.4% | 45% |
| Andere / Unbekannt | 3 | 4.1% | 20% |
| Skript/Dropper | 2 | 2.7% | 35% |
| Trojaner | 1 | 1.4% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 44 | 59.5% |
| 🟠 HOCH | 13 | 17.6% |
| 🟡 MITTEL | 14 | 18.9% |
| 🟢 NIEDRIG | 3 | 4.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [aa5ce2bb4008ae…](https://bazaar.abuse.ch/sample/aa5ce2bb4008ae026c4e8b2fa3d02d0fdd296305dad0e6e4cfb4e3e92485ac9e/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [e7071b4a526059…](https://bazaar.abuse.ch/sample/e7071b4a526059a4c8898bf6c0a44dc7083662e9d888b9cec15af823d75fa269/) | njrat | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [18438ce3e58bdb…](https://bazaar.abuse.ch/sample/18438ce3e58bdbe47c9d7058ce05f456d5792d99926be82eb894fba985c567c8/) | AMOS | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [a8eb68ed1d4439…](https://bazaar.abuse.ch/sample/a8eb68ed1d443959b4e0b4d66886ce01192d989b0c9016a32d9ab705cb4e8269/) | DCRat | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [3e8b6054cb27cd…](https://bazaar.abuse.ch/sample/3e8b6054cb27cd141480a30a38c22d9815c5e1b0d41e1b6cf37198a27b48b40b/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [8e707159237532…](https://bazaar.abuse.ch/sample/8e7071592375320ab92ce93067073888890ceb3a56e76b3e3880346d9f6cd73b/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [f1848b6ba5d2c5…](https://bazaar.abuse.ch/sample/f1848b6ba5d2c5d9a1b306193c92a72a2d7698b8fa76a4178dcd144b8f326b8a/) | XWorm | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [88e7a7bb311746…](https://bazaar.abuse.ch/sample/88e7a7bb3117463591b2a6233b30f7d79abfb7f00308462b1fe2d3f8d0a1d030/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [3bec42781eeac2…](https://bazaar.abuse.ch/sample/3bec42781eeac212063fe0baf4378f862e25d431260923d76191b51c3de9e191/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [9e93b11a4a69ee…](https://bazaar.abuse.ch/sample/9e93b11a4a69ee2923d75950309ceae5cbb197ba4b7444e8f98d113705122177/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6177/7625 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6177/7625 |
| 3 | ESET-NOD32 | 77.2% | 5884/7625 |
| 4 | Kaspersky | 75.8% | 5782/7624 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5417/7622 |
| 8 | Rising | 68.3% | 5206/7625 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5042/7621 |
| 11 | Avast | 65.1% | 4959/7621 |
| 12 | AVG | 65.1% | 4959/7620 |
| 13 | Tencent | 64.8% | 4796/7399 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4665/7618 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 34 | 45.9% |
| 🐧 Linux | 30 | 40.5% |
| ❓ Unbekannt | 6 | 8.1% |
| 📦 Archiv | 2 | 2.7% |
| 🍎 macOS | 1 | 1.4% |
| 📄 Dokument | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 66 | 89.2% |
| Drive-By / Exploit-Kit | 5 | 6.8% |
| MaaS-Loader | 2 | 2.7% |
| Phishing / E-Mail-Anhang | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 20 | 27.0% |
| 2 | 🇺🇸 US | 12 | 16.2% |
| 3 | 🇳🇱 NL | 12 | 16.2% |
| 4 | 🇫🇷 FR | 12 | 16.2% |
| 5 | 🇸🇪 SE | 8 | 10.8% |
| 6 | 🇷🇺 RU | 5 | 6.8% |
| 7 | 🌐 Unbekannt | 2 | 2.7% |
| 8 | 🇮🇩 ID | 2 | 2.7% |
| 9 | 🇨🇦 CA | 1 | 1.4% |

## MITRE ATT&CK

> 27 von 74 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 17 |
| Lateral Movement | 17 |
| Collection | 4 |
| Impact | 4 |
| Command and Control | 3 |
| Execution | 2 |
| Credential Access | 2 |
| Persistence | 1 |

<details><summary>aa5ce2bb4008ae026c4e… – AsyncRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>e7071b4a526059a4c889… – njrat | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>3e8b6054cb27cd141480… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [000043e54a1e76b09d10…](https://bazaar.abuse.ch/sample/000043e54a1e76b09d109363e5677ac88896df0363c90063f1174ac5bcf7aa8c/)

- **Familie:** SalatStealer
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Alibaba | `TrojanPSW:Win32/SalatStealer.65862e04` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.D0ED693` |
| CTX | `exe.trojan.salat` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent.VO trojan` |
| Elastic | `Multi.Generic.Threat` |
| Emsisoft | `Trojan.LummaStealer.103 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `W32/Agent.VO!tr` |
| GData | `Win32.Trojan.PSE.1NVXQG7` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Convagent.gen` |
| Kingsoft | `Win32.Trojan-PSW.Convagent.gen` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Win/SalatStealer.AA` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhsyvu` |
| Paloalto | `generic.ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vaqv` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!13F9160EF413` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Banker/W32.Agent.12570112` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!13F9160EF413` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGG3Z` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAB` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.JIX` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |

### [dc8626842cd1c53c2e02…](https://bazaar.abuse.ch/sample/dc8626842cd1c53c2e02eae80e4e635bda5d9921a3553236e090e50a41313db0/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Linux/Mirai-FQVY!B5CF0AD64138
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AEP [Trj]` |
| AhnLab-V3 | `Linux/Mirai01.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-AEP [Trj]` |
| Avast-Mobile | `ELF:Mirai-OZ [Trj]` |
| Avira | `EXP/ELF.Gafgyt.Z.A` |
| ClamAV | `Unix.Trojan.Mirai-7135937-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.BE trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.Z.A` |
| Fortinet | `ELF/UNSTABLE.AT!tr.botnet` |
| Google | `Detected` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.BP!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.1343B (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FQVY!B5CF0AD64138` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Gafgyt` |
| Tencent | `Backdoor.Linux.Mirai.wcg` |
| TrellixENS | `Linux/Mirai-FQVY!B5CF0AD64138` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| Varist | `E32/Mirai.DA.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Backdoor/Linux.Mirai.q` |

### [379c62956a5aaf9e804d…](https://bazaar.abuse.ch/sample/379c62956a5aaf9e804d57fe3a05fa36251cbc2b12ec40c3903137b6d1804878/)

- **Familie:** SalatStealer
- **Erkannt von:** 45 von 75 Engines (60.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (45/75):**

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
| Bkav | `W32.Malware.476760E7` |
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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9CDA9B2E1383` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!9CDA9B2E1383` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9CDA9B2E1383` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [02a42fa633a1eec74771…](https://bazaar.abuse.ch/sample/02a42fa633a1eec747716616d3cceff4fad4ab9c7f34af069893f11e0bd2f79b/)

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (44/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.4E3317B7` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Gen:Variant.Draftor.8401` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!AC3CA5D48FC5` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!B50E99D3FB68` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!B50E99D3FB68` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| Zillya | `Trojan.AgentAGen.Win32.203200` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7AntiVirus | `Trojan ( 0001140e1 )` |
| K7GW | `Hacktool ( a007e0071 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **exe** (32×)
- **elf** (20×)
- **Mirai** (16×)
- **SalatStealer** (15×)
- **upx** (9×)
- **sh** (8×)
- **upx-dec** (8×)
- **cowrie** (6×)
- **CoinMiner** (5×)
- **js** (5×)
- **RAT** (4×)
- **cryptojacking** (4×)
- **postgresql** (4×)
- **watchdog** (4×)
- **XMRig** (4×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -1 (18→17)
- ↑ **SalatStealer** +14 (3→17)
- ↓ **unbekannt** -5 (19→14)
- ↑ **CoinMiner** +4 (1→5)
- neu: **GCleaner** (2)
- neu: **Formbook** (2)
- neu: **AveMariaRAT** (2)
- neu: **AsyncRAT** (1)
- neu: **njrat** (1)
- neu: **DCRat** (1)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -2 (19→17)
- ↑ **SalatStealer** +15 (2→17)
- ↓ **unbekannt** -23 (37→14)
- ↑ **CoinMiner** +2 (3→5)
- neu: **GCleaner** (2)
- ↑ **Formbook** +1 (1→2)
- neu: **AveMariaRAT** (2)
- neu: **AsyncRAT** (1)
- neu: **njrat** (1)
- neu: **DCRat** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.849 MB |
| σ Dateigröße | 16.451 MB |
| Ø Risiko-Score | 69.2/100 |
| Ø Klassifikations-Konfidenz | 72.4% |
| Samples mit VT | 5/74 |
| Samples mit MITRE | 27/74 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 62 |
| Unbekannte Familien | 3 (4.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:52 | [aa5ce2bb4008…](https://bazaar.abuse.ch/sample/aa5ce2bb4008ae026c4e8b2fa3d02d0fdd296305dad0e6e4cfb4e3e92485ac9e/) | `exe` | AsyncRAT | 89.6 | – | – | 🇺🇸US |
| 12:45 | [1cba4edb62bd…](https://bazaar.abuse.ch/sample/1cba4edb62bda72cc1622bdf560f7d036131454915f4bd3c42041439b17b112f/) | `exe` | GCleaner | 38.9 | – | – | 🇳🇱NL |
| 12:35 | [e7071b4a5260…](https://bazaar.abuse.ch/sample/e7071b4a526059a4c8898bf6c0a44dc7083662e9d888b9cec15af823d75fa269/) | `exe` | njrat | 89.4 | – | – | 🇳🇱NL |
| 12:21 | [3bec42781eea…](https://bazaar.abuse.ch/sample/3bec42781eeac212063fe0baf4378f862e25d431260923d76191b51c3de9e191/) | `elf` | Mirai | 83.9 | – | – | 🇩🇪DE |
| 12:21 | [9e93b11a4a69…](https://bazaar.abuse.ch/sample/9e93b11a4a69ee2923d75950309ceae5cbb197ba4b7444e8f98d113705122177/) | `elf` | Mirai | 83.9 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 13:02 UTC*