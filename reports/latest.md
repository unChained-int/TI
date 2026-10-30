# MalwareBazaar – 30.10.2026 12:23 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **44** |
| Höchster Score | **88.6/100** – 19440d2263f4705c… |
| Häufigste Familie | **unbekannt** (57x) |
| Häufigster Typ | **bat** (57x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 20 Samples |
| Ø Dateigröße | 8.49 MB (σ=6.83) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `bat` | 57 | 56.4%  ███████████ |
| `elf` | 22 | 21.8%  ████ |
| `exe` | 13 | 12.9%  ██ |
| `js` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |
| `vbs` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |
| `lua` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 57 | 56.4% |
| 2 | Mirai | 19 | 18.8% |
| 3 | SalatStealer | 17 | 16.8% |
| 4 | Trojan.GenericFCA.12679 | 2 | 2.0% |
| 5 | Detected | 1 | 1.0% |
| 6 | LxBaseRAT | 1 | 1.0% |
| 7 | VShell | 1 | 1.0% |
| 8 | Prometei | 1 | 1.0% |
| 9 | AgentTesla | 1 | 1.0% |
| 10 | Formbook | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Skript/Dropper | 44 | 43.6% | 35% |
| Infostealer | 20 | 19.8% | 76% |
| Botnet/IoT | 19 | 18.8% | 95% |
| Windows-Malware | 5 | 5.0% | 35% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Linux-Malware | 3 | 3.0% | 45% |
| Trojaner | 3 | 3.0% | 65% |
| Ransomware | 2 | 2.0% | 75% |
| RAT | 2 | 2.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 44 | 43.6% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 52 | 51.5% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [19440d2263f470…](https://bazaar.abuse.ch/sample/19440d2263f4705ca92614fd9cf2c8d7a84141662a34e7d353cf0e0964c063a6/) | unbekannt | Ransomware | **88.6** | 🔴 KRITISCH | – | – | ? |
| [9814f9d8a8b129…](https://bazaar.abuse.ch/sample/9814f9d8a8b129d745d74d3069da69aaf4187146327cb615108e9ed1b5d3c58e/) | unbekannt | Ransomware | **88.6** | 🔴 KRITISCH | – | – | ? |
| [00f7650db646dc…](https://bazaar.abuse.ch/sample/00f7650db646dc56c9fb51b2d2d20f8a550a05e753a223a40e80f0bf69571504/) | Formbook | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [7cb2cc51cfa6eb…](https://bazaar.abuse.ch/sample/7cb2cc51cfa6eb8cb089013c758fba334f2a7cee579fcaba3d7a9199e0dfc352/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [e15022acca451c…](https://bazaar.abuse.ch/sample/e15022acca451c1ec2965f80b7dada39b6f4b7dd3896d40f333c73306b34dd84/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [06fd70c531fbcc…](https://bazaar.abuse.ch/sample/06fd70c531fbccfbf909b103eccf8d0e03f2465133bcbb9b9b8bb8183e4c4b2b/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [cb3254b2e4143e…](https://bazaar.abuse.ch/sample/cb3254b2e4143e16d244771beb68658b2aed297b1a9826527214a9357b2e690e/) | Detected | Trojaner | **83.6** | 🔴 KRITISCH | 4.0% | ⚠️ KAUM ERKANNT | ✗ |
| [88175d467626f9…](https://bazaar.abuse.ch/sample/88175d467626f9c0c640560847d345eb7abadf5b380e61de8d466746a3154c9d/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [a1f588d6edce8f…](https://bazaar.abuse.ch/sample/a1f588d6edce8fe5f36580acad41336c65d86eb71fa535be1805d7697a17f50c/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [5659ce381264cd…](https://bazaar.abuse.ch/sample/5659ce381264cd5a8dbacaa30f09466acc628aa45f51e6e24165f68a3e3dc162/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6261/7725 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.7% | 22/24 |
| 2 | Microsoft 🛡️ | 81.0% | 6261/7725 |
| 3 | MAX | 77.8% | 7/9 |
| 4 | ESET-NOD32 | 77.3% | 5968/7725 |
| 5 | Kaspersky | 75.5% | 5834/7724 |
| 6 | McAfee-GW-Edition | 75.0% | 3/4 |
| 7 | Google | 71.2% | 5497/7722 |
| 8 | Rising | 68.3% | 5276/7725 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5108/7721 |
| 11 | AVG | 65.2% | 5030/7720 |
| 12 | Avast | 65.1% | 5030/7721 |
| 13 | Tencent | 64.9% | 4867/7499 |
| 14 | McAfeeD | 61.2% | 4727/7718 |
| 15 | huorong | 60.8% | 4694/7718 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 71 | 70.3% |
| 🐧 Linux | 24 | 23.8% |
| ❓ Unbekannt | 4 | 4.0% |
| 📦 Archiv | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 70 | 69.3% |
| 2 | 🇩🇪 DE | 10 | 9.9% |
| 3 | 🇳🇱 NL | 10 | 9.9% |
| 4 | 🇷🇺 RU | 3 | 3.0% |
| 5 | 🇭🇺 HU | 2 | 2.0% |
| 6 | 🇫🇷 FR | 2 | 2.0% |
| 7 | 🇸🇪 SE | 1 | 1.0% |
| 8 | 🇨🇭 CH | 1 | 1.0% |
| 9 | 🇯🇵 JP | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 20 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 19 |
| Lateral Movement | 19 |
| Credential Access | 1 |
| Collection | 1 |

<details><summary>00f7650db646dc56c9fb… – Formbook | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>7cb2cc51cfa6eb8cb089… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e15022acca451c1ec296… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [cb3254b2e4143e16d244…](https://bazaar.abuse.ch/sample/cb3254b2e4143e16d244771beb68658b2aed297b1a9826527214a9357b2e690e/)

- **Familie:** Detected
- **Erkannt von:** 3 von 74 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Detected
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Varist | `E64/Coinminer.FW` |

### [e44e4ceaaa6d259e11c0…](https://bazaar.abuse.ch/sample/e44e4ceaaa6d259e11c0efe67a48b4cf86ce23528791abc5fea6600f1c5d941d/)

- **Familie:** Trojan.GenericFCA.12679
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericFCA.12679
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericFCA.12679`

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericFCA.12679` |
| Arcabit | `Trojan.GenericFCA.D3187` |
| BitDefender 🛡️ | `Trojan.GenericFCA.12679` |
| CTX | `batch.trojan.genericfca` |
| DrWeb | `BAT.MulDrop.358` |
| ESET-NOD32 | `BAT/TrojanDropper.Agent.OMO trojan` |
| Emsisoft | `Trojan.GenericFCA.12679 (B)` |
| Fortinet | `BAT/Agent.FCA!tr` |
| GData | `Trojan.GenericFCA.12679` |
| MicroWorld-eScan | `Trojan.GenericFCA.12679` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| VIPRE | `Trojan.GenericFCA.12679` |
| VirIT | `Trojan.BAT.Agent.KFX` |
| huorong | `TrojanDropper/BAT.Agent.bf` |

### [c588bd75b72c33bf6749…](https://bazaar.abuse.ch/sample/c588bd75b72c33bf6749af6661cad3a8a904e8663359375bb40de002d7e8c21c/)

- **Familie:** Mirai
- **Erkannt von:** 40 von 79 Engines (50.6%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.35304190
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (40/79):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.35304190` |
| AVG | `ELF:Mirai-AHC [Trj]` |
| Antiy-AVL | `Trojan/Linux.Mirai.a` |
| Arcabit | `Trojan.Generic.D21AB2FE` |
| Avast | `ELF:Mirai-AHC [Trj]` |
| Avira | `LINUX/Mirai.cxxwa` |
| BitDefender 🛡️ | `Trojan.GenericKD.35304190` |
| ClamAV | `Unix.Trojan.Mirai-9784385-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Siggen.9999` |
| ESET-NOD32 | `a variant of Linux/Mirai.A` |
| Emsisoft | `Trojan.GenericKD.35304190 (B)` |
| F-Secure | `Malware.LINUX/Mirai.cxxwa` |
| FireEye | `Trojan.GenericKD.35304190` |
| Fortinet | `ELF/Mirai.A!tr` |
| GData | `Trojan.GenericKD.35304190` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.r` |
| Kingsoft | `Linux.Backdoor.Mirai.b` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MAX | `malware (ai score=100)` |
| McAfee | `GenericRXMK-JM!7DA694CECEA8` |
| MicroWorld-eScan | `Trojan.GenericKD.35304190` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!MTB` |
| NANO-Antivirus | `Trojan.Elf32.Mirai.ibvzfg` |
| Rising | `Backdoor.Mirai/Linux!1.CEAD (CLOUD)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Skyhigh | `GenericRXMK-JM!7DA694CECEA8` |
| Sophos | `Linux/DDoS-CIA` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| VIPRE | `Trojan.GenericKD.35304190` |
| Varist | `E32/Mirai.OO` |
| VirIT | `Linux.Mirai.DUR` |
| Xcitium | `Malware@#nfclcys5jviw` |
| Zillya | `Trojan.Mirai.Linux.88393` |
| ZoneAlarm | `HEUR:Backdoor.Linux.Mirai.r` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.f` |

### [716a8743029934cd69fa…](https://bazaar.abuse.ch/sample/716a8743029934cd69fae1c42ec4abf8935f994545226a847370213a15b18e30/)

- **Familie:** Trojan.GenericFCA.12679
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericFCA.12679
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericFCA.12679`

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericFCA.12679` |
| Arcabit | `Trojan.GenericFCA.D3187` |
| BitDefender 🛡️ | `Trojan.GenericFCA.12679` |
| CTX | `script.trojan.generic` |
| DrWeb | `BAT.MulDrop.358` |
| ESET-NOD32 | `BAT/TrojanDropper.Agent.OMO trojan` |
| Emsisoft | `Trojan.GenericFCA.12679 (B)` |
| Fortinet | `BAT/Agent.FCA!tr` |
| GData | `Trojan.GenericFCA.12679` |
| Kingsoft | `Script.Troj.bat.2024083` |
| MicroWorld-eScan | `Trojan.GenericFCA.12679` |
| VIPRE | `Trojan.GenericFCA.12679` |
| VirIT | `Trojan.BAT.Agent.KFX` |
| huorong | `TrojanDropper/BAT.Agent.bf` |

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

- **bat** (57×)
- **elf** (21×)
- **Mirai** (16×)
- **SalatStealer** (15×)
- **exe** (12×)
- **upx** (12×)
- **upx-dec** (9×)
- **cowrie** (6×)
- **honeypot** (6×)
- **Torii** (3×)
- **js** (2×)
- **sh** (2×)
- **vbs** (1×)
- **rar** (1×)
- **wsf** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +29 (28→57)
- ↑ **Mirai** +5 (14→19)
- ↑ **SalatStealer** +7 (10→17)
- neu: **Trojan.GenericFCA.12679** (2)
- neu: **Detected** (1)
- neu: **VShell** (1)
- neu: **Prometei** (1)
- ↓ **AgentTesla** -1 (2→1)
- ↓ **Formbook** -6 (7→1)
- weg: **RemcosRAT** (war 4)
- weg: **MassLogger** (war 2)
- weg: **WannaCry** (war 2)
- weg: **CoinMiner** (war 2)
- weg: **KATARU** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +34 (23→57)
- ↓ **Mirai** -4 (23→19)
- ↑ **SalatStealer** +3 (14→17)
- neu: **Trojan.GenericFCA.12679** (2)
- neu: **Detected** (1)
- neu: **LxBaseRAT** (1)
- neu: **VShell** (1)
- neu: **Prometei** (1)
- ↓ **Formbook** -1 (2→1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.492 MB |
| σ Dateigröße | 6.833 MB |
| Ø Risiko-Score | 57.3/100 |
| Ø Klassifikations-Konfidenz | 56.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 20/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 42 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:17 | [8a8ce129b3b8…](https://bazaar.abuse.ch/sample/8a8ce129b3b8e9d9cd27fd9cb793f0e0868b67579d595f076e2ffc81d3dafce2/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 12:06 | [1f1e4e8fe8c8…](https://bazaar.abuse.ch/sample/1f1e4e8fe8c8f90542c6b95ba133be5a5b0eaf6034709d2e8b61b02b9522a9ff/) | `vbs` | unbekannt | 38.9 | – | – | 🇩🇪DE |
| 12:01 | [7cb2cc51cfa6…](https://bazaar.abuse.ch/sample/7cb2cc51cfa6eb8cb089013c758fba334f2a7cee579fcaba3d7a9199e0dfc352/) | `elf` | Mirai | 84.2 | – | – | 🇺🇸US |
| 12:00 | [a05f4ff652ea…](https://bazaar.abuse.ch/sample/a05f4ff652ead595faf098299f14c279f84873268ffca159ff8a3e1e6a713943/) | `rar` | unbekannt | 32.4 | – | – | 🌐HU |
| 11:54 | [0c94d77776c0…](https://bazaar.abuse.ch/sample/0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9/) | `wsf` | unbekannt | 32.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 30.10.2026 12:23 UTC*