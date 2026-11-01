# MalwareBazaar – 01.11.2026 00:47 UTC

Dieser Run hat **50 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **51** |
| Kritisch (≥75) | **35** |
| Höchster Score | **84.2/100** – c54c3592e1c1bc94… |
| Häufigste Familie | **unbekannt** (28x) |
| Häufigster Typ | **exe** (25x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 14 Samples |
| Ø Dateigröße | 11.75 MB (σ=22.81) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 25 | 49.0%  █████████ |
| `elf` | 12 | 23.5%  ████ |
| `zip` | 5 | 9.8%  █ |
| `hta` | 3 | 5.9%  █ |
| `ps1` | 2 | 3.9%   |
| `dll` | 1 | 2.0%   |
| `iso` | 1 | 2.0%   |
| `7z` | 1 | 2.0%   |
| `docm` | 1 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 28 | 54.9% |
| 2 | Mirai | 12 | 23.5% |
| 3 | CoinMiner | 4 | 7.8% |
| 4 | BZC | 1 | 2.0% |
| 5 | Trojan.GenericKD.82019844 | 1 | 2.0% |
| 6 | ValleyRAT | 1 | 2.0% |
| 7 | RaspberryRobin | 1 | 2.0% |
| 8 | Tofsee | 1 | 2.0% |
| 9 | RustyStealer | 1 | 2.0% |
| 10 | SalatStealer | 1 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 21 | 41.2% | 75% |
| Botnet/IoT | 12 | 23.5% | 95% |
| Loader | 5 | 9.8% | 75% |
| Windows-Malware | 5 | 9.8% | 35% |
| Skript/Dropper | 3 | 5.9% | 35% |
| Backdoor | 2 | 3.9% | 75% |
| Trojaner | 1 | 2.0% | 65% |
| RAT | 1 | 2.0% | 75% |
| Maldoc | 1 | 2.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 35 | 68.6% |
| 🟠 HOCH | 7 | 13.7% |
| 🟡 MITTEL | 9 | 17.6% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c54c3592e1c1bc…](https://bazaar.abuse.ch/sample/c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [a0432d0a7ca04b…](https://bazaar.abuse.ch/sample/a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [586cddc7b67e1c…](https://bazaar.abuse.ch/sample/586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [19520eea568e1e…](https://bazaar.abuse.ch/sample/19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b/) | unbekannt | Backdoor | **84.0** | 🔴 KRITISCH | – | – | ? |
| [c51e37c1622bff…](https://bazaar.abuse.ch/sample/c51e37c1622bff8c874a6452c30f70f0aef59ca9f2c09cf98e8e7c406535e4f3/) | unbekannt | Backdoor | **84.0** | 🔴 KRITISCH | – | – | ? |
| [9d248e41c44dc0…](https://bazaar.abuse.ch/sample/9d248e41c44dc04235c3fa71f09bbc620e1e4cd4a488436effdfa0de47a092b7/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [3cbaae896e2ac6…](https://bazaar.abuse.ch/sample/3cbaae896e2ac678aa0a43622ab6025d3cd3f9b5bf3970feccd2662b12b15dea/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [7b026f26374a7a…](https://bazaar.abuse.ch/sample/7b026f26374a7aea28f4c4e483fe9aad004ee3a7e33d308aa3a8de0bd5dfb303/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [d35eea4fca7cf1…](https://bazaar.abuse.ch/sample/d35eea4fca7cf1b35418f3fe62f5fc442b2af9a73e8b665961f915611895d12b/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [d912ad7735ac15…](https://bazaar.abuse.ch/sample/d912ad7735ac150a5b289f5c7f4ed61971288433786c5212d329e33037a9bf5a/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6291/7760 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6291/7760 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 5998/7760 |
| 6 | Kaspersky | 75.5% | 5860/7759 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5523/7756 |
| 9 | Rising | 68.3% | 5301/7760 |
| 10 | Varist | 66.2% | 5132/7755 |
| 11 | AVG | 65.2% | 5053/7755 |
| 12 | Avast | 65.1% | 5053/7756 |
| 13 | Tencent | 64.9% | 4892/7534 |
| 14 | McAfeeD | 61.3% | 4755/7752 |
| 15 | huorong | 60.8% | 4717/7752 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 30 | 58.8% |
| 🐧 Linux | 13 | 25.5% |
| 📦 Archiv | 7 | 13.7% |
| 📄 Dokument | 1 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 36 | 70.6% |
| C2 / Nachladen | 9 | 17.6% |
| MaaS-Loader | 5 | 9.8% |
| Phishing / E-Mail-Anhang | 1 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 16 | 31.4% |
| 2 | 🌐 PT | 15 | 29.4% |
| 3 | 🇩🇪 DE | 10 | 19.6% |
| 4 | 🇺🇸 US | 5 | 9.8% |
| 5 | 🇭🇺 HU | 3 | 5.9% |
| 6 | 🇨🇦 CA | 1 | 2.0% |
| 7 | 🌐 Unbekannt | 1 | 2.0% |

## MITRE ATT&CK

> 14 von 51 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 12 |
| Lateral Movement | 12 |
| Credential Access | 2 |
| Collection | 2 |
| Exfiltration | 1 |

<details><summary>c54c3592e1c1bc94f816… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a0432d0a7ca04b53e130… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>586cddc7b67e1c2072b3… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d51568526eb146d673f4…](https://bazaar.abuse.ch/sample/d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| GData | `Linux.Trojan.Mirai.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [bc7615f394446ebec2ee…](https://bazaar.abuse.ch/sample/bc7615f394446ebec2ee732636de22153f38756f63277359ca2f78eadb07f42a/)

- **Familie:** BZC
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** CMD:Heur.BZC.PZQ.Boxter.1223.5643670A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Tedy.37384` |
| APEX | `Malicious` |
| AVG | `Script:SNH-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5947730` |
| Arcabit | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A [many]` |
| Avast | `Script:SNH-gen [Trj]` |
| BitDefender 🛡️ | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A` |
| CTX | `exe.unknown.tedy` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen36.52760` |
| Emsisoft | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A (B)` |
| F-Secure | `Trojan.TR/SNH` |
| Fortinet | `W64/Vidar.AAR!tr` |
| GData | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A` |
| Gridinsoft | `Trojan.Heur!.02092423` |
| Ikarus | `Trojan.PowerShell.DefenderDisabler` |
| Kaspersky | `HEUR:Trojan.PowerShell.DefenderDisabler.gen` |
| McAfeeD | `ti!BC7615F39444` |
| Rising | `Trojan.Agent!8.B1E (CLOUD)` |
| Sophos | `Mal/Generic-S` |
| VIPRE | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A` |
| Varist | `W64/ABmRisk.IQSH-0403` |
| VirIT | `Trojan.PS.Agent.IXR` |

### [d9fead88582068c1d964…](https://bazaar.abuse.ch/sample/d9fead88582068c1d9642a109ab73669f168e7f7a45554cda6069819baf0dde0/)

- **Familie:** Trojan.GenericKD.82019844
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82019844
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82019844`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Arcabit | `Trojan.Generic.D4E38604` |
| Avast | `MalwareX-gen [Pws]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.82019844` |
| Bkav | `W32.Malware.23F09B31` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.DownLoader51.52790` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.82019844 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/Injector.AOW!tr` |
| GData | `Win64.Trojan.Agent.BPEH80` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| K7AntiVirus | `Trojan ( 006e94c31 )` |
| K7GW | `Trojan ( 006e94c31 )` |
| Kaspersky | `Trojan.Win32.Agent.xyedyd` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!D9FEAD885820` |
| MicroWorld-eScan | `Trojan.GenericKD.82019844` |
| Microsoft 🛡️ | `Trojan:Win32/Sabsik.FL.A!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik@AI.96 (RDML:GoKh/5jSgOFkc/T85tB4HQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Skyhigh | `BehavesLike.Win64.Rootkit.th` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!3274663A19E5` |
| Varist | `W64/ABTrojan.ZYZZ-3519` |
| ViRobot | `Trojan.Win.Z.Injector.1146368` |
| Webroot | `Win.Trojan.Gen` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |
| huorong | `Trojan/Injector.aj!crit` |

### [4f64901c53e903309136…](https://bazaar.abuse.ch/sample/4f64901c53e903309136e13892c4c8a5c4c57550b08acd1ae53757ca43c7d8e5/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-FU [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-FU [Trj]` |
| AhnLab-V3 | `Linux/Mirai17.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-FU [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-DO [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Fgt.6240!tr` |
| GData | `Linux.Trojan.Mirai.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Trojan:Linux/Multiverze!rfn` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Backdoor.Linux.Mirai.wav` |
| Varist | `E32/Mirai.DZ.gen!Eldorado` |
| alibabacloud | `DDoS:Linux/Mirai.QZ` |
| huorong | `Trojan/Linux.Mirai.q` |

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

- **exe** (24×)
- **elf** (12×)
- **Mirai** (9×)
- **WARDENStealer** (7×)
- **zip** (5×)
- **CoinMiner** (5×)
- **dropped-by-WARDENStealer** (5×)
- **Torii** (4×)
- **CorvusMiner** (4×)
- **mirai** (3×)
- **dll** (3×)
- **signed** (3×)
- **dropped-by-ACRStealer** (3×)
- **191-217-210-95** (3×)
- **hta** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +7 (21→28)
- ↓ **Mirai** -15 (27→12)
- neu: **CoinMiner** (4)
- neu: **BZC** (1)
- neu: **Trojan.GenericKD.82019844** (1)
- neu: **ValleyRAT** (1)
- neu: **RaspberryRobin** (1)
- neu: **Tofsee** (1)
- ↓ **RustyStealer** -3 (4→1)
- ↓ **SalatStealer** -13 (14→1)
- weg: **WannaCry** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +4 (24→28)
- ↓ **Mirai** -13 (25→12)
- ↑ **CoinMiner** +3 (1→4)
- neu: **BZC** (1)
- neu: **Trojan.GenericKD.82019844** (1)
- neu: **ValleyRAT** (1)
- neu: **RaspberryRobin** (1)
- neu: **Tofsee** (1)
- ↓ **SalatStealer** -16 (17→1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 11.753 MB |
| σ Dateigröße | 22.806 MB |
| Ø Risiko-Score | 72.3/100 |
| Ø Klassifikations-Konfidenz | 72.3% |
| Samples mit VT | 5/51 |
| Samples mit MITRE | 14/51 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 70 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:25 | [c54c3592e1c1…](https://bazaar.abuse.ch/sample/c54c3592e1c1bc94f81646ac0051fbac4109811b21a3831f91b3a77b0d8def11/) | `elf` | Mirai | 84.2 | – | – | 🇺🇸US |
| 00:25 | [a0432d0a7ca0…](https://bazaar.abuse.ch/sample/a0432d0a7ca04b53e130a54710338385de639fe9a9cc0b858bd1649d539630e5/) | `elf` | Mirai | 84.2 | – | – | 🇺🇸US |
| 00:25 | [931195a7237f…](https://bazaar.abuse.ch/sample/931195a7237f8213f80a0a76c76a9663061793e5b74ece9975d489c0eb971e2b/) | `exe` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 00:25 | [586cddc7b67e…](https://bazaar.abuse.ch/sample/586cddc7b67e1c2072b39cc6d0669b3031ab66c0075e91f8a81b8bd92b2e5c8e/) | `elf` | Mirai | 84.2 | – | – | 🇺🇸US |
| 00:25 | [d51568526eb1…](https://bazaar.abuse.ch/sample/d51568526eb146d673f4864629f21b40d70b35f5e25b88074a8bc63719cd67a8/) | `elf` | Mirai | 79.0 | 37.3% | 🟡 SCHWACH ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 01.11.2026 00:47 UTC*