# MalwareBazaar – 03.11.2026 11:43 UTC

Dieser Run hat **96 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **97** |
| Kritisch (≥75) | **59** |
| Höchster Score | **95.8/100** – 916574f7a6b66bf6… |
| Häufigste Familie | **Mirai** (22x) |
| Häufigster Typ | **exe** (29x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 35 Samples |
| Ø Dateigröße | 4.16 MB (σ=14.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 29 | 29.9%  █████ |
| `elf` | 27 | 27.8%  █████ |
| `bat` | 9 | 9.3%  █ |
| `vbs` | 9 | 9.3%  █ |
| `js` | 5 | 5.2%  █ |
| `msi` | 3 | 3.1%   |
| `rar` | 3 | 3.1%   |
| `wsf` | 2 | 2.1%   |
| `sh` | 2 | 2.1%   |
| `ps1` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 22 | 22.7% |
| 2 | unbekannt | 21 | 21.6% |
| 3 | AgentTesla | 10 | 10.3% |
| 4 | SalatStealer | 8 | 8.2% |
| 5 | Formbook | 7 | 7.2% |
| 6 | XWorm | 5 | 5.2% |
| 7 | WARDENStealer | 4 | 4.1% |
| 8 | RemcosRAT | 3 | 3.1% |
| 9 | SilentNet | 2 | 2.1% |
| 10 | NanoCore | 2 | 2.1% |
| 11 | ValleyRAT | 2 | 2.1% |
| 12 | Vjw0rm | 2 | 2.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 22 | 22.7% | 95% |
| Infostealer | 21 | 21.6% | 83% |
| RAT | 16 | 16.5% | 91% |
| Windows-Malware | 14 | 14.4% | 35% |
| Skript/Dropper | 8 | 8.2% | 35% |
| Linux-Malware | 6 | 6.2% | 45% |
| Andere / Unbekannt | 5 | 5.2% | 20% |
| Maldoc | 2 | 2.1% | 35% |
| Loader | 1 | 1.0% | 75% |
| Ransomware | 1 | 1.0% | 95% |
| Android-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 60.8% |
| 🟠 HOCH | 3 | 3.1% |
| 🟡 MITTEL | 29 | 29.9% |
| 🟢 NIEDRIG | 6 | 6.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [916574f7a6b66b…](https://bazaar.abuse.ch/sample/916574f7a6b66bf6fea909e04cbd31b744dcffb745de554e2ee595545dc62c35/) | WannaCry | Ransomware | **95.8** | 🔴 KRITISCH | – | – | ? |
| [853f51dcb03958…](https://bazaar.abuse.ch/sample/853f51dcb039588ee4b606b131da01658a52cd7f642a5a37237db909c8b14ca0/) | NanoCore | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [ecdc0af0b88a9e…](https://bazaar.abuse.ch/sample/ecdc0af0b88a9e93e7a409e510ffac0c9ae88f8e0cf314ea44ae6529fd841e3e/) | njrat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [cf22bd8e3ea7ec…](https://bazaar.abuse.ch/sample/cf22bd8e3ea7ec65e7537b4424ea6756d455f6a2aa0db6bf4e2c97bd2f776c63/) | njrat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [482489661cc06e…](https://bazaar.abuse.ch/sample/482489661cc06e8b22d952ac4cd29bf8cabeb064baea05aef6349397cccccdd0/) | Formbook | Infostealer | **87.6** | 🔴 KRITISCH | – | – | ? |
| [65e5183afe6e85…](https://bazaar.abuse.ch/sample/65e5183afe6e85b3e6efd534a2062e832691bf0091343de8f19212b703facdaf/) | Formbook | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [ba90978bc50304…](https://bazaar.abuse.ch/sample/ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [09cacaca92915a…](https://bazaar.abuse.ch/sample/09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [d2fff8c0e8477c…](https://bazaar.abuse.ch/sample/d2fff8c0e8477cc2d5228644cecc2b0b41dbd02d2cb560b2d4be7be05535462f/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [f94fe58fe411cf…](https://bazaar.abuse.ch/sample/f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6319/7798 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6319/7798 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6025/7798 |
| 6 | Kaspersky | 75.5% | 5886/7797 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5549/7794 |
| 9 | Rising | 68.3% | 5324/7798 |
| 10 | Varist | 66.2% | 5156/7793 |
| 11 | Avast | 65.1% | 5073/7794 |
| 12 | AVG | 65.1% | 5073/7793 |
| 13 | Tencent | 64.9% | 4914/7572 |
| 14 | McAfeeD | 61.3% | 4779/7790 |
| 15 | huorong | 60.9% | 4741/7790 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 54 | 55.7% |
| 🐧 Linux | 30 | 30.9% |
| ❓ Unbekannt | 6 | 6.2% |
| 📦 Archiv | 3 | 3.1% |
| 📄 Dokument | 2 | 2.1% |
| 🤖 Android | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 76 | 78.4% |
| Drive-By / Exploit-Kit | 7 | 7.2% |
| USB / Wechselmedium | 5 | 5.2% |
| Trojanisierte Software | 3 | 3.1% |
| Phishing / E-Mail-Anhang | 2 | 2.1% |
| MaaS-Loader | 2 | 2.1% |
| Exploit / N-Day | 1 | 1.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 31 | 32.0% |
| 2 | 🇦🇹 AT | 26 | 26.8% |
| 3 | 🇳🇱 NL | 14 | 14.4% |
| 4 | 🇭🇺 HU | 9 | 9.3% |
| 5 | 🇩🇪 DE | 9 | 9.3% |
| 6 | 🇫🇷 FR | 3 | 3.1% |
| 7 | 🇷🇴 RO | 2 | 2.1% |
| 8 | 🇨🇭 CH | 2 | 2.1% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 35 von 97 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 22 |
| Lateral Movement | 22 |
| Collection | 12 |
| Credential Access | 7 |
| Command and Control | 6 |
| Execution | 1 |

<details><summary>ecdc0af0b88a9e93e7a4… – njrat | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>cf22bd8e3ea7ec65e753… – njrat | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>482489661cc06e8b22d9… – Formbook | 🔴 KRITISCH 87.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a4ce5326a30b4d46a020…](https://bazaar.abuse.ch/sample/a4ce5326a30b4d46a0209b88fec2c2b618dd542606f646f0813c4797a06770f3/)

- **Familie:** BZC
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Tedy.37384` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Hack]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5947730` |
| Arcabit | `CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34 [many]` |
| Avast | `Win64:MalwareX-gen [Hack]` |
| BitDefender 🛡️ | `CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34` |
| CTX | `exe.unknown.tedy` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Remus.47` |
| ESET-NOD32 | `Win64/HackTool.Agent.QN trojan` |
| Emsisoft | `CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| GData | `CMD:Heur.BZC.PZQ.Boxter.1223.598A3B34` |
| Gridinsoft | `Trojan.Heur!.02092423` |
| Ikarus | `Program.Win32.Wacapew` |
| Kaspersky | `Trojan-Downloader.Win32.Remus.cmx` |
| Malwarebytes | `Malware.AI.61772058` |
| McAfeeD | `ti!A4CE5326A30B` |
| Rising | `HackTool.Agent!8.335 (TFE:5:9ex6Id5S9yE)` |
| Sophos | `Mal/Generic-S` |
| VBA32 | `Backdoor.Win64.RevShell` |
| VIPRE | `CMD:Heur.BZC.PZQ.Boxter.1223.5643670A` |
| Varist | `W64/ABRisk.SIIZ-2820` |

### [ab9eb8cfdc256a432204…](https://bazaar.abuse.ch/sample/ab9eb8cfdc256a43220429d9f111d941f8339babd4af147580644ac2415c9a70/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CYJ [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CYJ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CYJ [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `LINUX.AVF.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Linux/Mirai.ERM` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FQ!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.wcb` |
| Varist | `E32/Mirai.DZ.gen!Eldorado` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [5f795c3b455a4c4d379a…](https://bazaar.abuse.ch/sample/5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -1
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [48331236f584355935bf…](https://bazaar.abuse.ch/sample/48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d/)

- **Familie:** SalatStealer
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericFCA.12679
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericFCA.12679`

**Erkennende Engines (20/75):**

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
| Google | `Detected` |
| Ikarus | `Trojan.Malware` |
| Kaspersky | `Trojan-Dropper.BAT.Agent.iq` |
| Kingsoft | `Script.Troj.bat.2024083` |
| MaxSecure | `Trojan.W32.Salatloader` |
| MicroWorld-eScan | `Trojan.GenericFCA.12679` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Trojan.Maloader/BAT!9.88E9D (XSE:WFNFX0JBVDqXhhm0WpHktSYWXSqG/LSh)` |
| VIPRE | `Trojan.GenericFCA.12679` |
| VirIT | `Trojan.BAT.Agent.KFX` |
| huorong | `TrojanDropper/BAT.Agent.bf` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 56 von 75 Engines (74.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:MSIL/Nanocore!atmn`

**Erkennende Engines (56/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (39×)
- **Mirai** (17×)
- **Torii** (15×)
- **elf** (13×)
- **AgentTesla** (10×)
- **bat** (9×)
- **vbs** (9×)
- **SalatStealer** (8×)
- **Formbook** (7×)
- **RAT** (5×)
- **js** (5×)
- **XWorm** (5×)
- **upx-dec** (5×)
- **upx** (5×)
- **signed** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +16 (6→22)
- ↓ **unbekannt** -17 (38→21)
- ↑ **AgentTesla** +3 (7→10)
- ↑ **SalatStealer** +5 (3→8)
- ↑ **Formbook** +1 (6→7)
- ↑ **XWorm** +2 (3→5)
- ↑ **WARDENStealer** +2 (2→4)
- ↓ **RemcosRAT** -3 (6→3)
- neu: **SilentNet** (2)
- ↑ **NanoCore** +1 (1→2)
- weg: **GuLoader** (war 4)
- weg: **DonutLoader** (war 2)
- weg: **ConnectWise** (war 4)
- weg: **VShell** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -3 (25→22)
- ↓ **unbekannt** -7 (28→21)
- ↑ **AgentTesla** +9 (1→10)
- ↓ **SalatStealer** -3 (11→8)
- ↑ **Formbook** +5 (2→7)
- ↑ **XWorm** +4 (1→5)
- neu: **WARDENStealer** (4)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **SilentNet** +1 (1→2)
- neu: **NanoCore** (2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.159 MB |
| σ Dateigröße | 14.067 MB |
| Ø Risiko-Score | 65.2/100 |
| Ø Klassifikations-Konfidenz | 69.2% |
| Samples mit VT | 5/97 |
| Samples mit MITRE | 35/97 |
| Eindeutige Familien | 20 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 5 (5.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:28 | [dde505f27b7a…](https://bazaar.abuse.ch/sample/dde505f27b7a245044670679e49bab78c4b2629bcb56f265a0d79590327edcab/) | `msi` | unbekannt | 38.9 | – | – | 🌐HU |
| 11:23 | [1380de313395…](https://bazaar.abuse.ch/sample/1380de313395f6c8be7b99d54261ee64c2ee377457d2e717684be710498a951d/) | `ps1` | unbekannt | 38.8 | – | – | 🇺🇸US |
| 10:54 | [a4ce5326a30b…](https://bazaar.abuse.ch/sample/a4ce5326a30b4d46a0209b88fec2c2b618dd542606f646f0813c4797a06770f3/) | `exe` | BZC | 47.2 | 32.0% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 10:45 | [68d172e5d577…](https://bazaar.abuse.ch/sample/68d172e5d57758d7603c3bc9a60fea61cf5b3a530f22887077beacfb69d59b9a/) | `jar` | SilentNet | 31.9 | – | – | 🌐RO |
| 10:45 | [853f51dcb039…](https://bazaar.abuse.ch/sample/853f51dcb039588ee4b606b131da01658a52cd7f642a5a37237db909c8b14ca0/) | `exe` | NanoCore | 88.9 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 03.11.2026 11:43 UTC*