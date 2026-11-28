# MalwareBazaar – 28.11.2026 18:01 UTC

Dieser Run hat **68 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **69** |
| Kritisch (≥75) | **20** |
| Höchster Score | **81.4/100** – 3db94fe3fa303354… |
| Häufigste Familie | **unbekannt** (35x) |
| Häufigster Typ | **elf** (21x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 7 Samples |
| Ø Dateigröße | 10.28 MB (σ=22.71) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 21 | 30.4%  ██████ |
| `exe` | 17 | 24.6%  ████ |
| `apk` | 7 | 10.1%  ██ |
| `zip` | 5 | 7.2%  █ |
| `msi` | 4 | 5.8%  █ |
| `sh` | 3 | 4.3%   |
| `jar` | 3 | 4.3%   |
| `macho` | 2 | 2.9%   |
| `hta` | 2 | 2.9%   |
| `js` | 2 | 2.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 35 | 50.7% |
| 2 | Prometei | 11 | 15.9% |
| 3 | ConnectWise | 5 | 7.2% |
| 4 | Bombay | 3 | 4.3% |
| 5 | Mirai | 3 | 4.3% |
| 6 | SalatStealer | 3 | 4.3% |
| 7 | Expiro | 2 | 2.9% |
| 8 | WannaCry | 1 | 1.4% |
| 9 | Pony | 1 | 1.4% |
| 10 | ValleyRAT | 1 | 1.4% |
| 11 | CoinMiner | 1 | 1.4% |
| 12 | Python | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 17 | 24.6% | 45% |
| Windows-Malware | 12 | 17.4% | 35% |
| Andere / Unbekannt | 7 | 10.1% | 20% |
| Trojaner | 7 | 10.1% | 72% |
| Loader | 6 | 8.7% | 73% |
| RAT | 6 | 8.7% | 75% |
| Skript/Dropper | 4 | 5.8% | 35% |
| Botnet/IoT | 4 | 5.8% | 90% |
| Infostealer | 3 | 4.3% | 75% |
| Ransomware | 1 | 1.4% | 95% |
| Cryptominer | 1 | 1.4% | 75% |
| Backdoor | 1 | 1.4% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 20 | 29.0% |
| 🟠 HOCH | 9 | 13.0% |
| 🟡 MITTEL | 25 | 36.2% |
| 🟢 NIEDRIG | 15 | 21.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3db94fe3fa3033…](https://bazaar.abuse.ch/sample/3db94fe3fa303354cfda8061d25352b2382c335ecb72df84ab32aa0a217ae761/) | Python | Backdoor | **81.4** | 🔴 KRITISCH | 2.8% | ⚠️ KAUM ERKANNT | ✗ |
| [512aaec696e205…](https://bazaar.abuse.ch/sample/512aaec696e205d2b3b478504c3463387e4d53e50141544b915d700251bc833f/) | Mirai | Botnet/IoT | **80.5** | 🔴 KRITISCH | – | – | ? |
| [236a5409a4b4d5…](https://bazaar.abuse.ch/sample/236a5409a4b4d5a8cb2a4994cc673a2b3462e27388b4681c16b0277137b3fece/) | Script | Trojaner | **80.5** | 🔴 KRITISCH | 2.8% | ⚠️ KAUM ERKANNT | ✗ |
| [ce3fe5c7f94cc0…](https://bazaar.abuse.ch/sample/ce3fe5c7f94cc081643f94d0aa96560fbe4207a3b794dd413f35c27fa1affcca/) | Mirai | Botnet/IoT | **80.2** | 🔴 KRITISCH | – | – | ? |
| [bd02398ac7c2c0…](https://bazaar.abuse.ch/sample/bd02398ac7c2c02378cae4010e6b2936847326c7331a1aebebc01d506046a3a1/) | Mirai | Botnet/IoT | **80.2** | 🔴 KRITISCH | – | – | ? |
| [67b5613971c2b5…](https://bazaar.abuse.ch/sample/67b5613971c2b5d7f8d002f89803ad5324488151ec4c8efda003e0ec671b1788/) | ValleyRAT | RAT | **79.7** | 🔴 KRITISCH | – | – | ? |
| [155079ab793c77…](https://bazaar.abuse.ch/sample/155079ab793c77fc9d777ed6a19ba1dbfc8b1762e63d5ef63499333659a93699/) | unbekannt | Trojaner | **79.2** | 🔴 KRITISCH | – | – | ? |
| [bb865af57a169e…](https://bazaar.abuse.ch/sample/bb865af57a169e71674c398de50c389d159e817fe82b930bc9be84c70be17dc5/) | unbekannt | Trojaner | **79.2** | 🔴 KRITISCH | – | – | ? |
| [6bf4e05094f75c…](https://bazaar.abuse.ch/sample/6bf4e05094f75c75011e204734489d75e918d06d4d6d4e3cd3bdcecac50ba8d5/) | unbekannt | Trojaner | **79.2** | 🔴 KRITISCH | – | – | ? |
| [8df1b7eab9277a…](https://bazaar.abuse.ch/sample/8df1b7eab9277a4aac23ad873a3105cbbc50146787a0a1dd80e3bf15dfa70c68/) | unbekannt | Trojaner | **79.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6639/8178 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6639/8178 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6337/8178 |
| 6 | Kaspersky | 75.5% | 6172/8177 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5826/8174 |
| 9 | Rising | 68.7% | 5615/8178 |
| 10 | Varist | 66.1% | 5405/8173 |
| 11 | Tencent | 65.3% | 5191/7952 |
| 12 | Avast | 65.1% | 5321/8174 |
| 13 | AVG | 65.1% | 5321/8173 |
| 14 | McAfeeD | 61.3% | 5008/8170 |
| 15 | huorong | 61.1% | 4991/8170 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 25 | 36.2% |
| 🪟 Windows | 25 | 36.2% |
| 🤖 Android | 8 | 11.6% |
| ❓ Unbekannt | 5 | 7.2% |
| 📦 Archiv | 4 | 5.8% |
| 🍎 macOS | 2 | 2.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 50 | 72.5% |
| APK-Sideloading | 8 | 11.6% |
| MaaS-Loader | 4 | 5.8% |
| Trojanisierte Software | 4 | 5.8% |
| Drive-By / Exploit-Kit | 2 | 2.9% |
| Exploit / N-Day | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 16 | 23.2% |
| 2 | 🇩🇪 DE | 15 | 21.7% |
| 3 | 🇭🇺 HU | 13 | 18.8% |
| 4 | 🌐 UZ | 8 | 11.6% |
| 5 | 🇫🇷 FR | 5 | 7.2% |
| 6 | 🇳🇱 NL | 4 | 5.8% |
| 7 | 🇸🇬 SG | 3 | 4.3% |
| 8 | 🇪🇸 ES | 2 | 2.9% |
| 9 | 🌐 LT | 2 | 2.9% |
| 10 | 🌐 Unbekannt | 1 | 1.4% |

## MITRE ATT&CK

> 7 von 69 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 4 |
| Lateral Movement | 4 |
| Credential Access | 3 |
| Exfiltration | 3 |

<details><summary>512aaec696e205d2b3b4… – Mirai | 🔴 KRITISCH 80.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ce3fe5c7f94cc081643f… – Mirai | 🔴 KRITISCH 80.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>bd02398ac7c2c02378ca… – Mirai | 🔴 KRITISCH 80.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5005d734dfb77c2d7a11…](https://bazaar.abuse.ch/sample/5005d734dfb77c2d7a1199361bade368bb39a659f428146837837a90e92a19fa/)

- **Familie:** WannaCry
- **Erkannt von:** 57 von 72 Engines (79.2%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0147`

**Erkennende Engines (57/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0147` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Antiy-AVL | `Trojan[Exploit]/Win64.CVE-2017-0147` |
| Arcabit | `Exploit.CVE-2017-0147` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `EXP/W32.CVE-2017-01.E` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0147` |
| Bkav | `W32.Malware.F5514AEB` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.cve-2017-0147` |
| ClamAV | `Win.Ransomware.Wanna-9769986-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win64/Exploit.CVE-2017-0147.A trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Exploit.CVE-2017-0147 (B)` |
| F-Secure | `Exploit.EXP/W32.CVE-2017-01.E` |
| Fortinet | `W64/Wanna.AK!tr.ransom` |
| GData | `Exploit.CVE-2017-0147` |
| Gridinsoft | `Trojan.Win64.Downloader.oa!s1` |
| Ikarus | `Exploit.CVE-2017-0147` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan.Win32.Eb.s` |
| Kingsoft | `malware.kb.a.978` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| MaxSecure | `WannaCry.W32.040225.Ransomware.YR` |
| McAfeeD | `Trojan:Win/WannaCry.AA` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Panda | `Trj/GdSda.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Ransom!314099AE0002` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5298176` |
| Tencent | `Malware.Win32.Gencirc.11e5d4e3` |
| TrellixENS | `Ransom!314099AE0002` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-e4f863f0!Eldorado` |
| VirIT | `Ransom.Win64.GenX.IKBP` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| Zillya | `Adware.Eb.Win32.1` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `TrojanDropper/Agent.mh` |

### [3db94fe3fa303354cfda…](https://bazaar.abuse.ch/sample/3db94fe3fa303354cfda8061d25352b2382c335ecb72df84ab32aa0a217ae761/)

- **Familie:** Python
- **Erkannt von:** 2 von 72 Engines (2.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** HEUR:Backdoor.Python.Agent.gen
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/72):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Backdoor.Python.Agent.gen` |
| huorong | `TrojanSpy/Python.PwStealer.j` |

### [236a5409a4b4d5a8cb2a…](https://bazaar.abuse.ch/sample/236a5409a4b4d5a8cb2a4994cc673a2b3462e27388b4681c16b0277137b3fece/)

- **Familie:** Script
- **Erkannt von:** 2 von 72 Engines (2.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** HEUR:Trojan-Downloader.Script.Generic
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/72):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Trojan-Downloader.Script.Generic` |
| huorong | `TrojanDownloader/HTML.Agent.bk` |

### [6dec39c5070b55e66c3d…](https://bazaar.abuse.ch/sample/6dec39c5070b55e66c3d20ccd47fb8315171026b0f9e1c73747f37f9ca3786ab/)

- **Familie:** VBS
- **Erkannt von:** 3 von 72 Engines (4.2%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** BehavesLike.VBS.Dropper.zp
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/72):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Trojan-Downloader.VBS.SLoad.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Skyhigh | `BehavesLike.VBS.Dropper.zp` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **elf** (21×)
- **exe** (16×)
- **Prometei** (11×)
- **Android** (8×)
- **signed** (7×)
- **apk** (7×)
- **Banker** (5×)
- **msi** (4×)
- **zip** (4×)
- **cowrie** (4×)
- **honeypot** (4×)
- **Dropper** (4×)
- **RAT** (3×)
- **bombay** (3×)
- **drainer** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -15 (50→35)
- ↑ **Prometei** +3 (8→11)
- ↑ **ConnectWise** +3 (2→5)
- neu: **Bombay** (3)
- ↓ **Mirai** -19 (22→3)
- neu: **SalatStealer** (3)
- neu: **Expiro** (2)
- neu: **WannaCry** (1)
- neu: **Pony** (1)
- neu: **ValleyRAT** (1)
- weg: **CatStorm** (war 2)
- weg: **AsyncRAT** (war 2)
- weg: **njrat** (war 2)
- weg: **Stealer** (war 2)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -4 (39→35)
- ↑ **Prometei** +6 (5→11)
- ↑ **ConnectWise** +3 (2→5)
- neu: **Bombay** (3)
- ↓ **Mirai** -17 (20→3)
- neu: **SalatStealer** (3)
- neu: **Expiro** (2)
- neu: **WannaCry** (1)
- neu: **Pony** (1)
- weg: **njrat** (war 2)
- weg: **CatStorm** (war 2)
- weg: **Snowlight** (war 4)
- weg: **WARDENStealer** (war 3)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 10.279 MB |
| σ Dateigröße | 22.712 MB |
| Ø Risiko-Score | 52.9/100 |
| Ø Klassifikations-Konfidenz | 53.3% |
| Samples mit VT | 5/69 |
| Samples mit MITRE | 7/69 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 75 |
| Unbekannte Familien | 7 (10.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:55 | [bbd929d372f0…](https://bazaar.abuse.ch/sample/bbd929d372f02db6df058539ac5d1e9935f2559c91977c02e5ada9c70adb8124/) | `elf` | Prometei | 43.3 | – | – | 🇩🇪DE |
| 17:55 | [8549a29db452…](https://bazaar.abuse.ch/sample/8549a29db45204c5be89ba943adf577c3f21777bc6dd2dd4d14947d02a7b6b2d/) | `elf` | Prometei | 43.3 | – | – | 🇩🇪DE |
| 17:52 | [84d676414d36…](https://bazaar.abuse.ch/sample/84d676414d3611ab5d4a00304673e698098d116ec5361e1bab46c9ec67fa9e88/) | `exe` | unbekannt | 75.0 | – | – | 🌐ES |
| 17:15 | [5005d734dfb7…](https://bazaar.abuse.ch/sample/5005d734dfb77c2d7a1199361bade368bb39a659f428146837837a90e92a19fa/) | `exe` | WannaCry | 78.0 | 79.2% | ✅ GUT ERKANNT | 🇺🇸US |
| 17:10 | [4938fe6e8e0c…](https://bazaar.abuse.ch/sample/4938fe6e8e0c64341636136956ce7cf6fd63fe7219e1476b59b259783c8e9319/) | `exe` | Pony | 38.3 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.11.2026 18:01 UTC*