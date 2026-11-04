# MalwareBazaar – 04.11.2026 17:50 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **57** |
| Höchster Score | **90.7/100** – d5d1992604bf015d… |
| Häufigste Familie | **unbekannt** (33x) |
| Häufigster Typ | **elf** (37x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 32 Samples |
| Ø Dateigröße | 6.36 MB (σ=18.78) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 37 | 36.6%  ███████ |
| `exe` | 29 | 28.7%  █████ |
| `js` | 10 | 9.9%  █ |
| `vbe` | 4 | 4.0%   |
| `vbs` | 4 | 4.0%   |
| `ps1` | 4 | 4.0%   |
| `zip` | 3 | 3.0%   |
| `bat` | 2 | 2.0%   |
| `msi` | 2 | 2.0%   |
| `doc` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 33 | 32.7% |
| 2 | Mirai | 25 | 24.8% |
| 3 | PureLogsStealer | 5 | 5.0% |
| 4 | Formbook | 4 | 4.0% |
| 5 | AgentTesla | 4 | 4.0% |
| 6 | XWorm | 3 | 3.0% |
| 7 | LxBaseRAT | 2 | 2.0% |
| 8 | RemcosRAT | 2 | 2.0% |
| 9 | DonutLoader | 2 | 2.0% |
| 10 | RustyStealer | 2 | 2.0% |
| 11 | SalatStealer | 2 | 2.0% |
| 12 | DCRat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 26 | 25.7% | 95% |
| Infostealer | 17 | 16.8% | 80% |
| Windows-Malware | 16 | 15.8% | 35% |
| RAT | 11 | 10.9% | 87% |
| Linux-Malware | 9 | 8.9% | 45% |
| Skript/Dropper | 8 | 7.9% | 35% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Loader | 3 | 3.0% | 88% |
| Trojaner | 2 | 2.0% | 65% |
| Maldoc | 1 | 1.0% | 35% |
| Post-Exploitation | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 57 | 56.4% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 20 | 19.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [d5d1992604bf01…](https://bazaar.abuse.ch/sample/d5d1992604bf015d84b17710dc510ea6dd54c908445590e3ae5f0d35404d1790/) | Sliver | Post-Exploitat | **90.7** | 🔴 KRITISCH | – | – | ? |
| [b15e44bcb245ee…](https://bazaar.abuse.ch/sample/b15e44bcb245ee99bfbe2e500f20327868dc6a153f12d5f89d5fe0ffa149ce0f/) | DCRat | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [78bb8d2beb60bf…](https://bazaar.abuse.ch/sample/78bb8d2beb60bf28a7b6138dce4eca11bb5eabbe5ffa9015c302f510e642ed89/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [1ac71717899532…](https://bazaar.abuse.ch/sample/1ac717178995324e065590db5c4ebe43bb8dfce752b79f65f2e2e2702ac062e7/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [df13860b349b8e…](https://bazaar.abuse.ch/sample/df13860b349b8e4d674c02c53bbf1244e66db91f7431d866ae48adeec310cebb/) | XWorm | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [5e602fee9d46f5…](https://bazaar.abuse.ch/sample/5e602fee9d46f5c8f756e1b7d86b738ae7b3e6814ec83b40137ebe0966efc3ea/) | RemcosRAT | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [ee95d8904b4b06…](https://bazaar.abuse.ch/sample/ee95d8904b4b060eab664eae7174bdac8a4d9ce285bca2d00cf1ec95b1a442d0/) | XWorm | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [112d3c74ac9de3…](https://bazaar.abuse.ch/sample/112d3c74ac9de3d4f50db68e4386f126ae9442ee0c543922d9d6ed9dd1353c06/) | XWorm | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [e801820dc15bd2…](https://bazaar.abuse.ch/sample/e801820dc15bd2986ba90b05146915d3f79197c39d71c279c8f283a4f48f6ba9/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [846f99ae975964…](https://bazaar.abuse.ch/sample/846f99ae97596408069270acd2bdff9d45a3c23d547040c65d23348da50b0f9c/) | Formbook | Infostealer | **86.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6334/7818 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6334/7818 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6041/7818 |
| 6 | Kaspersky | 75.5% | 5901/7817 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5564/7814 |
| 9 | Rising | 68.3% | 5337/7818 |
| 10 | Varist | 66.2% | 5170/7813 |
| 11 | Avast | 65.1% | 5086/7814 |
| 12 | AVG | 65.1% | 5086/7813 |
| 13 | Tencent | 64.9% | 4926/7592 |
| 14 | McAfeeD | 61.3% | 4791/7810 |
| 15 | huorong | 60.9% | 4753/7810 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 39 | 38.6% |
| 🐧 Linux | 39 | 38.6% |
| ❓ Unbekannt | 18 | 17.8% |
| 📦 Archiv | 3 | 3.0% |
| 📄 Dokument | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 83 | 82.2% |
| Drive-By / Exploit-Kit | 11 | 10.9% |
| USB / Wechselmedium | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 24.8% |
| 2 | 🇸🇪 SE | 24 | 23.8% |
| 3 | 🇫🇷 FR | 13 | 12.9% |
| 4 | 🇦🇹 AT | 8 | 7.9% |
| 5 | 🇺🇸 US | 8 | 7.9% |
| 6 | 🇭🇺 HU | 7 | 6.9% |
| 7 | 🇳🇱 NL | 6 | 5.9% |
| 8 | 🇮🇳 IN | 2 | 2.0% |
| 9 | 🇮🇩 ID | 2 | 2.0% |
| 10 | 🌐 EG | 2 | 2.0% |
| 11 | 🇨🇭 CH | 1 | 1.0% |
| 12 | 🇪🇸 ES | 1 | 1.0% |
| 13 | 🇨🇦 CA | 1 | 1.0% |
| 14 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 32 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 26 |
| Lateral Movement | 26 |
| Collection | 6 |
| Credential Access | 4 |
| Command and Control | 2 |

<details><summary>78bb8d2beb60bf28a7b6… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>1ac717178995324e0655… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [781f62766df11733a887…](https://bazaar.abuse.ch/sample/781f62766df11733a88794e7ed5193b9173b8dc012c71131ecbdfe056cb1b249/)

- **Familie:** ELF:Agent-ETO [Trj]
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Avast | `ELF:Agent-ETO [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OZ trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Kaiji` |

### [265994409a3dbd511ff5…](https://bazaar.abuse.ch/sample/265994409a3dbd511ff5bd6a6d24dea5b089d41f1dea8dcaeaabccd530ea09dd/)

- **Familie:** Yogi
- **Erkannt von:** 47 von 75 Engines (62.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.86304
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.86304`

**Erkennende Engines (47/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.86304` |
| AVG | `Win64:MalwareX-gen [Hack]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5946861` |
| Alibaba | `HackTool:Win64/Knotweed.0b3a7d2d` |
| Antiy-AVL | `HackTool/Win64.Knotweed` |
| Arcabit | `Trojan.Yogi.D15120` |
| Avast | `Win64:MalwareX-gen [Hack]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.86304` |
| Bkav | `W32.Malware.8EAC924A` |
| CAT-QuickHeal | `HackTool.Win64` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Agent.CFJ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.86304 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/MALD2.81B7!tr` |
| GData | `Gen:Variant.Yogi.86304` |
| K7AntiVirus | `Hacktool ( 006e83f71 )` |
| K7GW | `Hacktool ( 006e83f71 )` |
| Kaspersky | `HackTool.Win64.Knotweed.cma` |
| Lionic | `Hacktool.Win32.Knotweed.3!c` |
| Malwarebytes | `Trojan.FakeMS` |
| MaxSecure | `Trojan.Malware.218555844.susgen` |
| McAfeeD | `ti!265994409A3D` |
| MicroWorld-eScan | `Gen:Variant.Yogi.86304` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Agent!8.B1E (TFE:1:hQrGGr5K77F)` |
| Sangfor | `Trojan.Win64.Agent.Vzt7` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006146` |
| TrellixENS | `Artemis!089AEF70772C` |
| TrendMicro | `Backdoor.Win32.KNOTWEED.USBLIR26` |
| TrendMicro-HouseCall | `Backdoor.Win32.KNOTWEED.USBLIR26` |
| VIPRE | `Gen:Variant.Yogi.86304` |
| Varist | `W64/ABTrojan.EUXD-7217` |
| Webroot | `W32.Trojan.Gen` |
| Zillya | `Trojan.Agent.Win64.286740` |
| alibabacloud | `HackTool:Win/Agent_AGen.RWG` |
| huorong | `Trojan/W64.Loader.bq` |

### [ae992ffe474500cd5c28…](https://bazaar.abuse.ch/sample/ae992ffe474500cd5c28922ac75f8fbc18a947d4e6565cedc221b9e979add806/)

- **Familie:** Malware
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.D2C0F9FE
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.D2C0F9FE` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `UDS:Trojan.Win64.Generic` |

### [765f42e351b17c6a36f8…](https://bazaar.abuse.ch/sample/765f42e351b17c6a36f85bebe587f501696faea748f6d8271623747b465f38e3/)

- **Familie:** malicious (moderate confidence
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** malicious (moderate confidence)
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Python.Downloader.274` |
| Elastic | `malicious (moderate confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.NSIS.Tipikal` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Trapmine | `suspicious.low.ml.score` |
| VirIT | `Trojan.Win32.Genus.DTDA` |
| alibabacloud | `Trojan[dropper]:Win/Wacatac.B9nj` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
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
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (30×)
- **exe** (26×)
- **Mirai** (25×)
- **Torii** (11×)
- **js** (10×)
- **cowrie** (7×)
- **honeypot** (7×)
- **arm** (6×)
- **upx-dec** (5×)
- **upx** (5×)
- **PureLogsStealer** (5×)
- **vbe** (4×)
- **Formbook** (4×)
- **AgentTesla** (4×)
- **ps1** (4×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -3 (36→33)
- ↑ **Mirai** +1 (24→25)
- ↑ **PureLogsStealer** +4 (1→5)
- ↑ **AgentTesla** +3 (1→4)
- neu: **XWorm** (3)
- neu: **LxBaseRAT** (2)
- neu: **DonutLoader** (2)
- neu: **RustyStealer** (2)
- weg: **Silentnet** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **WARDENStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +3 (30→33)
- ↑ **Mirai** +3 (22→25)
- neu: **PureLogsStealer** (5)
- ↑ **Formbook** +1 (3→4)
- ↑ **AgentTesla** +2 (2→4)
- ↑ **XWorm** +2 (1→3)
- neu: **LxBaseRAT** (2)
- neu: **DonutLoader** (2)
- ↑ **RustyStealer** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.358 MB |
| σ Dateigröße | 18.778 MB |
| Ø Risiko-Score | 62.7/100 |
| Ø Klassifikations-Konfidenz | 66.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 32/101 |
| Eindeutige Familien | 28 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:20 | [b15e44bcb245…](https://bazaar.abuse.ch/sample/b15e44bcb245ee99bfbe2e500f20327868dc6a153f12d5f89d5fe0ffa149ce0f/) | `exe` | DCRat | 89.3 | – | – | 🇳🇱NL |
| 17:15 | [4f54d288f1af…](https://bazaar.abuse.ch/sample/4f54d288f1afc013221f07f26ea33482addca8ecaff187891e1955f7f2aefcd7/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 16:59 | [111e83dc9ddd…](https://bazaar.abuse.ch/sample/111e83dc9ddd1770e104604ec5cd59ccc91d37603166cdf00f71129f537fcf04/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 16:48 | [7c841119c953…](https://bazaar.abuse.ch/sample/7c841119c9535d54b25b915bd97c30c6808f43c8f25198ba683bf456da143438/) | `elf` | unbekannt | 42.4 | – | – | 🇩🇪DE |
| 16:32 | [977e7f13d213…](https://bazaar.abuse.ch/sample/977e7f13d2135fff14aaaf04a9ca1905329646a1ec87330eb1c66e1f1ad9dca3/) | `zip` | unbekannt | 31.6 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 04.11.2026 17:50 UTC*