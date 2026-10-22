# MalwareBazaar – 22.10.2026 23:03 UTC

Dieser Run hat **52 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **53** |
| Kritisch (≥75) | **31** |
| Höchster Score | **88.6/100** – 46e7e61e0f518b19… |
| Häufigste Familie | **unbekannt** (24x) |
| Häufigster Typ | **elf** (26x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 5.36 MB (σ=11.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 26 | 49.1%  █████████ |
| `exe` | 15 | 28.3%  █████ |
| `js` | 3 | 5.7%  █ |
| `zip` | 3 | 5.7%  █ |
| `sh` | 2 | 3.8%   |
| `msi` | 2 | 3.8%   |
| `apk` | 1 | 1.9%   |
| `rar` | 1 | 1.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 24 | 45.3% |
| 2 | Mirai | 18 | 34.0% |
| 3 | ConnectWise | 3 | 5.7% |
| 4 | RemusStealer | 1 | 1.9% |
| 5 | MalwareX-gen [Pws] | 1 | 1.9% |
| 6 | p | 1 | 1.9% |
| 7 | RemcosRAT | 1 | 1.9% |
| 8 | Win64 | 1 | 1.9% |
| 9 | DCRat | 1 | 1.9% |
| 10 | Formbook | 1 | 1.9% |
| 11 | PythonStealer | 1 | 1.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 18 | 34.0% | 95% |
| Infostealer | 8 | 15.1% | 78% |
| Windows-Malware | 6 | 11.3% | 35% |
| Linux-Malware | 5 | 9.4% | 45% |
| Andere / Unbekannt | 5 | 9.4% | 20% |
| RAT | 3 | 5.7% | 88% |
| Loader | 2 | 3.8% | 65% |
| Backdoor | 2 | 3.8% | 75% |
| Android-Malware | 1 | 1.9% | 45% |
| Skript/Dropper | 1 | 1.9% | 35% |
| Cryptominer | 1 | 1.9% | 75% |
| Trojaner | 1 | 1.9% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 31 | 58.5% |
| 🟠 HOCH | 4 | 7.5% |
| 🟡 MITTEL | 13 | 24.5% |
| 🟢 NIEDRIG | 5 | 9.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [46e7e61e0f518b…](https://bazaar.abuse.ch/sample/46e7e61e0f518b191b94cfab6ef0c162209fda278615a22640701072cce545f9/) | RemcosRAT | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [a328a6ad3f17e7…](https://bazaar.abuse.ch/sample/a328a6ad3f17e7a74aba6a84d28c5b4bf46a732136f57a821ca646287b258e28/) | Formbook | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [28b73ce836e196…](https://bazaar.abuse.ch/sample/28b73ce836e196ccd13ceea6427928204e5c4f4da4e30d22a86b062eef4d72f9/) | DCRat | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [74fd8f8e014d46…](https://bazaar.abuse.ch/sample/74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [b9b00a11b0bdec…](https://bazaar.abuse.ch/sample/b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [b8529448ca17ba…](https://bazaar.abuse.ch/sample/b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [0cbe035f544844…](https://bazaar.abuse.ch/sample/0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [c266ce7a2343af…](https://bazaar.abuse.ch/sample/c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [42a052758f12f8…](https://bazaar.abuse.ch/sample/42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [7e8b2f481f827c…](https://bazaar.abuse.ch/sample/7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6124/7562 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6124/7562 |
| 3 | ESET-NOD32 | 77.3% | 5844/7562 |
| 4 | Kaspersky | 76.0% | 5748/7561 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5388/7559 |
| 8 | Rising | 68.5% | 5178/7562 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5005/7558 |
| 11 | AVG | 65.3% | 4931/7557 |
| 12 | Avast | 65.2% | 4931/7558 |
| 13 | Tencent | 65.0% | 4769/7336 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4628/7555 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 28 | 52.8% |
| 🪟 Windows | 18 | 34.0% |
| 📦 Archiv | 4 | 7.5% |
| ❓ Unbekannt | 2 | 3.8% |
| 🤖 Android | 1 | 1.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 47 | 88.7% |
| Drive-By / Exploit-Kit | 3 | 5.7% |
| Trojanisierte Software | 2 | 3.8% |
| APK-Sideloading | 1 | 1.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 23 | 43.4% |
| 2 | 🇺🇸 US | 21 | 39.6% |
| 3 | 🇭🇺 HU | 3 | 5.7% |
| 4 | 🇳🇱 NL | 2 | 3.8% |
| 5 | 🇬🇧 GB | 2 | 3.8% |
| 6 | 🇫🇷 FR | 1 | 1.9% |
| 7 | 🌐 Unbekannt | 1 | 1.9% |

## MITRE ATT&CK

> 21 von 53 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Collection | 2 |
| Impact | 2 |
| Command and Control | 1 |
| Credential Access | 1 |

<details><summary>46e7e61e0f518b191b94… – RemcosRAT | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>a328a6ad3f17e7a74aba… – Formbook | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>74fd8f8e014d46d84e66… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b9b00a11b0bdecee5e9e… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [92774f66be66de1cbab4…](https://bazaar.abuse.ch/sample/92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d/)

- **Familie:** MalwareX-gen [Pws]
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.11915215` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:QoSuDHGNKSObXDZ4zvmh8g)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [49ba06ed9ad582141964…](https://bazaar.abuse.ch/sample/49ba06ed9ad58214196441b05030b9f03e30621a366148f19998ecb587b666b6/)

- **Familie:** Mirai
- **Erkannt von:** 33 von 75 Engines (44.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** ELF:Gafgyt-KS [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (33/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-KS [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.XE228` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-KS [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| ClamAV | `Unix.Trojan.Mirai-9441505-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.CVA trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF/Mirai.CVA!tr` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.E!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FROZ!F9F2B8AF0B1F` |
| Sophos | `Linux/DDoS-FP` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `Linux/Mirai-FROZ!F9F2B8AF0B1F` |
| TrendMicro | `Backdoor.Linux.BASHLITE.SMJC11` |
| TrendMicro-HouseCall | `Backdoor.Linux.BASHLITE.SMJC11` |
| Varist | `E32/Mirai.DJ.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-FP` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [4a1349dfc0edd9acaaef…](https://bazaar.abuse.ch/sample/4a1349dfc0edd9acaaef62d11e4a3cde0ab4bc97db9cc8f993fa83f9de188f13/)

- **Familie:** p
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/Downloader.p
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Downloader/Shell.Generic.S2596` |
| Avira | `HTML/ExpKit.Gen2` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.37` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| Fortinet | `BASH/Dloader.P!tr` |
| Google | `Detected` |
| Ikarus | `HTML.ExploitKit` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Downloader.Mirai/BASH!9.4B1A0 (XSE:WFNFX0JBVDp42gYyY8g/PIwwCKX/ihRE)` |
| Sangfor | `Trojan.Generic-Script.Save.ba608` |
| Skyhigh | `Linux/Downloader.p` |
| Symantec | `CL.Downloader!gen277` |
| TrellixENS | `Linux/Downloader.p` |
| TrendMicro | `Possible_BASHDLOD.SMLBO1` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBO1` |
| Varist | `SH/Mirai.C.gen!Camelot` |
| huorong | `TrojanDownloader/Linux.Shell.ai` |

### [67c10a4f7db7fe55953b…](https://bazaar.abuse.ch/sample/67c10a4f7db7fe55953b9b57492d4e6aa9cf0e20f492d193328def2662840c97/)

- **Familie:** Win64
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** BehavesLike.Win64.Dropper.vt
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| McAfeeD | `ti!67C10A4F7DB7` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| Skyhigh | `BehavesLike.Win64.Dropper.vt` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!D202C2B177C6` |

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

- **elf** (26×)
- **Mirai** (18×)
- **exe** (15×)
- **stealer** (7×)
- **DvnX** (6×)
- **signed** (5×)
- **Warden** (5×)
- **WARDENStealer** (5×)
- **Yap** (5×)
- **YapStealer** (5×)
- **js** (3×)
- **ConnectWise** (3×)
- **zip** (3×)
- **RemusStealer** (2×)
- **sh** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -31 (55→24)
- ↑ **Mirai** +3 (15→18)
- neu: **ConnectWise** (3)
- neu: **RemusStealer** (1)
- neu: **MalwareX-gen [Pws]** (1)
- neu: **p** (1)
- ↓ **RemcosRAT** -2 (3→1)
- neu: **Win64** (1)
- neu: **DCRat** (1)
- weg: **CoinMiner** (war 14)
- weg: **Kaiji** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -16 (40→24)
- ↓ **Mirai** -4 (22→18)
- neu: **ConnectWise** (3)
- neu: **MalwareX-gen [Pws]** (1)
- neu: **p** (1)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **Win64** (1)
- neu: **DCRat** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.359 MB |
| σ Dateigröße | 11.068 MB |
| Ø Risiko-Score | 66.5/100 |
| Ø Klassifikations-Konfidenz | 68.5% |
| Samples mit VT | 5/53 |
| Samples mit MITRE | 21/53 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 36 |
| Unbekannte Familien | 5 (9.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:58 | [74fd8f8e014d…](https://bazaar.abuse.ch/sample/74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 22:55 | [b9b00a11b0bd…](https://bazaar.abuse.ch/sample/b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 22:34 | [b8529448ca17…](https://bazaar.abuse.ch/sample/b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 22:29 | [0cbe035f5448…](https://bazaar.abuse.ch/sample/0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 22:28 | [a9892231ad05…](https://bazaar.abuse.ch/sample/a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf/) | `exe` | RemusStealer | 81.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.10.2026 23:03 UTC*