# MalwareBazaar – 04.11.2026 23:23 UTC

Dieser Run hat **83 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **84** |
| Kritisch (≥75) | **45** |
| Höchster Score | **90.6/100** – f1a794a6fc6f33eb… |
| Häufigste Familie | **unbekannt** (28x) |
| Häufigster Typ | **elf** (22x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 28 Samples |
| Ø Dateigröße | 1.62 MB (σ=3.33) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 22 | 26.2%  █████ |
| `exe` | 18 | 21.4%  ████ |
| `ps1` | 15 | 17.9%  ███ |
| `zip` | 7 | 8.3%  █ |
| `js` | 7 | 8.3%  █ |
| `jar` | 6 | 7.1%  █ |
| `vbs` | 4 | 4.8%   |
| `bat` | 2 | 2.4%   |
| `sh` | 1 | 1.2%   |
| `lnk` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 28 | 33.3% |
| 2 | Mirai | 18 | 21.4% |
| 3 | WARDENStealer | 9 | 10.7% |
| 4 | Vidar | 4 | 4.8% |
| 5 | Silentnet | 4 | 4.8% |
| 6 | AsyncRAT | 3 | 3.6% |
| 7 | RemcosRAT | 2 | 2.4% |
| 8 | XWorm | 2 | 2.4% |
| 9 | AgentTesla | 2 | 2.4% |
| 10 | MassLogger | 2 | 2.4% |
| 11 | Trojan | 1 | 1.2% |
| 12 | RemusStealer | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 18 | 21.4% | 95% |
| Skript/Dropper | 17 | 20.2% | 35% |
| Infostealer | 16 | 19.0% | 81% |
| Andere / Unbekannt | 13 | 15.5% | 20% |
| RAT | 9 | 10.7% | 93% |
| Linux-Malware | 4 | 4.8% | 45% |
| Trojaner | 3 | 3.6% | 68% |
| Windows-Malware | 2 | 2.4% | 35% |
| Loader | 2 | 2.4% | 85% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 45 | 53.6% |
| 🟠 HOCH | 3 | 3.6% |
| 🟡 MITTEL | 23 | 27.4% |
| 🟢 NIEDRIG | 13 | 15.5% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f1a794a6fc6f33…](https://bazaar.abuse.ch/sample/f1a794a6fc6f33eb667f96e2b712e00ff5d996d0d1226b90b892a8ccfb07404b/) | Vidar | Infostealer | **90.6** | 🔴 KRITISCH | – | – | ? |
| [dc1b8b56067da9…](https://bazaar.abuse.ch/sample/dc1b8b56067da9cb0cd129571ef420a912f34338051ee60b93916de567a664d0/) | Vidar | Infostealer | **90.4** | 🔴 KRITISCH | – | – | ? |
| [4f4bc8808557df…](https://bazaar.abuse.ch/sample/4f4bc8808557df3e853c3de556995242348068b2f70e7463bbac54cf828292a4/) | Vidar | Infostealer | **90.4** | 🔴 KRITISCH | – | – | ? |
| [9cd9cdce44e323…](https://bazaar.abuse.ch/sample/9cd9cdce44e3233cf2d1e13a97f6572a21666e295ee646e89dfd99a9f6da9406/) | Vidar | Infostealer | **90.4** | 🔴 KRITISCH | – | – | ? |
| [a888b7abbc74c0…](https://bazaar.abuse.ch/sample/a888b7abbc74c0666814d452e8364bf668f429a513a1f68ab63047aa94c3d83d/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [b7964bf2bb01a5…](https://bazaar.abuse.ch/sample/b7964bf2bb01a509c1f1428ffa5e5a32eb5fc523d84847c44bab58a1ee6087e2/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [9eafdcbfc74a42…](https://bazaar.abuse.ch/sample/9eafdcbfc74a42f9479cdfecf0077b102158381ed5efb8113ee150628ebcb78c/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [81dd2cd977747b…](https://bazaar.abuse.ch/sample/81dd2cd977747b6de7fb2fa1af6c50f4dd23773681c9a9e08295172c61e457c5/) | RemcosRAT | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [6fabecf11ca4d4…](https://bazaar.abuse.ch/sample/6fabecf11ca4d4e43ec3b35276c1cbb3103f97eb26976c12d91b9a39e8c48aa6/) | XWorm | RAT | **86.1** | 🔴 KRITISCH | – | – | ? |
| [0535c0dc125655…](https://bazaar.abuse.ch/sample/0535c0dc125655cf2424c6ac0d42184208f88795e476ba4fd3091ce1f4323063/) | AsyncRAT | RAT | **86.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6337/7823 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6337/7823 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6045/7823 |
| 6 | Kaspersky | 75.5% | 5904/7822 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5566/7819 |
| 9 | Rising | 68.3% | 5340/7823 |
| 10 | Varist | 66.2% | 5172/7818 |
| 11 | Avast | 65.1% | 5087/7819 |
| 12 | AVG | 65.1% | 5087/7818 |
| 13 | Tencent | 64.9% | 4928/7597 |
| 14 | McAfeeD | 61.3% | 4794/7815 |
| 15 | huorong | 60.8% | 4755/7815 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 40 | 47.6% |
| 🐧 Linux | 24 | 28.6% |
| ❓ Unbekannt | 13 | 15.5% |
| 📦 Archiv | 7 | 8.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 74 | 88.1% |
| Drive-By / Exploit-Kit | 7 | 8.3% |
| USB / Wechselmedium | 2 | 2.4% |
| Trojanisierte Software | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 18 | 21.4% |
| 2 | 🇧🇷 BR | 14 | 16.7% |
| 3 | 🇩🇪 DE | 12 | 14.3% |
| 4 | 🇸🇪 SE | 12 | 14.3% |
| 5 | 🇺🇸 US | 7 | 8.3% |
| 6 | 🇭🇺 HU | 7 | 8.3% |
| 7 | 🇳🇱 NL | 6 | 7.1% |
| 8 | 🇪🇸 ES | 5 | 6.0% |
| 9 | 🌐 CO | 1 | 1.2% |
| 10 | 🇷🇴 RO | 1 | 1.2% |
| 11 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 28 von 84 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Collection | 7 |
| Credential Access | 5 |
| Command and Control | 5 |
| Exfiltration | 4 |
| Execution | 3 |

<details><summary>f1a794a6fc6f33eb667f… – Vidar | 🔴 KRITISCH 90.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>dc1b8b56067da9cb0cd1… – Vidar | 🔴 KRITISCH 90.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>4f4bc8808557df3e853c… – Vidar | 🔴 KRITISCH 90.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>9cd9cdce44e3233cf2d1… – Vidar | 🔴 KRITISCH 90.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>a888b7abbc74c0666814… – AsyncRAT | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ec8235b5960803d7643e…](https://bazaar.abuse.ch/sample/ec8235b5960803d7643edef94deeb503105f07fa33de1c2e949d433f4452a694/)

- **Familie:** Trojan
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Unix.Trojan.Generic-9910178-0
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ClamAV | `Unix.Trojan.Generic-9910178-0` |
| ESET-NOD32 | `Linux/Packed.Obfuscated.B suspicious application` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Backdoor.Linux.Gafgyt.uytra` |

### [d6764984fbab82394d8d…](https://bazaar.abuse.ch/sample/d6764984fbab82394d8d70d1cb02a1d2a57668a4cf14d21f4cded57a282093ab/)

- **Familie:** RemusStealer
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** malicious (high confidence)
- **VT-Reputation:** -13
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.R799895` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| ESET-NOD32 | `Win64/GenKryptik.HWSN trojan` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `VHO:Trojan.Win32.Injuke.gen` |
| McAfeeD | `Trojan:Win/StealC.NEI` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik!8.8 (TFE:3:iy7eWrPtUQR)` |
| Symantec | `ML.Attribute.HighConfidence` |
| VirIT | `Trojan.Win64.Gen_Heur.C` |
| huorong | `Trojan/Agent.cqw` |

### [cdedc5faa354c3504e91…](https://bazaar.abuse.ch/sample/cdedc5faa354c3504e918dd88a469a6391be37558e4e8cc9b461d61c883f03f2/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [d470bca281b979feb3ce…](https://bazaar.abuse.ch/sample/d470bca281b979feb3ce0e12b33b23e8bc508ab422396916bba28a10c23b4bf8/)

- **Familie:** Trojan.GenericKD.82045216
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82045216
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82045216`

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82045216` |
| Antiy-AVL | `Trojan/Win64.RemusStealer` |
| Arcabit | `Trojan.Generic.D4E3E920` |
| Avira | `TR/W64.Malware` |
| BitDefender 🛡️ | `Trojan.GenericKD.82045216` |
| CTX | `unknown.trojan.generic` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `WinGo/Kryptik.AFE trojan` |
| Emsisoft | `Trojan.GenericKD.82045216 (B)` |
| F-Secure | `Trojan.TR/W64.Malware` |
| Fortinet | `W64/RemusStealer.AAO!tr` |
| GData | `Generic.Trojan.Agent.2PBKAP` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Agent` |
| Kaspersky | `Trojan.Win64.Agent.smhwpu` |
| McAfeeD | `ti!D470BCA281B9` |
| Microsoft 🛡️ | `Trojan:Win32/Malgent` |
| Rising | `Trojan.Undefined!8.1327C (CLOUD)` |
| Sangfor | `Trojan.Win64.Agent.V6ft` |
| Sophos | `Mal/Generic-S` |
| TrellixENS | `Artemis!C9474B6B0714` |
| TrendMicro | `TrojanSpy.Win64.VIDAR.YXGKBZ` |
| TrendMicro-HouseCall | `TrojanSpy.Win64.VIDAR.YXGKBZ` |
| VIPRE | `Trojan.GenericKD.82045216` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

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

- **elf** (22×)
- **exe** (16×)
- **ps1** (15×)
- **Mirai** (14×)
- **upx** (10×)
- **Torii** (10×)
- **upx-dec** (9×)
- **WARDENStealer** (9×)
- **zip** (7×)
- **js** (7×)
- **Warden** (6×)
- **jar** (6×)
- **java** (6×)
- **RAT** (5×)
- **python** (5×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -11 (39→28)
- ↓ **Mirai** -12 (30→18)
- ↑ **WARDENStealer** +7 (2→9)
- neu: **Vidar** (4)
- neu: **Silentnet** (4)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **XWorm** +1 (1→2)
- neu: **MassLogger** (2)
- weg: **VShell** (war 3)
- weg: **PureLogsStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -2 (30→28)
- ↓ **Mirai** -2 (20→18)
- ↑ **WARDENStealer** +8 (1→9)
- neu: **Vidar** (4)
- neu: **Silentnet** (4)
- neu: **AsyncRAT** (3)
- ↑ **XWorm** +1 (1→2)
- neu: **MassLogger** (2)
- weg: **SalatStealer** (war 9)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.616 MB |
| σ Dateigröße | 3.334 MB |
| Ø Risiko-Score | 62.3/100 |
| Ø Klassifikations-Konfidenz | 63.4% |
| Samples mit VT | 5/84 |
| Samples mit MITRE | 28/84 |
| Eindeutige Familien | 20 |
| Eindeutige Tags | 61 |
| Unbekannte Familien | 13 (15.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:13 | [f1a794a6fc6f…](https://bazaar.abuse.ch/sample/f1a794a6fc6f33eb667f96e2b712e00ff5d996d0d1226b90b892a8ccfb07404b/) | `exe` | Vidar | 90.6 | – | – | 🇺🇸US |
| 23:12 | [ab77b5add3ac…](https://bazaar.abuse.ch/sample/ab77b5add3aced744d93c35efbb7f964119fb2feaa1c75eebefe1ac099bec83f/) | `exe` | WARDENStealer | 82.1 | – | – | 🇫🇷FR |
| 23:12 | [51b67895b2cf…](https://bazaar.abuse.ch/sample/51b67895b2cf359f88c0877ae8b9829fbe60840852dd5755f61495cf6a11f594/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 23:11 | [bc5765c10b18…](https://bazaar.abuse.ch/sample/bc5765c10b18ea6639cec70422dbdcf67d9f54df59cfd054eaf29ae5d8158580/) | `exe` | WARDENStealer | 82.1 | – | – | 🇫🇷FR |
| 23:10 | [567494e1c6dd…](https://bazaar.abuse.ch/sample/567494e1c6dd311e48387ce2656c13bc52f5f645ffbf89974f12f0a28dea2414/) | `exe` | WARDENStealer | 82.0 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 04.11.2026 23:23 UTC*