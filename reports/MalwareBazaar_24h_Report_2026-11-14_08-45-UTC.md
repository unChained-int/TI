# MalwareBazaar – 14.11.2026 08:45 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **71** |
| Höchster Score | **86.8/100** – 323912fe9add1c43… |
| Häufigste Familie | **Mirai** (67x) |
| Häufigster Typ | **elf** (69x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 68 Samples |
| Ø Dateigröße | 3.61 MB (σ=17.02) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 69 | 68.3%  █████████████ |
| `exe` | 9 | 8.9%  █ |
| `sh` | 8 | 7.9%  █ |
| `jar` | 5 | 5.0%   |
| `py` | 4 | 4.0%   |
| `ps1` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `xls` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 67 | 66.3% |
| 2 | unbekannt | 29 | 28.7% |
| 3 | WARDENStealer | 2 | 2.0% |
| 4 | Chisel | 2 | 2.0% |
| 5 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 67 | 66.3% | 95% |
| Andere / Unbekannt | 18 | 17.8% | 20% |
| Windows-Malware | 4 | 4.0% | 35% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Infostealer | 2 | 2.0% | 75% |
| Trojaner | 2 | 2.0% | 75% |
| Linux-Malware | 2 | 2.0% | 45% |
| Maldoc | 1 | 1.0% | 35% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 71 | 70.3% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 11 | 10.9% |
| 🟢 NIEDRIG | 18 | 17.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [323912fe9add1c…](https://bazaar.abuse.ch/sample/323912fe9add1c43a654a013e3184335ad70270db8bbd452851b8e5a15c7c352/) | Mirai | Botnet/IoT | **86.8** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [6c6ec81758db9f…](https://bazaar.abuse.ch/sample/6c6ec81758db9f2385cc18755eaef6586a553d17ffe0a13fe338061f42925259/) | Mirai | Botnet/IoT | **86.8** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [8a0b5db24b9d49…](https://bazaar.abuse.ch/sample/8a0b5db24b9d498af3f3ee1311a79ee7abd1bc00f42840c36e9e4a4ef6d6fda6/) | Mirai | Botnet/IoT | **86.8** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [546bc17e05773d…](https://bazaar.abuse.ch/sample/546bc17e05773d7dc061abd01ad00da45b0de68d0b10247003186488b023316b/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [77e57670562d92…](https://bazaar.abuse.ch/sample/77e57670562d923b0f86b9b1f4e802dab2b04f82766041be259244f98ceab6a9/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [555075dea0a109…](https://bazaar.abuse.ch/sample/555075dea0a1094ed5ed1d1755d41c5aa7f6f3da48df6fc39b5141a01fb4e559/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [23c3719c7f949d…](https://bazaar.abuse.ch/sample/23c3719c7f949d6074fd3505928116df52de0e95e18a0a9e8c966b276b08e4ee/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [4500024d090636…](https://bazaar.abuse.ch/sample/4500024d090636cefc7429749212b21f1608d66c002ccec8e674ab789d1b10b2/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [58aa64f6b3f0e3…](https://bazaar.abuse.ch/sample/58aa64f6b3f0e3fbb8c4dc1993933ee06b1611d4a8040dd5b92b4cf93a9fb82d/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [159ada78dbccab…](https://bazaar.abuse.ch/sample/159ada78dbccab89cc9a0f5e991b377045f90c171ffb928e1253f98858b50354/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6474/7980 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6474/7980 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6168/7980 |
| 6 | Kaspersky | 75.5% | 6023/7979 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5681/7976 |
| 9 | Rising | 68.4% | 5459/7980 |
| 10 | Varist | 66.1% | 5268/7975 |
| 11 | Avast | 65.2% | 5197/7976 |
| 12 | AVG | 65.2% | 5197/7975 |
| 13 | Tencent | 65.0% | 5039/7754 |
| 14 | McAfeeD | 61.4% | 4896/7972 |
| 15 | huorong | 60.8% | 4850/7972 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 77 | 76.2% |
| 🪟 Windows | 13 | 12.9% |
| ❓ Unbekannt | 9 | 8.9% |
| 📄 Dokument | 1 | 1.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| MaaS-Loader | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 86 | 85.1% |
| 2 | 🇸🇪 SE | 4 | 4.0% |
| 3 | 🇩🇪 DE | 4 | 4.0% |
| 4 | 🇫🇷 FR | 2 | 2.0% |
| 5 | 🇳🇱 NL | 2 | 2.0% |
| 6 | 🇧🇷 BR | 2 | 2.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 68 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 67 |
| Lateral Movement | 67 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>323912fe9add1c43a654… – Mirai | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6c6ec81758db9f2385cc… – Mirai | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>8a0b5db24b9d498af3f3… – Mirai | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>546bc17e05773d7dc061… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>77e57670562d923b0f86… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ae80863fd98d887bb70a…](https://bazaar.abuse.ch/sample/ae80863fd98d887bb70aa7f8c4ff5fa85251a4b9092699769840ea09df3a4543/)

- **Familie:** WARDENStealer
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** -60
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| APEX | `Malicious` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| Bkav | `W32.Malware.530047F5` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.DEDF!tr` |
| GData | `Gen:Variant.Yogi.85599` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `VHO:Trojan.Win32.Dllhijack.gen` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Tencent | `OB:Trojan.Win64.Shellcoderunner.16009525` |
| VIPRE | `Gen:Variant.Yogi.85599` |

### [323912fe9add1c43a654…](https://bazaar.abuse.ch/sample/323912fe9add1c43a654a013e3184335ad70270db8bbd452851b8e5a15c7c352/)

- **Familie:** Mirai
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.C!ml
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [6c6ec81758db9f2385cc…](https://bazaar.abuse.ch/sample/6c6ec81758db9f2385cc18755eaef6586a553d17ffe0a13fe338061f42925259/)

- **Familie:** Mirai
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Unix.Trojan.Mirai-10058997-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ClamAV | `Unix.Trojan.Mirai-10058997-0` |

### [8a0b5db24b9d498af3f3…](https://bazaar.abuse.ch/sample/8a0b5db24b9d498af3f3ee1311a79ee7abd1bc00f42840c36e9e4a4ef6d6fda6/)

- **Familie:** Mirai
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Static AI - Suspicious ELF
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| SentinelOne | `Static AI - Suspicious ELF` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **Mirai** (67×)
- **exe** (7×)
- **elf** (5×)
- **wraith** (3×)
- **Torii** (2×)
- **sh** (2×)
- **WARDENStealer** (2×)
- **Prometei** (2×)
- **Python** (2×)
- **TrojanDownloader** (2×)
- **WEBRAT** (2×)
- **ps1** (2×)
- **Chisel** (2×)
- **xls** (1×)
- **upx-dec** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +37 (30→67)
- ↑ **unbekannt** +3 (26→29)
- ↓ **WARDENStealer** -4 (6→2)
- neu: **Chisel** (2)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **GuLoader** (war 3)
- weg: **RevStealer** (war 6)
- weg: **AgentTesla** (war 3)
- weg: **Formbook** (war 3)
- weg: **ConnectWise** (war 2)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +37 (30→67)
- ↑ **unbekannt** +3 (26→29)
- ↓ **WARDENStealer** -2 (4→2)
- neu: **Chisel** (2)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Snowlight** (war 3)
- weg: **RevStealer** (war 2)
- weg: **SalatStealer** (war 6)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.610 MB |
| σ Dateigröße | 17.021 MB |
| Ø Risiko-Score | 68.8/100 |
| Ø Klassifikations-Konfidenz | 74.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 68/101 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 19 |
| Unbekannte Familien | 18 (17.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:36 | [1642da3f86d8…](https://bazaar.abuse.ch/sample/1642da3f86d827e935605af676efc58893250309cb7b0a64da8db1f0c64e1aa0/) | `xls` | unbekannt | 39.0 | – | – | 🌐SE |
| 08:36 | [0f167dadd71f…](https://bazaar.abuse.ch/sample/0f167dadd71faafd20d448df735d5b16567fa47b727826214f1a1629230ee61e/) | `exe` | unbekannt | 39.0 | – | – | 🌐SE |
| 08:35 | [e087bfa71a87…](https://bazaar.abuse.ch/sample/e087bfa71a879069491b2097e75a3b3301713a10715e2b544e8703b3b4a2ec9f/) | `exe` | unbekannt | 39.0 | – | – | 🌐SE |
| 08:32 | [f34256af9499…](https://bazaar.abuse.ch/sample/f34256af9499b7dd18c2c03d49cb65f99c03cc69ffbdeaf86b20f6eb7e0505d9/) | `exe` | unbekannt | 38.9 | – | – | 🌐SE |
| 08:09 | [546bc17e0577…](https://bazaar.abuse.ch/sample/546bc17e05773d7dc061abd01ad00da45b0de68d0b10247003186488b023316b/) | `elf` | Mirai | 84.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.11.2026 08:45 UTC*