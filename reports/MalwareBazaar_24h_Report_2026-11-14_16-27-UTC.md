# MalwareBazaar – 14.11.2026 16:27 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **88** |
| Höchster Score | **93.9/100** – 690638f098adb2a5… |
| Häufigste Familie | **Mirai** (62x) |
| Häufigster Typ | **elf** (64x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 70 Samples |
| Ø Dateigröße | 5.14 MB (σ=22.86) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 64 | 63.4%  ████████████ |
| `exe` | 29 | 28.7%  █████ |
| `js` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `vbs` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 62 | 61.4% |
| 2 | unbekannt | 10 | 9.9% |
| 3 | WARDENStealer | 7 | 6.9% |
| 4 | SalatStealer | 6 | 5.9% |
| 5 | njrat | 4 | 4.0% |
| 6 | RemusStealer | 3 | 3.0% |
| 7 | Vidar | 2 | 2.0% |
| 8 | AsyncRAT | 1 | 1.0% |
| 9 | RustyStealer | 1 | 1.0% |
| 10 | Patchwork | 1 | 1.0% |
| 11 | Panchan | 1 | 1.0% |
| 12 | WannaCry | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 62 | 61.4% | 95% |
| Infostealer | 20 | 19.8% | 77% |
| RAT | 6 | 5.9% | 95% |
| Windows-Malware | 4 | 4.0% | 35% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Linux-Malware | 1 | 1.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 88 | 87.1% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 8 | 7.9% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [690638f098adb2…](https://bazaar.abuse.ch/sample/690638f098adb2a5940c2409a412626fb95aa6bfb38a3b9c151008fb99274391/) | WannaCry | Ransomware | **93.9** | 🔴 KRITISCH | – | – | ? |
| [0e5e6d03bf59d4…](https://bazaar.abuse.ch/sample/0e5e6d03bf59d4f929b6585e2d284d84d448b946ebe28a0ba6f21d81a25c0bca/) | Vidar | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [7c2c2e9b864f38…](https://bazaar.abuse.ch/sample/7c2c2e9b864f38e2b915cb87250f51b2a88b95b3a8737fd9588107da125e9b7e/) | Vidar | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [fc84ea86574c7b…](https://bazaar.abuse.ch/sample/fc84ea86574c7ba49fd45a223f667905bf7d0cf201b35848c50078b061722747/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [30161f3b7d0ce2…](https://bazaar.abuse.ch/sample/30161f3b7d0ce2c86522cec3a4e97ea2b2a8065eddddfda258d80606da3af449/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [e8c4ac6ff2aa1b…](https://bazaar.abuse.ch/sample/e8c4ac6ff2aa1bebaa07311ba9d6d993d49966daf5b050bf3e911fe926a4f251/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [3cbe356f710667…](https://bazaar.abuse.ch/sample/3cbe356f710667bb1673a36ee74e3d241f3d7680207cfddfa56c72afa74c80fb/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [9f0346d0bb09ea…](https://bazaar.abuse.ch/sample/9f0346d0bb09eae27177b9f5f44efcab33ab6e1cd4782bf815b6dd94cb11d7fa/) | njrat | RAT | **88.4** | 🔴 KRITISCH | – | – | ? |
| [f736f7457ddf4b…](https://bazaar.abuse.ch/sample/f736f7457ddf4ba1f4ad083dd88f3f2e0dae29d69f7fe381b4ee07c7f1890639/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [f808ddc9479b81…](https://bazaar.abuse.ch/sample/f808ddc9479b816c35f7b14d4170802feee8ff8dc7790a80ff35ea6b03f60414/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6479/7985 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6479/7985 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6172/7985 |
| 6 | Kaspersky | 75.5% | 6026/7984 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5685/7981 |
| 9 | Rising | 68.4% | 5462/7985 |
| 10 | Varist | 66.1% | 5271/7980 |
| 11 | Avast | 65.2% | 5200/7981 |
| 12 | AVG | 65.2% | 5200/7980 |
| 13 | Tencent | 65.0% | 5043/7759 |
| 14 | McAfeeD | 61.4% | 4900/7977 |
| 15 | huorong | 60.8% | 4852/7977 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 66 | 65.3% |
| 🪟 Windows | 32 | 31.7% |
| ❓ Unbekannt | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 96 | 95.0% |
| Drive-By / Exploit-Kit | 3 | 3.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 62 | 61.4% |
| 2 | 🇳🇱 NL | 15 | 14.9% |
| 3 | 🇺🇸 US | 12 | 11.9% |
| 4 | 🇸🇪 SE | 4 | 4.0% |
| 5 | 🇫🇷 FR | 3 | 3.0% |
| 6 | 🌐 Unbekannt | 2 | 2.0% |
| 7 | 🇭🇺 HU | 2 | 2.0% |
| 8 | 🇨🇦 CA | 1 | 1.0% |

## MITRE ATT&CK

> 70 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 62 |
| Lateral Movement | 62 |
| Collection | 7 |
| Command and Control | 6 |
| Credential Access | 2 |
| Exfiltration | 2 |
| Execution | 1 |

<details><summary>0e5e6d03bf59d4f929b6… – Vidar | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>7c2c2e9b864f38e2b915… – Vidar | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>fc84ea86574c7ba49fd4… – njrat | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>30161f3b7d0ce2c86522… – njrat | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [061399a07809070e98f8…](https://bazaar.abuse.ch/sample/061399a07809070e98f870df08e4c7d1d53000d62f012f5231758d0b85793930/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-COW [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-COW [Trj]` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-COW [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.COW` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.COW` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Linux.Backdoor.Mirai.Qzfl` |
| Varist | `E32/Mirai.DK.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.av` |

### [9d70873d687091dd5475…](https://bazaar.abuse.ch/sample/9d70873d687091dd54758a1d88a19e5d01dd3854e897c7d910dfd435bc1e7f31/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39502263` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39502263 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39502263` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [595e5017547ba635330a…](https://bazaar.abuse.ch/sample/595e5017547ba635330a2a183bc0b42150198b38a073cc7af21b4374ed03b8f3/)

- **Familie:** C!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.C!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [a0c71e84cce690420384…](https://bazaar.abuse.ch/sample/a0c71e84cce69042038424379097d2ff450d7303d5adaf51aa517fc12e1f5402/)

- **Familie:** Mirai
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.K!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avira | `TR/LINUX.Mirai.DDO` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DDO` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Sangfor | `Backdoor.Linux.Mirai.Vmkr` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Mirai.AT.gen!Eldorado` |
| alibabacloud | `DDoS:Linux/Mirai.FXS` |

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

- **elf** (64×)
- **Mirai** (62×)
- **Torii** (51×)
- **exe** (28×)
- **Prometei** (9×)
- **WARDENStealer** (7×)
- **stealer** (7×)
- **upx-dec** (6×)
- **upx** (6×)
- **RAT** (5×)
- **Warden** (5×)
- **njrat** (4×)
- **salat** (4×)
- **salatstealer** (4×)
- **js** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +19 (43→62)
- ↓ **unbekannt** -14 (24→10)
- ↑ **WARDENStealer** +1 (6→7)
- neu: **SalatStealer** (6)
- neu: **njrat** (4)
- ↑ **RemusStealer** +2 (1→3)
- neu: **Vidar** (2)
- neu: **Patchwork** (1)
- weg: **Formbook** (war 2)
- weg: **SilentNet** (war 2)
- weg: **RevStealer** (war 4)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +31 (31→62)
- ↓ **unbekannt** -16 (26→10)
- ↑ **WARDENStealer** +3 (4→7)
- neu: **njrat** (4)
- neu: **RemusStealer** (3)
- ↑ **Vidar** +1 (1→2)
- neu: **RustyStealer** (1)
- neu: **Patchwork** (1)
- weg: **Snowlight** (war 3)
- weg: **RevStealer** (war 2)
- weg: **AgentTesla** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.136 MB |
| σ Dateigröße | 22.863 MB |
| Ø Risiko-Score | 76.2/100 |
| Ø Klassifikations-Konfidenz | 84.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 70/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 53 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:01 | [f736f7457ddf…](https://bazaar.abuse.ch/sample/f736f7457ddf4ba1f4ad083dd88f3f2e0dae29d69f7fe381b4ee07c7f1890639/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 15:50 | [fc84ea86574c…](https://bazaar.abuse.ch/sample/fc84ea86574c7ba49fd45a223f667905bf7d0cf201b35848c50078b061722747/) | `exe` | njrat | 89.2 | – | – | 🇳🇱NL |
| 15:50 | [30161f3b7d0c…](https://bazaar.abuse.ch/sample/30161f3b7d0ce2c86522cec3a4e97ea2b2a8065eddddfda258d80606da3af449/) | `exe` | njrat | 89.2 | – | – | 🇳🇱NL |
| 15:50 | [e8c4ac6ff2aa…](https://bazaar.abuse.ch/sample/e8c4ac6ff2aa1bebaa07311ba9d6d993d49966daf5b050bf3e911fe926a4f251/) | `exe` | njrat | 89.2 | – | – | 🇳🇱NL |
| 15:42 | [0e85f8776c68…](https://bazaar.abuse.ch/sample/0e85f8776c68237fe42e85901b16a05de595cde5f4b3faa77307925dc0405d0b/) | `vbs` | unbekannt | 38.4 | – | – | 🌐SE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.11.2026 16:27 UTC*