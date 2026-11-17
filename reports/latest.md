# MalwareBazaar – 17.11.2026 00:02 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **59** |
| Höchster Score | **89.4/100** – 35fe363aa0563cec… |
| Häufigste Familie | **unbekannt** (29x) |
| Häufigster Typ | **elf** (35x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 35 Samples |
| Ø Dateigröße | 3.28 MB (σ=14.04) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 35 | 35.0%  ███████ |
| `exe` | 33 | 33.0%  ██████ |
| `js` | 8 | 8.0%  █ |
| `apk` | 5 | 5.0%  █ |
| `ps1` | 5 | 5.0%  █ |
| `vbs` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `vbe` | 2 | 2.0%   |
| `sh` | 1 | 1.0%   |
| `pdf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 29 | 29.0% |
| 2 | Mirai | 25 | 25.0% |
| 3 | WARDENStealer | 14 | 14.0% |
| 4 | Prometei | 10 | 10.0% |
| 5 | njrat | 4 | 4.0% |
| 6 | Formbook | 4 | 4.0% |
| 7 | RemusStealer | 3 | 3.0% |
| 8 | AgentTesla | 2 | 2.0% |
| 9 | MassLogger | 2 | 2.0% |
| 10 | Bash | 1 | 1.0% |
| 11 | GuLoader | 1 | 1.0% |
| 12 | SilentNet | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 28 | 28.0% | 92% |
| Infostealer | 26 | 26.0% | 78% |
| Skript/Dropper | 10 | 10.0% | 35% |
| Linux-Malware | 8 | 8.0% | 45% |
| RAT | 6 | 6.0% | 95% |
| Windows-Malware | 5 | 5.0% | 35% |
| Android-Malware | 5 | 5.0% | 45% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Loader | 4 | 4.0% | 80% |
| Backdoor | 2 | 2.0% | 75% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 59.0% |
| 🟠 HOCH | 7 | 7.0% |
| 🟡 MITTEL | 22 | 22.0% |
| 🟢 NIEDRIG | 12 | 12.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [35fe363aa0563c…](https://bazaar.abuse.ch/sample/35fe363aa0563cec047592159893a0ea9624eac57a30653b43630593a85ee360/) | njrat | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [86c9f0f3fdb2b9…](https://bazaar.abuse.ch/sample/86c9f0f3fdb2b9f7043e1e8a6344af535331c5a12e3efad398aa61b7da1fbeec/) | njrat | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [72e7b037325af8…](https://bazaar.abuse.ch/sample/72e7b037325af85447366ea96d8e76d49ebc3cfbb3817064a29ec34ed4173a87/) | njrat | RAT | **85.4** | 🔴 KRITISCH | – | – | ? |
| [20de26142bd7a4…](https://bazaar.abuse.ch/sample/20de26142bd7a4ca054a26a55be4b980a8bdaaa451bdbb5e24ccd20fe4e5f06d/) | Formbook | Infostealer | **85.4** | 🔴 KRITISCH | – | – | ? |
| [4460fafd3de774…](https://bazaar.abuse.ch/sample/4460fafd3de774d00defa0c094e0ef221de7eba72b49b75c183f6bb83a3d4898/) | Formbook | Infostealer | **85.4** | 🔴 KRITISCH | – | – | ? |
| [4b1b560687e36f…](https://bazaar.abuse.ch/sample/4b1b560687e36fbcd456dd7e2b05ecf5f7d55734b0e5aa32befa4a8ae67f4a0b/) | Formbook | Infostealer | **85.4** | 🔴 KRITISCH | – | – | ? |
| [1625aa946c9a05…](https://bazaar.abuse.ch/sample/1625aa946c9a0599c59048c907cb7ce2d63978aa4621756ddc242cb903afd711/) | Formbook | Infostealer | **85.4** | 🔴 KRITISCH | – | – | ? |
| [a510660899a5b2…](https://bazaar.abuse.ch/sample/a510660899a5b29e59470bd2747ed9af0475e7c41b48d7920fe9a8cbadbca4d9/) | RemcosRAT | RAT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [e16b02bc6b332b…](https://bazaar.abuse.ch/sample/e16b02bc6b332b3b8f2b639df0f39136592cb9a1691d4b51af8c753334e30610/) | XWorm | RAT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [1916cec36c808a…](https://bazaar.abuse.ch/sample/1916cec36c808ac872b826cd4fd981031cc3eab2bdab5ffeff2cc05eb5ca67ff/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6511/8022 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6511/8022 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6203/8022 |
| 6 | Kaspersky | 75.5% | 6057/8021 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5713/8018 |
| 9 | Rising | 68.5% | 5492/8022 |
| 10 | Varist | 66.0% | 5295/8017 |
| 11 | Avast | 65.2% | 5226/8018 |
| 12 | AVG | 65.2% | 5226/8017 |
| 13 | Tencent | 65.1% | 5074/7796 |
| 14 | McAfeeD | 61.5% | 4927/8014 |
| 15 | huorong | 60.8% | 4876/8014 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 43 | 43.0% |
| 🐧 Linux | 36 | 36.0% |
| ❓ Unbekannt | 10 | 10.0% |
| 🤖 Android | 6 | 6.0% |
| 📦 Archiv | 4 | 4.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 84 | 84.0% |
| Drive-By / Exploit-Kit | 9 | 9.0% |
| APK-Sideloading | 5 | 5.0% |
| MaaS-Loader | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 37 | 37.0% |
| 2 | 🇫🇷 FR | 24 | 24.0% |
| 3 | 🇸🇪 SE | 11 | 11.0% |
| 4 | 🇺🇸 US | 10 | 10.0% |
| 5 | 🇳🇱 NL | 7 | 7.0% |
| 6 | 🌐 CL | 4 | 4.0% |
| 7 | 🇭🇺 HU | 3 | 3.0% |
| 8 | 🇭🇰 HK | 2 | 2.0% |
| 9 | 🇯🇵 JP | 1 | 1.0% |
| 10 | 🇨🇭 CH | 1 | 1.0% |

## MITRE ATT&CK

> 35 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 9 |
| Command and Control | 5 |
| Credential Access | 4 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>35fe363aa0563cec0475… – njrat | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>86c9f0f3fdb2b9f7043e… – njrat | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>72e7b037325af8544736… – njrat | 🔴 KRITISCH 85.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>20de26142bd7a4ca054a… – Formbook | 🔴 KRITISCH 85.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4460fafd3de774d00def… – Formbook | 🔴 KRITISCH 85.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [92e1ca790d0088f721f8…](https://bazaar.abuse.ch/sample/92e1ca790d0088f721f87946c05249f8737494ba59225dcb24d4498187a68f65/)

- **Familie:** Bash
- **Erkannt von:** 25 von 74 Engines (33.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.Bash.MiraiA.34E9BE57
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Bash.MiraiA.34E9BE57`

**Erkennende Engines (25/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Bash.MiraiA.34E9BE57` |
| AVG | `BV:Downloader-AMZ [Drp]` |
| Arcabit | `Generic.Bash.MiraiA.34E9BE57` |
| Avast | `BV:Downloader-AMZ [Drp]` |
| Avira | `DR/BAT.Downloader.AMZ` |
| BitDefender 🛡️ | `Generic.Bash.MiraiA.34E9BE57` |
| CTX | `script.unknown.bash` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2249` |
| Emsisoft | `Generic.Bash.MiraiA.34E9BE57 (B)` |
| F-Secure | `Dropper.DR/BAT.Downloader.AMZ` |
| Fortinet | `BASH/Mirai.AEH!tr.dldr` |
| GData | `Generic.Bash.MiraiA.34E9BE57` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.gen` |
| MicroWorld-eScan | `Generic.Bash.MiraiA.34E9BE57` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Sophos | `Mal/ShellDl-A` |
| Symantec | `CL.Downloader!gen277` |
| TrendMicro | `Possible_BASHDLOD.SMLBO1` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBO1` |
| VIPRE | `Generic.Bash.MiraiA.34E9BE57` |
| Varist | `SH/Mirai.D.gen!Camelot` |
| ZoneAlarm | `Mal/ShellDl-A` |
| huorong | `TrojanDownloader/Linux.Agent.aj` |

### [85960027b28d9f3e4f27…](https://bazaar.abuse.ch/sample/85960027b28d9f3e4f27e909be33296459dcc0eebe6aa95393d73120a24a4118/)

- **Familie:** Prometei
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
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
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [ef21526056ab733e9d17…](https://bazaar.abuse.ch/sample/ef21526056ab733e9d1793d82a892050a03f415499686ad036383099a91b5aad/)

- **Familie:** Prometei
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
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
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **elf** (35×)
- **exe** (31×)
- **Mirai** (25×)
- **WARDENStealer** (16×)
- **stealer** (13×)
- **Torii** (11×)
- **Prometei** (10×)
- **Warden** (10×)
- **js** (8×)
- **upx-dec** (6×)
- **upx** (6×)
- **apk** (5×)
- **signed** (5×)
- **ps1** (5×)
- **njrat** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +1 (28→29)
- ↑ **Mirai** +7 (18→25)
- ↑ **WARDENStealer** +12 (2→14)
- ↑ **Prometei** +8 (2→10)
- neu: **njrat** (4)
- neu: **Formbook** (4)
- neu: **RemusStealer** (3)
- neu: **MassLogger** (2)
- neu: **Bash** (1)
- weg: **SalatStealer** (war 2)
- weg: **Snowlight** (war 2)
- weg: **FunStealer** (war 14)
- weg: **PhantomStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +4 (25→29)
- ↓ **Mirai** -12 (37→25)
- ↑ **WARDENStealer** +10 (4→14)
- ↑ **Prometei** +9 (1→10)
- ↑ **njrat** +3 (1→4)
- ↑ **Formbook** +3 (1→4)
- neu: **RemusStealer** (3)
- ↑ **AgentTesla** +1 (1→2)
- neu: **MassLogger** (2)
- neu: **Bash** (1)
- weg: **SalatStealer** (war 7)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.280 MB |
| σ Dateigröße | 14.035 MB |
| Ø Risiko-Score | 66.0/100 |
| Ø Klassifikations-Konfidenz | 68.8% |
| Samples mit VT | 4/100 |
| Samples mit MITRE | 35/100 |
| Eindeutige Familien | 16 |
| Eindeutige Tags | 61 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:01 | [64c16da27d7c…](https://bazaar.abuse.ch/sample/64c16da27d7c500b1583e7cab12e1b305dc18974f563aa2ad4f192e8b304eb42/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 23:44 | [1916cec36c80…](https://bazaar.abuse.ch/sample/1916cec36c808ac872b826cd4fd981031cc3eab2bdab5ffeff2cc05eb5ca67ff/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 23:44 | [da604139df0b…](https://bazaar.abuse.ch/sample/da604139df0b04644cb0abfdd282c3cd94075ddd8b314c2d1c8d70ec3e501e7e/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 23:43 | [a7ca946b668d…](https://bazaar.abuse.ch/sample/a7ca946b668da66c65e09b2fab524c88c83dd975fb3ed3ffdfeaae00820149ff/) | `apk` | unbekannt | 43.1 | – | – | 🌐JP |
| 23:41 | [7f6965637733…](https://bazaar.abuse.ch/sample/7f696563773344269f6793cba6f38e5f54a8603e13832d1f3ed1918723a71ee7/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.11.2026 00:02 UTC*