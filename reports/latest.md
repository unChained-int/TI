# MalwareBazaar – 23.10.2026 14:44 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **71** |
| Höchster Score | **89.6/100** – 1e678e7e10ffe96f… |
| Häufigste Familie | **unbekannt** (30x) |
| Häufigster Typ | **js** (35x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 51 Samples |
| Ø Dateigröße | 6.59 MB (σ=24.19) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 35 | 34.7%  ██████ |
| `elf` | 31 | 30.7%  ██████ |
| `vbs` | 17 | 16.8%  ███ |
| `exe` | 15 | 14.9%  ██ |
| `apk` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 30 | 29.7% |
| 2 | Mirai | 25 | 24.8% |
| 3 | Formbook | 10 | 9.9% |
| 4 | RemcosRAT | 9 | 8.9% |
| 5 | XWorm | 5 | 5.0% |
| 6 | GuLoader | 5 | 5.0% |
| 7 | AgentTesla | 4 | 4.0% |
| 8 | LxBaseRAT | 2 | 2.0% |
| 9 | VIPKeylogger | 2 | 2.0% |
| 10 | Vidar | 2 | 2.0% |
| 11 | MassLogger | 1 | 1.0% |
| 12 | Malware | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 24.8% | 95% |
| RAT | 20 | 19.8% | 89% |
| Skript/Dropper | 19 | 18.8% | 35% |
| Infostealer | 17 | 16.8% | 90% |
| Loader | 8 | 7.9% | 90% |
| Linux-Malware | 4 | 4.0% | 45% |
| Cryptominer | 3 | 3.0% | 75% |
| Trojaner | 2 | 2.0% | 70% |
| Spyware | 2 | 2.0% | 75% |
| Windows-Malware | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 71 | 70.3% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 24 | 23.8% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1e678e7e10ffe9…](https://bazaar.abuse.ch/sample/1e678e7e10ffe96f9a10feef547ababb34e3b38b74d64bcb7d52486f3dbd961c/) | Formbook | Infostealer | **89.6** | 🔴 KRITISCH | – | – | ? |
| [d5f6b98a539364…](https://bazaar.abuse.ch/sample/d5f6b98a539364201e34f8b3fc2715211b9af6b2bbb58fa9c9958c89677a02c7/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [34f510e92d94d8…](https://bazaar.abuse.ch/sample/34f510e92d94d85c393c15b7fcb5127fcdc3db144e8a2444d2b246f733b77570/) | Vidar | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [2d1b4b3cd07c20…](https://bazaar.abuse.ch/sample/2d1b4b3cd07c20bf13b7c64246a89a8c0a6f6a6f13c274c9dd568ee5a580947c/) | Vidar | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [551664a77acba9…](https://bazaar.abuse.ch/sample/551664a77acba99d858062715ee9b39cb52c69bb7e866fd56a63f57436a0c839/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [ffc3f8bdd9d370…](https://bazaar.abuse.ch/sample/ffc3f8bdd9d37069c190378fc681e70992d9b88d9b8810cf00a1d89080c9ee8f/) | AMOS | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [fa4995194b70cb…](https://bazaar.abuse.ch/sample/fa4995194b70cb23f65d1bdbed434fa3ab9c2c78b952d24227d27270d484c497/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [05bc838713eb86…](https://bazaar.abuse.ch/sample/05bc838713eb8604436c99b355c39a92f2c5aa37bba35860f1f56def8649da4f/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [8c9f578d68e9b2…](https://bazaar.abuse.ch/sample/8c9f578d68e9b21866c1381b6711d0d11c01c59ea586f3a7717d8bc2a9109b6e/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [b84207adf48237…](https://bazaar.abuse.ch/sample/b84207adf48237216e597cdebd504f32957673128bdc27c14dc8620bcba3d2a8/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6136/7577 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6136/7577 |
| 3 | ESET-NOD32 | 77.3% | 5854/7577 |
| 4 | Kaspersky | 76.0% | 5757/7576 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5395/7574 |
| 8 | Rising | 68.4% | 5184/7577 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5016/7573 |
| 11 | Avast | 65.2% | 4937/7573 |
| 12 | AVG | 65.2% | 4937/7572 |
| 13 | Tencent | 65.0% | 4775/7351 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4637/7570 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 35 | 34.7% |
| 🪟 Windows | 33 | 32.7% |
| 🐧 Linux | 31 | 30.7% |
| 🤖 Android | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 53 | 52.5% |
| Drive-By / Exploit-Kit | 40 | 39.6% |
| MaaS-Loader | 5 | 5.0% |
| USB / Wechselmedium | 2 | 2.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 43 | 42.6% |
| 2 | 🇩🇪 DE | 17 | 16.8% |
| 3 | 🇳🇱 NL | 13 | 12.9% |
| 4 | 🇨🇭 CH | 8 | 7.9% |
| 5 | 🇺🇸 US | 7 | 6.9% |
| 6 | 🇷🇴 RO | 3 | 3.0% |
| 7 | 🇪🇸 ES | 3 | 3.0% |
| 8 | 🌐 Unbekannt | 3 | 3.0% |
| 9 | 🇫🇷 FR | 2 | 2.0% |
| 10 | 🇮🇹 IT | 1 | 1.0% |
| 11 | 🇭🇺 HU | 1 | 1.0% |

## MITRE ATT&CK

> 51 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 21 |
| Credential Access | 12 |
| Command and Control | 9 |
| Defense Evasion | 5 |
| Execution | 5 |
| Exfiltration | 2 |

<details><summary>1e678e7e10ffe96f9a10… – Formbook | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>d5f6b98a539364201e34… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>34f510e92d94d85c393c… – Vidar | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2d1b4b3cd07c20bf13b7… – Vidar | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>551664a77acba99d8580… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b987f336ca9303260bc8…](https://bazaar.abuse.ch/sample/b987f336ca9303260bc8603394f1711fd468fe19ad483a2789e8fd231f1566e0/)

- **Familie:** Malware
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.970EC5FA
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801182` |
| Bkav | `W32.Malware.970EC5FA` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Kingsoft | `malware.kb.a.919` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.89 (RDML:dxHveX4OTno7C3e2UHfsgQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |

### [708a739e1a8fa65007dd…](https://bazaar.abuse.ch/sample/708a739e1a8fa65007dd3b0fce5f70c151514641919006b554194d366df0c381/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| AVG | `ELF:Hajime-Q [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan/Linux.Mirai.b` |
| Arcabit | `Trojan.Linux.Cling.1` |
| Avast | `ELF:Hajime-Q [Trj]` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.unknown.cling` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.WJ trojan` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.r` |
| McAfeeD | `ti!708A739E1A8F` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.E816 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.f` |

### [ba4b55478cbfdc31b83b…](https://bazaar.abuse.ch/sample/ba4b55478cbfdc31b83baaf3410d3f9fc4781a8b2161a647c70ec245191370e2/)

- **Familie:** GuLoader
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** TROJ_GEN.F04IE00JM26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `TR/SNH` |
| ESET-NOD32 | `PowerShell/CloudEye.OI trojan` |
| GData | `Script.Trojan.Agent.GV9SR7` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Symantec | `Scr.Guloader!gen3` |
| TrendMicro | `TROJ_GEN.F04IE00JM26` |
| TrendMicro-HouseCall | `TROJ_GEN.F04IE00JM26` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

### [a4ddc3b5eb4ffbf32051…](https://bazaar.abuse.ch/sample/a4ddc3b5eb4ffbf3205179219a920b72f1c8c9b6497fc169ba1a6ca4b1a3dfc8/)

- **Familie:** RemcosRAT
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Scr.Guloader!gen3
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/CloudEye.OI trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Microsoft 🛡️ | `Trojan:Win32/Malgent` |
| Symantec | `Scr.Guloader!gen3` |
| Varist | `VBS/Agent.CJZ2!Eldorado` |

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

- **js** (35×)
- **elf** (31×)
- **Mirai** (25×)
- **vbs** (17×)
- **exe** (14×)
- **Formbook** (10×)
- **upx** (10×)
- **RemcosRAT** (9×)
- **upx-dec** (9×)
- **XWorm** (5×)
- **GuLoader** (5×)
- **AgentTesla** (4×)
- **PatchedHostLoader** (3×)
- **SilverFox** (3×)
- **ValleyRAT** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -7 (37→30)
- ↑ **Mirai** +4 (21→25)
- ↑ **Formbook** +9 (1→10)
- ↑ **RemcosRAT** +8 (1→9)
- neu: **XWorm** (5)
- neu: **GuLoader** (5)
- neu: **AgentTesla** (4)
- neu: **LxBaseRAT** (2)
- neu: **VIPKeylogger** (2)
- neu: **Vidar** (2)
- weg: **CoinMiner** (war 4)
- weg: **Kaiji** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -9 (39→30)
- ↑ **Mirai** +2 (23→25)
- ↑ **Formbook** +9 (1→10)
- ↑ **RemcosRAT** +8 (1→9)
- neu: **XWorm** (5)
- neu: **GuLoader** (5)
- neu: **AgentTesla** (4)
- neu: **LxBaseRAT** (2)
- neu: **VIPKeylogger** (2)
- neu: **Vidar** (2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.591 MB |
| σ Dateigröße | 24.190 MB |
| Ø Risiko-Score | 72.4/100 |
| Ø Klassifikations-Konfidenz | 77.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 51/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 56 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:32 | [392c61d9c20a…](https://bazaar.abuse.ch/sample/392c61d9c20a4087633e6593292a6ff42e422b49dc917bea972bccd5f8b88ce3/) | `exe` | MassLogger | 38.9 | – | – | 🌐CH |
| 14:09 | [243c526b8b42…](https://bazaar.abuse.ch/sample/243c526b8b42f252bcdc20a0b6494b66fdf5fb3a5a1f9c913c463f02739bc6a3/) | `exe` | unbekannt | 80.8 | – | – | 🇺🇸US |
| 14:09 | [5218c6eb3d4c…](https://bazaar.abuse.ch/sample/5218c6eb3d4c071cb40f75bd4a9aab8eb9426dbd1cf23f1cea4f6ef3b31d3a87/) | `exe` | unbekannt | 80.8 | – | – | 🇺🇸US |
| 14:07 | [26fa8cb35725…](https://bazaar.abuse.ch/sample/26fa8cb35725b85cb01b90fae752bca122ed730276481c47a8aadb182bf76fb7/) | `exe` | unbekannt | 80.7 | – | – | 🇺🇸US |
| 13:55 | [6d6a677eea21…](https://bazaar.abuse.ch/sample/6d6a677eea2174b07ce6565c4698e316ae46ddf56d7f97ec37eb2af05ba202b6/) | `exe` | unbekannt | 81.5 | – | – | 🌐RO |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.10.2026 14:44 UTC*