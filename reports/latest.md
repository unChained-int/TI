# MalwareBazaar – 28.10.2026 22:20 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **69** |
| Höchster Score | **84.2/100** – a92ced0445ff6bff… |
| Häufigste Familie | **Mirai** (67x) |
| Häufigster Typ | **elf** (70x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 67 Samples |
| Ø Dateigröße | 2.68 MB (σ=11.53) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 70 | 69.3%  █████████████ |
| `exe` | 12 | 11.9%  ██ |
| `sh` | 8 | 7.9%  █ |
| `cmd` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `bat` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |
| `vbs` | 1 | 1.0%   |
| `gz` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 67 | 66.3% |
| 2 | unbekannt | 29 | 28.7% |
| 3 | Prometei | 1 | 1.0% |
| 4 | SilentNet | 1 | 1.0% |
| 5 | SheetRAT | 1 | 1.0% |
| 6 | VShell | 1 | 1.0% |
| 7 | SalatStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 67 | 66.3% | 95% |
| Andere / Unbekannt | 14 | 13.9% | 20% |
| Windows-Malware | 7 | 6.9% | 35% |
| Infostealer | 5 | 5.0% | 73% |
| Linux-Malware | 4 | 4.0% | 45% |
| Skript/Dropper | 3 | 3.0% | 35% |
| RAT | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 69 | 68.3% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 14 | 13.9% |
| 🟢 NIEDRIG | 14 | 13.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a92ced0445ff6b…](https://bazaar.abuse.ch/sample/a92ced0445ff6bffc6c65d06fd7e493f1fc4db17db051a8005582ae5c0cd46dd/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [faf7e7f8829799…](https://bazaar.abuse.ch/sample/faf7e7f88297993457e5e931583221ee95495a1d5410c1fae748922a08bcd682/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [be4535f271865e…](https://bazaar.abuse.ch/sample/be4535f271865eb759580522d939b258cb025886799b9a7b9eb8866e33da0da9/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [5522a4881eecdf…](https://bazaar.abuse.ch/sample/5522a4881eecdf2af1fd859c1c8b5db0c825f675359c40c0e6f836841183f5a2/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [e438b3e37f587e…](https://bazaar.abuse.ch/sample/e438b3e37f587efe64cb5211d7247a36873d882d493290fd306f26950a3026c8/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [3c06d76127afd0…](https://bazaar.abuse.ch/sample/3c06d76127afd00985b6adbcdefa1d8f75a5db301f3df76267b249ae94f0961c/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [4f3d0d7c9276aa…](https://bazaar.abuse.ch/sample/4f3d0d7c9276aa2f585b52d01d0f923a8b15eeee45342d8c6f778d1c6163c224/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [f50ec11f3ba8b1…](https://bazaar.abuse.ch/sample/f50ec11f3ba8b1b2c4aff3c26e082cc33f7c267738217a7cd1d70efc44ec8018/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [fcac708f62bb05…](https://bazaar.abuse.ch/sample/fcac708f62bb05f14aaadc4b81291b60f5ad1a56a431050dfee8e55906641589/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [733d00f2ba83a6…](https://bazaar.abuse.ch/sample/733d00f2ba83a605c152dab22980f8f7c26a7b608cd84ec3c34daa59129ffded/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6238/7696 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6238/7696 |
| 3 | ESET-NOD32 | 77.2% | 5942/7696 |
| 4 | Kaspersky | 75.6% | 5814/7695 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5475/7693 |
| 8 | Rising | 68.3% | 5257/7696 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5090/7692 |
| 11 | Avast | 65.1% | 5009/7692 |
| 12 | AVG | 65.1% | 5009/7691 |
| 13 | Tencent | 64.9% | 4848/7470 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4709/7689 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 80 | 79.2% |
| 🪟 Windows | 14 | 13.9% |
| ❓ Unbekannt | 4 | 4.0% |
| 📦 Archiv | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 100 | 99.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇦🇹 AT | 37 | 36.6% |
| 2 | 🇺🇸 US | 26 | 25.7% |
| 3 | 🇩🇪 DE | 10 | 9.9% |
| 4 | 🇳🇱 NL | 10 | 9.9% |
| 5 | 🇭🇺 HU | 8 | 7.9% |
| 6 | 🇫🇷 FR | 6 | 5.9% |
| 7 | 🇨🇿 CZ | 1 | 1.0% |
| 8 | 🌐 EG | 1 | 1.0% |
| 9 | 🇬🇧 GB | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 67 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 67 |
| Lateral Movement | 67 |

<details><summary>a92ced0445ff6bffc6c6… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>faf7e7f88297993457e5… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>be4535f271865eb75958… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5522a4881eecdf2af1fd… – Mirai | 🔴 KRITISCH 82.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e438b3e37f587efe64cb… – Mirai | 🔴 KRITISCH 82.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [250baff7500d0dd3c95e…](https://bazaar.abuse.ch/sample/250baff7500d0dd3c95e4d9827a79fd12b58a2434af464995b7f9c7d02663144/)

- **Familie:** Mirai
- **Erkannt von:** 37 von 75 Engines (49.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.39829618
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39829618`

**Erkennende Engines (37/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39829618` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D25FC072` |
| Avast-Mobile | `ELF:Mirai-FY [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| BitDefender 🛡️ | `Trojan.Generic.39829618` |
| CTX | `elf.trojan.generic` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Trojan.Generic.39829618 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `Linux/Mirai.IZ1H9!tr` |
| GData | `Trojan.Generic.39829618` |
| Google | `Detected` |
| Ikarus | `Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.jjyt` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Generic.39829618` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.P!MTB` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `OB:Trojan.Linux.Shb0.Sh0ra` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| VBA32 | `Trojan.Linux.Mirai` |
| VIPRE | `Trojan.Generic.39829618` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| VirIT | `Linux.Mirai.T` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.fk` |

### [863bb4f272fd3669c542…](https://bazaar.abuse.ch/sample/863bb4f272fd3669c54294bb06839418821b7362b7bfc305a25f1d5e53976032/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.7
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.7`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.7` |
| AVG | `ELF:Mirai-AHC [Trj]` |
| AhnLab-V3 | `Linux/Mirai07.Exp` |
| Antiy-AVL | `Trojan/Linux.Mirai.a` |
| Arcabit | `Trojan.Linux.Mirai.7` |
| Avast | `ELF:Mirai-AHC [Trj]` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.7` |
| CTX | `elf.trojan.mirai` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Trojan.Ircbot` |
| Emsisoft | `Trojan.Linux.Mirai.7 (B)` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Trojan.Linux.Mirai.7` |
| Google | `Detected` |
| Jiangmin | `Backdoor.Linux.jkax` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.h` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.7` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `OB:Trojan.Linux.Agent.X64ra` |
| VIPRE | `Trojan.Linux.Mirai.7` |
| Varist | `E64/Mirai.HV.gen!Eldorado` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.fk` |

### [bfe198fadddb5b30b461…](https://bazaar.abuse.ch/sample/bfe198fadddb5b30b4617344426a52cf36db2ad75aa94b386646dcce33f62491/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Mirai-ABP [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen10` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Mirai-ABP [Trj]` |
| Avast-Mobile | `ELF:Agent-AGS [Trj]` |
| Avira | `TR/LINUX.Mirai.ABP` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135881-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.SQ trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.ABP` |
| Fortinet | `ELF/UNSTABLE.AT!tr.botnet` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| Kingsoft | `Linux.Backdoor.elf.2023796` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Bushido.A!xp` |
| Rising | `Backdoor.Mirai/Linux!1.106E5 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Lnx/Mirai-FEBN!B91F1AEF3065` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| TrellixENS | `Lnx/Mirai-FEBN!B91F1AEF3065` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.f` |

### [166269adee08ef69470f…](https://bazaar.abuse.ch/sample/166269adee08ef69470f92eafe76a0bf4f8e539ddadcdb342d81eef7b943df76/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Mirai-ABP [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen10` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Mirai-ABP [Trj]` |
| Avast-Mobile | `ELF:Agent-AGS [Trj]` |
| Avira | `TR/LINUX.Mirai.ABP` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-6981989-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.SQ trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.ABP` |
| Fortinet | `ELF/Mirai.H!tr` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| Kingsoft | `Linux.Backdoor.elf.2023796` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Bushido.A!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `GenericRXJY-KA!CCAF2796FC8F` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wba` |
| TrellixENS | `GenericRXJY-KA!CCAF2796FC8F` |
| TrendMicro | `Possible_MIRAI.SMLBO21` |
| TrendMicro-HouseCall | `Possible_MIRAI.SMLBO21` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.CF.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.f` |

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

- **Mirai** (67×)
- **elf** (18×)
- **Torii** (15×)
- **upx-dec** (10×)
- **upx** (10×)
- **exe** (9×)
- **DvnX** (4×)
- **stealer** (4×)
- **Warden** (4×)
- **WARDENStealer** (4×)
- **Yap** (4×)
- **YapStealer** (4×)
- **cmd** (3×)
- **deepveindrilling-com** (3×)
- **zip** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +33 (34→67)
- ↑ **unbekannt** +1 (28→29)
- neu: **Prometei** (1)
- neu: **SheetRAT** (1)
- neu: **VShell** (1)
- ↓ **SalatStealer** -21 (22→1)
- weg: **AsyncRAT** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +46 (21→67)
- ↑ **unbekannt** +2 (27→29)
- neu: **Prometei** (1)
- neu: **SheetRAT** (1)
- neu: **VShell** (1)
- ↓ **SalatStealer** -9 (10→1)
- weg: **CoinMiner** (war 3)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.678 MB |
| σ Dateigröße | 11.526 MB |
| Ø Risiko-Score | 68.4/100 |
| Ø Klassifikations-Konfidenz | 75.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 67/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 35 |
| Unbekannte Familien | 14 (13.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:15 | [279010a4ffff…](https://bazaar.abuse.ch/sample/279010a4ffffc75756377e1e5b6bff8aaf3a736cce53b643150d08280062e24d/) | `zip` | unbekannt | 32.7 | – | – | 🌐HU |
| 22:00 | [a92ced0445ff…](https://bazaar.abuse.ch/sample/a92ced0445ff6bffc6c65d06fd7e493f1fc4db17db051a8005582ae5c0cd46dd/) | `elf` | Mirai | 84.2 | – | – | 🌐CZ |
| 21:46 | [09c8e61d4954…](https://bazaar.abuse.ch/sample/09c8e61d495491b45c76ebf52e45b3ed5a3c1ffe16ef965e32f95c89181e8606/) | `bat` | unbekannt | 38.6 | – | – | 🌐HU |
| 21:43 | [578e1fbbe490…](https://bazaar.abuse.ch/sample/578e1fbbe490350de49b54d5cd3d8dc716c146af68330bc65a5871ad78d3cb7e/) | `exe` | unbekannt | 81.7 | – | – | 🇺🇸US |
| 21:42 | [7e784c1edb9d…](https://bazaar.abuse.ch/sample/7e784c1edb9db2db10490da3ce9d53979e372d2e887e4d9968cd83d491fd8fa6/) | `exe` | unbekannt | 81.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.10.2026 22:20 UTC*