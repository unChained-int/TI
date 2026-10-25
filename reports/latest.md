# MalwareBazaar – 25.10.2026 20:33 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **69** |
| Höchster Score | **94.4/100** – 56501cd9abec0699… |
| Häufigste Familie | **Mirai** (45x) |
| Häufigster Typ | **elf** (56x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 58 Samples |
| Ø Dateigröße | 3.61 MB (σ=5.46) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 56 | 55.4%  ███████████ |
| `exe` | 34 | 33.7%  ██████ |
| `jar` | 9 | 8.9%  █ |
| `zip` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 45 | 44.6% |
| 2 | unbekannt | 28 | 27.7% |
| 3 | SalatStealer | 23 | 22.8% |
| 4 | AokigaharaStealer | 1 | 1.0% |
| 5 | Sliver | 1 | 1.0% |
| 6 | Malware | 1 | 1.0% |
| 7 | RustyStealer | 1 | 1.0% |
| 8 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 45 | 44.6% | 95% |
| Infostealer | 23 | 22.8% | 75% |
| Linux-Malware | 11 | 10.9% | 45% |
| Andere / Unbekannt | 9 | 8.9% | 20% |
| Windows-Malware | 8 | 7.9% | 35% |
| Loader | 2 | 2.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 69 | 68.3% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 9 | 8.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [56501cd9abec06…](https://bazaar.abuse.ch/sample/56501cd9abec0699a1d242de0aa9a26c9b937b15828b30e37602585112f2aa7e/) | Sliver | Post-Exploitat | **94.4** | 🔴 KRITISCH | – | – | ? |
| [37eb44f7067138…](https://bazaar.abuse.ch/sample/37eb44f7067138300caa9331fb93e1a99b86015333d2f9af396f2934849cd534/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [c2184f6df31a14…](https://bazaar.abuse.ch/sample/c2184f6df31a14d5bde555b63cfd897cbab4b262b248f56ca97746c1b87a01e5/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [3e58d175f08fe7…](https://bazaar.abuse.ch/sample/3e58d175f08fe7a183330fddc222c0fa793054dc64ecb35645913b7ca464f498/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [bd3f2f7d114b9a…](https://bazaar.abuse.ch/sample/bd3f2f7d114b9a83080c7d40717c2a46ca26d04e8542442fbda28f35de86a2be/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [83ee7cd932725e…](https://bazaar.abuse.ch/sample/83ee7cd932725e3de23db7861742bde84f1945c10c00ca5ac6ba1b4a2c4ec497/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [52798f2ded7d38…](https://bazaar.abuse.ch/sample/52798f2ded7d3856cf7d6e0c63415d37eccf05d11749a57f58c55f9e37dc1770/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [8359fc1925367c…](https://bazaar.abuse.ch/sample/8359fc1925367cd525255da4fc9f0d30f182b54e6ffe06b346bd7ad0803597a1/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [3625aa321074e6…](https://bazaar.abuse.ch/sample/3625aa321074e66100ed2fa56e46ca69ca2d1c710b47e5cb2e3e46fa67d1022e/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b27757d81bb6de…](https://bazaar.abuse.ch/sample/b27757d81bb6de6fd7865b09378b05cbf6297604b4a200bb8c60e094ac5816c3/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6187/7635 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6187/7635 |
| 3 | ESET-NOD32 | 77.2% | 5892/7635 |
| 4 | Kaspersky | 75.8% | 5788/7634 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5426/7632 |
| 8 | Rising | 68.3% | 5212/7635 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5050/7631 |
| 11 | Avast | 65.1% | 4966/7631 |
| 12 | AVG | 65.1% | 4966/7630 |
| 13 | Tencent | 64.8% | 4800/7409 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4672/7628 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 56 | 55.4% |
| 🪟 Windows | 35 | 34.7% |
| ❓ Unbekannt | 9 | 8.9% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| MaaS-Loader | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 44 | 43.6% |
| 2 | 🇫🇷 FR | 28 | 27.7% |
| 3 | 🇳🇱 NL | 16 | 15.8% |
| 4 | 🇺🇸 US | 8 | 7.9% |
| 5 | 🇨🇦 CA | 2 | 2.0% |
| 6 | 🌐 Unbekannt | 2 | 2.0% |
| 7 | 🌐 PT | 1 | 1.0% |

## MITRE ATT&CK

> 58 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 45 |
| Lateral Movement | 45 |
| Credential Access | 13 |
| Exfiltration | 13 |

<details><summary>37eb44f7067138300caa… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c2184f6df31a14d5bde5… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3e58d175f08fe7a18333… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>bd3f2f7d114b9a83080c… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [bd4632826803f35e47e9…](https://bazaar.abuse.ch/sample/bd4632826803f35e47e9be3e6e81878ddedb9e1930e4a22ca2665a9e56420c0f/)

- **Familie:** Mirai
- **Erkannt von:** 32 von 75 Engines (42.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40688755
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40688755`

**Erkennende Engines (32/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40688755` |
| AVG | `ELF:Mirai-OD [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D26CDC73` |
| Avast | `ELF:Mirai-OD [Trj]` |
| Avast-Mobile | `ELF:Mirai-OD [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Trojan.Generic.40688755` |
| ClamAV | `Unix.Trojan.Mirai-9951087-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10541` |
| ESET-NOD32 | `Linux/Mirai.CXF trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Generic.40688755 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.IA!tr.botnet` |
| GData | `Trojan.Generic.40688755` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Script/Mirai.EBP` |
| MicroWorld-eScan | `Trojan.Generic.40688755` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.128BE (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-JBMX!F52246CFBBB9` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `LINUX/Mirai-JBMX!F52246CFBBB9` |
| VIPRE | `Trojan.Generic.40688755` |
| Varist | `E32/Mirai.BX.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.dh` |

### [eb1fe212d334f5fa2089…](https://bazaar.abuse.ch/sample/eb1fe212d334f5fa2089ed579dc5380b2ca64dabae7fa49b34e39bd31fdf6a1a/)

- **Familie:** Mirai
- **Erkannt von:** 39 von 75 Engines (52.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40417908
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40417908`

**Erkennende Engines (39/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40417908` |
| AVG | `ELF:CVE-2014-8361-B [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai.ba` |
| Arcabit | `Trojan.Generic.D268BA74` |
| Avast | `ELF:CVE-2014-8361-B [Expl]` |
| Avast-Mobile | `ELF:Mirai-UM [Trj]` |
| Avira | `EXP/LINUX.CVE-2014-.B` |
| BitDefender 🛡️ | `Trojan.Generic.40417908` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135987-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.FDK trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| Emsisoft | `Trojan.Generic.40417908 (B)` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2014-.B` |
| Fortinet | `Linux/Mirai.FDK!tr` |
| GData | `Trojan.Generic.40417908` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.bj` |
| Kingsoft | `Linux.Backdoor.Gafgyt.bj` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!EB1FE212D334` |
| MicroWorld-eScan | `Trojan.Generic.40417908` |
| Microsoft 🛡️ | `DDoS:Linux/Gafgyt.YA!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.BAFF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Backdoor.Linux.Mirai.yap` |
| TrendMicro | `Backdoor.Linux.MIRAI.USBLHG26` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.USBLHG26` |
| VIPRE | `Trojan.Generic.40417908` |
| Varist | `E64/ABApplication.PN` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `Backdoor:Linux/Mirai.BTO` |
| huorong | `Trojan/Linux.Mirai.f` |

### [08d9eef3574199853097…](https://bazaar.abuse.ch/sample/08d9eef3574199853097949ba18e9c67e7254576d2eab9b18065adb87f1e7105/)

- **Familie:** Malware
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.20209037
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.20209037` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Program:Win32/Contebrew.A!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:EUwSp1V0LSNaoUGdA5xc0w)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| huorong | `Trojan/Injector.aj!crit` |

### [433c150a9c4b4cfb6b5c…](https://bazaar.abuse.ch/sample/433c150a9c4b4cfb6b5caf3a74f1b9d23226c30c00797a98ac945c9b8b7f9202/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-MV [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-MV [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-MV [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.A!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Kingsoft | `Linux.Backdoor.Mirai.b` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/Mirai.EQY` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.bktra` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7AntiVirus | `Trojan ( 0001140e1 )` |
| K7GW | `Hacktool ( a007e0071 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (56×)
- **Mirai** (42×)
- **exe** (33×)
- **SalatStealer** (18×)
- **upx-dec** (16×)
- **upx** (15×)
- **bombay** (13×)
- **lumma.cy** (13×)
- **jar** (9×)
- **stealer** (3×)
- **Warden** (3×)
- **WARDENStealer** (3×)
- **Yap** (3×)
- **YapStealer** (3×)
- **Gafgyt** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +30 (15→45)
- ↑ **unbekannt** +11 (17→28)
- ↑ **SalatStealer** +15 (8→23)
- neu: **AokigaharaStealer** (1)
- neu: **Sliver** (1)
- neu: **Malware** (1)
- neu: **RustyStealer** (1)
- weg: **CoinMiner** (war 3)
- weg: **AveMariaRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +26 (19→45)
- ↓ **unbekannt** -9 (37→28)
- ↑ **SalatStealer** +21 (2→23)
- neu: **AokigaharaStealer** (1)
- neu: **Sliver** (1)
- neu: **Malware** (1)
- neu: **RustyStealer** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.614 MB |
| σ Dateigröße | 5.459 MB |
| Ø Risiko-Score | 68.8/100 |
| Ø Klassifikations-Konfidenz | 72.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 58/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 28 |
| Unbekannte Familien | 9 (8.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:18 | [37eb44f70671…](https://bazaar.abuse.ch/sample/37eb44f7067138300caa9331fb93e1a99b86015333d2f9af396f2934849cd534/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 20:12 | [bd4632826803…](https://bazaar.abuse.ch/sample/bd4632826803f35e47e9be3e6e81878ddedb9e1930e4a22ca2665a9e56420c0f/) | `elf` | Mirai | 77.7 | 42.7% | 🟠 MÄSSIG ERKANNT | 🇺🇸US |
| 20:11 | [c2184f6df31a…](https://bazaar.abuse.ch/sample/c2184f6df31a14d5bde555b63cfd897cbab4b262b248f56ca97746c1b87a01e5/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 20:06 | [3e58d175f08f…](https://bazaar.abuse.ch/sample/3e58d175f08fe7a183330fddc222c0fa793054dc64ecb35645913b7ca464f498/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 20:03 | [02d213ad094e…](https://bazaar.abuse.ch/sample/02d213ad094e748a4071d00a3bb4e41afe68b0584a4c01d3354abdfbb61aa6de/) | `exe` | SalatStealer | 81.8 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 20:33 UTC*