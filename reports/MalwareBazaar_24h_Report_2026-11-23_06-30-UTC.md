# MalwareBazaar – 23.11.2026 06:30 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **87** |
| Höchster Score | **88.5/100** – 33aedf60dd4925f6… |
| Häufigste Familie | **Mirai** (52x) |
| Häufigster Typ | **elf** (77x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 55 Samples |
| Ø Dateigröße | 1.53 MB (σ=2.91) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 77 | 76.2%  ███████████████ |
| `exe` | 8 | 7.9%  █ |
| `macho` | 8 | 7.9%  █ |
| `sh` | 3 | 3.0%   |
| `vbs` | 2 | 2.0%   |
| `rar` | 2 | 2.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 52 | 51.5% |
| 2 | unbekannt | 40 | 39.6% |
| 3 | Prometei | 6 | 5.9% |
| 4 | RemcosRAT | 2 | 2.0% |
| 5 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 52 | 51.5% | 95% |
| RAT | 31 | 30.7% | 77% |
| Linux-Malware | 5 | 5.0% | 45% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| Infostealer | 4 | 4.0% | 75% |
| Windows-Malware | 2 | 2.0% | 35% |
| Android-Malware | 1 | 1.0% | 45% |
| Trojaner | 1 | 1.0% | 65% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 87 | 86.1% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 8 | 7.9% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [33aedf60dd4925…](https://bazaar.abuse.ch/sample/33aedf60dd4925f6a980a142182a9b6961a94d86a7f0910cde828d658066a18f/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [80e8fe686db6dc…](https://bazaar.abuse.ch/sample/80e8fe686db6dcdca07ac944a616b673afb65a8ce2b704086a748891fb41cd3f/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [d0868826e42a8b…](https://bazaar.abuse.ch/sample/d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [ae744069e73d8f…](https://bazaar.abuse.ch/sample/ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [032bbeaa3106ef…](https://bazaar.abuse.ch/sample/032bbeaa3106eff8c14d11a3439ee8e58d7ff8a87019155065f190e71e5fa730/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [44ba2238310ceb…](https://bazaar.abuse.ch/sample/44ba2238310ceb94198d0f086f9ed4edf727b680569b330b10344140e41d08f0/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [82b7ab720e0a78…](https://bazaar.abuse.ch/sample/82b7ab720e0a787544b9d8a71ae71e73ddefbbab6b7aebcf9cdd085b4943b9f3/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [f353cd7de97831…](https://bazaar.abuse.ch/sample/f353cd7de97831ec9577ae8270a9adab5a1d84061f7f476213322a6af2ab8e03/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [fcd8384dabe51c…](https://bazaar.abuse.ch/sample/fcd8384dabe51cd85b8df552a97a77402c92c35fb5be42327023894ceef5f87e/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [23c1f8ea43b5c7…](https://bazaar.abuse.ch/sample/23c1f8ea43b5c7d627971dd381436fcab6613ecb2c57c41cc545649d5494fe11/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6584/8111 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6584/8111 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6281/8111 |
| 6 | Kaspersky | 75.6% | 6134/8110 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5781/8107 |
| 9 | Rising | 68.6% | 5563/8111 |
| 10 | Varist | 66.1% | 5360/8106 |
| 11 | Tencent | 65.2% | 5141/7885 |
| 12 | Avast | 65.2% | 5289/8107 |
| 13 | AVG | 65.2% | 5289/8106 |
| 14 | McAfeeD | 61.5% | 4984/8103 |
| 15 | huorong | 61.0% | 4944/8103 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 88 | 87.1% |
| 🪟 Windows | 10 | 9.9% |
| 📦 Archiv | 2 | 2.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| APK-Sideloading | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 50 | 49.5% |
| 2 | 🇺🇸 US | 35 | 34.7% |
| 3 | 🇫🇷 FR | 6 | 5.9% |
| 4 | 🇮🇩 ID | 4 | 4.0% |
| 5 | 🇳🇱 NL | 2 | 2.0% |
| 6 | 🇯🇵 JP | 1 | 1.0% |
| 7 | 🇪🇸 ES | 1 | 1.0% |
| 8 | 🇸🇬 SG | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 55 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 52 |
| Lateral Movement | 52 |
| Command and Control | 3 |
| Collection | 3 |

<details><summary>33aedf60dd4925f6a980… – RemcosRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>80e8fe686db6dcdca07a… – RemcosRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>d0868826e42a8b12a7dd… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ae744069e73d8fa89e8e… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>032bbeaa3106eff8c14d… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5f27bb695949987e1fef…](https://bazaar.abuse.ch/sample/5f27bb695949987e1feff780c5cc002842342e128c2153fc19a10e56ab7b73e8/)

- **Familie:** Prometei
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.16
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37937637`

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.16` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D242E1E5` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37937637` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37937637 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39503691` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37937637` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.16` |
| Varist | `E64/PrometeiS.C` |
| huorong | `Trojan/Prometei.c` |

### [3c2743136c545fad314f…](https://bazaar.abuse.ch/sample/3c2743136c545fad314f328a5f45cf0176e8a8e8042ec09a0f81e47271b3f5f7/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [d1b7e1661e6db02b1144…](https://bazaar.abuse.ch/sample/d1b7e1661e6db02b11443b0093a3c41fcae239f36b241b3e7e777fa8b548ab56/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 74 Engines (33.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Kingsoft | `Linux.Backdoor.Mirai.ld` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [f80a5a923001773ec75d…](https://bazaar.abuse.ch/sample/f80a5a923001773ec75d74129508b495dd9bb295ed540fcc93c9891aaef18245/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 74 Engines (41.9%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!21C6D0197FE0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (31/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B75 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!21C6D0197FE0` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Trojan.Linux.Mirai.nn` |
| TrellixENS | `LINUX/Mirai-FQU!21C6D0197FE0` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.USBLKN26` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `Backdoor:Linux/Mirai.ASJ` |
| huorong | `Trojan/Linux.Mirai.na` |

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

- **elf** (77×)
- **Mirai** (52×)
- **Torii** (47×)
- **EasyShell** (28×)
- **RAT** (28×)
- **Rust** (28×)
- **SnoopyTriage** (28×)
- **macho** (8×)
- **exe** (7×)
- **Prometei** (6×)
- **stealer** (4×)
- **Warden** (4×)
- **WARDENStealer** (4×)
- **upx-dec** (3×)
- **upx** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +35 (17→52)
- ↓ **unbekannt** -10 (50→40)
- ↑ **Prometei** +1 (5→6)
- ↑ **RemcosRAT** +1 (1→2)
- ↓ **njrat** -3 (4→1)
- weg: **CoinMiner** (war 2)
- weg: **WARDENStealer** (war 6)
- weg: **EasyShell** (war 6)
- weg: **ValleyRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +22 (30→52)
- ↑ **unbekannt** +7 (33→40)
- ↑ **Prometei** +1 (5→6)
- ↓ **RemcosRAT** -1 (3→2)
- ↓ **njrat** -1 (2→1)
- weg: **AgentTesla** (war 2)
- weg: **WARDENStealer** (war 5)
- weg: **FantasyHub** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.533 MB |
| σ Dateigröße | 2.912 MB |
| Ø Risiko-Score | 76.6/100 |
| Ø Klassifikations-Konfidenz | 81.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 55/101 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 27 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 06:27 | [b2b386edce5a…](https://bazaar.abuse.ch/sample/b2b386edce5af8084484858ac2310f214bf01e363714133ed0f9c322f2c727a1/) | `apk` | unbekannt | 43.3 | – | – | 🌐JP |
| 06:26 | [f54c081f2165…](https://bazaar.abuse.ch/sample/f54c081f216590deb7b964981d911f66e5bfdb603da976dfd125ceb677a65738/) | `sh` | unbekannt | 32.7 | – | – | 🇳🇱NL |
| 06:18 | [1d536954415b…](https://bazaar.abuse.ch/sample/1d536954415b2bf1dc25e03e8f73f94b58a8646d4e6d672b71880389843c5d4b/) | `sh` | unbekannt | 32.6 | – | – | 🇩🇪DE |
| 06:18 | [d0868826e42a…](https://bazaar.abuse.ch/sample/d0868826e42a8b12a7dda66a13680161b79e518611258622c8dfa9d74558d381/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 06:13 | [ae744069e73d…](https://bazaar.abuse.ch/sample/ae744069e73d8fa89e8e5414c85a8b0fd1dd6d648647eced09ddfa47188c7374/) | `elf` | Mirai | 84.3 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.11.2026 06:30 UTC*