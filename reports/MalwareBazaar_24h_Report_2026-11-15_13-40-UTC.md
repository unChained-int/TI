# MalwareBazaar – 15.11.2026 13:40 UTC

Dieser Run hat **99 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **79** |
| Höchster Score | **84.3/100** – 1326656c7f0f4203… |
| Häufigste Familie | **Mirai** (65x) |
| Häufigster Typ | **elf** (76x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 67 Samples |
| Ø Dateigröße | 7.41 MB (σ=26.48) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 76 | 76.0%  ███████████████ |
| `exe` | 14 | 14.0%  ██ |
| `apk` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |
| `zsh` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `7z` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 65 | 65.0% |
| 2 | unbekannt | 22 | 22.0% |
| 3 | SalatStealer | 7 | 7.0% |
| 4 | WARDENStealer | 2 | 2.0% |
| 5 | QD:Trojan.GenericKDQ.E2110ADC6 | 1 | 1.0% |
| 6 | CoinMiner | 1 | 1.0% |
| 7 | Amadey | 1 | 1.0% |
| 8 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 65 | 65.0% | 95% |
| Linux-Malware | 11 | 11.0% | 45% |
| Infostealer | 9 | 9.0% | 75% |
| RAT | 5 | 5.0% | 79% |
| Loader | 4 | 4.0% | 80% |
| Android-Malware | 2 | 2.0% | 45% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 79 | 79.0% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 14 | 14.0% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1326656c7f0f42…](https://bazaar.abuse.ch/sample/1326656c7f0f42038a87a323e0a9c6688150ac5d7fae4c1b4196c02006f99aab/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [5b448c3f93af88…](https://bazaar.abuse.ch/sample/5b448c3f93af8830774e5c69feae106d5652e38ec988b9e075e909d7ad0a3c9b/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [7e8fd4522b03da…](https://bazaar.abuse.ch/sample/7e8fd4522b03dacaadbaabcf4f93adf7c9562333d4bdafced811a591221e8301/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [15b557dd6ad7bd…](https://bazaar.abuse.ch/sample/15b557dd6ad7bd33830b895ea381134d457998a480ae9efa58de93390cde0abb/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [74fc187f4dac2c…](https://bazaar.abuse.ch/sample/74fc187f4dac2c32a56ae200825dec4b13ed7cff4ab0ac845b93f67cb95a0fe9/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [7792d3f21e592c…](https://bazaar.abuse.ch/sample/7792d3f21e592ce2a31191b447eadbd82875515c1441ebf5bd423fbc8ab67c2a/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [354edb3e1701ca…](https://bazaar.abuse.ch/sample/354edb3e1701ca8f58ac9945fcf88f0481e25ee97cce3fe4192e21573c0c9755/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [a74f60e5deac9e…](https://bazaar.abuse.ch/sample/a74f60e5deac9ecf7953ee0f855a5a493832b6b143141e75526bf954720f303f/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [1bcae1cc9e696b…](https://bazaar.abuse.ch/sample/1bcae1cc9e696bf47265291c7a94519b011d988e35289c39023a9b58b5f31b5a/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [a29e1b672b34b6…](https://bazaar.abuse.ch/sample/a29e1b672b34b653aa3bf4f40c0f26f4735e1c1fd3360e135c65b2b38d515692/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6491/7999 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6491/7999 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6184/7999 |
| 6 | Kaspersky | 75.5% | 6037/7998 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5696/7995 |
| 9 | Rising | 68.4% | 5473/7999 |
| 10 | Varist | 66.0% | 5280/7994 |
| 11 | Avast | 65.1% | 5208/7995 |
| 12 | AVG | 65.1% | 5208/7994 |
| 13 | Tencent | 65.0% | 5054/7773 |
| 14 | McAfeeD | 61.4% | 4910/7991 |
| 15 | huorong | 60.8% | 4860/7991 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 79 | 79.0% |
| 🪟 Windows | 16 | 16.0% |
| 🤖 Android | 2 | 2.0% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 93 | 93.0% |
| MaaS-Loader | 4 | 4.0% |
| APK-Sideloading | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 61 | 61.0% |
| 2 | 🇺🇸 US | 16 | 16.0% |
| 3 | 🇳🇱 NL | 11 | 11.0% |
| 4 | 🇨🇿 CZ | 5 | 5.0% |
| 5 | 🇫🇷 FR | 3 | 3.0% |
| 6 | 🇷🇴 RO | 2 | 2.0% |
| 7 | 🌐 DO | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 67 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 65 |
| Lateral Movement | 65 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>1326656c7f0f42038a87… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5b448c3f93af8830774e… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7e8fd4522b03dacaadba… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>15b557dd6ad7bd33830b… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>74fc187f4dac2c32a56a… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3df036123e1ef0d0c7ef…](https://bazaar.abuse.ch/sample/3df036123e1ef0d0c7ef63f735f2357eb7c58e36daf091745427b999f1786ba1/)

- **Familie:** QD:Trojan.GenericKDQ.E2110ADC6
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** QD:Trojan.GenericKDQ.E2110ADC6A
- **VT-Reputation:** -2
- **Microsoft Defender:** ✓ **JA** – `QD:Trojan.GenericKDQ.E2110ADC6A`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `QD:Trojan.GenericKDQ.E2110ADC6A` |
| AVG | `Win64:Evo-gen [Trj]` |
| Alibaba | `TrojanDropper:Win32/Kryptik.917f8ef2` |
| Arcabit | `QD:Trojan.GenericQ.E2110ADC6A` |
| Avast | `Win64:Evo-gen [Trj]` |
| BitDefender 🛡️ | `QD:Trojan.GenericKDQ.E2110ADC6A` |
| CTX | `exe.trojan.generic` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik.GXY trojan` |
| Emsisoft | `QD:Trojan.GenericKDQ.E2110ADC6A (B)` |
| Fortinet | `W64/Kryptik.GXY!tr` |
| GData | `QD:Trojan.GenericKDQ.E2110ADC6A` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Crypt` |
| Kaspersky | `UDS:Trojan-Dropper.Win32.Generic` |
| Lionic | `Trojan.Win32.GenericKDQ.b!c` |
| Malwarebytes | `Trojan.Dropper` |
| MaxSecure | `Trojan.Malware.1698455.susgen` |
| McAfeeD | `ti!3DF036123E1E` |
| MicroWorld-eScan | `QD:Trojan.GenericKDQ.E2110ADC6A` |
| Panda | `Trj/Chgt.BF` |
| Rising | `Trojan.Kryptik/x64!1.14301 (CLOUD)` |
| Sangfor | `Dropper.Win32.Kryptik.Vlpu` |
| Skyhigh | `Artemis` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win32.Trojan.Obfuscate.Qgil` |
| VIPRE | `QD:Trojan.GenericKDQ.E2110ADC6A` |
| Varist | `W32/ABTrojan.ASCH-8625` |
| alibabacloud | `Trojan[dropper]:Win/Wacatac.B9nj` |
| huorong | `Trojan/Generic!EB2A5C4C3BE40640` |

### [b90996cd3c1f7d8bbfe6…](https://bazaar.abuse.ch/sample/b90996cd3c1f7d8bbfe687750ed00eb0fbfebf0892cf7b688cec02d37fa873bc/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.K!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai.ba` |
| Avast-Mobile | `ELF:Mirai-AAU [Trj]` |
| Avira | `TR/LINUX.Mirai.BJH` |
| ClamAV | `Unix.Dropper.Mirai-7135925-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9788` |
| ESET-NOD32 | `Linux/Mirai.CBS trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BJH` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.hv` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Script/Dirtydecrypt.EAA` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.B` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Artemis!Trojan` |
| Symantec | `Linux.Mirai` |
| Tencent | `Malware.Linux.Generic.1c0c8844` |
| alibabacloud | `Trojan:Linux/Mirai.BH` |
| huorong | `Trojan/Linux.Tsunami.o` |

### [829c639b1525d178fea7…](https://bazaar.abuse.ch/sample/829c639b1525d178fea796b7706ade940d62e839995ccf589e022349f50daec5/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Flooder-AEK [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Flooder-AEK [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Flooder-AEK [Trj]` |
| Avast-Mobile | `ELF:Flooder-AEG [Trj]` |
| Avira | `EXP/ELF.Agent.J.8` |
| ClamAV | `Unix.Trojan.Mirai-8041698-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3343` |
| ESET-NOD32 | `Linux/Flooder.Agent.NQ trojan` |
| F-Secure | `Exploit.EXP/ELF.Agent.J.8` |
| Fortinet | `ELF/Flooder.NQ!tr` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nd` |
| Lionic | `Trojan.Linux.Flooder.m!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GL!MTB` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `OB:Backdoor.Linux.Flooder.mipra` |
| Varist | `E32/Mirai.DZ.gen!Eldorado` |
| alibabacloud | `DDoS:Linux/Mirai.GE8PHU` |
| huorong | `Trojan/Linux.DDos.dw` |

### [6ca187b9eaf08c9ee99d…](https://bazaar.abuse.ch/sample/6ca187b9eaf08c9ee99d9afdb7948cbbc9472beabbc6ea38edee672d4b514f0b/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-BQZ [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-BQZ [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Agent-BQZ [PUP]` |
| Avira | `PUA/LINUX.Agent.BQZ` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3343` |
| ESET-NOD32 | `Linux/Flooder.Agent.NQ trojan` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.BQZ` |
| Fortinet | `ELF/UNSTABLE.OX!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!6CA187B9EAF0` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sangfor | `PUP.Linux.Mirai.V3zd` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Symantec | `PUA.Gen.2` |
| Tencent | `OB:Backdoor.Linux.Flooder.mipra` |
| Varist | `E32/Mirai.BNH` |
| alibabacloud | `Backdoor:Linux/Flooder.Akgpp` |
| huorong | `Trojan/Linux.DDos.dw` |

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

- **elf** (74×)
- **Mirai** (61×)
- **Torii** (30×)
- **exe** (13×)
- **upx-dec** (13×)
- **upx** (13×)
- **Prometei** (6×)
- **SalatStealer** (5×)
- **SilverFox** (4×)
- **ValleyRAT** (4×)
- **wraith** (3×)
- **stealer** (3×)
- **apk** (2×)
- **crypto** (2×)
- **FakeApp** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +17 (48→65)
- ↓ **unbekannt** -7 (29→22)
- ↑ **SalatStealer** +4 (3→7)
- ↓ **WARDENStealer** -3 (5→2)
- neu: **QD:Trojan.GenericKDQ.E2110ADC6** (1)
- neu: **CoinMiner** (1)
- neu: **Amadey** (1)
- weg: **njrat** (war 2)
- weg: **RemusStealer** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **RevStealer** (war 2)
- weg: **ConnectWise** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +30 (35→65)
- ↓ **unbekannt** -4 (26→22)
- ↑ **SalatStealer** +1 (6→7)
- ↓ **WARDENStealer** -3 (5→2)
- neu: **QD:Trojan.GenericKDQ.E2110ADC6** (1)
- neu: **Amadey** (1)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 2)
- weg: **RevStealer** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.409 MB |
| σ Dateigröße | 26.482 MB |
| Ø Risiko-Score | 73.4/100 |
| Ø Klassifikations-Konfidenz | 83.0% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 67/100 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 39 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:32 | [3df036123e1e…](https://bazaar.abuse.ch/sample/3df036123e1ef0d0c7ef63f735f2357eb7c58e36daf091745427b999f1786ba1/) | `exe` | QD:Trojan.GenericKDQ.E | 76.1 | 41.3% | 🟠 MÄSSIG ERKANNT | 🇺🇸US |
| 13:29 | [ccc8053c432e…](https://bazaar.abuse.ch/sample/ccc8053c432e7bc0ab10d874e6727b9ebf411899c47af5be974e19073c4dd777/) | `exe` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 13:27 | [33037dd37f1a…](https://bazaar.abuse.ch/sample/33037dd37f1a6aae3e3ebe4a4b60a638db3a41cf73c8493f3b698b9c334c0fb5/) | `exe` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 13:25 | [1326656c7f0f…](https://bazaar.abuse.ch/sample/1326656c7f0f42038a87a323e0a9c6688150ac5d7fae4c1b4196c02006f99aab/) | `elf` | Mirai | 84.3 | – | – | 🇳🇱NL |
| 13:25 | [20702c4400a4…](https://bazaar.abuse.ch/sample/20702c4400a465a0d9935ddbcacb66d99e81c3eb90336df5f1a13d1b2a674922/) | `exe` | unbekannt | 81.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.11.2026 13:40 UTC*