# MalwareBazaar – 16.11.2026 15:11 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **58** |
| Höchster Score | **95.4/100** – c08c3354bea091ba… |
| Häufigste Familie | **unbekannt** (32x) |
| Häufigster Typ | **exe** (48x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 24 Samples |
| Ø Dateigröße | 4.94 MB (σ=6.54) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 48 | 47.5%  █████████ |
| `elf` | 25 | 24.8%  ████ |
| `xls` | 9 | 8.9%  █ |
| `js` | 9 | 8.9%  █ |
| `apk` | 7 | 6.9%  █ |
| `iso` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 32 | 31.7% |
| 2 | FunStealer | 29 | 28.7% |
| 3 | Mirai | 20 | 19.8% |
| 4 | Prometei | 5 | 5.0% |
| 5 | PhantomStealer | 4 | 4.0% |
| 6 | RemcosRAT | 3 | 3.0% |
| 7 | AgentTesla | 3 | 3.0% |
| 8 | RustyStealer | 2 | 2.0% |
| 9 | AsyncRAT | 1 | 1.0% |
| 10 | WannaCry | 1 | 1.0% |
| 11 | CVE-2017-0199 | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 35 | 34.7% | 75% |
| Botnet/IoT | 20 | 19.8% | 95% |
| Windows-Malware | 14 | 13.9% | 35% |
| Android-Malware | 7 | 6.9% | 45% |
| Maldoc | 7 | 6.9% | 35% |
| Linux-Malware | 6 | 5.9% | 45% |
| RAT | 4 | 4.0% | 95% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Ransomware | 1 | 1.0% | 95% |
| Exploit | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 58 | 57.4% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 38 | 37.6% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c08c3354bea091…](https://bazaar.abuse.ch/sample/c08c3354bea091ba3ab640b8131ebf750eb35c064accb95d8d4d7a2760ac1bd1/) | WannaCry | Ransomware | **95.4** | 🔴 KRITISCH | – | – | ? |
| [b3385f0b6c15c5…](https://bazaar.abuse.ch/sample/b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [ee010c49c934f2…](https://bazaar.abuse.ch/sample/ee010c49c934f251fa43339d7156167390be0ec3554f40e68ecd640b1077f3a6/) | RemcosRAT | RAT | **86.6** | 🔴 KRITISCH | – | – | ? |
| [b891d778ca2efd…](https://bazaar.abuse.ch/sample/b891d778ca2efd0b9017a168038783139e4a954f3e2212058c2ffbe122471a52/) | RemcosRAT | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [5f1bab1609ded2…](https://bazaar.abuse.ch/sample/5f1bab1609ded2ad78242512b487af2e6ccd0c3741b7f0df53342ffb63e36af9/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [28b1b1ad79b5bd…](https://bazaar.abuse.ch/sample/28b1b1ad79b5bdb766c52ca9096092c83e414a84be0a39b773e1fc00b230ff73/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [fc6926cdc544f1…](https://bazaar.abuse.ch/sample/fc6926cdc544f183e18b2704377dd6071d810739bd7247f53e0b163c704b06a0/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [02766b58243e99…](https://bazaar.abuse.ch/sample/02766b58243e998764e8652e7477dc7b407d1b7e4640bbde03e20dd7ca045775/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [48a6ed74b65d52…](https://bazaar.abuse.ch/sample/48a6ed74b65d5229892170be2b155df66976e618424b43f2a9acddf24b3d39f9/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [092c63baffd654…](https://bazaar.abuse.ch/sample/092c63baffd654fa3da6364e535a3a426d701677a171be5663e31c4db37e1272/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6507/8018 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6507/8018 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6200/8018 |
| 6 | Kaspersky | 75.5% | 6053/8017 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5709/8014 |
| 9 | Rising | 68.5% | 5489/8018 |
| 10 | Varist | 66.1% | 5293/8013 |
| 11 | Avast | 65.2% | 5222/8014 |
| 12 | AVG | 65.2% | 5222/8013 |
| 13 | Tencent | 65.1% | 5071/7792 |
| 14 | McAfeeD | 61.5% | 4924/8010 |
| 15 | huorong | 60.8% | 4872/8010 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 48 | 47.5% |
| 🐧 Linux | 26 | 25.7% |
| 📄 Dokument | 9 | 8.9% |
| ❓ Unbekannt | 9 | 8.9% |
| 🤖 Android | 7 | 6.9% |
| 📦 Archiv | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 75 | 74.3% |
| Phishing / E-Mail-Anhang | 9 | 8.9% |
| Drive-By / Exploit-Kit | 9 | 8.9% |
| APK-Sideloading | 7 | 6.9% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 42 | 41.6% |
| 2 | 🇩🇪 DE | 25 | 24.8% |
| 3 | 🇦🇹 AT | 18 | 17.8% |
| 4 | 🌐 CL | 7 | 6.9% |
| 5 | 🇺🇸 US | 4 | 4.0% |
| 6 | 🇭🇺 HU | 2 | 2.0% |
| 7 | 🇳🇱 NL | 1 | 1.0% |
| 8 | 🇵🇱 PL | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 24 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |
| Command and Control | 4 |
| Collection | 3 |
| Execution | 1 |

<details><summary>b3385f0b6c15c5abe66c… – AsyncRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>ee010c49c934f251fa43… – RemcosRAT | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>b891d778ca2efd0b9017… – RemcosRAT | 🔴 KRITISCH 86.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>5f1bab1609ded2ad7824… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [577c114ca3bfeb16260e…](https://bazaar.abuse.ch/sample/577c114ca3bfeb16260eb5d6d46b3a8754e0c393cc1e3b51f34600eabba89bc7/)

- **Familie:** FunStealer
- **Erkannt von:** 34 von 74 Engines (46.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Lazy.742399
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Lazy.742399`

**Erkennende Engines (34/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Lazy.742399` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R805874` |
| Arcabit | `Trojan.Lazy.DB53FF` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Lazy.742399` |
| Bkav | `W32.Malware.5F2119A1` |
| CTX | `exe.unknown.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.52029` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Lazy.742399 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Gen:Variant.Lazy.742399` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kingsoft | `malware.kb.a.909` |
| Malwarebytes | `Malware.AI.2728875401` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| MicroWorld-eScan | `Gen:Variant.Lazy.742399` |
| Rising | `Trojan.Kryptik@AI.94 (RDML:+p7Na9HhYZCCmw6bTdBqHA)` |
| Sophos | `Generic ML PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006302` |
| Trapmine | `suspicious.low.ml.score` |
| VIPRE | `Gen:Variant.Lazy.742399` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |

### [0989934a927be84c483b…](https://bazaar.abuse.ch/sample/0989934a927be84c483b4ea16f347177792fb989d20efef8d685e7ddb6c8fdc4/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 74 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [5c868a889bc09e9dccf2…](https://bazaar.abuse.ch/sample/5c868a889bc09e9dccf261c4955c695523153112fe43833f6357742e5b329910/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 74 Engines (41.9%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (31/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.Gafgyt.SE180` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avira | `EXP/ELF.Mirai.D` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| ClamAV | `Unix.Trojan.Gafgyt-6981160-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.D` |
| Fortinet | `ELF/Fodcha.080F!tr` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ns` |
| Kingsoft | `Linux.Backdoor.elf.2023761` |
| Lionic | `Trojan.Linux.Gafgyt.m!c` |
| MaxSecure | `Trojan.Malware.344458885.susgen.npe` |
| McAfeeD | `ti!5C868A889BC0` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.DE80 (CLASSIC)` |
| Sangfor | `Backdoor.Linux.Mirai.V6h2` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Zhtrap.dhyra` |
| TrendMicro | `Backdoor.Linux.MIRAI.USBLKE26` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.USBLKE26` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| alibabacloud | `DDoS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.f` |

### [7dc345594fbe8bf066e2…](https://bazaar.abuse.ch/sample/7dc345594fbe8bf066e279583ceac04a2f184e5b1433ffb0ded2b951188d27e5/)

- **Familie:** CVE-2017-0199
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0199.04.Gen
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0199.04.Gen`

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0199.04.Gen` |
| Arcabit | `Exploit.CVE-2017-0199.04.Gen` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0199.04.Gen` |
| CTX | `xls.exploit-kit.cve-2017-0199` |
| ESET-NOD32 | `probably Win32/Exploit.CVE-2017-0199.C trojan` |
| Emsisoft | `Exploit.CVE-2017-0199.04.Gen (B)` |
| Fortinet | `MSExcel/CVE_2017_0199.DD!exploit` |
| GData | `Exploit.CVE-2017-0199.04.Gen` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.OLE2.UrcBadur.genw` |
| Lionic | `Trojan.MSExcel.UrcBadur.4!c` |
| McAfeeD | `Trojan:Office/Exploit.AJ` |
| MicroWorld-eScan | `Exploit.CVE-2017-0199.04.Gen` |
| Rising | `Exploit.CVE-2017-0199!1.E43C (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious OLE` |
| Symantec | `Trojan.Gen.NPE` |
| TACHYON | `Downloader/W97.CVE-2017-0199` |
| Tencent | `Exp.MsOffice.Cve2019_0199.11022680` |
| TrendMicro | `HEUR_CVE170199.L` |
| TrendMicro-HouseCall | `HEUR_CVE170199.L` |
| VIPRE | `Exploit.CVE-2017-0199.04.Gen` |
| Varist | `CVE-2017-0199.A.gen!Camelot` |
| alibabacloud | `Exploit:Win/CVE-2017-0199.C` |
| huorong | `Exploit/CVE-2017-0199.t` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 74 Engines (83.8%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/74):**

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
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
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
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (47×)
- **FunStealer** (29×)
- **elf** (25×)
- **Mirai** (20×)
- **CVE-2017-0199** (9×)
- **xls** (9×)
- **js** (9×)
- **apk** (7×)
- **Prometei** (5×)
- **PhantomStealer** (4×)
- **AgentTesla** (3×)
- **RustyStealer** (2×)
- **RemcosRAT** (2×)
- **AsyncRAT** (1×)
- **RAT** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +16 (16→32)
- neu: **FunStealer** (29)
- ↓ **Mirai** -13 (33→20)
- ↑ **Prometei** +3 (2→5)
- neu: **PhantomStealer** (4)
- ↑ **RemcosRAT** +2 (1→3)
- neu: **AgentTesla** (3)
- ↑ **RustyStealer** +1 (1→2)
- neu: **WannaCry** (1)
- weg: **WARDENStealer** (war 6)
- weg: **SilentNet** (war 2)
- weg: **GuLoader** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +7 (25→32)
- neu: **FunStealer** (29)
- ↓ **Mirai** -16 (36→20)
- neu: **Prometei** (5)
- neu: **PhantomStealer** (4)
- ↑ **AgentTesla** +1 (2→3)
- ↑ **RustyStealer** +1 (1→2)
- weg: **SalatStealer** (war 6)
- weg: **WARDENStealer** (war 5)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.939 MB |
| σ Dateigröße | 6.540 MB |
| Ø Risiko-Score | 64.5/100 |
| Ø Klassifikations-Konfidenz | 65.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 24/101 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 25 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 15:00 | [b3385f0b6c15…](https://bazaar.abuse.ch/sample/b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27/) | `exe` | AsyncRAT | 89.6 | – | – | 🇳🇱NL |
| 14:24 | [1e8f4ed2322f…](https://bazaar.abuse.ch/sample/1e8f4ed2322f3d07c75929bcefa42a26b6d14b73e749b5064f5b15163130dad2/) | `iso` | unbekannt | 32.0 | – | – | 🌐HU |
| 14:24 | [3801e28d2571…](https://bazaar.abuse.ch/sample/3801e28d257196b3d5527b8992c1a6da442da6cf1c29621ca1b5c0d18361b044/) | `apk` | unbekannt | 42.6 | – | – | 🌐CL |
| 14:23 | [611bf3eac523…](https://bazaar.abuse.ch/sample/611bf3eac523eebf110bd58980d24a597d8a3408288bf722a9965f086aae3346/) | `apk` | unbekannt | 42.6 | – | – | 🌐CL |
| 14:23 | [a67e2dd4a88a…](https://bazaar.abuse.ch/sample/a67e2dd4a88a4854f631f0008bfc0671966b44a01e6573d68f8d9f739c687349/) | `apk` | unbekannt | 42.6 | – | – | 🌐CL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.11.2026 15:11 UTC*