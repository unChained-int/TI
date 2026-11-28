# MalwareBazaar – 28.11.2026 09:56 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **19** |
| Höchster Score | **88.0/100** – f501cb01971be1f5… |
| Häufigste Familie | **unbekannt** (76x) |
| Häufigster Typ | **exe** (74x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 12 Samples |
| Ø Dateigröße | 4.86 MB (σ=3.50) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 74 | 73.3%  ██████████████ |
| `elf` | 16 | 15.8%  ███ |
| `macho` | 3 | 3.0%   |
| `js` | 2 | 2.0%   |
| `jar` | 2 | 2.0%   |
| `zsh` | 2 | 2.0%   |
| `zip` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 76 | 75.2% |
| 2 | Mirai | 12 | 11.9% |
| 3 | Stealer | 4 | 4.0% |
| 4 | AMOS | 4 | 4.0% |
| 5 | AgentTesla | 2 | 2.0% |
| 6 | Prometei | 2 | 2.0% |
| 7 | ConnectWise | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 68 | 67.3% | 35% |
| Botnet/IoT | 12 | 11.9% | 95% |
| Infostealer | 8 | 7.9% | 82% |
| Linux-Malware | 4 | 4.0% | 45% |
| Trojaner | 3 | 3.0% | 65% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Backdoor | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 19 | 18.8% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 74 | 73.3% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f501cb01971be1…](https://bazaar.abuse.ch/sample/f501cb01971be1f5b4b51e730dfab51445c6c21a413f575a495401f219da41d9/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [1b7d288cfcffed…](https://bazaar.abuse.ch/sample/1b7d288cfcffed6d8703e358f1715a73277168e0c945f424ad93ebeb4ea22006/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [e3c60ab3a2d893…](https://bazaar.abuse.ch/sample/e3c60ab3a2d893498e74f87fe313f522a7e29dfcdd9fc64b285c9d935d3d2ae2/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [848c85bbc2f175…](https://bazaar.abuse.ch/sample/848c85bbc2f1753b9e156b378cd21e57b483b31f3423feca7362faa222a6be0b/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [d10d266ee9e7da…](https://bazaar.abuse.ch/sample/d10d266ee9e7daf94f2d47005246bb773dc32353cf1c5631c8c34f0d0febbcf2/) | unbekannt | Backdoor | **83.7** | 🔴 KRITISCH | – | – | ? |
| [0b49dce0731b35…](https://bazaar.abuse.ch/sample/0b49dce0731b35db15aa641e7cb8b517326afbb055f4bc2509687abbd77cf6ed/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [f5d0ff8dfd1123…](https://bazaar.abuse.ch/sample/f5d0ff8dfd112319f4dc22bdc9d9c7451ec8749e2b799c675d1fc49d70cd5f58/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [5a5d7ddef9b52e…](https://bazaar.abuse.ch/sample/5a5d7ddef9b52ea0acec23ee73a5680b2afb3ba23514c8a26a989676845fd733/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [a696e2f25c13e3…](https://bazaar.abuse.ch/sample/a696e2f25c13e37a8775abd8f06c0a0ea3363c8eb924306abe1a8f9f3007bb86/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [e6de86722393a7…](https://bazaar.abuse.ch/sample/e6de86722393a7991b6d15bf57cf78171cd4203265e20fbc98052d1b212f8f88/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6636/8173 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6636/8173 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6335/8173 |
| 6 | Kaspersky | 75.5% | 6168/8172 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5825/8169 |
| 9 | Rising | 68.7% | 5613/8173 |
| 10 | Varist | 66.1% | 5403/8168 |
| 11 | Tencent | 65.3% | 5189/7947 |
| 12 | Avast | 65.1% | 5320/8169 |
| 13 | AVG | 65.1% | 5320/8168 |
| 14 | McAfeeD | 61.3% | 5007/8165 |
| 15 | huorong | 61.1% | 4987/8165 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 73 | 72.3% |
| 🐧 Linux | 20 | 19.8% |
| ❓ Unbekannt | 4 | 4.0% |
| 🍎 macOS | 3 | 3.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 97 | 96.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 51 | 50.5% |
| 2 | 🇭🇺 HU | 23 | 22.8% |
| 3 | 🇩🇪 DE | 17 | 16.8% |
| 4 | 🇺🇸 US | 5 | 5.0% |
| 5 | 🌐 Unbekannt | 3 | 3.0% |
| 6 | 🇨🇭 CH | 2 | 2.0% |

## MITRE ATT&CK

> 12 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 12 |
| Lateral Movement | 12 |


## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d5e858faed2b4384e0c8…](https://bazaar.abuse.ch/sample/d5e858faed2b4384e0c819313f8fc4af52abe12f035d2268ef68da6f91120dbe/)

- **Familie:** Stealer
- **Erkannt von:** 33 von 72 Engines (45.8%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.3041
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.3041`

**Erkennende Engines (33/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.3041` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R806282` |
| Arcabit | `Trojan.Stealer.DBE1` |
| Avast | `Win64:MalwareX-gen [Pws]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.Stealer.3041` |
| Bkav | `W32.Malware.CA8D5776` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Stealer.3041 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Trojan.Stealer.3041` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.FunStealer` |
| Malwarebytes | `Malware.AI.3936861095` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| MicroWorld-eScan | `Trojan.Stealer.3041` |
| Microsoft 🛡️ | `Trojan:Win64/ZStealer.AZ!MTB` |
| Rising | `Trojan.Kryptik@AI.94 (RDML:NAWaqTqNWVkA8LezwBdwgQ)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006303` |
| VIPRE | `Trojan.Stealer.3041` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `W32.Trojan.Gen` |
| huorong | `Trojan/W64.Agent.dp!crit` |

### [cb174e7be2cb1d0c8e23…](https://bazaar.abuse.ch/sample/cb174e7be2cb1d0c8e23654d7e80be14073a552927cbc64a34931d4572ada512/)

- **Familie:** Stealer
- **Erkannt von:** 36 von 72 Engines (50.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.3040
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.3040`

**Erkennende Engines (36/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.3040` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R805737` |
| Arcabit | `Trojan.Stealer.DBE0` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.Stealer.3040` |
| Bkav | `W32.Malware.203C1552` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.52029` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Stealer.3040 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Trojan.Stealer.3040` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.FunStealer` |
| Kingsoft | `malware.kb.a.923` |
| Malwarebytes | `Malware.Heuristic.2108` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| McAfeeD | `Trojan:Win/MSILoader.NE` |
| MicroWorld-eScan | `Trojan.Stealer.3040` |
| Microsoft 🛡️ | `Trojan:Win64/Yogi.GB!MTB` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:cBFmoa1Q26g29LIZq/p5Zw)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006302` |
| VIPRE | `Trojan.Stealer.3040` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |
| huorong | `Trojan/W64.Agent.dp!crit` |

### [345f0009fd110b322dfb…](https://bazaar.abuse.ch/sample/345f0009fd110b322dfb88c234d4720f228fa70f098510b2403d6cb408af62b0/)

- **Familie:** Stealer
- **Erkannt von:** 33 von 72 Engines (45.8%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Stealer.2111
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Stealer.2111`

**Erkennende Engines (33/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Stealer.2111` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R799187` |
| Arcabit | `Trojan.Stealer.D83F` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Stealer.2111` |
| Bkav | `W32.Malware.9E00A33C` |
| CTX | `exe.spyware.generic` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.HHS trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Stealer.2111 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Gen:Variant.Stealer.2111` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.FunStealer` |
| Kingsoft | `malware.kb.a.938` |
| Malwarebytes | `Malware.AI.3278944558` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| MicroWorld-eScan | `Gen:Variant.Stealer.2111` |
| Microsoft 🛡️ | `Trojan:Win64/Yogi.GB!MTB` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:dQrXvjBgExfWdVj83HxQtQ)` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Yogi.145734` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |
| huorong | `TrojanSpy/W64.Stealer.abc` |

### [62d29172e7eb5f1ff35f…](https://bazaar.abuse.ch/sample/62d29172e7eb5f1ff35f84de215cadade4bf036d9b968f12b137533c5d83a482/)

- **Familie:** Stealer
- **Erkannt von:** 34 von 72 Engines (47.2%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Stealer.2112
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Stealer.2112`

**Erkennende Engines (34/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Stealer.2112` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R799187` |
| Arcabit | `Trojan.Stealer.D840` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Stealer.2112` |
| Bkav | `W32.Malware.9158264F` |
| CTX | `exe.spyware.generic` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Stealer.2112 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Gen:Variant.Stealer.2112` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.FunStealer` |
| Kaspersky | `UDS:Trojan.Win64.Injects` |
| Kingsoft | `malware.kb.a.994` |
| Malwarebytes | `Malware.AI.3612445331` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| McAfeeD | `Trojan:Win/Malwarex.EMO` |
| MicroWorld-eScan | `Gen:Variant.Stealer.2112` |
| Microsoft 🛡️ | `Trojan:Win64/ZStealer.AZ!MTB` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:5FgrmCmBBPxFPlmZ+JbpQg)` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Stealer.2112` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| huorong | `Trojan/W64.Agent.dp!crit` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **exe** (73×)
- **elf** (16×)
- **Mirai** (12×)
- **ClickFix** (5×)
- **Foxveil** (5×)
- **macOS** (5×)
- **AMOS** (4×)
- **Mach-O** (3×)
- **macho** (3×)
- **AgentTesla** (2×)
- **js** (2×)
- **clipper** (2×)
- **jar** (2×)
- **osrs** (2×)
- **runelure** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +32 (44→76)
- ↓ **Mirai** -12 (24→12)
- neu: **Stealer** (4)
- neu: **AMOS** (4)
- neu: **AgentTesla** (2)
- ↓ **Prometei** -5 (7→2)
- ↓ **ConnectWise** -1 (2→1)
- weg: **WARDENStealer** (war 2)
- weg: **CatStorm** (war 4)
- weg: **AsyncRAT** (war 2)
- weg: **njrat** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +38 (38→76)
- ↓ **Mirai** -8 (20→12)
- neu: **Stealer** (4)
- neu: **AMOS** (4)
- neu: **AgentTesla** (2)
- ↓ **Prometei** -4 (6→2)
- ↓ **ConnectWise** -1 (2→1)
- weg: **CatStorm** (war 2)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 4)
- weg: **WARDENStealer** (war 3)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.862 MB |
| σ Dateigröße | 3.496 MB |
| Ø Risiko-Score | 48.8/100 |
| Ø Klassifikations-Konfidenz | 47.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 12/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 26 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 09:51 | [ebfd12b01c8d…](https://bazaar.abuse.ch/sample/ebfd12b01c8da9f0abff803a6aac6cb80654d8ebf9d7d58afbcff5b98dbc6706/) | `zip` | unbekannt | 32.7 | – | – | 🌐HU |
| 09:16 | [cd48f3692a0e…](https://bazaar.abuse.ch/sample/cd48f3692a0e31f83f296c767b7b57e7a3aada395cfc5de3b797c67d931ed409/) | `exe` | unbekannt | 38.5 | – | – | 🌐HU |
| 09:16 | [bddbc417daec…](https://bazaar.abuse.ch/sample/bddbc417daec36a92faaf4d48696d0d97789d3269f76320a72ab1437f79213d5/) | `exe` | unbekannt | 38.5 | – | – | 🌐HU |
| 09:16 | [a4f84ada3554…](https://bazaar.abuse.ch/sample/a4f84ada35544accec83365fdd4ddeeb770d26098c2d2048bbe999d9b18637b4/) | `exe` | unbekannt | 38.5 | – | – | 🌐HU |
| 09:16 | [2f92ba3bb06c…](https://bazaar.abuse.ch/sample/2f92ba3bb06c52323d476d6a97994f163c6791b4663ea4da81abc86f99359496/) | `exe` | unbekannt | 38.5 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.11.2026 09:56 UTC*