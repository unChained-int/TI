# MalwareBazaar – 20.10.2026 21:23 UTC

Dieser Run hat **71 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **72** |
| Kritisch (≥75) | **34** |
| Höchster Score | **88.5/100** – 3464447f8b816cfb… |
| Häufigste Familie | **unbekannt** (37x) |
| Häufigster Typ | **elf** (28x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 29 Samples |
| Ø Dateigröße | 3.78 MB (σ=13.34) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 28 | 38.9%  ███████ |
| `exe` | 23 | 31.9%  ██████ |
| `jar` | 5 | 6.9%  █ |
| `doc` | 4 | 5.6%  █ |
| `js` | 4 | 5.6%  █ |
| `zsh` | 2 | 2.8%   |
| `macho` | 2 | 2.8%   |
| `docm` | 1 | 1.4%   |
| `zip` | 1 | 1.4%   |
| `sh` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 37 | 51.4% |
| 2 | Mirai | 22 | 30.6% |
| 3 | AMOS | 3 | 4.2% |
| 4 | RemcosRAT | 2 | 2.8% |
| 5 | VShell | 1 | 1.4% |
| 6 | RemusStealer | 1 | 1.4% |
| 7 | Trojan ( 006e54f91 ) | 1 | 1.4% |
| 8 | njrat | 1 | 1.4% |
| 9 | SalatStealer | 1 | 1.4% |
| 10 | Phorpiex | 1 | 1.4% |
| 11 | FileRepMalware [Misc] | 1 | 1.4% |
| 12 | PythonStealer | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 22 | 30.6% | 95% |
| Loader | 16 | 22.2% | 75% |
| Infostealer | 7 | 9.7% | 84% |
| Windows-Malware | 6 | 8.3% | 35% |
| Linux-Malware | 5 | 6.9% | 45% |
| Andere / Unbekannt | 5 | 6.9% | 20% |
| RAT | 4 | 5.6% | 90% |
| Trojaner | 3 | 4.2% | 65% |
| Skript/Dropper | 2 | 2.8% | 35% |
| Cryptominer | 2 | 2.8% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 34 | 47.2% |
| 🟠 HOCH | 20 | 27.8% |
| 🟡 MITTEL | 13 | 18.1% |
| 🟢 NIEDRIG | 5 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3464447f8b816c…](https://bazaar.abuse.ch/sample/3464447f8b816cfb5d61575cf343971394e5f4834adb2b7d3964c305dbb18182/) | njrat | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [2e5bb8cc0558df…](https://bazaar.abuse.ch/sample/2e5bb8cc0558dfed95e93207bdcc39dfd3ed21851d7ba1e8d56dee83088c5e66/) | AMOS | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [2ff0a9594923b8…](https://bazaar.abuse.ch/sample/2ff0a9594923b8896910fd338b4a899649bb89bca20ace4d00b9fada9da93441/) | AMOS | Infostealer | **87.6** | 🔴 KRITISCH | – | – | ? |
| [04d13a3126b1ba…](https://bazaar.abuse.ch/sample/04d13a3126b1ba562bd9d379d5870d5965702272ce62aade3b5186965f308981/) | AMOS | Infostealer | **87.6** | 🔴 KRITISCH | – | – | ? |
| [ffe615cf5607d1…](https://bazaar.abuse.ch/sample/ffe615cf5607d1fc36d694ab6419d7babc9c0b164ef8848bea077da734b98d92/) | RemcosRAT | RAT | **87.0** | 🔴 KRITISCH | – | – | ? |
| [e70289fc6447f6…](https://bazaar.abuse.ch/sample/e70289fc6447f602170549811635e82a9bdd3b85ea32c3f4eea140366acc00b3/) | Mirai | Botnet/IoT | **86.5** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ✗ |
| [3f0a76b609410d…](https://bazaar.abuse.ch/sample/3f0a76b609410df35e89bb5c5a42c675e787813a92ff54bc7a0598af04b8444b/) | RemcosRAT | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [fab2b4610eed54…](https://bazaar.abuse.ch/sample/fab2b4610eed54774a700d587514e9c7c53c9aea744362339ec1ded4dbf36b66/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [e1a4d414cb857b…](https://bazaar.abuse.ch/sample/e1a4d414cb857b1535f0b3f7306492153e5d4726b2dae796937fa1cf106e535c/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [8d9712ff3e284b…](https://bazaar.abuse.ch/sample/8d9712ff3e284b100fd1c4bc11dff5e3f14202ab34c24e33b1bb7e52f58aa489/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6086/7519 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6086/7519 |
| 3 | ESET-NOD32 | 77.3% | 5815/7519 |
| 4 | Kaspersky | 76.2% | 5730/7518 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5370/7516 |
| 8 | Rising | 68.7% | 5164/7519 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4979/7515 |
| 11 | Tencent | 65.2% | 4752/7293 |
| 12 | Avast | 65.2% | 4900/7515 |
| 13 | AVG | 65.2% | 4900/7514 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4605/7512 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 32 | 44.4% |
| 🪟 Windows | 23 | 31.9% |
| ❓ Unbekannt | 9 | 12.5% |
| 📄 Dokument | 5 | 6.9% |
| 🍎 macOS | 2 | 2.8% |
| 📦 Archiv | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 48 | 66.7% |
| C2 / Nachladen | 12 | 16.7% |
| Phishing / E-Mail-Anhang | 5 | 6.9% |
| Drive-By / Exploit-Kit | 4 | 5.6% |
| MaaS-Loader | 3 | 4.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 28 | 38.9% |
| 2 | 🇩🇪 DE | 11 | 15.3% |
| 3 | 🇬🇧 GB | 8 | 11.1% |
| 4 | 🇭🇺 HU | 8 | 11.1% |
| 5 | 🌐 DK | 6 | 8.3% |
| 6 | 🌐 EG | 4 | 5.6% |
| 7 | 🇳🇱 NL | 3 | 4.2% |
| 8 | 🇨🇭 CH | 2 | 2.8% |
| 9 | 🇸🇪 SE | 1 | 1.4% |
| 10 | 🌐 Unbekannt | 1 | 1.4% |

## MITRE ATT&CK

> 29 von 72 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 22 |
| Lateral Movement | 22 |
| Command and Control | 3 |
| Collection | 3 |
| Execution | 2 |
| Persistence | 2 |
| Impact | 2 |

<details><summary>3464447f8b816cfb5d61… – njrat | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>ffe615cf5607d1fc36d6… – RemcosRAT | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b560eddf7b3c61f9192b…](https://bazaar.abuse.ch/sample/b560eddf7b3c61f9192b427afa34aa6094a453fc0104a160805e84a25762cf53/)

- **Familie:** VShell
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Application.Jaik.45622
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.Jaik.45622`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Jaik.45622` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5508256` |
| Antiy-AVL | `Trojan/Win32.Mikey` |
| Arcabit | `Trojan.Application.Jaik.DB236` |
| Avast | `Win32:MalwareX-gen [Trj]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Application.Jaik.45622` |
| Bkav | `W32.Malware.6317B18A` |
| CTX | `exe.unknown.jaik` |
| ClamAV | `Win.Trojan.Mikey-10038331-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen33.25221` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Application.Jaik.45622 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `W32/Rozena.ZA!tr` |
| GData | `Win32.Trojan.Loader.Q` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Win64.Small` |
| Jiangmin | `Trojan.Generic.hscze` |
| K7AntiVirus | `Trojan ( 001203481 )` |
| K7GW | `Trojan ( 001203481 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!B560EDDF7B3C` |
| MicroWorld-eScan | `Gen:Variant.Application.Jaik.45622` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Virus.Win32.Gen.ccmw` |
| Rising | `Backdoor.VShell!1.13126 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Mikey` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Rozena.hj` |
| Trapmine | `suspicious.low.ml.score` |
| VBA32 | `Trojan.Rozena` |
| VIPRE | `Gen:Variant.Application.Jaik.45622` |
| Varist | `W32/Rozena.JO.gen!Eldorado` |
| VirIT | `Trojan.Win32.Genus.ZQO` |
| Webroot | `W32.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Backdoor:Win/shellcode.api(dyn)` |
| huorong | `Trojan/Fake.ao` |

### [ff32a1880f17fbf63ae7…](https://bazaar.abuse.ch/sample/ff32a1880f17fbf63ae7baa71b2d1e4a118f4c3eab958ca84c740d5704f177ca/)

- **Familie:** Trojan ( 006e54f91 )
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 006e54f91 )
- **VT-Reputation:** -1
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Stealc.R798434` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Packed.CAB.CF trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.oa!s1` |
| Ikarus | `Backdoor.Win32.Agent` |
| K7AntiVirus | `Trojan ( 006e54f91 )` |
| K7GW | `Trojan ( 006e54f91 )` |
| McAfeeD | `ti!FF32A1880F17` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!10E5196B6604` |
| Webroot | `Win.Trojan.Gen` |

### [e70289fc6447f6021705…](https://bazaar.abuse.ch/sample/e70289fc6447f602170549811635e82a9bdd3b85ea32c3f4eea140366acc00b3/)

- **Familie:** Mirai
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [5171a36daaf750b07b98…](https://bazaar.abuse.ch/sample/5171a36daaf750b07b987cd0aa73e2228a25b77c6cbfd9db2bd17270c6cdf077/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.6A906BAD` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVTE trojan` |
| Elastic | `malicious (high confidence)` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Malwarebytes | `Trojan.UACBypass` |
| McAfeeD | `ti!5171A36DAAF7` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Kryptik@AI.96 (RDML:IOFZ94S7Hvk7I2ZSUMTwxQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `suspicious.low.ml.score` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (28×)
- **Mirai** (22×)
- **exe** (19×)
- **honeypot** (9×)
- **dropped-by-GCleaner** (9×)
- **arm** (8×)
- **wraith** (5×)
- **APT28** (5×)
- **Dropper** (5×)
- **Hookedge** (5×)
- **jar** (5×)
- **java** (5×)
- **doc** (4×)
- **js** (4×)
- **ClickFix** (4×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -17 (54→37)
- ↓ **Mirai** -2 (24→22)
- ↑ **AMOS** +2 (1→3)
- ↑ **RemcosRAT** +1 (1→2)
- neu: **VShell** (1)
- neu: **Trojan ( 006e54f91 )** (1)
- neu: **njrat** (1)
- ↓ **SalatStealer** -1 (2→1)
- neu: **Phorpiex** (1)
- weg: **Formbook** (war 2)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +7 (30→37)
- ↑ **AMOS** +2 (1→3)
- neu: **VShell** (1)
- neu: **Trojan ( 006e54f91 )** (1)
- neu: **njrat** (1)
- neu: **Phorpiex** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.780 MB |
| σ Dateigröße | 13.344 MB |
| Ø Risiko-Score | 68.4/100 |
| Ø Klassifikations-Konfidenz | 72.0% |
| Samples mit VT | 5/72 |
| Samples mit MITRE | 29/72 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 68 |
| Unbekannte Familien | 5 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:17 | [fab2b4610eed…](https://bazaar.abuse.ch/sample/fab2b4610eed54774a700d587514e9c7c53c9aea744362339ec1ded4dbf36b66/) | `elf` | Mirai | 84.5 | – | – | 🇬🇧GB |
| 21:17 | [e1a4d414cb85…](https://bazaar.abuse.ch/sample/e1a4d414cb857b1535f0b3f7306492153e5d4726b2dae796937fa1cf106e535c/) | `elf` | Mirai | 84.5 | – | – | 🇬🇧GB |
| 21:17 | [c99f4b61d0e5…](https://bazaar.abuse.ch/sample/c99f4b61d0e5c2c8b80910244a58eaa80bc62bf9a12c81209170a1ee428e4a77/) | `elf` | unbekannt | 43.3 | – | – | 🇬🇧GB |
| 21:17 | [28a75347665e…](https://bazaar.abuse.ch/sample/28a75347665e8e8b377558741aa333d5f76df4a87020a37184154eef71de353c/) | `elf` | unbekannt | 43.3 | – | – | 🇬🇧GB |
| 21:15 | [8d9712ff3e28…](https://bazaar.abuse.ch/sample/8d9712ff3e284b100fd1c4bc11dff5e3f14202ab34c24e33b1bb7e52f58aa489/) | `elf` | Mirai | 84.4 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.10.2026 21:23 UTC*