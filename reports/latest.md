# MalwareBazaar – 23.10.2026 19:51 UTC

Dieser Run hat **68 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **69** |
| Kritisch (≥75) | **39** |
| Höchster Score | **96.4/100** – bb5b00bc5cda9b14… |
| Häufigste Familie | **unbekannt** (40x) |
| Häufigster Typ | **exe** (30x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 7.57 MB (σ=21.53) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 30 | 43.5%  ████████ |
| `elf` | 21 | 30.4%  ██████ |
| `js` | 5 | 7.2%  █ |
| `macho` | 3 | 4.3%   |
| `sh` | 3 | 4.3%   |
| `jar` | 1 | 1.4%   |
| `zip` | 1 | 1.4%   |
| `dll` | 1 | 1.4%   |
| `ps1` | 1 | 1.4%   |
| `apk` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 40 | 58.0% |
| 2 | Mirai | 14 | 20.3% |
| 3 | SalatStealer | 6 | 8.7% |
| 4 | RemusStealer | 2 | 2.9% |
| 5 | WannaCry | 2 | 2.9% |
| 6 | Malware | 1 | 1.4% |
| 7 | AokigaharaStealer | 1 | 1.4% |
| 8 | Obfuscated | 1 | 1.4% |
| 9 | Linux | 1 | 1.4% |
| 10 | PythonStealer | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 19 | 27.5% | 75% |
| Botnet/IoT | 15 | 21.7% | 93% |
| Loader | 9 | 13.0% | 75% |
| Windows-Malware | 6 | 8.7% | 35% |
| Andere / Unbekannt | 5 | 7.2% | 20% |
| Skript/Dropper | 5 | 7.2% | 35% |
| Cryptominer | 4 | 5.8% | 75% |
| Trojaner | 3 | 4.3% | 72% |
| Ransomware | 2 | 2.9% | 95% |
| Maldoc | 1 | 1.4% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 39 | 56.5% |
| 🟠 HOCH | 13 | 18.8% |
| 🟡 MITTEL | 12 | 17.4% |
| 🟢 NIEDRIG | 5 | 7.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [bb5b00bc5cda9b…](https://bazaar.abuse.ch/sample/bb5b00bc5cda9b146954913b67558c1e6fe522b3448dd34338ddf0a1bc48f4d1/) | WannaCry | Ransomware | **96.4** | 🔴 KRITISCH | – | – | ? |
| [5c20fc1a89052d…](https://bazaar.abuse.ch/sample/5c20fc1a89052d2b5fcdce69d9331783105542776a5919f82f62cfa5174670b4/) | WannaCry | Ransomware | **95.7** | 🔴 KRITISCH | – | – | ? |
| [88692caa13f4ec…](https://bazaar.abuse.ch/sample/88692caa13f4ec03f0854844f05bff0799608adb21ca638acee21eb478c4b7b6/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [57e8e36a0427c4…](https://bazaar.abuse.ch/sample/57e8e36a0427c437409ceca50a44df4112765477efe2e3ac0c0729403f02de2f/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [71b0487e535e5d…](https://bazaar.abuse.ch/sample/71b0487e535e5da1853aa845a6740121018faf9394174089832bc95ec1b0c744/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [88de3e51c7c8d5…](https://bazaar.abuse.ch/sample/88de3e51c7c8d56d82d03c5fbdccf1e36e9094095cd1a3dcef48a78fed10fb38/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [9ba8fb35915173…](https://bazaar.abuse.ch/sample/9ba8fb35915173f692c625f8f93c392886ca060e4546cdd5d1b5c68ac8dab477/) | unbekannt | Trojaner | **82.9** | 🔴 KRITISCH | – | – | ? |
| [a5d4f63e443a39…](https://bazaar.abuse.ch/sample/a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b/) | AokigaharaStealer | Infostealer | **82.6** | 🔴 KRITISCH | 16.0% | 🟡 SCHWACH ERKANNT | ✗ |
| [f1b14957a8245d…](https://bazaar.abuse.ch/sample/f1b14957a8245dbde7a4b09856e395a2d3aa931488dc079665192fb20dc92f29/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [b1477bd0243b8e…](https://bazaar.abuse.ch/sample/b1477bd0243b8e9cf8761187e92e2403917e17f10d4215eeb892a5a0f8559f5c/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6139/7582 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6139/7582 |
| 3 | ESET-NOD32 | 77.2% | 5857/7582 |
| 4 | Kaspersky | 76.0% | 5760/7581 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5396/7579 |
| 8 | Rising | 68.4% | 5185/7582 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5019/7578 |
| 11 | Avast | 65.2% | 4938/7578 |
| 12 | AVG | 65.2% | 4938/7577 |
| 13 | Tencent | 64.9% | 4775/7356 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4639/7575 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 32 | 46.4% |
| 🐧 Linux | 26 | 37.7% |
| ❓ Unbekannt | 5 | 7.2% |
| 🍎 macOS | 3 | 4.3% |
| 📦 Archiv | 1 | 1.4% |
| 🤖 Android | 1 | 1.4% |
| 📄 Dokument | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 54 | 78.3% |
| MaaS-Loader | 5 | 7.2% |
| Drive-By / Exploit-Kit | 5 | 7.2% |
| Exploit / N-Day | 2 | 2.9% |
| Trojanisierte Software | 1 | 1.4% |
| APK-Sideloading | 1 | 1.4% |
| Phishing / E-Mail-Anhang | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 32 | 46.4% |
| 2 | 🇩🇪 DE | 12 | 17.4% |
| 3 | 🇯🇵 JP | 6 | 8.7% |
| 4 | 🇳🇱 NL | 5 | 7.2% |
| 5 | 🇫🇷 FR | 4 | 5.8% |
| 6 | 🌐 Unbekannt | 4 | 5.8% |
| 7 | 🇬🇧 GB | 3 | 4.3% |
| 8 | 🇭🇺 HU | 1 | 1.4% |
| 9 | 🇨🇭 CH | 1 | 1.4% |
| 10 | 🇨🇦 CA | 1 | 1.4% |

## MITRE ATT&CK

> 21 von 69 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Impact | 9 |

<details><summary>88692caa13f4ec03f085… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>57e8e36a0427c437409c… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>71b0487e535e5da1853a… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [eea8223c913f91493dd3…](https://bazaar.abuse.ch/sample/eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4/)

- **Familie:** Malware
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.910242C5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.910242C5` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Kingsoft | `malware.kb.a.854` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Malware.Gen` |

### [a5d4f63e443a39d7bd7b…](https://bazaar.abuse.ch/sample/a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b/)

- **Familie:** AokigaharaStealer
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Trj]` |
| Avast | `FileRepMalware [Trj]` |
| Bkav | `W32.Malware.8FC97718` |
| ESET-NOD32 | `WinGo/Kryptik.XF trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Agent.gen` |
| Malwarebytes | `Malware.AI.3091469254` |
| McAfeeD | `ti!A5D4F63E443A` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [9aade612521dab5600f5…](https://bazaar.abuse.ch/sample/9aade612521dab5600f59b0660e19fb8392a42570408673e824f3bbd2532c85b/)

- **Familie:** Obfuscated
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Packed.Obfuscated.B suspicious application
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Supershell` |
| ESET-NOD32 | `Linux/Packed.Obfuscated.B suspicious application` |
| Kaspersky | `not-a-virus:UDS:RiskTool.Linux.Miner.gen` |
| Rising | `Trojan.CoinMiner/Linux!1.141AF (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| alibabacloud | `VirTool:Linux/Wacatac.C9nj` |

### [03b40131a41aa9da237b…](https://bazaar.abuse.ch/sample/03b40131a41aa9da237b6abd86d978324cf3351cb309ad4f914954f4b86a8560/)

- **Familie:** Linux
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** UDS:Backdoor.Linux.Mirai.gen
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `UDS:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.Mirai.gen` |

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

- **exe** (29×)
- **elf** (21×)
- **Mirai** (14×)
- **stealer** (10×)
- **xmrig** (9×)
- **signed** (7×)
- **cryptojacking** (7×)
- **CVE-2026-110447** (7×)
- **honeypot** (6×)
- **go** (6×)
- **SalatStealer** (6×)
- **dropper** (5×)
- **DvnX** (5×)
- **Warden** (5×)
- **WARDENStealer** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +14 (26→40)
- ↓ **Mirai** -9 (23→14)
- neu: **SalatStealer** (6)
- neu: **RemusStealer** (2)
- neu: **WannaCry** (2)
- neu: **Malware** (1)
- neu: **AokigaharaStealer** (1)
- neu: **Obfuscated** (1)
- neu: **Linux** (1)
- weg: **RemcosRAT** (war 4)
- weg: **Formbook** (war 4)
- weg: **GuLoader** (war 2)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +1 (39→40)
- ↓ **Mirai** -9 (23→14)
- ↑ **SalatStealer** +5 (1→6)
- ↑ **RemusStealer** +1 (1→2)
- neu: **WannaCry** (2)
- neu: **Malware** (1)
- neu: **AokigaharaStealer** (1)
- neu: **Obfuscated** (1)
- neu: **Linux** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.565 MB |
| σ Dateigröße | 21.531 MB |
| Ø Risiko-Score | 68.2/100 |
| Ø Klassifikations-Konfidenz | 68.4% |
| Samples mit VT | 5/69 |
| Samples mit MITRE | 21/69 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 81 |
| Unbekannte Familien | 5 (7.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:41 | [b3c1d7ad6100…](https://bazaar.abuse.ch/sample/b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea/) | `jar` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 19:37 | [0590fd1d1bd9…](https://bazaar.abuse.ch/sample/0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a/) | `exe` | unbekannt | 82.0 | – | – | 🇺🇸US |
| 19:14 | [782b519154f1…](https://bazaar.abuse.ch/sample/782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898/) | `zip` | unbekannt | 32.2 | – | – | 🌐HU |
| 19:12 | [eea8223c913f…](https://bazaar.abuse.ch/sample/eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4/) | `exe` | Malware | 81.0 | 22.7% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 19:12 | [744f82adda79…](https://bazaar.abuse.ch/sample/744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2/) | `exe` | RemusStealer | 81.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.10.2026 19:51 UTC*