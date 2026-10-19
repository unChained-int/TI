# MalwareBazaar – 19.10.2026 23:26 UTC

Dieser Run hat **94 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **95** |
| Kritisch (≥75) | **34** |
| Höchster Score | **89.1/100** – cb355db1df97d676… |
| Häufigste Familie | **unbekannt** (60x) |
| Häufigster Typ | **elf** (32x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 3.10 MB (σ=10.12) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 32 | 33.7%  ██████ |
| `js` | 23 | 24.2%  ████ |
| `exe` | 18 | 18.9%  ███ |
| `zip` | 8 | 8.4%  █ |
| `msi` | 4 | 4.2%   |
| `macho` | 4 | 4.2%   |
| `sh` | 3 | 3.2%   |
| `jar` | 1 | 1.1%   |
| `html` | 1 | 1.1%   |
| `rar` | 1 | 1.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 60 | 63.2% |
| 2 | Mirai | 27 | 28.4% |
| 3 | RemcosRAT | 1 | 1.1% |
| 4 | njrat | 1 | 1.1% |
| 5 | Malware | 1 | 1.1% |
| 6 | FileRepMalware [Misc] | 1 | 1.1% |
| 7 | RemusStealer | 1 | 1.1% |
| 8 | VShell | 1 | 1.1% |
| 9 | MassLogger | 1 | 1.1% |
| 10 | PythonStealer | 1 | 1.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 27 | 28.4% | 95% |
| Skript/Dropper | 23 | 24.2% | 35% |
| Andere / Unbekannt | 10 | 10.5% | 20% |
| Windows-Malware | 10 | 10.5% | 35% |
| Cryptominer | 8 | 8.4% | 75% |
| Infostealer | 5 | 5.3% | 75% |
| Loader | 5 | 5.3% | 75% |
| Linux-Malware | 4 | 4.2% | 45% |
| RAT | 2 | 2.1% | 95% |
| Trojaner | 1 | 1.1% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 34 | 35.8% |
| 🟠 HOCH | 14 | 14.7% |
| 🟡 MITTEL | 37 | 38.9% |
| 🟢 NIEDRIG | 10 | 10.5% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [cb355db1df97d6…](https://bazaar.abuse.ch/sample/cb355db1df97d67687f92fe94a4d84ef4856f43169b10a49c733c302130f68ab/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [d90ec6fb084a6a…](https://bazaar.abuse.ch/sample/d90ec6fb084a6ab655146a8380cfbc94b0732f427eb820971284af43a4a7b732/) | njrat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [b20ae4658f8cc0…](https://bazaar.abuse.ch/sample/b20ae4658f8cc07c805fad7486cc4fa79017954bd1f49e2b5ea2eac7a76dcee3/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [b8d32ae2c2c5aa…](https://bazaar.abuse.ch/sample/b8d32ae2c2c5aa9b07aff0911502928a6977bd9a1cb4d8e036494fa07d629cdf/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [c73a4b3fca0391…](https://bazaar.abuse.ch/sample/c73a4b3fca03917d7a618aab2c8bc34eb6a16390701ff702a05737219a6cc5dd/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [c22621982c9758…](https://bazaar.abuse.ch/sample/c22621982c97580c6bb782a0d3e051157aab7a3c02d0f637f5c2c921d09d04b7/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [b345d74cd963e1…](https://bazaar.abuse.ch/sample/b345d74cd963e1303ef53df8b1515a5750d9cdf6ccc06a188a38a6becda44bf9/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [3961cb76603e40…](https://bazaar.abuse.ch/sample/3961cb76603e40e64368b769437a3f60665f8ed942089ea44ec53d9e594b8122/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [9485247a2038a7…](https://bazaar.abuse.ch/sample/9485247a2038a7d8f95b8baf7edda02da9a8ef63eb761f728878dc40b82dbfbd/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [9e0d7b64f1d77d…](https://bazaar.abuse.ch/sample/9e0d7b64f1d77dfeddc4a5f620c79e5811d32ac91594759da09040580fc7261f/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6069/7500 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6069/7500 |
| 3 | ESET-NOD32 | 77.4% | 5803/7500 |
| 4 | Kaspersky | 76.3% | 5719/7499 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5359/7497 |
| 8 | Rising | 68.7% | 5153/7500 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4968/7496 |
| 11 | Tencent | 65.2% | 4743/7274 |
| 12 | Avast | 65.2% | 4886/7496 |
| 13 | AVG | 65.2% | 4886/7495 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4590/7493 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 43 | 45.3% |
| ❓ Unbekannt | 25 | 26.3% |
| 🪟 Windows | 21 | 22.1% |
| 🍎 macOS | 4 | 4.2% |
| 📦 Archiv | 2 | 2.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 62 | 65.3% |
| Drive-By / Exploit-Kit | 23 | 24.2% |
| C2 / Nachladen | 6 | 6.3% |
| Trojanisierte Software | 4 | 4.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇷🇴 RO | 27 | 28.4% |
| 2 | 🇺🇸 US | 20 | 21.1% |
| 3 | 🇩🇪 DE | 13 | 13.7% |
| 4 | 🇵🇱 PL | 11 | 11.6% |
| 5 | 🇬🇧 GB | 8 | 8.4% |
| 6 | 🇨🇭 CH | 6 | 6.3% |
| 7 | 🇫🇷 FR | 5 | 5.3% |
| 8 | 🇳🇱 NL | 2 | 2.1% |
| 9 | 🇭🇺 HU | 2 | 2.1% |
| 10 | 🌐 Unbekannt | 1 | 1.1% |

## MITRE ATT&CK

> 30 von 95 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 27 |
| Lateral Movement | 27 |
| Command and Control | 2 |
| Collection | 2 |
| Impact | 1 |

<details><summary>cb355db1df97d67687f9… – RemcosRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>d90ec6fb084a6ab65514… – njrat | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>b20ae4658f8cc07c805f… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b8d32ae2c2c5aa9b07af… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c73a4b3fca03917d7a61… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [76a5c51320f3f21411e6…](https://bazaar.abuse.ch/sample/76a5c51320f3f21411e6795eedc52011df51bad6500923083e3127fe2245911f/)

- **Familie:** Malware
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.F2306928
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.F2306928` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/GenKryptik.HVNC trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:Uu7RtYEt7K9U8dkWE80qBQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [90aecc35f9263bff1f93…](https://bazaar.abuse.ch/sample/90aecc35f9263bff1f9394b2ab2c1664dbf46a3c7b281efa6f7ec72138c8a417/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.2BE39002` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `VHO:Trojan-PSW.Win32.Convagent.gen` |
| McAfeeD | `ti!90AECC35F926` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Convagent!8.1326D (CLOUD)` |
| Sangfor | `Trojan.Win32.Agent.Vtep` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.ShellcodeRunner.Akjl` |
| Trapmine | `suspicious.low.ml.score` |

### [527ef3616e707990c2f8…](https://bazaar.abuse.ch/sample/527ef3616e707990c2f8a84b6a7ff67b3cdf7ae7e9c913638cc260b6c106ff92/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!EE86C0F0AB77
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.jw` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14331 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!EE86C0F0AB77` |
| TrellixENS | `LINUX/Mirai-FQU!EE86C0F0AB77` |
| Varist | `E32/Mirai.EN.gen!Camelot` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| Varist | `W64/ABTrojan.ANKV-0822` |


## Top Tags

- **elf** (32×)
- **Mirai** (27×)
- **0xf00dbeef** (27×)
- **analystic** (27×)
- **Coruna** (27×)
- **DarkSword** (27×)
- **GHOSTBLADE** (27×)
- **iOS** (27×)
- **P7** (27×)
- **js** (23×)
- **exe** (17×)
- **cowrie** (15×)
- **honeypot** (15×)
- **miner** (8×)
- **zip** (8×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +26 (34→60)
- ↑ **Mirai** +9 (18→27)
- neu: **RemcosRAT** (1)
- neu: **njrat** (1)
- neu: **Malware** (1)
- neu: **FileRepMalware [Misc]** (1)
- neu: **MassLogger** (1)
- weg: **AMOS** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **BlakcSeeStealer** (war 2)
- weg: **Prometei** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +32 (28→60)
- ↑ **Mirai** +3 (24→27)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **njrat** (1)
- neu: **Malware** (1)
- neu: **FileRepMalware [Misc]** (1)
- neu: **VShell** (1)
- neu: **MassLogger** (1)
- neu: **PythonStealer** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.096 MB |
| σ Dateigröße | 10.120 MB |
| Ø Risiko-Score | 57.6/100 |
| Ø Klassifikations-Konfidenz | 60.1% |
| Samples mit VT | 4/95 |
| Samples mit MITRE | 30/95 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 59 |
| Unbekannte Familien | 10 (10.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:14 | [38625a26dbde…](https://bazaar.abuse.ch/sample/38625a26dbde158541b55e09913456456496fdedb5a2f1882a33c4c4de596584/) | `sh` | unbekannt | 32.6 | – | – | 🇩🇪DE |
| 22:49 | [b20ae4658f8c…](https://bazaar.abuse.ch/sample/b20ae4658f8cc07c805fad7486cc4fa79017954bd1f49e2b5ea2eac7a76dcee3/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 22:49 | [b8d32ae2c2c5…](https://bazaar.abuse.ch/sample/b8d32ae2c2c5aa9b07aff0911502928a6977bd9a1cb4d8e036494fa07d629cdf/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 22:38 | [1fc5375a4158…](https://bazaar.abuse.ch/sample/1fc5375a4158db97631f2f0ed37dfb019b29e2cfec8dd800fa4a38b256efc77f/) | `msi` | unbekannt | 38.4 | – | – | 🇫🇷FR |
| 22:38 | [cb355db1df97…](https://bazaar.abuse.ch/sample/cb355db1df97d67687f92fe94a4d84ef4856f43169b10a49c733c302130f68ab/) | `exe` | RemcosRAT | 89.1 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.10.2026 23:26 UTC*