# MalwareBazaar – 24.10.2026 13:53 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **62** |
| Höchster Score | **87.2/100** – 2df7b49b9987822e… |
| Häufigste Familie | **unbekannt** (37x) |
| Häufigster Typ | **elf** (46x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 39 Samples |
| Ø Dateigröße | 4.29 MB (σ=6.49) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 46 | 45.5%  █████████ |
| `exe` | 40 | 39.6%  ███████ |
| `jar` | 3 | 3.0%   |
| `vbs` | 3 | 3.0%   |
| `js` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |
| `bat` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 37 | 36.6% |
| 2 | Mirai | 34 | 33.7% |
| 3 | SalatStealer | 7 | 6.9% |
| 4 | SilnetNet | 3 | 3.0% |
| 5 | XorDDoS | 2 | 2.0% |
| 6 | Vidar | 2 | 2.0% |
| 7 | Trojan-FXFZ!CE055D1CD5D4 | 1 | 1.0% |
| 8 | AokigaharaStealer | 1 | 1.0% |
| 9 | Win64 | 1 | 1.0% |
| 10 | Unsafe | 1 | 1.0% |
| 11 | Prometei | 1 | 1.0% |
| 12 | QuasarRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 36 | 35.6% | 94% |
| Infostealer | 19 | 18.8% | 80% |
| Windows-Malware | 18 | 17.8% | 35% |
| Linux-Malware | 10 | 9.9% | 45% |
| RAT | 6 | 5.9% | 78% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Loader | 2 | 2.0% | 80% |
| Trojaner | 2 | 2.0% | 65% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 62 | 61.4% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 31 | 30.7% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2df7b49b998782…](https://bazaar.abuse.ch/sample/2df7b49b9987822e437f1b88efedd9fbe58a7f524ec02974034c6188f6e39c35/) | AMOS | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [7b37e5fe1acef6…](https://bazaar.abuse.ch/sample/7b37e5fe1acef63557026bbfebfc64cfd2ce6a62ea58911db9c20de8f799d2d4/) | QuasarRAT | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [cf1bcecfc5e216…](https://bazaar.abuse.ch/sample/cf1bcecfc5e2164d2d0e6bfab7b54462d34c6074070bf58a96b96463f789c497/) | Vidar | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [f0884102362412…](https://bazaar.abuse.ch/sample/f0884102362412aa950b9a1efc4199633a7fd72c8efb8f00d554960ecdeef622/) | Vidar | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [7a371062478c41…](https://bazaar.abuse.ch/sample/7a371062478c41955fef40544dfe1930c1f4e174e5746021f8b6aeaa7522d2d4/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [9f0f9d81aebe06…](https://bazaar.abuse.ch/sample/9f0f9d81aebe0635e801279c32936387dcce71a3791fe9c4e2c8e4e7083309dc/) | SnakeKeylogger | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [ce17e1126d1685…](https://bazaar.abuse.ch/sample/ce17e1126d1685c7b720c9e3bbfbde10cb5b81b0d51c4a0d53d5dcce58234a2c/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [62e3e86a758617…](https://bazaar.abuse.ch/sample/62e3e86a7586174df485af5936639769971cfc62fd9d0f2d5385d5bfa61ea88c/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [917293de84f76d…](https://bazaar.abuse.ch/sample/917293de84f76d7c3524185b22b6bab9838e884c794f0d9dea170717095fc8f6/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [85baa2398a8fd9…](https://bazaar.abuse.ch/sample/85baa2398a8fd9434c63110ef9264f1da3dabc5a3b548915151e039940e42111/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6156/7602 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6156/7602 |
| 3 | ESET-NOD32 | 77.2% | 5867/7602 |
| 4 | Kaspersky | 75.9% | 5769/7601 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5404/7599 |
| 8 | Rising | 68.3% | 5194/7602 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5029/7598 |
| 11 | Avast | 65.1% | 4944/7598 |
| 12 | AVG | 65.1% | 4944/7597 |
| 13 | Tencent | 64.9% | 4784/7376 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4650/7595 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 49 | 48.5% |
| 🪟 Windows | 45 | 44.6% |
| ❓ Unbekannt | 6 | 5.9% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 93 | 92.1% |
| MaaS-Loader | 4 | 4.0% |
| Drive-By / Exploit-Kit | 4 | 4.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 24.8% |
| 2 | 🌐 EG | 18 | 17.8% |
| 3 | 🇺🇸 US | 15 | 14.9% |
| 4 | 🇪🇸 ES | 14 | 13.9% |
| 5 | 🇳🇱 NL | 11 | 10.9% |
| 6 | 🇸🇪 SE | 11 | 10.9% |
| 7 | 🇦🇹 AT | 5 | 5.0% |
| 8 | 🌐 DK | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 39 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 34 |
| Lateral Movement | 34 |
| Collection | 4 |
| Exfiltration | 3 |
| Credential Access | 3 |
| Command and Control | 2 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>7b37e5fe1acef6355702… – QuasarRAT | 🔴 KRITISCH 87.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>cf1bcecfc5e2164d2d0e… – Vidar | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>f0884102362412aa950b… – Vidar | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>7a371062478c41955fef… – Formbook | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [2b9ea6388458cf38b7a1…](https://bazaar.abuse.ch/sample/2b9ea6388458cf38b7a152a213b4b93fbd9114d4c3580c12eb2b2db6cf4b07d2/)

- **Familie:** Trojan-FXFZ!CE055D1CD5D4
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan-FXFZ!CE055D1CD5D4
- **VT-Reputation:** -12
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.FXFZ.R802706` |
| Avira | `TR/W64.Malware` |
| Bkav | `W32.Malware.4685CD5F` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cynet | `Malicious (score: 100)` |
| DrWeb | `Trojan.Siggen36.46428` |
| ESET-NOD32 | `Win64/Agent.DML.gen trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Malware` |
| Fortinet | `W64/Agent.DML!tr` |
| GData | `Gen:Variant.Yogi.105636` |
| Kaspersky | `HEUR:Trojan-Dropper.Win32.Generic` |
| McAfeeD | `ti!2B9EA6388458` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Skyhigh | `Trojan-FXFZ!CE055D1CD5D4` |
| Tencent | `Backdoor.Win32.Phish.16004758` |
| TrellixENS | `Trojan-FXFZ!CE055D1CD5D4` |
| huorong | `Trojan/Injector.e!crit` |

### [ac6b5896c847a73fd6ab…](https://bazaar.abuse.ch/sample/ac6b5896c847a73fd6abbc48144a684e450c93dd807aade647cd1005c0bcb4ab/)

- **Familie:** SalatStealer
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.24470
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.24470`

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.24470` |
| APEX | `Malicious` |
| Arcabit | `Trojan.Draftor.D5F96` |
| Avira | `TR/Crypt.XPACK.Gen3` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.24470` |
| Bkav | `W32.Malware.6DFA050A` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Draftor.24470 (B)` |
| F-Secure | `Trojan.TR/Crypt.XPACK.Gen3` |
| GData | `Gen:Variant.Draftor.24470` |
| Kaspersky | `VHO:Trojan-PSW.Win32.Stealer.gen` |
| MicroWorld-eScan | `Gen:Variant.Draftor.24470` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.high.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VIPRE | `Gen:Variant.Draftor.24470` |

### [2fab76025c5017fc6859…](https://bazaar.abuse.ch/sample/2fab76025c5017fc68596b34ad3fc897507beba462fb192be30c43249eeb7afd/)

- **Familie:** Win64
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** BehavesLike.Win64.Dropper.th
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Win64/PSW.Agent.AXJ trojan` |
| Skyhigh | `BehavesLike.Win64.Dropper.th` |
| TrellixENS | `Artemis!182765BD2D73` |

### [61b942e18277d374b782…](https://bazaar.abuse.ch/sample/61b942e18277d374b782c4741f8de7cc04e8d16c4ec6449919c8c3bbb15f7d23/)

- **Familie:** Unsafe
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unsafe
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961088` |
| Avira | `TR/W32.Agent` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (moderate confidence)` |
| F-Secure | `Trojan.TR/W32.Agent` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sangfor | `Trojan.Win32.Agent.V2uu` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!14A45AA30281` |
| Webroot | `Win.Trojan.Gen` |

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

- **elf** (46×)
- **exe** (39×)
- **Mirai** (34×)
- **ddos** (14×)
- **leviathan** (14×)
- **salat** (6×)
- **salatstealer** (6×)
- **upx-dec** (5×)
- **upx** (5×)
- **arm** (5×)
- **Prometei** (4×)
- **signed** (4×)
- **SalatStealer** (4×)
- **dropper** (3×)
- **wraith** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +13 (24→37)
- ↑ **Mirai** +18 (16→34)
- ↑ **SalatStealer** +4 (3→7)
- neu: **SilnetNet** (3)
- neu: **XorDDoS** (2)
- ↑ **Vidar** +1 (1→2)
- neu: **Trojan-FXFZ!CE055D1CD5D4** (1)
- neu: **AokigaharaStealer** (1)
- neu: **Win64** (1)
- neu: **Unsafe** (1)
- weg: **RemcosRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -1 (38→37)
- ↑ **Mirai** +14 (20→34)
- ↑ **SalatStealer** +6 (1→7)
- neu: **SilnetNet** (3)
- neu: **XorDDoS** (2)
- neu: **Vidar** (2)
- neu: **Trojan-FXFZ!CE055D1CD5D4** (1)
- neu: **AokigaharaStealer** (1)
- neu: **Win64** (1)
- neu: **Unsafe** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.286 MB |
| σ Dateigröße | 6.489 MB |
| Ø Risiko-Score | 65.9/100 |
| Ø Klassifikations-Konfidenz | 69.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 39/101 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 76 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:49 | [2bdd795ab5ff…](https://bazaar.abuse.ch/sample/2bdd795ab5ffd8a9f25c512e812ca604091229688eb114ae3be5796197dcb015/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 13:48 | [3f8028b2d52b…](https://bazaar.abuse.ch/sample/3f8028b2d52bab13a15d815a82cc8b8447187d6b2d28fa31a874d66cac429c2d/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 13:47 | [700d7caf6efe…](https://bazaar.abuse.ch/sample/700d7caf6efe26cc31b6bbef7015036baebeb4e8116b433a15425746100e42d0/) | `ps1` | unbekannt | 82.1 | – | – | 🇳🇱NL |
| 13:46 | [900ffdefc364…](https://bazaar.abuse.ch/sample/900ffdefc3647ee8e9e6269ecd394f46c10ea92687c6a3c409f959cfe4754e79/) | `exe` | unbekannt | 82.1 | – | – | 🇳🇱NL |
| 13:44 | [4dc34b240a97…](https://bazaar.abuse.ch/sample/4dc34b240a972474b036fa7813f1db6331c84909ad2d2eb345239e2f8919bf1f/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.10.2026 13:53 UTC*