# MalwareBazaar – 22.10.2026 03:50 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **22** |
| Höchster Score | **90.7/100** – 8caf5bde87f11b92… |
| Häufigste Familie | **unbekannt** (51x) |
| Häufigster Typ | **exe** (75x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 75 Samples |
| Ø Dateigröße | 14.33 MB (σ=14.04) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 75 | 74.3%  ██████████████ |
| `elf` | 16 | 15.8%  ███ |
| `macho` | 5 | 5.0%   |
| `msi` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 51 | 50.5% |
| 2 | CoinMiner | 23 | 22.8% |
| 3 | Mirai | 12 | 11.9% |
| 4 | Prometei | 4 | 4.0% |
| 5 | RustyStealer | 3 | 3.0% |
| 6 | Yogi | 2 | 2.0% |
| 7 | Adware.OfferCore | 1 | 1.0% |
| 8 | Doina | 1 | 1.0% |
| 9 | RemcosRAT | 1 | 1.0% |
| 10 | AMOS | 1 | 1.0% |
| 11 | Gh0stRAT | 1 | 1.0% |
| 12 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 66 | 65.3% | 75% |
| Botnet/IoT | 12 | 11.9% | 95% |
| Windows-Malware | 7 | 6.9% | 35% |
| Infostealer | 5 | 5.0% | 77% |
| Linux-Malware | 4 | 4.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Skript/Dropper | 1 | 1.0% | 35% |
| RAT | 1 | 1.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 22 | 21.8% |
| 🟠 HOCH | 64 | 63.4% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8caf5bde87f11b…](https://bazaar.abuse.ch/sample/8caf5bde87f11b927bf11813b6a9d234f5a559a333dc71c2331a239549484f57/) | Gh0stRAT | Backdoor | **90.7** | 🔴 KRITISCH | – | – | ? |
| [c81b8c0775f0fa…](https://bazaar.abuse.ch/sample/c81b8c0775f0fa25cfe09cab180e88426340cd1e171c033cd70145294504fefd/) | AMOS | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [db7064aedd34c9…](https://bazaar.abuse.ch/sample/db7064aedd34c959fbb19ac70da43ff9f08be90e7a85f3d1fa996a3f3186dd53/) | RemcosRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [72d191ea359d56…](https://bazaar.abuse.ch/sample/72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [4537002cbc3e77…](https://bazaar.abuse.ch/sample/4537002cbc3e7711a5878d880ffa6ac5cf0a2cfd8735d6be41da38d1a623ab78/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [400d22f6ea66e0…](https://bazaar.abuse.ch/sample/400d22f6ea66e0f002936ce5cfaaf46e9d279d7b3bf04e37810ef34a18a8b298/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [3f09df05e96189…](https://bazaar.abuse.ch/sample/3f09df05e961893fb8ec3197357dbcfee2ac492a122b227dc9214c3ed2623a98/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [d81398e4ca4f3d…](https://bazaar.abuse.ch/sample/d81398e4ca4f3d6711ec00dd3a3c2423c537fe7caf38c741fbfe81e44659fce1/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [e71c131c07d125…](https://bazaar.abuse.ch/sample/e71c131c07d125f11202e3a48b73a6de02fcfdbaddf5598633f59ee02efb331a/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [0b70ad78aaf9df…](https://bazaar.abuse.ch/sample/0b70ad78aaf9dff31b712f91cee5d1dfae0c8378f67b5fdac27625c07ce092ee/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6108/7542 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6108/7542 |
| 3 | ESET-NOD32 | 77.3% | 5831/7542 |
| 4 | Kaspersky | 76.1% | 5738/7541 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5379/7539 |
| 8 | Rising | 68.6% | 5173/7542 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4993/7538 |
| 11 | Avast | 65.2% | 4917/7538 |
| 12 | AVG | 65.2% | 4917/7537 |
| 13 | Tencent | 65.1% | 4763/7316 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4619/7535 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 78 | 77.2% |
| 🐧 Linux | 17 | 16.8% |
| 🍎 macOS | 5 | 5.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| C2 / Nachladen | 63 | 62.4% |
| Unbekannt / nicht bestimmbar | 33 | 32.7% |
| MaaS-Loader | 3 | 3.0% |
| Trojanisierte Software | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 92 | 91.1% |
| 2 | 🇩🇪 DE | 3 | 3.0% |
| 3 | 🇳🇱 NL | 2 | 2.0% |
| 4 | 🇫🇷 FR | 1 | 1.0% |
| 5 | 🌐 CO | 1 | 1.0% |
| 6 | 🇨🇦 CA | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 75 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 63 |
| Credential Access | 62 |
| Exfiltration | 62 |
| Initial Access | 12 |
| Lateral Movement | 12 |
| Command and Control | 1 |

<details><summary>db7064aedd34c959fbb1… – RemcosRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>72d191ea359d563f97dc… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4537002cbc3e7711a587… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [0d04183546002117b1d6…](https://bazaar.abuse.ch/sample/0d04183546002117b1d691ecb513140d2f17834e98b22e809e7328a09c49b106/)

- **Familie:** Yogi
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R801890` |
| Arcabit | `Trojan.Yogi.D170F6` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.988DAA98` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| Google | `Detected` |
| Malwarebytes | `Trojan.CoinMiner` |
| McAfeeD | `ti!0D0418354600` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win64/Barys.BN!MTB` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Varist | `W64/AEi.C04E9928!Eldorado` |
| Webroot | `W32.Malware.Gen` |

### [c0fce2ccc2d64f1a3f56…](https://bazaar.abuse.ch/sample/c0fce2ccc2d64f1a3f56c12535769019ce41830c33a80fcb62493640f2fe31e6/)

- **Familie:** Doina
- **Erkannt von:** 43 von 75 Engines (57.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Doina.128020
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Doina.128020`

**Erkennende Engines (43/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Doina.128020` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5956152` |
| Alibaba | `Trojan:Win64/MalwareX.f09eb021` |
| Arcabit | `Trojan.Doina.D1F414` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Gen:Variant.Doina.128020` |
| CTX | `exe.trojan.doina` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/Agent.BXY trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Doina.128020 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| GData | `Gen:Variant.Doina.128020` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.sa` |
| K7AntiVirus | `Password-Stealer ( 005cdefe1 )` |
| K7GW | `Password-Stealer ( 005cdefe1 )` |
| Kaspersky | `Trojan.Win32.Scar.uyqv` |
| Malwarebytes | `Backdoor.ShadowLoader` |
| McAfeeD | `Trojan:Win/GenericY.IYM` |
| MicroWorld-eScan | `Gen:Variant.Doina.128020` |
| Microsoft 🛡️ | `Trojan:Win32/Ravartar!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Trojan.Agent!8.B1E (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.10c4ce9d` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!46E48C27F4EC` |
| TrendMicro | `Trojan.Win64.SCAR.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win64.SCAR.USBLJJ26` |
| VIPRE | `Gen:Variant.Doina.128020` |
| Varist | `W64/ABTrojan.EALY-6185` |
| ViRobot | `Trojan.Win.Z.Doina.8254485` |
| VirIT | `Trojan.Win64.Agent.IXC` |
| alibabacloud | `Trojan:Win/Scar.gyf` |
| huorong | `Trojan/FakeApp.amr` |

### [94838aaa9ba0554f2bd0…](https://bazaar.abuse.ch/sample/94838aaa9ba0554f2bd0735fb2b10db74fb815b8873e7955a631112e576d2bdf/)

- **Familie:** Yogi
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AhnLab-V3 | `Trojan/Win.Generic.C5960944` |
| Arcabit | `Trojan.Yogi.D170F6` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.3CF21F97` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| Google | `Detected` |
| Malwarebytes | `Trojan.CoinMiner` |
| McAfeeD | `ti!94838AAA9BA0` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win64/Barys.BN!MTB` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Varist | `W64/AEi.C04E9928!Eldorado` |
| Webroot | `W32.Malware.Gen` |

### [a8d32c028eeddcdb8734…](https://bazaar.abuse.ch/sample/a8d32c028eeddcdb8734ecd455054b19937c909cb3cab5defd424df18645b440/)

- **Familie:** CoinMiner
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R802328` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (high confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

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

- **exe** (74×)
- **dropped-by-Vidar** (62×)
- **signed** (56×)
- **c1399bfb1be0a51415613edd6f0068c5** (24×)
- **CoinMiner** (23×)
- **19ccb70dbc12ef919d5869277e598933** (19×)
- **elf** (16×)
- **d852ede598d72f2b3a4050576466ec62** (11×)
- **55001da20373e92a4261b69e9f1087ac** (9×)
- **Mirai** (7×)
- **ClickFix** (6×)
- **Foxveil** (6×)
- **macOS** (6×)
- **Prometei** (5×)
- **wraith** (5×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -7 (58→51)
- ↑ **CoinMiner** +16 (7→23)
- ↓ **Mirai** -10 (22→12)
- neu: **Prometei** (4)
- ↑ **RustyStealer** +2 (1→3)
- neu: **Yogi** (2)
- neu: **Adware.OfferCore** (1)
- neu: **Doina** (1)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **AMOS** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +16 (35→51)
- ↑ **CoinMiner** +22 (1→23)
- ↓ **Mirai** -10 (22→12)
- neu: **Prometei** (4)
- neu: **RustyStealer** (3)
- neu: **Yogi** (2)
- neu: **Adware.OfferCore** (1)
- neu: **Doina** (1)
- ↓ **RemcosRAT** -1 (2→1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 14.331 MB |
| σ Dateigröße | 14.042 MB |
| Ø Risiko-Score | 70.2/100 |
| Ø Klassifikations-Konfidenz | 71.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 75/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:48 | [95b32434fe39…](https://bazaar.abuse.ch/sample/95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 03:47 | [0507e4c85849…](https://bazaar.abuse.ch/sample/0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 03:47 | [41e1ca8515fb…](https://bazaar.abuse.ch/sample/41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 03:47 | [1fffae3cb845…](https://bazaar.abuse.ch/sample/1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b/) | `exe` | unbekannt | 39.1 | – | – | 🇫🇷FR |
| 03:44 | [706cc7d2b5dc…](https://bazaar.abuse.ch/sample/706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1/) | `elf` | Prometei | 43.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.10.2026 03:50 UTC*