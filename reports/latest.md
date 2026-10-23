# MalwareBazaar – 23.10.2026 22:58 UTC

Dieser Run hat **39 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **40** |
| Kritisch (≥75) | **26** |
| Höchster Score | **84.4/100** – 638fe6527fcaeb06… |
| Häufigste Familie | **Mirai** (21x) |
| Häufigster Typ | **elf** (24x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 4.31 MB (σ=10.92) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 24 | 60.0%  ████████████ |
| `exe` | 8 | 20.0%  ████ |
| `msi` | 3 | 7.5%  █ |
| `7z` | 1 | 2.5%   |
| `macho` | 1 | 2.5%   |
| `sh` | 1 | 2.5%   |
| `js` | 1 | 2.5%   |
| `bat` | 1 | 2.5%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 21 | 52.5% |
| 2 | unbekannt | 12 | 30.0% |
| 3 | DDoSAgent | 2 | 5.0% |
| 4 | Linux | 1 | 2.5% |
| 5 | GoToResolve | 1 | 2.5% |
| 6 | Malware | 1 | 2.5% |
| 7 | CoinMiner | 1 | 2.5% |
| 8 | PythonStealer | 1 | 2.5% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 22 | 55.0% | 94% |
| Windows-Malware | 5 | 12.5% | 35% |
| Infostealer | 4 | 10.0% | 75% |
| Andere / Unbekannt | 2 | 5.0% | 20% |
| Skript/Dropper | 2 | 5.0% | 35% |
| Linux-Malware | 2 | 5.0% | 45% |
| Trojaner | 2 | 5.0% | 65% |
| Cryptominer | 1 | 2.5% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 26 | 65.0% |
| 🟠 HOCH | 3 | 7.5% |
| 🟡 MITTEL | 9 | 22.5% |
| 🟢 NIEDRIG | 2 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [638fe6527fcaeb…](https://bazaar.abuse.ch/sample/638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [b1b5dd6e77801c…](https://bazaar.abuse.ch/sample/b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [e2ea41d1deab66…](https://bazaar.abuse.ch/sample/e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [a20170667b22b3…](https://bazaar.abuse.ch/sample/a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [9aba42d500b094…](https://bazaar.abuse.ch/sample/9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [c76ed9ab219d00…](https://bazaar.abuse.ch/sample/c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [308ee11f9b4fa8…](https://bazaar.abuse.ch/sample/308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [0d23bcb2e85eba…](https://bazaar.abuse.ch/sample/0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [7eaf8ecbbabcf0…](https://bazaar.abuse.ch/sample/7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [8112b3afd6d0ec…](https://bazaar.abuse.ch/sample/8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6143/7587 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6143/7587 |
| 3 | ESET-NOD32 | 77.2% | 5859/7587 |
| 4 | Kaspersky | 76.0% | 5762/7586 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5398/7584 |
| 8 | Rising | 68.4% | 5188/7587 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5021/7583 |
| 11 | Avast | 65.1% | 4939/7583 |
| 12 | AVG | 65.1% | 4939/7582 |
| 13 | Tencent | 64.9% | 4777/7361 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4640/7580 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 25 | 62.5% |
| 🪟 Windows | 12 | 30.0% |
| 📦 Archiv | 1 | 2.5% |
| 🍎 macOS | 1 | 2.5% |
| ❓ Unbekannt | 1 | 2.5% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 36 | 90.0% |
| Trojanisierte Software | 3 | 7.5% |
| Drive-By / Exploit-Kit | 1 | 2.5% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 14 | 35.0% |
| 2 | 🇺🇸 US | 8 | 20.0% |
| 3 | 🌐 Unbekannt | 6 | 15.0% |
| 4 | 🇷🇴 RO | 3 | 7.5% |
| 5 | 🇬🇧 GB | 2 | 5.0% |
| 6 | 🇳🇱 NL | 2 | 5.0% |
| 7 | 🇭🇺 HU | 2 | 5.0% |
| 8 | 🇫🇷 FR | 1 | 2.5% |
| 9 | 🌐 CO | 1 | 2.5% |
| 10 | 🇷🇺 RU | 1 | 2.5% |

## MITRE ATT&CK

> 21 von 40 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 21 |
| Lateral Movement | 21 |

<details><summary>638fe6527fcaeb06f619… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b1b5dd6e77801cd112ec… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e2ea41d1deab665e2f47… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a20170667b22b3776fdc… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9aba42d500b0941aad7b… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b5e7c5dfa2888d052a75…](https://bazaar.abuse.ch/sample/b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Tsunami.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Tsunami.5`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Tsunami.5` |
| AVG | `ELF:Mirai-BJI [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Tsunami.5` |
| Avast | `ELF:Mirai-BJI [Trj]` |
| Avast-Mobile | `ELF:Mirai-BJI [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Tsunami.5` |
| CTX | `elf.unknown.tsunami` |
| ClamAV | `Unix.Dropper.Mirai-7135928-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| Emsisoft | `Gen:Variant.Linux.Tsunami.5 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.hv` |
| MicroWorld-eScan | `Gen:Variant.Linux.Tsunami.5` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| VIPRE | `Gen:Variant.Linux.Tsunami.5` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.l` |

### [19e4b77737c683d34e36…](https://bazaar.abuse.ch/sample/19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e/)

- **Familie:** Linux
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** HEUR:Trojan.Linux.Agent.ja
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Linux/Xarcen.Gen` |
| DrWeb | `Linux.Siggen.15631` |
| Fortinet | `ELF/Xorddos.Y!tr` |
| Jiangmin | `LINUX.Mirai.fm` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.ja` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Trojan.XorDDoS/Linux!1.A3E4 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Trojan.Linux.Agent.gqtra` |
| huorong | `Trojan/Linux.Xorddos.d` |

### [1e0bc3cab7b9207ec929…](https://bazaar.abuse.ch/sample/1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5/)

- **Familie:** GoToResolve
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** RiskWare.MisusedLegit.GoToResolve
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Malwarebytes | `RiskWare.MisusedLegit.GoToResolve` |

### [d0018cd3ddfcb900f6cc…](https://bazaar.abuse.ch/sample/d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511/)

- **Familie:** Malware
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.754A7B4D
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.754A7B4D` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.90 (RDML:b2xcKgXJzVs0rXmV3tI07A)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| huorong | `Trojan/Injector.aj!crit` |

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

- **elf** (23×)
- **Mirai** (21×)
- **exe** (8×)
- **cowrie** (5×)
- **honeypot** (5×)
- **msi** (3×)
- **WARDENstealer** (3×)
- **mips** (2×)
- **upx-dec** (2×)
- **upx** (2×)
- **signed** (2×)
- **infostealer** (1×)
- **7z** (1×)
- **infected** (1×)
- **arm** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -17 (29→12)
- neu: **DDoSAgent** (2)
- neu: **Linux** (1)
- neu: **GoToResolve** (1)
- neu: **CoinMiner** (1)
- weg: **RemcosRAT** (war 3)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -2 (23→21)
- ↓ **unbekannt** -27 (39→12)
- neu: **DDoSAgent** (2)
- neu: **Linux** (1)
- neu: **GoToResolve** (1)
- neu: **Malware** (1)
- ↓ **CoinMiner** -2 (3→1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.315 MB |
| σ Dateigröße | 10.924 MB |
| Ø Risiko-Score | 69.8/100 |
| Ø Klassifikations-Konfidenz | 73.8% |
| Samples mit VT | 5/40 |
| Samples mit MITRE | 21/40 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 31 |
| Unbekannte Familien | 2 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:47 | [638fe6527fca…](https://bazaar.abuse.ch/sample/638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 22:41 | [1212bfc031aa…](https://bazaar.abuse.ch/sample/1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d/) | `msi` | unbekannt | 82.0 | – | – | 🇫🇷FR |
| 22:37 | [b1b5dd6e7780…](https://bazaar.abuse.ch/sample/b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 22:37 | [e2ea41d1deab…](https://bazaar.abuse.ch/sample/e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 22:33 | [a20170667b22…](https://bazaar.abuse.ch/sample/a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 23.10.2026 22:58 UTC*