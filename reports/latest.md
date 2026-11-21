# MalwareBazaar – 21.11.2026 12:16 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **73** |
| Höchster Score | **96.4/100** – c8e23fca28fd79f6… |
| Häufigste Familie | **unbekannt** (56x) |
| Häufigster Typ | **elf** (77x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 27 Samples |
| Ø Dateigröße | 5.93 MB (σ=19.88) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 77 | 76.2%  ███████████████ |
| `macho` | 13 | 12.9%  ██ |
| `exe` | 4 | 4.0%   |
| `sh` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `py` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 56 | 55.4% |
| 2 | Mirai | 24 | 23.8% |
| 3 | CatStorm | 8 | 7.9% |
| 4 | Prometei | 7 | 6.9% |
| 5 | Hajime | 1 | 1.0% |
| 6 | WannaCry | 1 | 1.0% |
| 7 | BTN trojan | 1 | 1.0% |
| 8 | VIPKeylogger | 1 | 1.0% |
| 9 | CoinMiner | 1 | 1.0% |
| 10 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 46 | 45.5% | 75% |
| Botnet/IoT | 25 | 24.8% | 94% |
| Linux-Malware | 17 | 16.8% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Loader | 3 | 3.0% | 75% |
| Cryptominer | 2 | 2.0% | 75% |
| Trojaner | 2 | 2.0% | 65% |
| Ransomware | 1 | 1.0% | 95% |
| Android-Malware | 1 | 1.0% | 45% |
| Infostealer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 73 | 72.3% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 18 | 17.8% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c8e23fca28fd79…](https://bazaar.abuse.ch/sample/c8e23fca28fd79f6127faf3e1c9d91778661ba033028521d4d18664b7c7c1525/) | WannaCry | Ransomware | **96.4** | 🔴 KRITISCH | – | – | ? |
| [258454701aa8d1…](https://bazaar.abuse.ch/sample/258454701aa8d1d2ef8b40ef952c4722a3c8b780fdf33caa60717bc1d551be7d/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b87cf4e22708cc…](https://bazaar.abuse.ch/sample/b87cf4e22708cc35bb66d6c6f959830779877b91c6dd1d8d9514aaadc46c57da/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [600988cdf835f7…](https://bazaar.abuse.ch/sample/600988cdf835f71feed50703b4d33da70b2af3fda9dbb955e5bf0b4e2fb75171/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [8c254cf993722c…](https://bazaar.abuse.ch/sample/8c254cf993722c1dd89744ce07dd29e374a0c59eaddc2537b7a971b0bf097bcc/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b2fd82bd96660d…](https://bazaar.abuse.ch/sample/b2fd82bd96660db4220e31e6ba85da09abd13b2a02826bbdf236508fa0e5bdb3/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [4a5a96612e7316…](https://bazaar.abuse.ch/sample/4a5a96612e7316586a4c61a4d7dd28dfadf087be9ccfa2c04b06206cca610de7/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [3110e9e8e12e5d…](https://bazaar.abuse.ch/sample/3110e9e8e12e5d3a8ca8789bbddf1d86497f7f3aadacfe4d1fe64d724585801c/) | BTN trojan | RAT | **83.3** | 🔴 KRITISCH | 5.4% | ⚠️ KAUM ERKANNT | ✗ |
| [90429399cf489e…](https://bazaar.abuse.ch/sample/90429399cf489e75bfa5b46211f5af2da4ac9c5d50795b9a224e87f106d31f45/) | unbekannt | RAT | **81.1** | 🔴 KRITISCH | – | – | ? |
| [3624c7b2fdc001…](https://bazaar.abuse.ch/sample/3624c7b2fdc001f8b8e674b58c8d2054d552722c7f499c80003494c7eeda4fe7/) | unbekannt | RAT | **81.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6560/8084 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6560/8084 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6256/8084 |
| 6 | Kaspersky | 75.6% | 6108/8083 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5761/8080 |
| 9 | Rising | 68.5% | 5540/8084 |
| 10 | Varist | 66.1% | 5340/8079 |
| 11 | Tencent | 65.2% | 5122/7858 |
| 12 | Avast | 65.2% | 5269/8080 |
| 13 | AVG | 65.2% | 5269/8079 |
| 14 | McAfeeD | 61.5% | 4969/8076 |
| 15 | huorong | 61.0% | 4923/8076 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 93 | 92.1% |
| 🪟 Windows | 4 | 4.0% |
| 📦 Archiv | 2 | 2.0% |
| ❓ Unbekannt | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| Exploit / N-Day | 1 | 1.0% |
| APK-Sideloading | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 58 | 57.4% |
| 2 | 🇩🇪 DE | 26 | 25.7% |
| 3 | 🇦🇹 AT | 9 | 8.9% |
| 4 | 🌐 LT | 2 | 2.0% |
| 5 | 🇳🇱 NL | 1 | 1.0% |
| 6 | 🇪🇸 ES | 1 | 1.0% |
| 7 | 🇸🇪 SE | 1 | 1.0% |
| 8 | 🇮🇹 IT | 1 | 1.0% |
| 9 | 🇨🇭 CH | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 27 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Impact | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>258454701aa8d1d2ef8b… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b87cf4e22708cc35bb66… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>600988cdf835f71feed5… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>8c254cf993722c1dd897… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [030eda7d2af2ee9c74ec…](https://bazaar.abuse.ch/sample/030eda7d2af2ee9c74ecefb999315d15ed351a0576f1ebadc80f8d3190bbd48e/)

- **Familie:** CatStorm
- **Erkannt von:** 12 von 74 Engines (16.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Antiy-AVL | `Trojan[Miner]/Linux.CoinMiner` |
| Avast | `ELF:Agent-ETO [Trj]` |
| DrWeb | `Linux.Siggen.12973` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.wo` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Tencent | `OB:Trojan.Linux.Catstorm.qzira` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/CoinMiner.dm` |

### [e13c957c605cf1842b94…](https://bazaar.abuse.ch/sample/e13c957c605cf1842b9407902f073e5c6b08d40b33f10d13d1f7f8f1377f5ecf/)

- **Familie:** CatStorm
- **Erkannt von:** 12 von 74 Engines (16.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Avast | `ELF:Agent-ETO [Trj]` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.wo` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `OB:Trojan.Linux.Catstorm.qzvra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/Linux.CoinMiner.eb` |

### [3110e9e8e12e5d3a8ca8…](https://bazaar.abuse.ch/sample/3110e9e8e12e5d3a8ca8789bbddf1d86497f7f3aadacfe4d1fe64d724585801c/)

- **Familie:** BTN trojan
- **Erkannt von:** 4 von 74 Engines (5.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Tencent | `Linux.Trojan.Linux.Zchl` |
| alibabacloud | `Trojan:Linux/Wacatac.B9nj` |

### [5f15e7ad7460d52d1c9b…](https://bazaar.abuse.ch/sample/5f15e7ad7460d52d1c9b67bbd4a9dcaca103f3a999777552133f9e1b7a3e33b6/)

- **Familie:** Mirai
- **Erkannt von:** 39 von 74 Engines (52.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (39/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Gafgyt-MV [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Gafgyt-MV [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| ClamAV | `Unix.Trojan.Mirai-7100807-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF/Gafgyt.WN!tr` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| K7GW | `Trojan ( 0041108c1 )` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.ha` |
| Kingsoft | `Linux.Backdoor.Gafgyt.ha` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MaxSecure | `Backdoor.WIN32.120721.linux.Mirai.b.YR` |
| McAfeeD | `ti!5F15E7AD7460` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.E330 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Gafgyt!ATN` |
| Tencent | `Backdoor.Linux.Mirai.wao` |
| TrendMicro | `Backdoor.Linux.GAFGYT.SMMR2` |
| TrendMicro-HouseCall | `Backdoor.Linux.GAFGYT.SMMR2` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| Varist | `E32/Mirai.DZ.gen!Eldorado` |
| alibabacloud | `Trojan:Linux/Mirai.AHE` |
| huorong | `Backdoor/Linux.Mirai.lk` |

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

- **elf** (61×)
- **EasyShell** (45×)
- **RAT** (45×)
- **Rust** (45×)
- **SnoopyTriage** (45×)
- **Mirai** (25×)
- **Torii** (17×)
- **macho** (13×)
- **CatStorm** (8×)
- **Prometei** (7×)
- **Gafgyt** (7×)
- **exe** (3×)
- **CoinMiner** (2×)
- **dropper** (2×)
- **signed** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +15 (41→56)
- ↑ **Mirai** +2 (22→24)
- neu: **CatStorm** (8)
- neu: **Hajime** (1)
- neu: **WannaCry** (1)
- neu: **BTN trojan** (1)
- neu: **VIPKeylogger** (1)
- neu: **CoinMiner** (1)
- weg: **AsyncRAT** (war 2)
- weg: **WARDENStealer** (war 5)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +31 (25→56)
- ↓ **Mirai** -12 (36→24)
- neu: **CatStorm** (8)
- ↑ **Prometei** +3 (4→7)
- neu: **Hajime** (1)
- neu: **WannaCry** (1)
- neu: **BTN trojan** (1)
- neu: **VIPKeylogger** (1)
- neu: **CoinMiner** (1)
- ↓ **njrat** -1 (2→1)
- weg: **WARDENStealer** (war 5)
- weg: **SalatStealer** (war 2)
- weg: **RemcosRAT** (war 3)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.927 MB |
| σ Dateigröße | 19.880 MB |
| Ø Risiko-Score | 71.2/100 |
| Ø Klassifikations-Konfidenz | 73.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 27/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 33 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:06 | [90429399cf48…](https://bazaar.abuse.ch/sample/90429399cf489e75bfa5b46211f5af2da4ac9c5d50795b9a224e87f106d31f45/) | `elf` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 12:06 | [3624c7b2fdc0…](https://bazaar.abuse.ch/sample/3624c7b2fdc001f8b8e674b58c8d2054d552722c7f499c80003494c7eeda4fe7/) | `elf` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 12:06 | [a1f904c29d70…](https://bazaar.abuse.ch/sample/a1f904c29d708e924825b3d035cf573f35a1f95cc5fbd11af1a7d1af6bee9bf5/) | `elf` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 12:06 | [d925294fd83f…](https://bazaar.abuse.ch/sample/d925294fd83fc490453ec389d9b67a62c3b0e06bdcfe7fcf8ab90ad04c01ec56/) | `macho` | unbekannt | 81.1 | – | – | 🇺🇸US |
| 12:05 | [f519dc62db92…](https://bazaar.abuse.ch/sample/f519dc62db929a97414210bef34127cfe3e29060b51c7a945494926de94efa30/) | `macho` | unbekannt | 81.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.11.2026 12:16 UTC*