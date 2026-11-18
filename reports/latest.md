# MalwareBazaar – 18.11.2026 21:44 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **77** |
| Höchster Score | **87.8/100** – fe9c9769f131067b… |
| Häufigste Familie | **Mirai** (59x) |
| Häufigster Typ | **elf** (68x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 62 Samples |
| Ø Dateigröße | 1.32 MB (σ=4.37) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 68 | 67.3%  █████████████ |
| `exe` | 10 | 9.9%  █ |
| `js` | 6 | 5.9%  █ |
| `sh` | 4 | 4.0%   |
| `ps1` | 4 | 4.0%   |
| `apk` | 4 | 4.0%   |
| `jar` | 3 | 3.0%   |
| `msi` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 59 | 58.4% |
| 2 | unbekannt | 21 | 20.8% |
| 3 | Prometei | 6 | 5.9% |
| 4 | WARDENStealer | 5 | 5.0% |
| 5 | Gafgyt | 2 | 2.0% |
| 6 | SilentNet | 2 | 2.0% |
| 7 | RemcosRAT | 2 | 2.0% |
| 8 | AveMariaRAT | 1 | 1.0% |
| 9 | DarkCoreRAT | 1 | 1.0% |
| 10 | AndroRAT | 1 | 1.0% |
| 11 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 61 | 60.4% | 95% |
| RAT | 11 | 10.9% | 80% |
| Linux-Malware | 8 | 7.9% | 45% |
| Infostealer | 5 | 5.0% | 75% |
| Skript/Dropper | 5 | 5.0% | 35% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Windows-Malware | 4 | 4.0% | 35% |
| Trojaner | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 77 | 76.2% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 17 | 16.8% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [fe9c9769f13106…](https://bazaar.abuse.ch/sample/fe9c9769f131067b526bf7c90b5cbbe74d9beb15d2f139a3768dd1f9369da1e2/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [746bc10bd67baa…](https://bazaar.abuse.ch/sample/746bc10bd67baa3f910c3a481f2cc2432d77e53e52138901fc7e82ae3d23db50/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [2ce942487b7c5c…](https://bazaar.abuse.ch/sample/2ce942487b7c5cabed6f9a383133af635b8b10921c08f0ce518cad47df914af6/) | Gafgyt | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [f7643e40cad86b…](https://bazaar.abuse.ch/sample/f7643e40cad86bc7558fa7f704f7c1ea070692fac78d68573a41ca37907267ff/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [939577c968ac85…](https://bazaar.abuse.ch/sample/939577c968ac852f110a63749f92366a65a91c27983757664c05381a131436bc/) | unbekannt | Trojaner | **83.1** | 🔴 KRITISCH | – | – | ? |
| [9c883ac7e0bfa1…](https://bazaar.abuse.ch/sample/9c883ac7e0bfa1c10480f8da05c6ec5760dc1ab16c806bd673857d1b9bd67690/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [366156d36ada00…](https://bazaar.abuse.ch/sample/366156d36ada00719581954432cfe902ea1cfe1f8acccdd57ca491a284b87553/) | WARDENStealer | Infostealer | **81.7** | 🔴 KRITISCH | – | – | ? |
| [298f151b3ec98f…](https://bazaar.abuse.ch/sample/298f151b3ec98f8e55154b4d51c5c4ab8150a00582fe7a484a9c3630d2da0a08/) | Mirai | Botnet/IoT | **81.5** | 🔴 KRITISCH | – | – | ? |
| [2a637eb5495e69…](https://bazaar.abuse.ch/sample/2a637eb5495e69e99859f86d61b88be33b8b41628a229eb9620c0358b98365e9/) | Mirai | Botnet/IoT | **81.5** | 🔴 KRITISCH | – | – | ? |
| [50d407409e3581…](https://bazaar.abuse.ch/sample/50d407409e35818b51c7d9e2648a4f57b1b6618e670d734770eb49db86390e06/) | Mirai | Botnet/IoT | **81.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6528/8046 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6528/8046 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6224/8046 |
| 6 | Kaspersky | 75.5% | 6077/8045 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5731/8042 |
| 9 | Rising | 68.5% | 5511/8046 |
| 10 | Varist | 66.1% | 5312/8041 |
| 11 | Avast | 65.2% | 5244/8042 |
| 12 | AVG | 65.2% | 5244/8041 |
| 13 | Tencent | 65.1% | 5093/7820 |
| 14 | McAfeeD | 61.5% | 4944/8038 |
| 15 | huorong | 60.9% | 4895/8038 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 73 | 72.3% |
| 🪟 Windows | 15 | 14.9% |
| ❓ Unbekannt | 9 | 8.9% |
| 🤖 Android | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 87 | 86.1% |
| Drive-By / Exploit-Kit | 6 | 5.9% |
| APK-Sideloading | 4 | 4.0% |
| Trojanisierte Software | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 69 | 68.3% |
| 2 | 🇺🇸 US | 13 | 12.9% |
| 3 | 🇳🇱 NL | 5 | 5.0% |
| 4 | 🇭🇺 HU | 3 | 3.0% |
| 5 | 🇧🇷 BR | 3 | 3.0% |
| 6 | 🇫🇷 FR | 3 | 3.0% |
| 7 | 🇮🇹 IT | 2 | 2.0% |
| 8 | 🇪🇸 ES | 1 | 1.0% |
| 9 | 🇦🇹 AT | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 62 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 59 |
| Lateral Movement | 59 |
| Command and Control | 3 |
| Collection | 3 |

<details><summary>fe9c9769f131067b526b… – RemcosRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>746bc10bd67baa3f910c… – RemcosRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>f7643e40cad86bc7558f… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [229e1ac1790cfc795430…](https://bazaar.abuse.ch/sample/229e1ac1790cfc795430640985d9c429aca3a5fb11061c2f53f04c05163dcbca/)

- **Familie:** WARDENStealer
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.9A0E9922` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Lionic | `Trojan.Win32.WARDENStealer.4!c` |
| Malwarebytes | `Trojan.Injector.RND.Generic` |
| McAfeeD | `Trojan:Win/RavenStealer.NE` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:yMVv29YMr0kQXaqTw5RNJA)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Generic ML PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| Varist | `W64/Agent.NRC.gen!Eldorado` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [46409d5d99ef2f60e3c9…](https://bazaar.abuse.ch/sample/46409d5d99ef2f60e3c92cefc9986e8aca6ce63f3648a1c80081dc7cbf16a9d8/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `OB:Backdoor.Linux.Mirai.cerra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [e451831cac31d85e8964…](https://bazaar.abuse.ch/sample/e451831cac31d85e8964c586b94f52090b8d654e2c19d0eb1f0bbd8c643d5b03/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

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

- **elf** (68×)
- **Mirai** (59×)
- **Torii** (53×)
- **exe** (9×)
- **Prometei** (6×)
- **js** (6×)
- **WARDENStealer** (5×)
- **signed** (5×)
- **ps1** (4×)
- **Androrat** (4×)
- **apk** (4×)
- **opendir** (4×)
- **RAT** (3×)
- **jar** (3×)
- **Gafgyt** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +23 (36→59)
- ↑ **unbekannt** +3 (18→21)
- ↓ **WARDENStealer** -1 (6→5)
- neu: **Gafgyt** (2)
- neu: **SilentNet** (2)
- ↓ **RemcosRAT** -4 (6→2)
- neu: **AveMariaRAT** (1)
- neu: **DarkCoreRAT** (1)
- neu: **AndroRAT** (1)
- weg: **CoinMiner** (war 2)
- weg: **AgentTesla** (war 6)
- weg: **Formbook** (war 3)
- weg: **AsyncRAT** (war 3)
- weg: **MassLogger** (war 2)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +22 (37→59)
- ↓ **unbekannt** -2 (23→21)
- ↑ **Prometei** +4 (2→6)
- ↓ **WARDENStealer** -1 (6→5)
- neu: **Gafgyt** (2)
- ↑ **SilentNet** +1 (1→2)
- ↓ **RemcosRAT** -1 (3→2)
- neu: **AveMariaRAT** (1)
- neu: **DarkCoreRAT** (1)
- neu: **AndroRAT** (1)
- weg: **SalatStealer** (war 4)
- weg: **RevStealer** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.319 MB |
| σ Dateigröße | 4.367 MB |
| Ø Risiko-Score | 71.2/100 |
| Ø Klassifikations-Konfidenz | 79.0% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 62/101 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 37 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:30 | [c811ed75c730…](https://bazaar.abuse.ch/sample/c811ed75c7307308c98e1e343025e50b06d1c9a029e1178c7f64dd8b79f290ea/) | `exe` | unbekannt | 38.9 | – | – | 🌐HU |
| 21:30 | [3bb1875c2c9f…](https://bazaar.abuse.ch/sample/3bb1875c2c9fa46eef1260e860dcb5e52d45622169571686c2b1b246a95c4304/) | `elf` | Prometei | 43.1 | – | – | 🇩🇪DE |
| 21:20 | [dae755694851…](https://bazaar.abuse.ch/sample/dae7556948516a8371a09eeef1543a54b6b45ad64b01bc012309338eb5024ae8/) | `exe` | unbekannt | 80.9 | – | – | 🇧🇷BR |
| 21:10 | [2ce942487b7c…](https://bazaar.abuse.ch/sample/2ce942487b7c5cabed6f9a383133af635b8b10921c08f0ce518cad47df914af6/) | `sh` | Gafgyt | 84.0 | – | – | 🇳🇱NL |
| 21:08 | [366156d36ada…](https://bazaar.abuse.ch/sample/366156d36ada00719581954432cfe902ea1cfe1f8acccdd57ca491a284b87553/) | `ps1` | WARDENStealer | 81.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.11.2026 21:44 UTC*