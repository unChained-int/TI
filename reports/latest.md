# MalwareBazaar – 17.11.2026 20:37 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **39** |
| Höchster Score | **87.1/100** – 661533027142b822… |
| Häufigste Familie | **FantasyHub** (38x) |
| Häufigster Typ | **apk** (38x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 34 Samples |
| Ø Dateigröße | 3.59 MB (σ=5.43) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `apk` | 38 | 37.6%  ███████ |
| `elf` | 37 | 36.6%  ███████ |
| `exe` | 12 | 11.9%  ██ |
| `jar` | 4 | 4.0%   |
| `ps1` | 2 | 2.0%   |
| `msi` | 2 | 2.0%   |
| `hta` | 2 | 2.0%   |
| `bat` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | FantasyHub | 38 | 37.6% |
| 2 | Mirai | 29 | 28.7% |
| 3 | unbekannt | 11 | 10.9% |
| 4 | WARDENStealer | 5 | 5.0% |
| 5 | SilentNet | 5 | 5.0% |
| 6 | Prometei | 4 | 4.0% |
| 7 | SalatStealer | 3 | 3.0% |
| 8 | Hajime | 2 | 2.0% |
| 9 | Amadey | 1 | 1.0% |
| 10 | RevStealer | 1 | 1.0% |
| 11 | RemcosRAT | 1 | 1.0% |
| 12 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Android-Malware | 38 | 37.6% | 45% |
| Botnet/IoT | 31 | 30.7% | 94% |
| Infostealer | 9 | 8.9% | 75% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Linux-Malware | 6 | 5.9% | 45% |
| Windows-Malware | 4 | 4.0% | 35% |
| Skript/Dropper | 3 | 3.0% | 35% |
| RAT | 2 | 2.0% | 95% |
| Loader | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 39 | 38.6% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 51 | 50.5% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [661533027142b8…](https://bazaar.abuse.ch/sample/661533027142b82295979f390c219ce11e8f1fdce54415f90b20b15c333c460b/) | RemcosRAT | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [c5f41fff34f1e1…](https://bazaar.abuse.ch/sample/c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b/) | Amadey | Loader | **83.0** | 🔴 KRITISCH | – | – | ? |
| [1000d27c354917…](https://bazaar.abuse.ch/sample/1000d27c354917b5ee14611ea61c22b286ebcef58e90a4b9a08cef9b2c0b4986/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [718bc3345fa9fa…](https://bazaar.abuse.ch/sample/718bc3345fa9fa0256b3c5802c8d6b4d0772d5fbc53149fa3c6400550896d2c6/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [c152e53dabae8f…](https://bazaar.abuse.ch/sample/c152e53dabae8f11b0c99eebb0cdfc3fabaad89a21be99a4b534a2d054fc3abe/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [a4d862a042a184…](https://bazaar.abuse.ch/sample/a4d862a042a1841da4b41ef6161de008b0f0c27e9ac04f51be66df42374dd10d/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [fb0a209934a17a…](https://bazaar.abuse.ch/sample/fb0a209934a17ad71e4bb7d89ed6caff00edfc4a0987295861718f6ab7b7768b/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [e9b80ad2c4253f…](https://bazaar.abuse.ch/sample/e9b80ad2c4253fb76c094c339cb974cde922af788a3952df4714261f3ba08b8d/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [3bc69a0d358efc…](https://bazaar.abuse.ch/sample/3bc69a0d358efcf0bef611462ffd519fd1902ea9c7a59ed5288c465a68f4958e/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [feb0d8bbb23787…](https://bazaar.abuse.ch/sample/feb0d8bbb237870641f1f57a7938b22b597bf405af012b98bb6f1ac8004eebca/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6518/8032 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6518/8032 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6211/8032 |
| 6 | Kaspersky | 75.5% | 6066/8031 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5719/8028 |
| 9 | Rising | 68.5% | 5500/8032 |
| 10 | Varist | 66.1% | 5303/8027 |
| 11 | Avast | 65.2% | 5232/8028 |
| 12 | AVG | 65.2% | 5232/8027 |
| 13 | Tencent | 65.1% | 5081/7806 |
| 14 | McAfeeD | 61.5% | 4934/8024 |
| 15 | huorong | 60.8% | 4882/8024 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 38 | 37.6% |
| 🤖 Android | 38 | 37.6% |
| 🪟 Windows | 19 | 18.8% |
| ❓ Unbekannt | 4 | 4.0% |
| 📦 Archiv | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 60 | 59.4% |
| APK-Sideloading | 38 | 37.6% |
| Trojanisierte Software | 2 | 2.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 38 | 37.6% |
| 2 | 🌐 CL | 38 | 37.6% |
| 3 | 🇳🇱 NL | 9 | 8.9% |
| 4 | 🇺🇸 US | 7 | 6.9% |
| 5 | 🇭🇺 HU | 5 | 5.0% |
| 6 | 🇨🇿 CZ | 2 | 2.0% |
| 7 | 🇫🇷 FR | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 34 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 31 |
| Lateral Movement | 31 |
| Command and Control | 2 |
| Collection | 2 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>661533027142b8229597… – RemcosRAT | 🔴 KRITISCH 87.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c5f41fff34f1e18dad19… – Amadey | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |
| Persistence | [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution |

</details>
<details><summary>1000d27c354917b5ee14… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>718bc3345fa9fa0256b3… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c152e53dabae8f11b0c9… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9a9cc78702d4085e9f50…](https://bazaar.abuse.ch/sample/9a9cc78702d4085e9f503105500d7d27fa3d1aba24d6109ae4b2da9ea6805be1/)

- **Familie:** SilentNet
- **Erkannt von:** 0 von 74 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -12
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [6815b65f894493f17509…](https://bazaar.abuse.ch/sample/6815b65f894493f175099caddde86422e0bead3309b398813324db11b761540b/)

- **Familie:** SalatStealer
- **Erkannt von:** 33 von 74 Engines (44.6%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.1833
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.1833`

**Erkennende Engines (33/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.1833` |
| AVG | `Win64:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.WallStealer.R803269` |
| Arcabit | `Trojan.Stealer.D729` |
| Avast | `Win64:MalwareX-gen [Pws]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.Stealer.1833` |
| Bkav | `W32.Malware.322132F2` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Backdoor.LucidRook-10059729-0` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/Agent.CJZ trojan` |
| Elastic | `Windows.Exploit.Generic` |
| Emsisoft | `Trojan.Stealer.1833 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/MALD2.CC69!tr` |
| GData | `Trojan.Stealer.1833` |
| Kaspersky | `HEUR:Trojan-PSW.Win64.Coins.pef` |
| Malwarebytes | `Spyware.Stealer` |
| MaxSecure | `Trojan.W32.121225.SalatStealer.YR` |
| McAfeeD | `ti!6815B65F8944` |
| MicroWorld-eScan | `Trojan.Stealer.1833` |
| Microsoft 🛡️ | `PWS:Win64/WallStealer.CI!MTB` |
| Rising | `Backdoor.Agent!8.C5D (TFE:5:uUuztGE45cU)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Dropper.vh` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `backdoor.win64.agentcjz.16008246` |
| Trapmine | `suspicious.low.ml.score` |
| VIPRE | `Trojan.Stealer.1833` |
| Varist | `W64/Agent.NQZ.gen!Eldorado` |
| huorong | `TrojanSpy/Stealer.gg` |

### [ec2954fcd45284a9a5c5…](https://bazaar.abuse.ch/sample/ec2954fcd45284a9a5c5d740b112fb939e59679819b2f0a1dc3238edb0841d58/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 74 Engines (23.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Hajime-R [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Hajime-R [Trj]` |
| Avast | `ELF:Hajime-R [Trj]` |
| Avira | `TR/LINUX.Hajime.R` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai.FQE trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Trojan.TR/LINUX.Hajime.R` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2018-10561.a` |
| McAfeeD | `Trojan:Linux/Mirai.ERM` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner.C12` |
| Rising | `Backdoor.Mirai/Linux!1.BAFE (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| huorong | `Trojan/Linux.Mirai.q` |

### [4454ac5f9a6528b94b24…](https://bazaar.abuse.ch/sample/4454ac5f9a6528b94b24be17b9713f99681d6ecc5391e4f8b0e1e79f4b415c1c/)

- **Familie:** Mirai
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40685120
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40685120`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40685120` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D26CCE40` |
| Avira | `TR/LINUX.Mirai.DAU` |
| BitDefender 🛡️ | `Trojan.Generic.40685120` |
| CAT-QuickHeal | `Elf.Backdoor.A29035618` |
| CTX | `elf.trojan.generic` |
| ClamAV | `Unix.Trojan.Mirai-9760303-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.DKR trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Generic.40685120 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DAU` |
| GData | `Trojan.Generic.40685120` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| K7GW | `Trojan ( 004117141 )` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.lc` |
| Kingsoft | `Linux.Backdoor.Mirai.lc` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MaxSecure | `Trojan.Malware.344458885.susgen.npe` |
| McAfeeD | `Trojan:Linux/Mirai.EAF` |
| MicroWorld-eScan | `Trojan.Generic.40685120` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HQ!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Symantec | `Linux.Mirai` |
| Tencent | `Malware.Linux.Generic.1c0c9946` |
| TrendMicro | `Backdoor.Linux.MIRAI.USBLJU26` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.USBLJU26` |
| VIPRE | `Trojan.Generic.40685120` |
| Varist | `E32/ABTrojan.AYZQ-` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.kb` |

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

- **apk** (38×)
- **elf** (34×)
- **signed** (31×)
- **Mirai** (29×)
- **FantasyHub** (23×)
- **Fantasyhub** (15×)
- **exe** (11×)
- **Torii** (11×)
- **Hajime** (10×)
- **upx-dec** (7×)
- **upx** (7×)
- **WARDENStealer** (5×)
- **jar** (4×)
- **SilentNet** (4×)
- **Prometei** (4×)

## Änderungen – 24h-Vergleich

- neu: **FantasyHub** (38)
- ↑ **Mirai** +15 (14→29)
- ↓ **unbekannt** -11 (22→11)
- ↓ **WARDENStealer** -3 (8→5)
- neu: **SilentNet** (5)
- ↓ **Prometei** -2 (6→4)
- neu: **SalatStealer** (3)
- neu: **Hajime** (2)
- neu: **Amadey** (1)
- neu: **RevStealer** (1)
- weg: **Formbook** (war 6)
- weg: **RemusStealer** (war 2)
- weg: **AgentTesla** (war 7)
- weg: **MassLogger** (war 4)
- weg: **GuLoader** (war 2)
- weg: **XWorm** (war 2)
- weg: **AsyncRAT** (war 2)
- weg: **VIPKeylogger** (war 2)
- weg: **LxBaseRAT** (war 2)

## Änderungen – 7d-Vergleich

- neu: **FantasyHub** (38)
- ↓ **Mirai** -7 (36→29)
- ↓ **unbekannt** -13 (24→11)
- ↑ **SilentNet** +4 (1→5)
- ↑ **Prometei** +3 (1→4)
- ↓ **SalatStealer** -3 (6→3)
- neu: **Hajime** (2)
- neu: **Amadey** (1)
- ↓ **RevStealer** -1 (2→1)
- weg: **GuLoader** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.589 MB |
| σ Dateigröße | 5.433 MB |
| Ø Risiko-Score | 57.4/100 |
| Ø Klassifikations-Konfidenz | 61.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 34/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 38 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:27 | [5e9ac74be9c6…](https://bazaar.abuse.ch/sample/5e9ac74be9c6d5d0a75d5f3004e16c6ba19ec452660f7f24c9344e6e2438ec85/) | `bat` | unbekannt | 39.0 | – | – | 🌐HU |
| 20:23 | [5dc9e05308a0…](https://bazaar.abuse.ch/sample/5dc9e05308a0eaa6bf7110be5a6ec9798314434ecb519bb930358f35a6c9787f/) | `ps1` | WARDENStealer | 82.0 | – | – | 🇺🇸US |
| 20:08 | [581b425104b1…](https://bazaar.abuse.ch/sample/581b425104b197535d1693afc4a18ca98ebe5128eab2f5ef3aec32164a553e64/) | `rar` | unbekannt | 32.3 | – | – | 🌐HU |
| 20:00 | [c5f41fff34f1…](https://bazaar.abuse.ch/sample/c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b/) | `msi` | Amadey | 83.0 | – | – | 🇺🇸US |
| 19:54 | [b5c57c808fe4…](https://bazaar.abuse.ch/sample/b5c57c808fe4258a8de52fdc315633c8f8cfb2d25be5d0252ceb942426dbe7fe/) | `exe` | unbekannt | 38.5 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.11.2026 20:37 UTC*