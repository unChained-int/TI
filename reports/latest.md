# MalwareBazaar – 07.11.2026 23:30 UTC

Dieser Run hat **55 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **56** |
| Kritisch (≥75) | **39** |
| Höchster Score | **84.1/100** – 8784f9fc2603eb31… |
| Häufigste Familie | **Mirai** (24x) |
| Häufigster Typ | **elf** (24x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 25 Samples |
| Ø Dateigröße | 11.17 MB (σ=20.74) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 24 | 42.9%  ████████ |
| `exe` | 19 | 33.9%  ██████ |
| `sh` | 4 | 7.1%  █ |
| `zip` | 4 | 7.1%  █ |
| `apk` | 3 | 5.4%  █ |
| `iso` | 1 | 1.8%   |
| `7z` | 1 | 1.8%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 24 | 42.9% |
| 2 | unbekannt | 19 | 33.9% |
| 3 | WARDENStealer | 7 | 12.5% |
| 4 | VShell | 2 | 3.6% |
| 5 | Gafgyt | 1 | 1.8% |
| 6 | Malware | 1 | 1.8% |
| 7 | CoinMiner | 1 | 1.8% |
| 8 | NanoCore | 1 | 1.8% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 44.6% | 95% |
| Infostealer | 12 | 21.4% | 75% |
| Windows-Malware | 9 | 16.1% | 35% |
| Android-Malware | 3 | 5.4% | 45% |
| Loader | 3 | 5.4% | 75% |
| Backdoor | 2 | 3.6% | 75% |
| Andere / Unbekannt | 1 | 1.8% | 20% |
| RAT | 1 | 1.8% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 39 | 69.6% |
| 🟠 HOCH | 4 | 7.1% |
| 🟡 MITTEL | 12 | 21.4% |
| 🟢 NIEDRIG | 1 | 1.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8784f9fc2603eb…](https://bazaar.abuse.ch/sample/8784f9fc2603eb31259b16c88471b42538b15f6a4cb8f7c649957967818686d3/) | Gafgyt | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [8ca7253a252671…](https://bazaar.abuse.ch/sample/8ca7253a25267116aa6c006f77b2e0d7fb49c661993a7458895b963062398ce0/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [6652ad2f9fc321…](https://bazaar.abuse.ch/sample/6652ad2f9fc3217b7ed0c241920d18a7c73dfb31406cc2839a5d430667bce32e/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [e4f6e093ff4126…](https://bazaar.abuse.ch/sample/e4f6e093ff412635a158b2fd42f921b11856ef75a4091252436434d0b30d1350/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [c03d763d8499ba…](https://bazaar.abuse.ch/sample/c03d763d8499ba41248ed4d29012ccf43ff3679eab9087ade630734e3921c17a/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [97c3abadc50732…](https://bazaar.abuse.ch/sample/97c3abadc50732e7b76cd4b9e9825ea8e79aaccdbc92f70e60b723f181ff621f/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b1cbb819ccfc1a…](https://bazaar.abuse.ch/sample/b1cbb819ccfc1ad14f1973df7c175bfb060fc09b115ffb047d7a73430cf53d61/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [f351ba1bb0cfc1…](https://bazaar.abuse.ch/sample/f351ba1bb0cfc19c3601ca046095c3fe00d03e3e99e2a7eebd55c4d5cbb91153/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [8498e6d29f8d37…](https://bazaar.abuse.ch/sample/8498e6d29f8d370a1397fc5287e8346ed0086ae368fce6fffcfe00380c91ac72/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [6ec09159ac78b3…](https://bazaar.abuse.ch/sample/6ec09159ac78b35531ce0a894d30bc6b5157fc2b26e32869fa7f769b9c1c63c9/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6382/7876 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6382/7876 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6085/7876 |
| 6 | Kaspersky | 75.5% | 5942/7875 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5605/7872 |
| 9 | Rising | 68.3% | 5380/7876 |
| 10 | Varist | 66.1% | 5206/7871 |
| 11 | Avast | 65.1% | 5125/7872 |
| 12 | AVG | 65.1% | 5125/7871 |
| 13 | Tencent | 64.9% | 4966/7650 |
| 14 | McAfeeD | 61.4% | 4832/7868 |
| 15 | huorong | 60.9% | 4791/7868 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 30 | 53.6% |
| 🪟 Windows | 17 | 30.4% |
| 📦 Archiv | 6 | 10.7% |
| 🤖 Android | 3 | 5.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 47 | 83.9% |
| MaaS-Loader | 4 | 7.1% |
| APK-Sideloading | 3 | 5.4% |
| C2 / Nachladen | 2 | 3.6% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🌐 PT | 16 | 28.6% |
| 2 | 🇩🇪 DE | 15 | 26.8% |
| 3 | 🌐 Unbekannt | 12 | 21.4% |
| 4 | 🇺🇸 US | 4 | 7.1% |
| 5 | 🇳🇱 NL | 4 | 7.1% |
| 6 | 🇫🇷 FR | 4 | 7.1% |
| 7 | 🇯🇵 JP | 1 | 1.8% |

## MITRE ATT&CK

> 25 von 56 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |

<details><summary>8784f9fc2603eb31259b… – Gafgyt | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>8ca7253a25267116aa6c… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6652ad2f9fc3217b7ed0… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e4f6e093ff412635a158… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c03d763d8499ba41248e… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [37ebe9ab1cbcb5ceafc5…](https://bazaar.abuse.ch/sample/37ebe9ab1cbcb5ceafc51f3f6d6d81da89c0e4017fe6bdcd44329bb490d47168/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.Gafgyt.SE180` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.AXA trojan` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| McAfeeD | `Trojan:Script/Mirai.EFV` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.nk` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [c106b2327d36815a0dda…](https://bazaar.abuse.ch/sample/c106b2327d36815a0dda951accf27589cca0b6e66e03ea688cae015a8ab0b74c/)

- **Familie:** Malware
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.8D908EE5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.8D908EE5` |
| Elastic | `malicious (high confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Sabsik.FL.A!ml` |
| Sophos | `CXrep/MalGo-A` |
| Symantec | `ML.Attribute.HighConfidence` |

### [0c8712524dd77d81292e…](https://bazaar.abuse.ch/sample/0c8712524dd77d81292e0c084a5c27d3f022552deef8493d76bdaeac28c19a36/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **Mirai** (25×)
- **elf** (24×)
- **exe** (18×)
- **Torii** (13×)
- **honeypot** (11×)
- **cowrie** (10×)
- **WARDENStealer** (8×)
- **signed** (7×)
- **arm** (4×)
- **zip** (4×)
- **apk** (3×)
- **RemusStealer** (3×)
- **mips** (2×)
- **dropper** (2×)
- **sh** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -6 (30→24)
- ↓ **unbekannt** -3 (22→19)
- ↑ **WARDENStealer** +4 (3→7)
- ↓ **VShell** -2 (4→2)
- neu: **Gafgyt** (1)
- neu: **Malware** (1)
- neu: **CoinMiner** (1)
- weg: **Snowlight** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +6 (18→24)
- ↓ **unbekannt** -16 (35→19)
- ↑ **WARDENStealer** +5 (2→7)
- neu: **Gafgyt** (1)
- neu: **Malware** (1)
- weg: **SalatStealer** (war 3)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 11.166 MB |
| σ Dateigröße | 20.743 MB |
| Ø Risiko-Score | 70.4/100 |
| Ø Klassifikations-Konfidenz | 75.3% |
| Samples mit VT | 4/56 |
| Samples mit MITRE | 25/56 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 50 |
| Unbekannte Familien | 1 (1.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:02 | [8784f9fc2603…](https://bazaar.abuse.ch/sample/8784f9fc2603eb31259b16c88471b42538b15f6a4cb8f7c649957967818686d3/) | `elf` | Gafgyt | 84.1 | – | – | 🇩🇪DE |
| 22:59 | [5bb41baf3b0f…](https://bazaar.abuse.ch/sample/5bb41baf3b0f8491a80e913c3c328974f9de5840580e3f59dbf3521460e6453d/) | `apk` | unbekannt | 42.9 | – | – | 🌐JP |
| 22:59 | [8ca7253a2526…](https://bazaar.abuse.ch/sample/8ca7253a25267116aa6c006f77b2e0d7fb49c661993a7458895b963062398ce0/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 22:41 | [6652ad2f9fc3…](https://bazaar.abuse.ch/sample/6652ad2f9fc3217b7ed0c241920d18a7c73dfb31406cc2839a5d430667bce32e/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 22:39 | [e4f6e093ff41…](https://bazaar.abuse.ch/sample/e4f6e093ff412635a158b2fd42f921b11856ef75a4091252436434d0b30d1350/) | `elf` | Mirai | 83.8 | – | – | 🌐unknown |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 07.11.2026 23:30 UTC*