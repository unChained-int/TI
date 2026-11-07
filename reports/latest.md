# MalwareBazaar – 07.11.2026 12:40 UTC

Dieser Run hat **80 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **81** |
| Kritisch (≥75) | **57** |
| Höchster Score | **95.8/100** – 14e1dd3f1ab9b602… |
| Häufigste Familie | **Mirai** (42x) |
| Häufigster Typ | **elf** (48x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 49 Samples |
| Ø Dateigröße | 2.42 MB (σ=6.60) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 48 | 59.3%  ███████████ |
| `js` | 11 | 13.6%  ██ |
| `sh` | 8 | 9.9%  █ |
| `exe` | 6 | 7.4%  █ |
| `ps1` | 5 | 6.2%  █ |
| `msi` | 1 | 1.2%   |
| `apk` | 1 | 1.2%   |
| `bat` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 42 | 51.9% |
| 2 | unbekannt | 24 | 29.6% |
| 3 | Formbook | 3 | 3.7% |
| 4 | Panchan | 2 | 2.5% |
| 5 | Gafgyt | 2 | 2.5% |
| 6 | AgentTesla | 1 | 1.2% |
| 7 | SMLBO1 | 1 | 1.2% |
| 8 | WannaCry | 1 | 1.2% |
| 9 | CoinMiner | 1 | 1.2% |
| 10 | RemcosRAT | 1 | 1.2% |
| 11 | QuasarRAT | 1 | 1.2% |
| 12 | ConnectWise | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 44 | 54.3% | 95% |
| Skript/Dropper | 10 | 12.3% | 35% |
| Linux-Malware | 8 | 9.9% | 45% |
| RAT | 5 | 6.2% | 87% |
| Infostealer | 3 | 3.7% | 95% |
| Worm | 3 | 3.7% | 75% |
| Trojaner | 2 | 2.5% | 75% |
| Andere / Unbekannt | 2 | 2.5% | 20% |
| Loader | 1 | 1.2% | 65% |
| Ransomware | 1 | 1.2% | 95% |
| Android-Malware | 1 | 1.2% | 45% |
| Cryptominer | 1 | 1.2% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 57 | 70.4% |
| 🟠 HOCH | 3 | 3.7% |
| 🟡 MITTEL | 17 | 21.0% |
| 🟢 NIEDRIG | 4 | 4.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [14e1dd3f1ab9b6…](https://bazaar.abuse.ch/sample/14e1dd3f1ab9b60277b0f5ea15ce926ffb9bfd5b2dcfb0186729f6f487c33348/) | WannaCry | Ransomware | **95.8** | 🔴 KRITISCH | – | – | ? |
| [c244dc93f8a675…](https://bazaar.abuse.ch/sample/c244dc93f8a675b0c0012b07d9f09f89e1d65db87f44ffee9fa04dc57dc711f3/) | Formbook | Infostealer | **89.6** | 🔴 KRITISCH | – | – | ? |
| [7cb082bfc14dda…](https://bazaar.abuse.ch/sample/7cb082bfc14dda0a44863ee70af57c35d7ad2ae2e83293a5c7d26f5bff56d450/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [98323d89afdbd6…](https://bazaar.abuse.ch/sample/98323d89afdbd6e681be3412a79d49722a0a9a5fbe49f53026142a8063cfef5a/) | Formbook | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [b0cdd26c89023b…](https://bazaar.abuse.ch/sample/b0cdd26c89023be886d331252b5501d6b773bbb6f7414eae98090169b654c105/) | RemcosRAT | RAT | **85.6** | 🔴 KRITISCH | – | – | ? |
| [adbb5f9901db4f…](https://bazaar.abuse.ch/sample/adbb5f9901db4f8042f6b95a7f77a5eef8488aabc8b22d297381ea5551c7ee43/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [4689a824b8d338…](https://bazaar.abuse.ch/sample/4689a824b8d338949996ab54d6dce23c53ad9cd70357acec2fc693f27e5601ee/) | QuasarRAT | RAT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [185a78a83641d0…](https://bazaar.abuse.ch/sample/185a78a83641d0abe00a04e69c45611f10e0095bb957618571cd172e75db93ae/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [fd59897621bf88…](https://bazaar.abuse.ch/sample/fd59897621bf88ecbd0962268e79677d7f0d9e4b994f276361f1c8a9890b896b/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [6ddead306e2d19…](https://bazaar.abuse.ch/sample/6ddead306e2d19b6c1a5ad81795046edcffc6442e4b5f442551465cc7360b16e/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6373/7867 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6373/7867 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6078/7867 |
| 6 | Kaspersky | 75.5% | 5935/7866 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5600/7863 |
| 9 | Rising | 68.3% | 5373/7867 |
| 10 | Varist | 66.2% | 5202/7862 |
| 11 | Avast | 65.1% | 5118/7863 |
| 12 | AVG | 65.1% | 5118/7862 |
| 13 | Tencent | 64.9% | 4959/7641 |
| 14 | McAfeeD | 61.4% | 4826/7859 |
| 15 | huorong | 60.9% | 4784/7859 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 59 | 72.8% |
| 🪟 Windows | 13 | 16.0% |
| ❓ Unbekannt | 8 | 9.9% |
| 🤖 Android | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 64 | 79.0% |
| Drive-By / Exploit-Kit | 11 | 13.6% |
| MaaS-Loader | 3 | 3.7% |
| Trojanisierte Software | 1 | 1.2% |
| Exploit / N-Day | 1 | 1.2% |
| APK-Sideloading | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 51 | 63.0% |
| 2 | 🇺🇸 US | 17 | 21.0% |
| 3 | 🇳🇱 NL | 6 | 7.4% |
| 4 | 🇹🇷 TR | 2 | 2.5% |
| 5 | 🇸🇬 SG | 1 | 1.2% |
| 6 | 🇫🇷 FR | 1 | 1.2% |
| 7 | 🇯🇵 JP | 1 | 1.2% |
| 8 | 🇸🇪 SE | 1 | 1.2% |
| 9 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 49 von 81 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 44 |
| Lateral Movement | 44 |
| Collection | 4 |
| Credential Access | 3 |
| Command and Control | 2 |
| Exfiltration | 1 |

<details><summary>c244dc93f8a675b0c001… – Formbook | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>7cb082bfc14dda0a4486… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>98323d89afdbd6e681be… – Formbook | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>b0cdd26c89023be886d3… – RemcosRAT | 🔴 KRITISCH 85.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [460e294f4a817a2d48f7…](https://bazaar.abuse.ch/sample/460e294f4a817a2d48f7376de4546a146e3bbc5315654a4e01b3489e4352f286/)

- **Familie:** Mirai
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Linux.Mozi.P
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Linux.Mozi.P`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Linux.Mozi.P` |
| AVG | `ELF:Agent-BSC [Cryp]` |
| AhnLab-V3 | `Trojan/Linux.Mirai.307960` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Linux.Mozi.P` |
| Avast | `ELF:Agent-BSC [Cryp]` |
| Avast-Mobile | `ELF:Mirai-UM [Trj]` |
| Avira | `EXP/ELF.Agent.L.26` |
| BitDefender 🛡️ | `Linux.Mozi.P` |
| CTX | `elf.unknown.mozi` |
| ClamAV | `Unix.Trojan.Mirai-7100807-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Packed.2018` |
| ESET-NOD32 | `Linux/Mozi.A trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| Emsisoft | `Linux.Mozi.P (B)` |
| F-Secure | `Exploit.EXP/ELF.Agent.L.26` |
| Fortinet | `ELF/Mozi.1962!tr` |
| GData | `Linux.Mozi.P` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Trojan.Linux.Generic` |
| Jiangmin | `Backdoor.Linux.fnqr` |
| K7GW | `Trojan ( 0040f08a1 )` |
| Kingsoft | `Linux.Backdoor.elf.2050727` |
| MaxSecure | `Backdoor.WIN32.030621.Linux.Mirai.b.YR` |
| McAfeeD | `Trojan:Script/Mirai.EEA` |
| MicroWorld-eScan | `Linux.Mozi.P` |
| Microsoft 🛡️ | `Trojan:Linux/Dakkatoni.A!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.148AF (CLASSIC)` |
| Sangfor | `Trojan.Linux.Save.Generic301` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Trojan.Linux.Mozi.mipra` |
| VBA32 | `Trojan.Linux.Mozi` |
| VIPRE | `Linux.Mozi.P` |
| Varist | `E32/Mirai.AJR` |
| VirIT | `Linux.Mirai.HGK` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDoS:Linux/mozi.83592073` |
| huorong | `Trojan/Linux.Mirai.f` |

### [72a77c71bf3fc29c82fd…](https://bazaar.abuse.ch/sample/72a77c71bf3fc29c82fde2f7514f9f1ef6d7705963ed9902b814b5a3054f7b12/)

- **Familie:** SMLBO1
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_BASHDLOD.SMLBO1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `BV:Downloader-AEH [Drp]` |
| AhnLab-V3 | `Downloader/Shell.Generic.S2600` |
| Avast | `BV:Downloader-AEH [Drp]` |
| DrWeb | `Linux.DownLoader.2250` |
| Google | `Detected` |
| Ikarus | `HTML.ExploitKit` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| TrendMicro | `Possible_BASHDLOD.SMLBO1` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBO1` |

### [d75aa2ce6207f86ae240…](https://bazaar.abuse.ch/sample/d75aa2ce6207f86ae240c60c36f1b92138855939b20f3c63b2570ef406f18c7b/)

- **Familie:** Mirai
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
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
| Elastic | `Linux.Trojan.Mirai` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.Mirai.gen` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Script/Mirai.EFV` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Trojan.Linux.Mirai.nk` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `Backdoor:Linux/Mirai.ASJ` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [b90a23defdcdcb13a316…](https://bazaar.abuse.ch/sample/b90a23defdcdcb13a316304081a0b52ea38b5d7e37901a63ac8989efa55a9a5b/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.K!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avira | `PUA/LINUX.Agent.BQZ` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3343` |
| ESET-NOD32 | `Linux/Flooder.Agent.NQ trojan` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.BQZ` |
| Fortinet | `ELF/UNSTABLE.OX!tr.botnet` |
| GData | `Linux.Trojan.Agent.69J7M0` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nd` |
| Kingsoft | `Linux.Backdoor.Mirai.nd` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!B90A23DEFDCD` |
| Microsoft 🛡️ | `Backdoor:Linux/Multiverze!rfn` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sangfor | `DDoS.Linux.Mirai.Vtnw` |
| Sophos | `Mal/Generic-S` |
| Symantec | `PUA.Gen.2` |
| Tencent | `Malware.Linux.Generic.1c0ca188` |
| Varist | `E32/Mirai.BNH` |
| alibabacloud | `Backdoor:Linux/Flooder.Akgpp` |
| huorong | `Trojan/Linux.DDos.du` |

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

- **elf** (47×)
- **Mirai** (40×)
- **Torii** (23×)
- **js** (11×)
- **sh** (8×)
- **DPRK** (6×)
- **EtherHiding** (6×)
- **NullReceiver** (6×)
- **PolinRider** (6×)
- **exe** (5×)
- **ps1** (5×)
- **upx-dec** (5×)
- **upx** (5×)
- **arm** (4×)
- **fake-font** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +14 (28→42)
- ↑ **unbekannt** +3 (21→24)
- ↑ **Formbook** +1 (2→3)
- neu: **Panchan** (2)
- neu: **Gafgyt** (2)
- neu: **AgentTesla** (1)
- neu: **SMLBO1** (1)
- ↓ **CoinMiner** -1 (2→1)
- neu: **RemcosRAT** (1)
- weg: **RevStealer** (war 9)
- weg: **Silentnet** (war 3)
- weg: **VShell** (war 6)
- weg: **WARDENStealer** (war 2)
- weg: **Snowlight** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +23 (19→42)
- ↓ **unbekannt** -11 (35→24)
- ↑ **Formbook** +1 (2→3)
- neu: **Panchan** (2)
- neu: **Gafgyt** (2)
- ↓ **AgentTesla** -2 (3→1)
- neu: **SMLBO1** (1)
- neu: **WannaCry** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **SalatStealer** (war 3)
- weg: **WARDENStealer** (war 2)
- weg: **VShell** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.415 MB |
| σ Dateigröße | 6.595 MB |
| Ø Risiko-Score | 69.7/100 |
| Ø Klassifikations-Konfidenz | 77.8% |
| Samples mit VT | 5/81 |
| Samples mit MITRE | 49/81 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 2 (2.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:35 | [fcb28ebda388…](https://bazaar.abuse.ch/sample/fcb28ebda38809c87d78c10c2fc42bd0c6074b9d8ae4440538ebcdf0c7c50d3a/) | `exe` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 12:33 | [2d106560abb1…](https://bazaar.abuse.ch/sample/2d106560abb19ccb1039fff48bfb4d00b0354371d095ec7669ef7f629eadd2df/) | `exe` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 12:23 | [adbb5f9901db…](https://bazaar.abuse.ch/sample/adbb5f9901db4f8042f6b95a7f77a5eef8488aabc8b22d297381ea5551c7ee43/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 12:04 | [9899ffecf141…](https://bazaar.abuse.ch/sample/9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de/) | `msi` | unbekannt | 83.1 | – | – | 🌐TR |
| 12:02 | [666140cb796c…](https://bazaar.abuse.ch/sample/666140cb796c70ba0187af66f33a2b1b6932770a200a4b968288bf795d2a852d/) | `exe` | AgentTesla | 83.1 | – | – | 🌐TR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 07.11.2026 12:40 UTC*