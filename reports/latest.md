# MalwareBazaar – 13.10.2026 21:02 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **59** |
| Höchster Score | **89.1/100** – f95b0132f12c542e… |
| Häufigste Familie | **unbekannt** (40x) |
| Häufigster Typ | **elf** (44x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 43 Samples |
| Ø Dateigröße | 2.55 MB (σ=5.15) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 44 | 43.6%  ████████ |
| `exe` | 28 | 27.7%  █████ |
| `sh` | 9 | 8.9%  █ |
| `jar` | 4 | 4.0%   |
| `bat` | 3 | 3.0%   |
| `msi` | 3 | 3.0%   |
| `macho` | 3 | 3.0%   |
| `vbs` | 2 | 2.0%   |
| `zip` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 40 | 39.6% |
| 2 | Mirai | 38 | 37.6% |
| 3 | SalatStealer | 5 | 5.0% |
| 4 | ValleyRAT | 3 | 3.0% |
| 5 | AMOS | 3 | 3.0% |
| 6 | SilentNet | 2 | 2.0% |
| 7 | CoinMiner | 2 | 2.0% |
| 8 | ConnectWise | 2 | 2.0% |
| 9 | AsyncRAT | 1 | 1.0% |
| 10 | Formbook | 1 | 1.0% |
| 11 | DL1 | 1 | 1.0% |
| 12 | RemusStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 38 | 37.6% | 95% |
| Infostealer | 13 | 12.9% | 81% |
| Andere / Unbekannt | 12 | 11.9% | 20% |
| Loader | 10 | 9.9% | 74% |
| Linux-Malware | 8 | 7.9% | 45% |
| Windows-Malware | 8 | 7.9% | 35% |
| Trojaner | 5 | 5.0% | 73% |
| RAT | 4 | 4.0% | 85% |
| Skript/Dropper | 3 | 3.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 58.4% |
| 🟠 HOCH | 11 | 10.9% |
| 🟡 MITTEL | 19 | 18.8% |
| 🟢 NIEDRIG | 12 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f95b0132f12c54…](https://bazaar.abuse.ch/sample/f95b0132f12c542e3137b1e1f33dac16904772d3e03a88bb9e731a5c96858191/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [476d7d093d3895…](https://bazaar.abuse.ch/sample/476d7d093d3895b58b30ed00330b1aea04f3c42ba2b99ad1def4bddcc6ea5f50/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [700f16a8510983…](https://bazaar.abuse.ch/sample/700f16a8510983959cc2ba47648257427940c5fd7980786a998ff59149219f6e/) | AMOS | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [9f110c4d67597b…](https://bazaar.abuse.ch/sample/9f110c4d67597b5c6ed43ae7834668883cce096b181163452377205b619dc56c/) | AMOS | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [486277d29cbefc…](https://bazaar.abuse.ch/sample/486277d29cbefcbd321d7c7ad5d72bf1983c110206ed607c6c371af7f7741308/) | AMOS | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [45c647386b7635…](https://bazaar.abuse.ch/sample/45c647386b7635257d6f832aaeac43c71996fabc0be65b70dd8b7885c3d30002/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [647f5873995342…](https://bazaar.abuse.ch/sample/647f5873995342314205d8397be7a7e568977d4121129e38123fb1403c383246/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [72ed964f4455c5…](https://bazaar.abuse.ch/sample/72ed964f4455c532e67ba9c5e00e7d84b8a0273d3acd4cdf90bc4e698b16c4fb/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [88174d3ffd24b8…](https://bazaar.abuse.ch/sample/88174d3ffd24b8b3c06beebb0dd9d58d6eb4371e089b4b2cde42d55f4177ba90/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | 12.0% | 🟡 SCHWACH ERKANNT | ✗ |
| [884416388cfc8a…](https://bazaar.abuse.ch/sample/884416388cfc8a12bb404cc6260d1839a446f0abecdfbe0d8b0b407e8a3c8ce6/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5946/7351 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5946/7351 |
| 3 | ESET-NOD32 | 77.4% | 5691/7351 |
| 4 | Kaspersky | 76.3% | 5611/7350 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5260/7348 |
| 8 | Rising | 68.7% | 5052/7351 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4882/7347 |
| 11 | Tencent | 65.3% | 4652/7125 |
| 12 | Avast | 65.0% | 4778/7347 |
| 13 | AVG | 65.0% | 4778/7346 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4506/7344 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 54 | 53.5% |
| 🪟 Windows | 36 | 35.6% |
| ❓ Unbekannt | 5 | 5.0% |
| 📦 Archiv | 3 | 3.0% |
| 🍎 macOS | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 83 | 82.2% |
| C2 / Nachladen | 11 | 10.9% |
| Trojanisierte Software | 3 | 3.0% |
| MaaS-Loader | 3 | 3.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 41 | 40.6% |
| 2 | 🇩🇪 DE | 27 | 26.7% |
| 3 | 🇨🇿 CZ | 9 | 8.9% |
| 4 | 🇳🇱 NL | 7 | 6.9% |
| 5 | 🇪🇸 ES | 6 | 5.9% |
| 6 | 🇭🇺 HU | 3 | 3.0% |
| 7 | 🇦🇹 AT | 3 | 3.0% |
| 8 | 🇧🇷 BR | 1 | 1.0% |
| 9 | 🇧🇪 BE | 1 | 1.0% |
| 10 | 🇨🇭 CH | 1 | 1.0% |
| 11 | 🇸🇬 SG | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 43 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 38 |
| Lateral Movement | 38 |
| Collection | 3 |
| Execution | 2 |
| Command and Control | 2 |
| Credential Access | 2 |
| Persistence | 1 |

<details><summary>f95b0132f12c542e3137… – AsyncRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>476d7d093d3895b58b30… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [88174d3ffd24b8b3c06b…](https://bazaar.abuse.ch/sample/88174d3ffd24b8b3c06beebb0dd9d58d6eb4371e089b4b2cde42d55f4177ba90/)

- **Familie:** Mirai
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:MiraiDownloader-BX [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:MiraiDownloader-BX [Trj]` |
| AhnLab-V3 | `Linux/Miraidown.Gen2` |
| Avast | `ELF:MiraiDownloader-BX [Trj]` |
| ESET-NOD32 | `Linux/TrojanDownloader.Mirai.Y trojan` |
| Fortinet | `ELF/Mirai.Y!tr.dldr` |
| Kaspersky | `HEUR:Trojan-Downloader.Linux.Mirai.d` |
| Rising | `Downloader.Mirai/Linux!8.13556 (CLOUD)` |
| Tencent | `Linux.Trojan-Downloader.Mirai.Majl` |
| huorong | `Trojan/Linux.Mirai.f` |

### [c915cbe413734215dc0d…](https://bazaar.abuse.ch/sample/c915cbe413734215dc0da1cc94f1d4e29561986fbf00ff806ed7f0b005f4403f/)

- **Familie:** DL1
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** HEUR_VBS.DL1
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| NANO-Antivirus | `Trojan.Script.MLW.dzxldj` |
| Skyhigh | `BehavesLike.VBS.Dropper.xv` |
| Symantec | `ISB.Downloader!gen60` |
| TrendMicro | `HEUR_VBS.DL1` |
| TrendMicro-HouseCall | `HEUR_VBS.DL1` |
| Yandex | `HTML.Psyme.Gen` |
| huorong | `TrojanDownloader/BAT.Agent.n` |

### [f04ec1bf6a2fdb9f2d72…](https://bazaar.abuse.ch/sample/f04ec1bf6a2fdb9f2d723c81b9ad75f4b177714e4212ea79663ebb95bb515db4/)

- **Familie:** SH
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/TrojanDownloader.SH.GSY trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DownLoader.2650` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.GSY trojan` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| Rising | `Downloader.Agent/BASH!9.86468 (XSE:WFNFX0JBVDra2k2do/TB7Mo76ONrjgoQ)` |
| Tencent | `Win32.Trojan-Downloader.Agent.Icnw` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (63/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| Zillya | `Trojan.Rescoms.Win32.2903` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (42×)
- **Mirai** (36×)
- **exe** (24×)
- **dropped-by-GCleaner** (7×)
- **ValleyRAT** (6×)
- **signed** (5×)
- **ClickFix** (5×)
- **macOS** (5×)
- **wraith** (5×)
- **SilverFox** (5×)
- **SalatStealer** (4×)
- **upx-dec** (4×)
- **upx** (4×)
- **jar** (4×)
- **java** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +8 (32→40)
- ↑ **Mirai** +3 (35→38)
- neu: **SalatStealer** (5)
- ↑ **ValleyRAT** +2 (1→3)
- ↑ **AMOS** +2 (1→3)
- ↓ **SilentNet** -3 (5→2)
- ↑ **CoinMiner** +1 (1→2)
- neu: **ConnectWise** (2)
- ↓ **AsyncRAT** -1 (2→1)
- ↓ **Formbook** -3 (4→1)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +12 (28→40)
- ↓ **Mirai** -1 (39→38)
- neu: **SalatStealer** (5)
- ↑ **ValleyRAT** +2 (1→3)
- neu: **AMOS** (3)
- ↑ **SilentNet** +1 (1→2)
- ↑ **CoinMiner** +1 (1→2)
- ↓ **Formbook** -1 (2→1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.545 MB |
| σ Dateigröße | 5.147 MB |
| Ø Risiko-Score | 66.5/100 |
| Ø Klassifikations-Konfidenz | 70.2% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 43/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 67 |
| Unbekannte Familien | 12 (11.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:46 | [e8af4e957dc0…](https://bazaar.abuse.ch/sample/e8af4e957dc045e60dc05044cb4ece18557f4c6df6fb86aaa9ad07e12d4878ff/) | `exe` | SalatStealer | 82.0 | – | – | 🇳🇱NL |
| 20:46 | [14ac2e6f011f…](https://bazaar.abuse.ch/sample/14ac2e6f011fa59ac58a539c852d70cd1257f9987676969b8ad26ff621ca1fac/) | `exe` | SalatStealer | 82.0 | – | – | 🇺🇸US |
| 20:37 | [45c647386b76…](https://bazaar.abuse.ch/sample/45c647386b7635257d6f832aaeac43c71996fabc0be65b70dd8b7885c3d30002/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 20:33 | [647f58739953…](https://bazaar.abuse.ch/sample/647f5873995342314205d8397be7a7e568977d4121129e38123fb1403c383246/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 20:33 | [08463c584fa0…](https://bazaar.abuse.ch/sample/08463c584fa09c1d57e232478a10975cb10bd2a2a669334dae2c430cc6686210/) | `elf` | unbekannt | 42.9 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.10.2026 21:02 UTC*