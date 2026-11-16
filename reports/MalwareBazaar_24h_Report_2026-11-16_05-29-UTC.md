# MalwareBazaar – 16.11.2026 05:29 UTC

Dieser Run hat **58 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **59** |
| Kritisch (≥75) | **30** |
| Höchster Score | **95.2/100** – 7c47f9d4b9496f75… |
| Häufigste Familie | **unbekannt** (24x) |
| Häufigster Typ | **elf** (26x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 23 Samples |
| Ø Dateigröße | 1.33 MB (σ=3.34) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 26 | 44.1%  ████████ |
| `exe` | 16 | 27.1%  █████ |
| `js` | 6 | 10.2%  ██ |
| `vbs` | 5 | 8.5%  █ |
| `macho` | 3 | 5.1%  █ |
| `ps1` | 1 | 1.7%   |
| `sh` | 1 | 1.7%   |
| `apk` | 1 | 1.7%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 24 | 40.7% |
| 2 | Mirai | 17 | 28.8% |
| 3 | GuLoader | 5 | 8.5% |
| 4 | SalatStealer | 4 | 6.8% |
| 5 | WARDENStealer | 3 | 5.1% |
| 6 | Snowlight | 3 | 5.1% |
| 7 | WannaCry | 1 | 1.7% |
| 8 | Babadeda | 1 | 1.7% |
| 9 | RemcosRAT | 1 | 1.7% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 17 | 28.8% | 95% |
| Linux-Malware | 8 | 13.6% | 45% |
| Skript/Dropper | 7 | 11.9% | 35% |
| Infostealer | 7 | 11.9% | 75% |
| Windows-Malware | 7 | 11.9% | 35% |
| Loader | 5 | 8.5% | 95% |
| Andere / Unbekannt | 4 | 6.8% | 20% |
| Ransomware | 1 | 1.7% | 95% |
| Trojaner | 1 | 1.7% | 65% |
| Android-Malware | 1 | 1.7% | 45% |
| RAT | 1 | 1.7% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 30 | 50.8% |
| 🟠 HOCH | 2 | 3.4% |
| 🟡 MITTEL | 23 | 39.0% |
| 🟢 NIEDRIG | 4 | 6.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7c47f9d4b9496f…](https://bazaar.abuse.ch/sample/7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3/) | WannaCry | Ransomware | **95.2** | 🔴 KRITISCH | – | – | ? |
| [78a495e04a829a…](https://bazaar.abuse.ch/sample/78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a/) | Mirai | Botnet/IoT | **88.5** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ? |
| [1409798cde3af5…](https://bazaar.abuse.ch/sample/1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [b48c71dac86b74…](https://bazaar.abuse.ch/sample/b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [88c32e47bcf484…](https://bazaar.abuse.ch/sample/88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [35f32b517039e4…](https://bazaar.abuse.ch/sample/35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [dabc05223d247f…](https://bazaar.abuse.ch/sample/dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [c20f4bf9d23948…](https://bazaar.abuse.ch/sample/c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [1c00f4f5230803…](https://bazaar.abuse.ch/sample/1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [c93858738a9957…](https://bazaar.abuse.ch/sample/c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6505/8013 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6505/8013 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6197/8013 |
| 6 | Kaspersky | 75.5% | 6050/8012 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5707/8009 |
| 9 | Rising | 68.5% | 5485/8013 |
| 10 | Varist | 66.1% | 5290/8008 |
| 11 | Avast | 65.2% | 5219/8009 |
| 12 | AVG | 65.2% | 5219/8008 |
| 13 | Tencent | 65.1% | 5067/7787 |
| 14 | McAfeeD | 61.5% | 4921/8005 |
| 15 | huorong | 60.8% | 4870/8005 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 27 | 45.8% |
| 🪟 Windows | 22 | 37.3% |
| ❓ Unbekannt | 6 | 10.2% |
| 🍎 macOS | 3 | 5.1% |
| 🤖 Android | 1 | 1.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 46 | 78.0% |
| Drive-By / Exploit-Kit | 11 | 18.6% |
| Exploit / N-Day | 1 | 1.7% |
| APK-Sideloading | 1 | 1.7% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 26 | 44.1% |
| 2 | 🇩🇪 DE | 15 | 25.4% |
| 3 | 🇫🇷 FR | 7 | 11.9% |
| 4 | 🇨🇭 CH | 5 | 8.5% |
| 5 | 🇳🇱 NL | 4 | 6.8% |
| 6 | 🇯🇵 JP | 1 | 1.7% |
| 7 | 🌐 Unbekannt | 1 | 1.7% |

## MITRE ATT&CK

> 23 von 59 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 17 |
| Lateral Movement | 17 |
| Defense Evasion | 5 |
| Execution | 5 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>78a495e04a829a4e9947… – Mirai | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1409798cde3af5837c76… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b48c71dac86b74e15394… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>88c32e47bcf484deb874… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [78a495e04a829a4e9947…](https://bazaar.abuse.ch/sample/78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a/)

- **Familie:** Mirai
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

### [4e039b8335f759c200f6…](https://bazaar.abuse.ch/sample/4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934/)

- **Familie:** Mirai
- **Erkannt von:** 14 von 74 Engines (18.9%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/Flooder.Agent.NQ trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Linux/Gafgyt01.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avira | `TR/LINUX.Flooder.AEG` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Flooder.Agent.NQ trojan` |
| F-Secure | `Trojan.TR/LINUX.Flooder.AEG` |
| Fortinet | `ELF/Flooder.NQ!tr` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nd` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.DA!MTB` |
| Tencent | `OB:Backdoor.Linux.Flooder.mipra` |
| Varist | `E32/Mirai.AT.gen!Eldorado` |
| huorong | `Trojan/Linux.DDos.dw` |

### [2403bcc927beb7b39dc4…](https://bazaar.abuse.ch/sample/2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39502263` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39502263 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39502263` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [e689fc21c768fd7467ee…](https://bazaar.abuse.ch/sample/e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac/)

- **Familie:** Snowlight
- **Erkannt von:** 27 von 74 Engines (36.5%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!D88038595A1A` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (24×)
- **Mirai** (17×)
- **exe** (15×)
- **Torii** (9×)
- **js** (6×)
- **GuLoader** (5×)
- **vbs** (5×)
- **SalatStealer** (4×)
- **WARDENStealer** (3×)
- **macho** (3×)
- **Snowlight** (3×)
- **Prometei** (2×)
- **dionaea** (2×)
- **upx-dec** (2×)
- **upx** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +7 (17→24)
- ↓ **Mirai** -31 (48→17)
- neu: **GuLoader** (5)
- ↑ **SalatStealer** +2 (2→4)
- ↓ **WARDENStealer** -3 (6→3)
- neu: **Snowlight** (3)
- neu: **WannaCry** (1)
- neu: **Babadeda** (1)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -1 (25→24)
- ↓ **Mirai** -20 (37→17)
- ↑ **GuLoader** +4 (1→5)
- ↓ **SalatStealer** -2 (6→4)
- ↓ **WARDENStealer** -2 (5→3)
- ↑ **Snowlight** +2 (1→3)
- neu: **WannaCry** (1)
- neu: **Babadeda** (1)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **AgentTesla** (war 2)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.329 MB |
| σ Dateigröße | 3.340 MB |
| Ø Risiko-Score | 60.7/100 |
| Ø Klassifikations-Konfidenz | 65.2% |
| Samples mit VT | 5/59 |
| Samples mit MITRE | 23/59 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 21 |
| Unbekannte Familien | 4 (6.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:28 | [59b6431ac5fc…](https://bazaar.abuse.ch/sample/59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40/) | `elf` | unbekannt | 43.4 | – | – | 🇩🇪DE |
| 05:28 | [77456632a5c2…](https://bazaar.abuse.ch/sample/77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0/) | `elf` | unbekannt | 43.4 | – | – | 🇩🇪DE |
| 05:27 | [d54a695c3923…](https://bazaar.abuse.ch/sample/d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 05:24 | [1409798cde3a…](https://bazaar.abuse.ch/sample/1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 05:22 | [b48c71dac86b…](https://bazaar.abuse.ch/sample/b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.11.2026 05:29 UTC*