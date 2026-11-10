# MalwareBazaar – 10.11.2026 16:14 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **52** |
| Höchster Score | **94.7/100** – ec138352c4726fa3… |
| Häufigste Familie | **unbekannt** (39x) |
| Häufigster Typ | **exe** (81x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 17 Samples |
| Ø Dateigröße | 1.95 MB (σ=2.69) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 81 | 80.2%  ████████████████ |
| `elf` | 13 | 12.9%  ██ |
| `zip` | 1 | 1.0%   |
| `bat` | 1 | 1.0%   |
| `7z` | 1 | 1.0%   |
| `vbs` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 39 | 38.6% |
| 2 | Mirai | 10 | 9.9% |
| 3 | PureRAT | 3 | 3.0% |
| 4 | RustyStealer | 3 | 3.0% |
| 5 | AsyncRAT | 2 | 2.0% |
| 6 | MassLogger | 2 | 2.0% |
| 7 | BrunoStealer | 2 | 2.0% |
| 8 | a310Logger | 2 | 2.0% |
| 9 | StormKitty | 2 | 2.0% |
| 10 | AntarctidaStealer | 2 | 2.0% |
| 11 | QuasarRAT | 2 | 2.0% |
| 12 | njrat | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 37 | 36.6% | 35% |
| Infostealer | 21 | 20.8% | 76% |
| RAT | 20 | 19.8% | 84% |
| Botnet/IoT | 10 | 9.9% | 95% |
| Linux-Malware | 3 | 3.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Loader | 2 | 2.0% | 75% |
| Ransomware | 2 | 2.0% | 85% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 52 | 51.5% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 42 | 41.6% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ec138352c4726f…](https://bazaar.abuse.ch/sample/ec138352c4726fa3b6706b30bf4692252f818108c8066e8518920dd9823a34bb/) | WannaCry | Ransomware | **94.7** | 🔴 KRITISCH | – | – | ? |
| [8bd40f06c025a2…](https://bazaar.abuse.ch/sample/8bd40f06c025a2d2f8ff739309b40a6f551617c9d5cb28544480260b50cb09c1/) | NanoCore | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [b75863d6b46b63…](https://bazaar.abuse.ch/sample/b75863d6b46b63a1e7c3fa435eb93c129a246c44206bf43332b7c75956763c1a/) | AsyncRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [b990de3e1fb640…](https://bazaar.abuse.ch/sample/b990de3e1fb6409ae260b0be0f5c4787439e9b695c887711e5f0855c095e4a4e/) | HawkEye | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [533d9a9dee3202…](https://bazaar.abuse.ch/sample/533d9a9dee32029c75115ff14704f8d7ba1f3ccbc27c28a68e6cc6268fea405e/) | XWorm | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [bfc5d48c6d6711…](https://bazaar.abuse.ch/sample/bfc5d48c6d67111d90eeeb6c69d1236f09c6bdfea94163e2af680e16a012a0ff/) | QuasarRAT | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [b95b2d2613b2b9…](https://bazaar.abuse.ch/sample/b95b2d2613b2b99b1855c0822e7995f47c79559a115758ee55048ce5a7bbe2e6/) | AsyncRAT | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [ebfa9915462163…](https://bazaar.abuse.ch/sample/ebfa991546216326f9e6cd9ce5c28f2c92011a4e95c42fe0b21728e0609029a8/) | njrat | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [6da7723b6964c0…](https://bazaar.abuse.ch/sample/6da7723b6964c0c7165bb57ddce18156668b0b94bc67b1aa2f4ec5fecc5ec0b6/) | QuasarRAT | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |
| [8b9973b990d5f5…](https://bazaar.abuse.ch/sample/8b9973b990d5f5f18e1668df15975f4d8eadb051bea0e82a939badda2cbba92a/) | njrat | RAT | **86.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6425/7921 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6425/7921 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6124/7921 |
| 6 | Kaspersky | 75.5% | 5981/7920 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5641/7917 |
| 9 | Rising | 68.4% | 5418/7921 |
| 10 | Varist | 66.2% | 5237/7916 |
| 11 | Avast | 65.2% | 5162/7917 |
| 12 | AVG | 65.2% | 5162/7916 |
| 13 | Tencent | 65.0% | 5001/7695 |
| 14 | McAfeeD | 61.4% | 4860/7913 |
| 15 | huorong | 61.0% | 4823/7913 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 82 | 81.2% |
| 🐧 Linux | 15 | 14.9% |
| 📦 Archiv | 3 | 3.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 96 | 95.0% |
| MaaS-Loader | 2 | 2.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 86 | 85.1% |
| 2 | 🇺🇸 US | 5 | 5.0% |
| 3 | 🇭🇺 HU | 4 | 4.0% |
| 4 | 🇳🇱 NL | 2 | 2.0% |
| 5 | 🇫🇷 FR | 2 | 2.0% |
| 6 | 🌐 CO | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 17 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 10 |
| Lateral Movement | 10 |
| Command and Control | 7 |
| Collection | 3 |
| Execution | 2 |
| Exfiltration | 2 |

<details><summary>b75863d6b46b63a1e7c3… – AsyncRAT | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [bc96d9b73a53b0aeef32…](https://bazaar.abuse.ch/sample/bc96d9b73a53b0aeef3289ad4500f3c1d19aaeb2138b1aa8ba5c64a391534a17/)

- **Familie:** Mirai
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Backdoor.win32.Linux.aa1.Gafgyt.YR` |
| McAfeeD | `Trojan:Script/Mirai.EFW` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Trojan.Linux.Guardian.grdra` |
| huorong | `Trojan/Linux.Mirai.l` |

### [3d6dc514485df66060d7…](https://bazaar.abuse.ch/sample/3d6dc514485df66060d72f2ce39629bf014ff059da8dce5a65318c8a2ec68ab5/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/DDoS-CIA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast-Mobile | `ELF:Mirai-AAU [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.BYQ trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF/Mirai.AE!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| McAfeeD | `Trojan:Linux/Mirai.EAF` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CIA` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CIA` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [da5f7780e90052ed2d9c…](https://bazaar.abuse.ch/sample/da5f7780e90052ed2d9c810548434ffa84b4231910fd3bfcd4a9f13043e00750/)

- **Familie:** LarpestanRAT
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ML.Attribute.HighConfidence
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Win64/Spy.Agent.YT trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan-PSW.Agent` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Agent.gen` |
| McAfeeD | `Trojan:Win/Malwarex.EIS` |
| Microsoft 🛡️ | `Trojan:Win32/LummaStealer.DO!MTB` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |

### [4f1666b5793b729c6ae8…](https://bazaar.abuse.ch/sample/4f1666b5793b729c6ae829a03d8c853de3e5238c80d03c411a4f3018537f80cc/)

- **Familie:** MalwareX-gen [Pws]
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `MalwareX-gen [Pws]` |
| Alibaba | `TrojanPSW:Win64/Generic.6082e7dd` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.672533D` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DrWeb | `Trojan.PWS.Siggen5.36044` |
| ESET-NOD32 | `Win64/Agent.GOJ trojan` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Trojan-Stealer.Cordimik.OGYJRN@gen` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Agent.gen` |
| Kingsoft | `Win32.Trojan-PSW.Agent.gen` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| Malwarebytes | `Malware.AI.3433736224` |
| McAfeeD | `Trojan:Win/Ravartar.EBM` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Stealer.Agent!8.C2 (CLOUD)` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.LummaStealer.Oqil` |
| TrellixENS | `Artemis!02A23D6C9A8F` |
| Varist | `W64/ABTrojan.XFLB-8516` |
| alibabacloud | `Trojan[stealer]:Win/Wacatac.B9nj` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 60 von 75 Engines (80.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (60/75):**

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
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vxic` |
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

- **exe** (80×)
- **elf** (13×)
- **Mirai** (10×)
- **Torii** (4×)
- **cowrie** (4×)
- **honeypot** (4×)
- **PureRAT** (3×)
- **RustyStealer** (3×)
- **AsyncRAT** (2×)
- **MassLogger** (2×)
- **Prometei** (2×)
- **stealer** (2×)
- **arm** (2×)
- **signed** (2×)
- **BrunoStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +11 (28→39)
- ↓ **Mirai** -17 (27→10)
- neu: **PureRAT** (3)
- neu: **RustyStealer** (3)
- neu: **AsyncRAT** (2)
- neu: **MassLogger** (2)
- neu: **BrunoStealer** (2)
- neu: **a310Logger** (2)
- neu: **StormKitty** (2)
- neu: **AntarctidaStealer** (2)
- weg: **Vidar** (war 2)
- weg: **CoinMiner** (war 2)
- weg: **SalatStealer** (war 11)
- weg: **Snowlight** (war 7)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +6 (33→39)
- ↓ **Mirai** -12 (22→10)
- neu: **PureRAT** (3)
- neu: **RustyStealer** (3)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **MassLogger** (2)
- neu: **BrunoStealer** (2)
- neu: **a310Logger** (2)
- neu: **StormKitty** (2)
- neu: **AntarctidaStealer** (2)
- weg: **Formbook** (war 2)
- weg: **VShell** (war 2)
- weg: **AgentTesla** (war 3)
- weg: **SalatStealer** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.954 MB |
| σ Dateigröße | 2.694 MB |
| Ø Risiko-Score | 60.7/100 |
| Ø Klassifikations-Konfidenz | 61.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 17/101 |
| Eindeutige Familien | 42 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 15:48 | [bd9e478065f6…](https://bazaar.abuse.ch/sample/bd9e478065f692690a650facb4fa9e7d8a0b22073cbf05df7ba60769005cd6b5/) | `elf` | unbekannt | 43.0 | – | – | 🇩🇪DE |
| 15:33 | [0ef2ea23bf88…](https://bazaar.abuse.ch/sample/0ef2ea23bf882ea6548149fc2f9b807eb677c1f918ce20c8d21645e2b3ecaf24/) | `exe` | unbekannt | 38.5 | – | – | 🇩🇪DE |
| 15:23 | [bc96d9b73a53…](https://bazaar.abuse.ch/sample/bc96d9b73a53b0aeef3289ad4500f3c1d19aaeb2138b1aa8ba5c64a391534a17/) | `elf` | Mirai | 82.9 | 20.0% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 15:01 | [22de20d18a51…](https://bazaar.abuse.ch/sample/22de20d18a51a7b294042bab83c66e14e50e20debed7340ac7bc01857d059d2b/) | `elf` | Mirai | 83.5 | – | – | 🇩🇪DE |
| 14:50 | [8bd40f06c025…](https://bazaar.abuse.ch/sample/8bd40f06c025a2d2f8ff739309b40a6f551617c9d5cb28544480260b50cb09c1/) | `exe` | NanoCore | 88.5 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 10.11.2026 16:14 UTC*