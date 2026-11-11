# MalwareBazaar – 11.11.2026 05:17 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **83** |
| Höchster Score | **85.8/100** – 4351a7e899a2d3d2… |
| Häufigste Familie | **SalatStealer** (50x) |
| Häufigster Typ | **exe** (73x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 18 Samples |
| Ø Dateigröße | 8.33 MB (σ=11.44) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 73 | 72.3%  ██████████████ |
| `elf` | 19 | 18.8%  ███ |
| `sh` | 3 | 3.0%   |
| `msi` | 2 | 2.0%   |
| `zip` | 2 | 2.0%   |
| `iso` | 1 | 1.0%   |
| `vbs` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 50 | 49.5% |
| 2 | unbekannt | 22 | 21.8% |
| 3 | Mirai | 16 | 15.8% |
| 4 | WARDENStealer | 6 | 5.9% |
| 5 | RevStealer | 3 | 3.0% |
| 6 | Arechclient2 | 1 | 1.0% |
| 7 | CoinMiner | 1 | 1.0% |
| 8 | GuLoader | 1 | 1.0% |
| 9 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 65 | 64.4% | 75% |
| Botnet/IoT | 16 | 15.8% | 95% |
| Windows-Malware | 10 | 9.9% | 35% |
| Linux-Malware | 3 | 3.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Backdoor | 2 | 2.0% | 75% |
| Loader | 1 | 1.0% | 95% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 83 | 82.2% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 13 | 12.9% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [4351a7e899a2d3…](https://bazaar.abuse.ch/sample/4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0/) | Arechclient2 | Infostealer | **85.8** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ✗ |
| [a629ffcf3eac76…](https://bazaar.abuse.ch/sample/a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [d2c18f8cc79df2…](https://bazaar.abuse.ch/sample/d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [6d6fd016c78e8f…](https://bazaar.abuse.ch/sample/6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [59b1072d546995…](https://bazaar.abuse.ch/sample/59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [8edc371dba9688…](https://bazaar.abuse.ch/sample/8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb/) | unbekannt | Backdoor | **82.9** | 🔴 KRITISCH | – | – | ? |
| [7db79169e43747…](https://bazaar.abuse.ch/sample/7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1/) | unbekannt | Backdoor | **82.9** | 🔴 KRITISCH | – | – | ? |
| [92ebc788fce25f…](https://bazaar.abuse.ch/sample/92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [8f17149c4abc15…](https://bazaar.abuse.ch/sample/8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [db8a601788f8dc…](https://bazaar.abuse.ch/sample/db8a601788f8dc8e618ae40e1f7bc43a0365b8088c030a573ba83b5160f87e6b/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6433/7931 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6433/7931 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6132/7931 |
| 6 | Kaspersky | 75.5% | 5988/7930 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5649/7927 |
| 9 | Rising | 68.4% | 5425/7931 |
| 10 | Varist | 66.1% | 5241/7926 |
| 11 | Avast | 65.2% | 5167/7927 |
| 12 | AVG | 65.2% | 5167/7926 |
| 13 | Tencent | 65.0% | 5008/7705 |
| 14 | McAfeeD | 61.4% | 4865/7923 |
| 15 | huorong | 60.9% | 4828/7923 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 75 | 74.3% |
| 🐧 Linux | 23 | 22.8% |
| 📦 Archiv | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 93 | 92.1% |
| MaaS-Loader | 3 | 3.0% |
| Trojanisierte Software | 2 | 2.0% |
| C2 / Nachladen | 2 | 2.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 38 | 37.6% |
| 2 | 🇳🇱 NL | 30 | 29.7% |
| 3 | 🌐 PT | 13 | 12.9% |
| 4 | 🇩🇪 DE | 10 | 9.9% |
| 5 | 🇫🇷 FR | 8 | 7.9% |
| 6 | 🇨🇭 CH | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 18 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 16 |
| Lateral Movement | 16 |
| Defense Evasion | 1 |
| Execution | 1 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>a629ffcf3eac76dd2265… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>d2c18f8cc79df2e13cc8… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6d6fd016c78e8f5d83ed… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>59b1072d546995aa7ac5… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [2814ef4cddbe575b6b3d…](https://bazaar.abuse.ch/sample/2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.10
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.10`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37119494` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.10` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.10` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Prometei.10 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Prometei.10` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.10` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37620874` |
| huorong | `Trojan/Prometei.c` |

### [4351a7e899a2d3d2b8fa…](https://bazaar.abuse.ch/sample/4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0/)

- **Familie:** Arechclient2
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [1dc3cfe1fc83ffd1a713…](https://bazaar.abuse.ch/sample/1dc3cfe1fc83ffd1a713e25aa7a671afe6ee070bfc8e2cd430bd1f36ccd5525f/)

- **Familie:** Mirai
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Backdoor.win32.Linux.aa1.Gafgyt.YR` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Trojan.Linux.Guardian.grdra` |
| huorong | `Trojan/Linux.Mirai.l` |

### [c2224e3b36e1796b0a22…](https://bazaar.abuse.ch/sample/c2224e3b36e1796b0a22770aae2743cd808c60ffe1d59241b083bf3c093c6c66/)

- **Familie:** SalatStealer
- **Erkannt von:** 53 von 75 Engines (70.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (53/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.130B807F` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Gen:Variant.Draftor.8401` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `malware.kb.b.939` |
| Lionic | `Trojan.Win64.Salat.i!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| McAfeeD | `Real Protect-LS!C96534FC6302` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Salat.lkswno` |
| Panda | `Trj/Agent.T` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!865BC7582C21` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570860` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!C96534FC6302` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/Trojan.CSAE-0249` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 59 von 75 Engines (78.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (59/75):**

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
| Sangfor | `Trojan.Win32.Autoit.Vjon` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (72×)
- **upx-dec** (30×)
- **upx** (27×)
- **salatstealer** (26×)
- **SalatStealer** (24×)
- **elf** (19×)
- **Mirai** (16×)
- **Torii** (9×)
- **WARDENStealer** (6×)
- **Prometei** (3×)
- **RevStealer** (3×)
- **RemusStealer** (3×)
- **85-11-167-82** (3×)
- **goxlr-live** (3×)
- **dropped-by-ACRStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +42 (8→50)
- ↓ **unbekannt** -12 (34→22)
- ↓ **Mirai** -1 (17→16)
- neu: **WARDENStealer** (6)
- ↑ **RevStealer** +2 (1→3)
- neu: **Arechclient2** (1)
- ↓ **GuLoader** -1 (2→1)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **Snowlight** (war 5)
- weg: **AgentTesla** (war 2)
- weg: **SilentNet** (war 5)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +48 (2→50)
- ↓ **unbekannt** -11 (33→22)
- ↓ **Mirai** -5 (21→16)
- ↑ **WARDENStealer** +3 (3→6)
- ↑ **RevStealer** +2 (1→3)
- neu: **Arechclient2** (1)
- neu: **GuLoader** (1)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **Formbook** (war 2)
- weg: **AgentTesla** (war 3)
- weg: **VShell** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.332 MB |
| σ Dateigröße | 11.442 MB |
| Ø Risiko-Score | 73.6/100 |
| Ø Klassifikations-Konfidenz | 72.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 18/101 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:25 | [b4b10c8daf78…](https://bazaar.abuse.ch/sample/b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf/) | `exe` | unbekannt | 38.3 | – | – | 🇳🇱NL |
| 04:25 | [1369c4076348…](https://bazaar.abuse.ch/sample/1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619/) | `exe` | unbekannt | 38.3 | – | – | 🇳🇱NL |
| 04:25 | [6d4f6858e88c…](https://bazaar.abuse.ch/sample/6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327/) | `exe` | unbekannt | 38.3 | – | – | 🇳🇱NL |
| 04:25 | [195288be3f11…](https://bazaar.abuse.ch/sample/195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38/) | `exe` | unbekannt | 38.3 | – | – | 🇳🇱NL |
| 04:24 | [8b2d30759910…](https://bazaar.abuse.ch/sample/8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d/) | `exe` | SalatStealer | 81.4 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.11.2026 05:17 UTC*