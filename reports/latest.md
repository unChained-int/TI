# MalwareBazaar – 06.11.2026 19:03 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **60** |
| Höchster Score | **97.1/100** – 43fe9dde201aa613… |
| Häufigste Familie | **RevStealer** (23x) |
| Häufigster Typ | **exe** (49x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 2.84 MB (σ=5.42) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 49 | 48.5%  █████████ |
| `elf` | 31 | 30.7%  ██████ |
| `jar` | 9 | 8.9%  █ |
| `zsh` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `macho` | 2 | 2.0%   |
| `ps1` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `xlsx` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | RevStealer | 23 | 22.8% |
| 2 | unbekannt | 20 | 19.8% |
| 3 | Mirai | 18 | 17.8% |
| 4 | Silentnet | 8 | 7.9% |
| 5 | Formbook | 6 | 5.9% |
| 6 | CoinMiner | 5 | 5.0% |
| 7 | Ngioweb | 3 | 3.0% |
| 8 | WannaCry | 2 | 2.0% |
| 9 | SilentNet | 2 | 2.0% |
| 10 | VShell | 2 | 2.0% |
| 11 | Vidar | 2 | 2.0% |
| 12 | QuasarRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 34 | 33.7% | 81% |
| Botnet/IoT | 19 | 18.8% | 95% |
| Linux-Malware | 10 | 9.9% | 45% |
| Andere / Unbekannt | 10 | 9.9% | 20% |
| Windows-Malware | 8 | 7.9% | 35% |
| Loader | 5 | 5.0% | 79% |
| Cryptominer | 5 | 5.0% | 75% |
| RAT | 3 | 3.0% | 95% |
| Backdoor | 3 | 3.0% | 75% |
| Ransomware | 2 | 2.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 60 | 59.4% |
| 🟠 HOCH | 12 | 11.9% |
| 🟡 MITTEL | 19 | 18.8% |
| 🟢 NIEDRIG | 10 | 9.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [43fe9dde201aa6…](https://bazaar.abuse.ch/sample/43fe9dde201aa613382486afacd94af75cd45de3ee1aaa2a49442e850acd9da9/) | WannaCry | Ransomware | **97.1** | 🔴 KRITISCH | – | – | ? |
| [4436f92229f527…](https://bazaar.abuse.ch/sample/4436f92229f527236c0847564351ef5147b2458a120f3402b0dd1b58a6a84f0a/) | WannaCry | Ransomware | **96.6** | 🔴 KRITISCH | – | – | ? |
| [7f76536fc2cb74…](https://bazaar.abuse.ch/sample/7f76536fc2cb747da0329d261abf8162f8b3ae75857a873525584835b0d141af/) | LummaStealer | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [02e1bfbf151148…](https://bazaar.abuse.ch/sample/02e1bfbf151148ad8bb5f57373bb27f70e355bd633ed2a4c523af9c8a897454c/) | QuasarRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [9f4606b6427b84…](https://bazaar.abuse.ch/sample/9f4606b6427b84917f6eddef94e3a833698ffcd4cea713efae40741ee5aaa458/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [a24038af0439cc…](https://bazaar.abuse.ch/sample/a24038af0439ccdb214d6299c199f04f0ef9e7c335b9d2d32549d4f13e7a7d07/) | SnakeKeylogger | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [3a34a7209bfb6b…](https://bazaar.abuse.ch/sample/3a34a7209bfb6b1e2b5e3cf530bcfd3989371b9cefa0beefbb838ea37ad6e415/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [c8e7f59b5de8f6…](https://bazaar.abuse.ch/sample/c8e7f59b5de8f6c571187d3f22f321e5bde8d4abb49f8084786da3d0bb3e4396/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [d68a914ac6395a…](https://bazaar.abuse.ch/sample/d68a914ac6395aff8d4b6bc75ae6d9898cf491878192831da943f1de5d360dc4/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [e16b604332f600…](https://bazaar.abuse.ch/sample/e16b604332f6007f51b62c04390760dbf6353aff04d49ce8203393c10cdc72fc/) | Formbook | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6360/7852 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6360/7852 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.2% | 6065/7852 |
| 6 | Kaspersky | 75.4% | 5923/7851 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5586/7848 |
| 9 | Rising | 68.3% | 5361/7852 |
| 10 | Varist | 66.2% | 5192/7847 |
| 11 | AVG | 65.1% | 5105/7847 |
| 12 | Avast | 65.0% | 5105/7848 |
| 13 | Tencent | 64.9% | 4948/7626 |
| 14 | McAfeeD | 61.4% | 4817/7844 |
| 15 | huorong | 60.8% | 4771/7844 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 49 | 48.5% |
| 🐧 Linux | 37 | 36.6% |
| ❓ Unbekannt | 10 | 9.9% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 95 | 94.1% |
| Exploit / N-Day | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 42 | 41.6% |
| 2 | 🇩🇪 DE | 19 | 18.8% |
| 3 | 🇺🇸 US | 18 | 17.8% |
| 4 | 🇮🇩 ID | 8 | 7.9% |
| 5 | 🇭🇺 HU | 5 | 5.0% |
| 6 | 🇳🇱 NL | 5 | 5.0% |
| 7 | 🇨🇦 CA | 1 | 1.0% |
| 8 | 🌐 DK | 1 | 1.0% |
| 9 | 🇧🇷 BR | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 30 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Credential Access | 9 |
| Collection | 9 |
| Exfiltration | 4 |
| Command and Control | 2 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>7f76536fc2cb747da032… – LummaStealer | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>02e1bfbf151148ad8bb5… – QuasarRAT | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>9f4606b6427b84917f6e… – Formbook | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [216fb7587c27745b4325…](https://bazaar.abuse.ch/sample/216fb7587c27745b4325b0ba14b20f0fdc45ff485de9030018364710d96fedc2/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 76 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [62e2b8a6c75cde2ec395…](https://bazaar.abuse.ch/sample/62e2b8a6c75cde2ec395c34ac5055be0d0c51d796e93d37b2f1681a833693896/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [4de1967a36849e08f239…](https://bazaar.abuse.ch/sample/4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb/)

- **Familie:** Vidar
- **Erkannt von:** 38 von 75 Engines (50.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Vidar.1241
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win64/Vidar.JS!MTB`

**Erkennende Engines (38/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.C5953983` |
| Alibaba | `TrojanPSW:Win32/Stealerc.073dc6da` |
| Antiy-AVL | `Trojan[PSW]/Win32.StealerC` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.9AFCC4AA` |
| ClamAV | `Win.Infostealer.Vidar-10060509-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/Vidar.D trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Vidar.1241 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/Vidar.D!tr` |
| GData | `Gen:Variant.Vidar.1241` |
| K7AntiVirus | `Password-Stealer ( 005ce1d71 )` |
| K7GW | `Password-Stealer ( 005ce1d71 )` |
| Lionic | `Trojan.Win32.Stealer.12!c` |
| Malwarebytes | `Malware.AI.1409990705` |
| MaxSecure | `Trojan.Malware.334132322.susgen` |
| McAfeeD | `ti!4DE1967A3684` |
| MicroWorld-eScan | `Gen:Variant.Vidar.1241` |
| Microsoft 🛡️ | `Trojan:Win64/Vidar.JS!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan-PWS/W64.Stealerc.1384960` |
| Tencent | `Trojan.Win32.Vidar.16006161` |
| TrellixENS | `Artemis!CB201373D521` |
| TrendMicro | `Trojan.Win32.VIDAR.USBLJ426` |
| TrendMicro-HouseCall | `Trojan.Win32.VIDAR.USBLJ426` |
| VIPRE | `Gen:Variant.Vidar.1241` |
| VirIT | `Trojan.Win64.GenusT.FZVY` |
| Webroot | `W32.Trojan.Gen` |
| Zillya | `Trojan.Stealerc.Win32.39001` |
| alibabacloud | `Trojan[stealer]:Win/Vidar.D` |
| huorong | `HVM:TrojanSpy/W64.Stealer.a` |

### [c3413ad2671abdee8b97…](https://bazaar.abuse.ch/sample/c3413ad2671abdee8b970ffec9b5bdbc763ede822faf93994d94c1a71f117d89/)

- **Familie:** RevStealer
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.8497F8BE
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Wacatac.B!ml`

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.R798027` |
| Alibaba | `Packed:Win64/VMProtect.7161f58f` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.8497F8BE` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Packed.VMProtect.AM suspicious application` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Kaspersky | `UDS:Backdoor.Win32.PMax` |
| Lionic | `Trojan.Win32.Sdum.4!c` |
| Malwarebytes | `Backdoor.Agent` |
| McAfeeD | `ti!C3413AD2671A` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Sdum!8.1155F (CLOUD)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| Zoner | `Probably Heur.ExeHeaderL` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |

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

- **exe** (48×)
- **elf** (31×)
- **RevStealer** (23×)
- **Mirai** (17×)
- **Torii** (12×)
- **honeypot** (10×)
- **python** (10×)
- **jar** (9×)
- **silentnet** (9×)
- **cowrie** (9×)
- **java** (8×)
- **Gafgyt** (6×)
- **Formbook** (6×)
- **signed** (6×)
- **ClickFix** (5×)

## Änderungen – 24h-Vergleich

- neu: **RevStealer** (23)
- ↓ **unbekannt** -36 (56→20)
- ↑ **Mirai** +13 (5→18)
- ↑ **Silentnet** +7 (1→8)
- ↑ **Formbook** +3 (3→6)
- ↑ **CoinMiner** +4 (1→5)
- neu: **Ngioweb** (3)
- neu: **WannaCry** (2)
- neu: **SilentNet** (2)
- weg: **RemcosRAT** (war 4)
- weg: **AsyncRAT** (war 2)
- weg: **XWorm** (war 3)
- weg: **WARDENStealer** (war 2)
- weg: **FunStealer** (war 5)

## Änderungen – 7d-Vergleich

- neu: **RevStealer** (23)
- ↓ **unbekannt** -15 (35→20)
- ↑ **Silentnet** +7 (1→8)
- ↑ **Formbook** +3 (3→6)
- ↑ **CoinMiner** +4 (1→5)
- neu: **Ngioweb** (3)
- neu: **WannaCry** (2)
- ↑ **SilentNet** +1 (1→2)
- ↑ **VShell** +1 (1→2)
- weg: **XWorm** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **WARDENStealer** (war 2)
- weg: **SalatStealer** (war 5)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.839 MB |
| σ Dateigröße | 5.423 MB |
| Ø Risiko-Score | 67.4/100 |
| Ø Klassifikations-Konfidenz | 69.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 30/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 10 (9.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:24 | [cd86aee4882b…](https://bazaar.abuse.ch/sample/cd86aee4882b93ccd3e993b9d8f12bd372640ed765893fcab27c5919d2f154d1/) | `zsh` | unbekannt | 81.7 | – | – | 🇺🇸US |
| 18:15 | [43fe9dde201a…](https://bazaar.abuse.ch/sample/43fe9dde201aa613382486afacd94af75cd45de3ee1aaa2a49442e850acd9da9/) | `exe` | WannaCry | 97.1 | – | – | 🇺🇸US |
| 17:47 | [a9a0525a0b82…](https://bazaar.abuse.ch/sample/a9a0525a0b826a517b19782d28ded1c0644b354386b007bea8f467e6ab80eb2d/) | `elf` | Mirai | 83.4 | – | – | 🇩🇪DE |
| 17:47 | [24058a81e1d7…](https://bazaar.abuse.ch/sample/24058a81e1d7507826ce3dfad1c6a26e8706af83234d4f4dd49e59b106696719/) | `ps1` | unbekannt | 38.0 | – | – | 🇺🇸US |
| 17:46 | [c6170759f9d3…](https://bazaar.abuse.ch/sample/c6170759f9d3b12082a496777dc6d42e08446d1b9a7a70f92b687271e2a0b807/) | `elf` | Mirai | 83.4 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 06.11.2026 19:03 UTC*