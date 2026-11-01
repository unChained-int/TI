# MalwareBazaar – 01.11.2026 08:54 UTC

Dieser Run hat **79 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **80** |
| Kritisch (≥75) | **36** |
| Höchster Score | **88.2/100** – 10102a03f78417f8… |
| Häufigste Familie | **unbekannt** (43x) |
| Häufigster Typ | **exe** (44x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 13 Samples |
| Ø Dateigröße | 3.44 MB (σ=5.90) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 44 | 55.0%  ███████████ |
| `macho` | 15 | 18.8%  ███ |
| `elf` | 12 | 15.0%  ███ |
| `vbs` | 2 | 2.5%   |
| `sh` | 2 | 2.5%   |
| `msi` | 2 | 2.5%   |
| `rtf` | 1 | 1.2%   |
| `hta` | 1 | 1.2%   |
| `bat` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 43 | 53.8% |
| 2 | Mirai | 11 | 13.8% |
| 3 | SalatStealer | 9 | 11.2% |
| 4 | PureRAT | 3 | 3.8% |
| 5 | AMOS | 3 | 3.8% |
| 6 | RustyStealer | 2 | 2.5% |
| 7 | VenomRAT | 1 | 1.2% |
| 8 | Trojan.GenericKD.81751028 | 1 | 1.2% |
| 9 | AsyncRAT | 1 | 1.2% |
| 10 | MSIL | 1 | 1.2% |
| 11 | ConnectWise | 1 | 1.2% |
| 12 | Amadey | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 21 | 26.2% | 35% |
| Infostealer | 17 | 21.2% | 78% |
| Loader | 14 | 17.5% | 76% |
| Botnet/IoT | 11 | 13.8% | 95% |
| RAT | 8 | 10.0% | 80% |
| Skript/Dropper | 3 | 3.8% | 35% |
| Trojaner | 2 | 2.5% | 65% |
| Linux-Malware | 1 | 1.2% | 45% |
| Maldoc | 1 | 1.2% | 35% |
| Backdoor | 1 | 1.2% | 65% |
| Andere / Unbekannt | 1 | 1.2% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 36 | 45.0% |
| 🟠 HOCH | 17 | 21.2% |
| 🟡 MITTEL | 24 | 30.0% |
| 🟢 NIEDRIG | 3 | 3.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [10102a03f78417…](https://bazaar.abuse.ch/sample/10102a03f78417f80f563e615ac7f1b8fbba2422ebda557f68d6263ad06dbd86/) | AsyncRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [42949634a09db0…](https://bazaar.abuse.ch/sample/42949634a09db058449c1c51a80ebfbad074ea1a6b6f14a583604a138a9f561b/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [1ec9297709a225…](https://bazaar.abuse.ch/sample/1ec9297709a225f912fc7145f43654bc1a6b61e56c9684bf22c6aaf0fad98289/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [95b3a52bad5da0…](https://bazaar.abuse.ch/sample/95b3a52bad5da0468d6af8a8c56e0ca7e307c2c0151f2531903e27c49458d308/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [95cca0c53fb872…](https://bazaar.abuse.ch/sample/95cca0c53fb872f2133364e7590d816a39983bf7aacab30768472cd45845ddfb/) | NanoCore | RAT | **85.1** | 🔴 KRITISCH | – | – | ? |
| [3e1225171d0414…](https://bazaar.abuse.ch/sample/3e1225171d0414feb8a4be697ce05b4875457187b558483399fcae0ed47d7c06/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [05ba0723c3c34f…](https://bazaar.abuse.ch/sample/05ba0723c3c34f246538bee06ac9d176051baa9b8ed7b22796cfa645ec97872f/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [92652da9820752…](https://bazaar.abuse.ch/sample/92652da982075237756afdec2a8208687acc2e12008acdddeebfe687377a12e1/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [51ca30c29c8d13…](https://bazaar.abuse.ch/sample/51ca30c29c8d13f9c4dc5d9db24665c93802b29c8cda6667e39f479494643ad3/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [c4baf48671c29f…](https://bazaar.abuse.ch/sample/c4baf48671c29fec17cb20bf6daf21583809b88936d7fc06ba6dec7eb2fbebb6/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6295/7765 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6295/7765 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6001/7765 |
| 6 | Kaspersky | 75.5% | 5864/7764 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5527/7761 |
| 9 | Rising | 68.3% | 5304/7765 |
| 10 | Varist | 66.2% | 5136/7760 |
| 11 | Avast | 65.2% | 5057/7761 |
| 12 | AVG | 65.2% | 5057/7760 |
| 13 | Tencent | 64.9% | 4895/7539 |
| 14 | McAfeeD | 61.4% | 4759/7757 |
| 15 | huorong | 60.9% | 4721/7757 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 50 | 62.5% |
| 🍎 macOS | 15 | 18.8% |
| 🐧 Linux | 14 | 17.5% |
| 📄 Dokument | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 62 | 77.5% |
| MaaS-Loader | 15 | 18.8% |
| Trojanisierte Software | 2 | 2.5% |
| Phishing / E-Mail-Anhang | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 33 | 41.2% |
| 2 | 🇫🇷 FR | 18 | 22.5% |
| 3 | 🇩🇪 DE | 14 | 17.5% |
| 4 | 🌐 DZ | 6 | 7.5% |
| 5 | 🇳🇱 NL | 5 | 6.2% |
| 6 | 🌐 Unbekannt | 2 | 2.5% |
| 7 | 🌐 PT | 2 | 2.5% |

## MITRE ATT&CK

> 13 von 80 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 11 |
| Lateral Movement | 11 |
| Execution | 2 |
| Command and Control | 1 |
| Persistence | 1 |

<details><summary>10102a03f78417f80f56… – AsyncRAT | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4d5aa53719682145cda2…](https://bazaar.abuse.ch/sample/4d5aa53719682145cda213e8b06ac483e7318c864d8c2bf951a19aa27fe74768/)

- **Familie:** Trojan.GenericKD.81751028
- **Erkannt von:** 53 von 75 Engines (70.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81751028
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81751028`

**Erkennende Engines (53/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81751028` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5957375` |
| Alibaba | `Trojan:Win64/GenKryptik.661c2764` |
| Antiy-AVL | `Trojan/Win64.GenKryptik` |
| Arcabit | `Trojan.Generic.D4DF6BF4` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.81751028` |
| Bkav | `W32.Malware.2EEC8810` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Siggen35.40474` |
| ESET-NOD32 | `Win64/TrojanDownloader.Agent.DTF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81751028 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| GData | `Trojan.GenericKD.81751028` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| K7AntiVirus | `Trojan ( 006e74e01 )` |
| K7GW | `Trojan ( 006e74e01 )` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Kingsoft | `Win32.Troj.Unknown.a` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Malware.AI.3262335159` |
| MaxSecure | `Trojan.Malware.698964193.susgen` |
| McAfeeD | `ti!4D5AA5371968` |
| MicroWorld-eScan | `Trojan.GenericKD.81751028` |
| Microsoft 🛡️ | `Trojan:Win32/Kepavll!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Dropper.Agent!8.2F (CLOUD)` |
| Sangfor | `Downloader.Win64.Agent.V2rb` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win64.Rootkit.dc` |
| Sophos | `Troj/DwnLd-AWP` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan.Win32.Agent.16006455` |
| TrellixENS | `Artemis!12E61BF5435A` |
| TrendMicro | `Trojan.Win32.GENKRYPTIKAGEN.USBLJ926` |
| TrendMicro-HouseCall | `Trojan.Win32.GENKRYPTIKAGEN.USBLJ926` |
| VBA32 | `Trojan.Wacatac` |
| VIPRE | `Trojan.GenericKD.81751028` |
| Varist | `W64/ABTrojan.JHKV-3664` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenKryptik_AGen!2/Vvlb49AsM` |
| Zillya | `Trojan.GenKryptikAGen.Win64.34473` |
| ZoneAlarm | `Troj/DwnLd-AWP` |
| alibabacloud | `Software:Win/GenKryptik_AGen.FJL` |
| huorong | `TrojanDropper/Agent.atq` |

### [b74fafdc709cf0a0bacc…](https://bazaar.abuse.ch/sample/b74fafdc709cf0a0baccd5b2660137ecef43e140d53cc2e970b08b71f95cfae5/)

- **Familie:** MSIL
- **Erkannt von:** 38 von 75 Engines (50.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Benin.5
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Benin.5`

**Erkennende Engines (38/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Spy]` |
| Arcabit | `Trojan.MSIL.Benin.5` |
| Avast | `Win32:MalwareX-gen [Spy]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Benin.5` |
| Bkav | `W32.Malware.7C51693B` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Loader.Generic-10060719-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Spy.PureLogs.A trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Benin.5 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| GData | `Gen:Heur.MSIL.Benin.5` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.MSIL.PureLogger` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.AsyncRat.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Malwarebytes | `Trojan.Crypt.MSIL.Generic` |
| McAfeeD | `Real Protect-LS!B59B699757B5` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Benin.5` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Rising | `Malware.Obfus/MSIL@AI.100 (RDM.MSIL2:35M6dNJ8YPK1CFyJm7K+4w)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `ML/PE-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `suspicious.low.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VIPRE | `Gen:Heur.MSIL.Benin.5` |
| Varist | `W32/MSIL_Kryptik.AFN.gen!Eldorado` |
| huorong | `Trojan/MSIL.Loader.bc` |
| tehtris | `Generic.Malware` |

### [c3137d7394274b81104b…](https://bazaar.abuse.ch/sample/c3137d7394274b81104bb6bd4943bb2265ca6373c8894a51e1c681e0d673634f/)

- **Familie:** VBS
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** BehavesLike.VBS.Backdoor.wv
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Skyhigh | `BehavesLike.VBS.Backdoor.wv` |

### [eaa1e4a9281a77116892…](https://bazaar.abuse.ch/sample/eaa1e4a9281a77116892f2ca249ac07f123a96a148afe2dbf1a9d3080fc834d6/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Gafgyt-DO [Trj]` |
| AhnLab-V3 | `Linux/Gafgyt01.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Gafgyt-DO [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-DO [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Gafgyt.WN!tr` |
| GData | `Linux.Trojan.Mirai.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GJ!MTB` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wam` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.AT.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.q` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Antiy-AVL | `Trojan/Win32.SalatStealer` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.62046A21` |
| CTX | `exe.trojan.lummastealer` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent.VO trojan` |
| Elastic | `Multi.Generic.Threat` |
| Emsisoft | `Trojan.LummaStealer.103 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `W32/Agent.VO!tr` |
| GData | `Trojan.LummaStealer.103` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **exe** (39×)
- **ClickFix** (15×)
- **Foxveil** (15×)
- **Mach-O** (15×)
- **macho** (15×)
- **macOS** (15×)
- **loader** (12×)
- **elf** (12×)
- **Mirai** (11×)
- **Torii** (8×)
- **SalatStealer** (8×)
- **signed** (5×)
- **upx-dec** (4×)
- **upx** (4×)
- **PureRAT** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +18 (25→43)
- ↓ **Mirai** -17 (28→11)
- ↑ **SalatStealer** +7 (2→9)
- neu: **PureRAT** (3)
- ↑ **AMOS** +2 (1→3)
- ↓ **RustyStealer** -1 (3→2)
- neu: **VenomRAT** (1)
- neu: **Trojan.GenericKD.81751028** (1)
- neu: **AsyncRAT** (1)
- neu: **MSIL** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +19 (24→43)
- ↓ **Mirai** -14 (25→11)
- ↓ **SalatStealer** -8 (17→9)
- neu: **PureRAT** (3)
- neu: **AMOS** (3)
- ↑ **RustyStealer** +1 (1→2)
- neu: **VenomRAT** (1)
- neu: **Trojan.GenericKD.81751028** (1)
- neu: **AsyncRAT** (1)
- neu: **MSIL** (1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.443 MB |
| σ Dateigröße | 5.902 MB |
| Ø Risiko-Score | 64.5/100 |
| Ø Klassifikations-Konfidenz | 65.2% |
| Samples mit VT | 5/80 |
| Samples mit MITRE | 13/80 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 39 |
| Unbekannte Familien | 1 (1.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:38 | [46b32e8232bd…](https://bazaar.abuse.ch/sample/46b32e8232bd0b359d3cdd5891c9030a58f0a949225cb3eba1b72014a034d5b3/) | `macho` | unbekannt | 74.9 | – | – | 🇺🇸US |
| 08:37 | [32da533a3e59…](https://bazaar.abuse.ch/sample/32da533a3e59d5b86c115b4302897f5d8a5d791b34f9deb2b933c3476979fcd1/) | `macho` | unbekannt | 74.9 | – | – | 🇺🇸US |
| 08:36 | [cd3569812aef…](https://bazaar.abuse.ch/sample/cd3569812aefac3396be7f11124c068e200dc83e7882832adf9161e7b2656f75/) | `macho` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 08:35 | [af95c361f4a0…](https://bazaar.abuse.ch/sample/af95c361f4a077a251c9879c2cbadd1394302db083b6753bba55784d792dcc2c/) | `macho` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 08:30 | [e9e8cbb6e60d…](https://bazaar.abuse.ch/sample/e9e8cbb6e60dec133269e83d5c9564b5fca8ff5293233ae2766bdfc1e17503d0/) | `macho` | unbekannt | 74.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 01.11.2026 08:54 UTC*