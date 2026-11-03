# MalwareBazaar – 03.11.2026 03:21 UTC

Dieser Run hat **81 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **82** |
| Kritisch (≥75) | **33** |
| Höchster Score | **95.5/100** – 40bd526a2b04656e… |
| Häufigste Familie | **unbekannt** (44x) |
| Häufigster Typ | **exe** (41x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 14 Samples |
| Ø Dateigröße | 4.28 MB (σ=6.20) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 41 | 50.0%  ██████████ |
| `macho` | 17 | 20.7%  ████ |
| `elf` | 9 | 11.0%  ██ |
| `sh` | 4 | 4.9%   |
| `msi` | 3 | 3.7%   |
| `jar` | 2 | 2.4%   |
| `vbs` | 2 | 2.4%   |
| `js` | 1 | 1.2%   |
| `dll` | 1 | 1.2%   |
| `apk` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 44 | 53.7% |
| 2 | Mirai | 9 | 11.0% |
| 3 | SalatStealer | 6 | 7.3% |
| 4 | ConnectWise | 6 | 7.3% |
| 5 | WARDENStealer | 4 | 4.9% |
| 6 | VShell | 3 | 3.7% |
| 7 | RustyStealer | 2 | 2.4% |
| 8 | AsyncRAT | 2 | 2.4% |
| 9 | Silentnet | 1 | 1.2% |
| 10 | WannaCry | 1 | 1.2% |
| 11 | Gh0stRAT | 1 | 1.2% |
| 12 | AokigaharaStealer | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 22 | 26.8% | 35% |
| Infostealer | 17 | 20.7% | 75% |
| Loader | 12 | 14.6% | 75% |
| Botnet/IoT | 9 | 11.0% | 95% |
| Andere / Unbekannt | 9 | 11.0% | 20% |
| RAT | 5 | 6.1% | 87% |
| Linux-Malware | 2 | 2.4% | 45% |
| Skript/Dropper | 2 | 2.4% | 35% |
| Trojaner | 2 | 2.4% | 70% |
| Ransomware | 1 | 1.2% | 95% |
| Backdoor | 1 | 1.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 33 | 40.2% |
| 🟠 HOCH | 14 | 17.1% |
| 🟡 MITTEL | 22 | 26.8% |
| 🟢 NIEDRIG | 13 | 15.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [40bd526a2b0465…](https://bazaar.abuse.ch/sample/40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57/) | WannaCry | Ransomware | **95.5** | 🔴 KRITISCH | – | – | ? |
| [276f8d720e1a7c…](https://bazaar.abuse.ch/sample/276f8d720e1a7c9c767dc1fe98528717c5508e36cdd4ae4cf3ddb08378f46317/) | Gh0stRAT | Backdoor | **90.3** | 🔴 KRITISCH | – | – | ? |
| [f5ee612748cedf…](https://bazaar.abuse.ch/sample/f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be/) | AsyncRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [7bcdc594eb3d76…](https://bazaar.abuse.ch/sample/7bcdc594eb3d76d271007ac5fcc2603f03e65553b533a7c0a5d1ab89c8a6d247/) | AsyncRAT | RAT | **85.2** | 🔴 KRITISCH | – | – | ? |
| [5699f25feac04e…](https://bazaar.abuse.ch/sample/5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [1f6bf76318997e…](https://bazaar.abuse.ch/sample/1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [34f608eba7b1d9…](https://bazaar.abuse.ch/sample/34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [3893fa3da89174…](https://bazaar.abuse.ch/sample/3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [a6447a059d57eb…](https://bazaar.abuse.ch/sample/a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [cca1ee815fea88…](https://bazaar.abuse.ch/sample/cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6316/7793 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6316/7793 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6021/7793 |
| 6 | Kaspersky | 75.5% | 5882/7792 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5547/7789 |
| 9 | Rising | 68.3% | 5320/7793 |
| 10 | Varist | 66.2% | 5153/7788 |
| 11 | Avast | 65.1% | 5071/7789 |
| 12 | AVG | 65.1% | 5071/7788 |
| 13 | Tencent | 64.9% | 4912/7567 |
| 14 | McAfeeD | 61.3% | 4776/7785 |
| 15 | huorong | 60.9% | 4738/7785 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 44 | 53.7% |
| 🍎 macOS | 17 | 20.7% |
| 🐧 Linux | 16 | 19.5% |
| ❓ Unbekannt | 3 | 3.7% |
| 🤖 Android | 1 | 1.2% |
| 📦 Archiv | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 64 | 78.0% |
| MaaS-Loader | 12 | 14.6% |
| Trojanisierte Software | 3 | 3.7% |
| Drive-By / Exploit-Kit | 1 | 1.2% |
| Exploit / N-Day | 1 | 1.2% |
| APK-Sideloading | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 43 | 52.4% |
| 2 | 🇫🇷 FR | 19 | 23.2% |
| 3 | 🇭🇺 HU | 6 | 7.3% |
| 4 | 🇩🇪 DE | 5 | 6.1% |
| 5 | 🇦🇹 AT | 3 | 3.7% |
| 6 | 🇳🇱 NL | 2 | 2.4% |
| 7 | 🇬🇧 GB | 1 | 1.2% |
| 8 | 🇨🇭 CH | 1 | 1.2% |
| 9 | 🇧🇷 BR | 1 | 1.2% |
| 10 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 14 von 82 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 9 |
| Lateral Movement | 9 |
| Credential Access | 3 |
| Collection | 3 |
| Exfiltration | 3 |
| Command and Control | 2 |
| Execution | 2 |

<details><summary>f5ee612748cedfd68340… – AsyncRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>7bcdc594eb3d76d27100… – AsyncRAT | 🔴 KRITISCH 85.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>5699f25feac04e73dbc1… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5443928a7d2098008bcc…](https://bazaar.abuse.ch/sample/5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646/)

- **Familie:** SalatStealer
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Dump:Generic.Dacic.18086.7A2E2D2A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Dump:Generic.Dacic.18086.7A2E2D2A` |
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.Generic.R798322` |
| Antiy-AVL | `Trojan/Win64.Kryptik` |
| Arcabit | `Dump:Generic.Dacic.18086.7A2E2D2A` |
| Avira | `TR/Crypt.ULPM.Gen` |
| Bkav | `W32.Malware.D6183FDE` |
| CTX | `exe.unknown.dacic` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Dump:Generic.Dacic.18086.7A2E2D2A (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| GData | `Dump:Generic.Dacic.18086.7A2E2D2A` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 006e163e1 )` |
| K7GW | `Trojan ( 006e163e1 )` |
| Malwarebytes | `Malware.AI.907022008` |
| McAfeeD | `ti!5443928A7D20` |
| MicroWorld-eScan | `Dump:Generic.Dacic.18086.7A2E2D2A` |
| Panda | `Trj/GdSda.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.11e65d7c` |
| VIPRE | `Dump:Generic.Dacic.18086.7A2E2D2A` |
| huorong | `Trojan/Agent.e!crit` |

### [e7439226c3569d26c7c1…](https://bazaar.abuse.ch/sample/e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d/)

- **Familie:** RustyStealer
- **Erkannt von:** 45 von 75 Engines (60.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81982291
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81982291`

**Erkennende Engines (45/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81982291` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R766321` |
| Alibaba | `Trojan:Win64/GenKryptik.34cc9e08` |
| Arcabit | `Trojan.Generic.D4E2F353` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Trojan.GenericKD.81982291` |
| Bkav | `W32.Malware.E738FD37` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop43.22004` |
| ESET-NOD32 | `Win64/GenKryptik.HWLO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81982291 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| GData | `Trojan.GenericKD.81982291` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Heur!.02012423` |
| Ikarus | `Trojan.Win64.Crypt` |
| K7AntiVirus | `Trojan ( 006e9b8d1 )` |
| K7GW | `Trojan ( 006e9b8d1 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| MaxSecure | `Trojan.Malware.698869727.susgen` |
| McAfeeD | `ti!E7439226C356` |
| MicroWorld-eScan | `Trojan.GenericKD.81982291` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik@AI.95 (RDML:tjLvaP/30NjHHe4Mse0fXg)` |
| Sangfor | `Trojan.Win32.Kryptik.Vur0` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.W64.Tsmw` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Artemis!056736CB92EF` |
| TrendMicro | `Trojan.Win32.GENKRYPTIK.USBLJU26` |
| TrendMicro-HouseCall | `Trojan.Win32.GENKRYPTIK.USBLJU26` |
| VIPRE | `Trojan.GenericKD.81982291` |
| Varist | `W64/ABTrojan.XFOV-8077` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |

### [a5417734311232461428…](https://bazaar.abuse.ch/sample/a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac/)

- **Familie:** ConnectWise
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.BFC0012A` |
| Cylance | `Unsafe` |
| DrWeb | `Trojan.MulDrop32.9992` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Backdoor.EvilConwi.A` |
| Google | `Detected` |
| Ikarus | `PUA.ClientConnect` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kaspersky | `not-a-virus:UDS:RemoteAdmin.MSIL.ConnectWise.gen` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| Rising | `Hacktool.ConnectWise!8.13A88 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win32.ScreenConnect.tc` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrellixENS | `PUP-IPR` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.PSWStealer.DIL` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| huorong | `HackTool/ConnectWiseControl.i` |

### [0da518a8446bf832d527…](https://bazaar.abuse.ch/sample/0da518a8446bf832d527a9859d96753b6740f9ae1991e0ca72c928f3fc46dec7/)

- **Familie:** Malware
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.5726D597
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.5726D597` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Vidar.AAR!tr` |
| Google | `Detected` |
| Kaspersky | `VHO:Trojan-PSW.Win32.Agent.gen` |
| McAfeeD | `ti!0DA518A8446B` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 56 von 75 Engines (74.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:MSIL/Nanocore!atmn`

**Erkennende Engines (56/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
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
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (41×)
- **macho** (17×)
- **ClickFix** (14×)
- **Foxveil** (13×)
- **Mach-O** (13×)
- **macOS** (13×)
- **loader** (12×)
- **signed** (10×)
- **Mirai** (9×)
- **SalatStealer** (6×)
- **ConnectWise** (6×)
- **elf** (4×)
- **stealer** (4×)
- **WARDENStealer** (4×)
- **Stealer** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +19 (25→44)
- ↓ **Mirai** -10 (19→9)
- ↑ **SalatStealer** +3 (3→6)
- ↑ **ConnectWise** +4 (2→6)
- neu: **WARDENStealer** (4)
- neu: **RustyStealer** (2)
- neu: **AsyncRAT** (2)
- neu: **Silentnet** (1)
- neu: **WannaCry** (1)
- weg: **RemcosRAT** (war 10)
- weg: **Formbook** (war 8)
- weg: **AgentTesla** (war 10)
- weg: **GuLoader** (war 5)
- weg: **XWorm** (war 4)
- weg: **DonutLoader** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +17 (27→44)
- ↓ **Mirai** -16 (25→9)
- ↓ **SalatStealer** -7 (13→6)
- ↑ **ConnectWise** +5 (1→6)
- neu: **WARDENStealer** (4)
- neu: **VShell** (3)
- ↑ **RustyStealer** +1 (1→2)
- neu: **AsyncRAT** (2)
- neu: **Silentnet** (1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.279 MB |
| σ Dateigröße | 6.199 MB |
| Ø Risiko-Score | 60.1/100 |
| Ø Klassifikations-Konfidenz | 59.8% |
| Samples mit VT | 5/82 |
| Samples mit MITRE | 14/82 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 9 (11.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:14 | [5443928a7d20…](https://bazaar.abuse.ch/sample/5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646/) | `exe` | SalatStealer | 77.1 | 40.0% | 🟠 MÄSSIG ERKANNT | 🇺🇸US |
| 02:54 | [c3b67f17b19f…](https://bazaar.abuse.ch/sample/c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3/) | `exe` | VShell | 38.7 | – | – | 🇺🇸US |
| 02:50 | [e7439226c356…](https://bazaar.abuse.ch/sample/e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d/) | `exe` | RustyStealer | 71.8 | 60.0% | 🟠 MÄSSIG ERKANNT | 🇺🇸US |
| 02:49 | [02b2f61aa7a3…](https://bazaar.abuse.ch/sample/02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814/) | `exe` | RustyStealer | 81.8 | – | – | 🇺🇸US |
| 02:19 | [5699f25feac0…](https://bazaar.abuse.ch/sample/5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b/) | `elf` | Mirai | 83.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 03.11.2026 03:21 UTC*