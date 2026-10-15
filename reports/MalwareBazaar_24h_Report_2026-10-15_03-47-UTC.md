# MalwareBazaar – 15.10.2026 03:47 UTC

Dieser Run hat **47 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **48** |
| Kritisch (≥75) | **28** |
| Höchster Score | **89.2/100** – 3b38f182ae0012ad… |
| Häufigste Familie | **Mirai** (22x) |
| Häufigster Typ | **elf** (34x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 25 Samples |
| Ø Dateigröße | 3.38 MB (σ=7.96) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 34 | 70.8%  ██████████████ |
| `exe` | 7 | 14.6%  ██ |
| `macho` | 5 | 10.4%  ██ |
| `js` | 1 | 2.1%   |
| `7z` | 1 | 2.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 22 | 45.8% |
| 2 | unbekannt | 16 | 33.3% |
| 3 | AMOS | 4 | 8.3% |
| 4 | AsyncRAT | 2 | 4.2% |
| 5 | RustyStealer | 1 | 2.1% |
| 6 | GCleaner | 1 | 2.1% |
| 7 | CatStorm | 1 | 2.1% |
| 8 | RemcosRAT | 1 | 2.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 22 | 45.8% | 95% |
| Linux-Malware | 11 | 22.9% | 45% |
| Infostealer | 5 | 10.4% | 91% |
| Loader | 3 | 6.2% | 75% |
| RAT | 3 | 6.2% | 95% |
| Andere / Unbekannt | 2 | 4.2% | 20% |
| Skript/Dropper | 1 | 2.1% | 35% |
| Cryptominer | 1 | 2.1% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 28 | 58.3% |
| 🟠 HOCH | 6 | 12.5% |
| 🟡 MITTEL | 12 | 25.0% |
| 🟢 NIEDRIG | 2 | 4.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3b38f182ae0012…](https://bazaar.abuse.ch/sample/3b38f182ae0012adbda7d6f396fa9c0265d0c8f6825ee13314e74397c21259f5/) | AMOS | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [5c5f5243923df0…](https://bazaar.abuse.ch/sample/5c5f5243923df0f7d0df186aea5e57a0afe61974d3b5661581658b041fc25985/) | AMOS | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [153ba36354b6be…](https://bazaar.abuse.ch/sample/153ba36354b6be51e389dc81643f6c5799c6a317ef115b0a56343042845e9ef2/) | AMOS | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [f3b1c6f4350d34…](https://bazaar.abuse.ch/sample/f3b1c6f4350d34063cd7b8ab8b255cd40ae6aebf4963aff71fcb3f96c3300000/) | AMOS | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [629a33ac1e45ae…](https://bazaar.abuse.ch/sample/629a33ac1e45aec4bed75114a4ef2d27f330305a1edcd77afc9301680cadfebb/) | AsyncRAT | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |
| [a54d0cb0a3296d…](https://bazaar.abuse.ch/sample/a54d0cb0a3296da690db7929453b676f1858c874dffacad7e79b29bad49d837a/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [348e4eb2a5f2c4…](https://bazaar.abuse.ch/sample/348e4eb2a5f2c4edd362558f292a571b270c220590fc9ad780f8e5a5efa5e62a/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [6e2c6c59045904…](https://bazaar.abuse.ch/sample/6e2c6c590459044f14284fd8fef7fbd4979620078820e3aa0c72d80b06799a10/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [4ec0c8d1d1d24e…](https://bazaar.abuse.ch/sample/4ec0c8d1d1d24ef725f9337683eecfd98402142ed043f5d857fb8b92eb39df3f/) | Mirai | Botnet/IoT | **82.2** | 🔴 KRITISCH | – | – | ? |
| [4887708f741e5b…](https://bazaar.abuse.ch/sample/4887708f741e5b210b72ac990581298e9c84c082da4c2174e7ceea8ebcc76f36/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5971/7381 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5971/7381 |
| 3 | ESET-NOD32 | 77.4% | 5715/7381 |
| 4 | Kaspersky | 76.4% | 5636/7380 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5282/7378 |
| 8 | Rising | 68.7% | 5074/7381 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4903/7377 |
| 11 | Tencent | 65.3% | 4674/7155 |
| 12 | Avast | 65.1% | 4799/7377 |
| 13 | AVG | 65.1% | 4799/7376 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4523/7374 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 34 | 70.8% |
| 🪟 Windows | 7 | 14.6% |
| 🍎 macOS | 5 | 10.4% |
| ❓ Unbekannt | 1 | 2.1% |
| 📦 Archiv | 1 | 2.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 40 | 83.3% |
| C2 / Nachladen | 4 | 8.3% |
| MaaS-Loader | 3 | 6.2% |
| Drive-By / Exploit-Kit | 1 | 2.1% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 32 | 66.7% |
| 2 | 🇺🇸 US | 12 | 25.0% |
| 3 | 🇨🇭 CH | 1 | 2.1% |
| 4 | 🌐 DK | 1 | 2.1% |
| 5 | 🇷🇺 RU | 1 | 2.1% |
| 6 | 🌐 Unbekannt | 1 | 2.1% |

## MITRE ATT&CK

> 25 von 48 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 22 |
| Lateral Movement | 22 |
| Command and Control | 3 |
| Execution | 2 |
| Collection | 1 |

<details><summary>629a33ac1e45aec4bed7… – AsyncRAT | 🔴 KRITISCH 87.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9cd6656e9d40aa6c49c0…](https://bazaar.abuse.ch/sample/9cd6656e9d40aa6c49c0fa7918837e807676d91c99727f9ad710d99c85b5b5c6/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Tsunami.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Tsunami.5`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Tsunami.5` |
| AVG | `ELF:Mirai-BJI [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Tsunami.5` |
| Avast | `ELF:Mirai-BJI [Trj]` |
| Avast-Mobile | `ELF:Mirai-BJI [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Tsunami.5` |
| CTX | `elf.unknown.tsunami` |
| ClamAV | `Unix.Dropper.Mirai-7135928-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| Emsisoft | `Gen:Variant.Linux.Tsunami.5 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.hv` |
| MicroWorld-eScan | `Gen:Variant.Linux.Tsunami.5` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| VIPRE | `Gen:Variant.Linux.Tsunami.5` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.l` |

### [fd50b29196735ec9680a…](https://bazaar.abuse.ch/sample/fd50b29196735ec9680a0f9c8b1c6c49e9bfaf6a98614705751620852ab75d8d/)

- **Familie:** AsyncRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** IL:Trojan.AsyncRAT.AD
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `IL:Trojan.AsyncRAT.AD`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `IL:Trojan.AsyncRAT.AD` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Drp]` |
| AhnLab-V3 | `Trojan/Win32.AsyncRAT.C3502839` |
| Alibaba | `Backdoor:MSIL/AsyncRAT.f2d439a1` |
| Antiy-AVL | `Trojan[Backdoor]/MSIL.Crysan` |
| Arcabit | `IL:Trojan.AsyncRAT.AD` |
| Avast | `Win32:MalwareX-gen [Drp]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `IL:Trojan.AsyncRAT.AD` |
| Bkav | `W32.Malware.5FF5AD65` |
| CAT-QuickHeal | `Trojan.WacatacFC.S12095901` |
| CTX | `exe.trojan.msil` |
| ClamAV | `Win.Packed.Razy-7486442-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.DownLoader31.47047` |
| ESET-NOD32 | `MSIL/AsyncRAT.A trojan` |
| Elastic | `Windows.Generic.Threat` |
| Emsisoft | `IL:Trojan.AsyncRAT.AD (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/AsyncRAT.A!tr` |
| GData | `MSIL.Trojan.PSE.16I8278` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Wacatac.oa!s2` |
| Ikarus | `Trojan.MSIL.AsyncRAT` |
| Jiangmin | `Backdoor.MSIL.cicp` |
| K7AntiVirus | `Trojan ( 005c228f1 )` |
| K7GW | `Trojan ( 005c228f1 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.Crysan.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.AsyncRAT.m!c` |
| Malwarebytes | `Backdoor.AsyncRAT` |
| MaxSecure | `Trojan.Malware.74418669.susgen` |
| McAfeeD | `Trojan:Win/Generic.BCX` |
| MicroWorld-eScan | `IL:Trojan.AsyncRAT.AD` |
| Microsoft 🛡️ | `Trojan:MSIL/CoinMiner` |
| NANO-Antivirus | `Trojan.Win32.AsyncRAT.lihgnp` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Trojan.AntiVM!1.CF63 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Kryptik` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Packed-FXY!3BA1D62B27D6` |
| Sophos | `Troj/AsyncRat-C` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.AsyncRAT.ha` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Packed-FXY!3BA1D62B27D6` |
| TrendMicro | `TrojanSpy.MSIL.MALXMR.USBLJE26` |
| TrendMicro-HouseCall | `Coinminer.MSIL.CRYSAN.SM` |
| VBA32 | `OScope.Backdoor.MSIL.Crysan` |
| VIPRE | `IL:Trojan.AsyncRAT.AD` |
| Varist | `W32/Samas.B.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Asyncrat.49664.CQ` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Webroot | `W32.Trojan.Gen` |
| ZoneAlarm | `Troj/AsyncRat-C` |
| alibabacloud | `Rat:Win/AsyncRAT.Stub` |
| huorong | `Trojan/MSIL.Autorun.a` |

### [9708e6d856be479b46c5…](https://bazaar.abuse.ch/sample/9708e6d856be479b46c5b97124f8ae7037b23ab21706a917fdde3b2dbf2a1a27/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Tsunami.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Tsunami.5`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Tsunami.5` |
| AVG | `ELF:Mirai-BJI [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Tsunami.5` |
| Avast | `ELF:Mirai-BJI [Trj]` |
| Avast-Mobile | `ELF:Mirai-BJI [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Tsunami.5` |
| CTX | `elf.unknown.tsunami` |
| ClamAV | `Unix.Dropper.Mirai-7135928-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| Emsisoft | `Gen:Variant.Linux.Tsunami.5 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.hv` |
| MicroWorld-eScan | `Gen:Variant.Linux.Tsunami.5` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| VIPRE | `Gen:Variant.Linux.Tsunami.5` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.l` |

### [dad102989b34414e4e3b…](https://bazaar.abuse.ch/sample/dad102989b34414e4e3bbd4b311972a80bb0fffbc526b90a17d52266724ee8e8/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CYJ [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CYJ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CYJ [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Linux/Mirai.EQY` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

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
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (34×)
- **Mirai** (22×)
- **exe** (6×)
- **AMOS** (5×)
- **ClickFix** (5×)
- **Foxveil** (5×)
- **Mach-O** (5×)
- **macho** (5×)
- **macOS** (5×)
- **dropped-by-GCleaner** (4×)
- **F** (3×)
- **loader** (3×)
- **MIX2.file** (2×)
- **AsyncRAT** (2×)
- **Gafgyt** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -5 (27→22)
- ↓ **unbekannt** -16 (32→16)
- ↑ **AMOS** +2 (2→4)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **RustyStealer** (1)
- neu: **GCleaner** (1)
- neu: **CatStorm** (1)
- ↓ **RemcosRAT** -3 (4→1)
- weg: **Formbook** (war 4)
- weg: **Vidar** (war 2)
- weg: **DCRat** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **RemusStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -16 (38→22)
- ↓ **unbekannt** -13 (29→16)
- ↑ **AMOS** +3 (1→4)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **RustyStealer** (1)
- neu: **GCleaner** (1)
- neu: **CatStorm** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.383 MB |
| σ Dateigröße | 7.956 MB |
| Ø Risiko-Score | 68.3/100 |
| Ø Klassifikations-Konfidenz | 77.1% |
| Samples mit VT | 5/48 |
| Samples mit MITRE | 25/48 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 29 |
| Unbekannte Familien | 2 (4.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:44 | [a9cd105e5cdf…](https://bazaar.abuse.ch/sample/a9cd105e5cdf8b3cafb0fe9ffb886ab7becd7dbafa7c4cf0ce214d2d5e5686c8/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 03:43 | [cee4690dbf65…](https://bazaar.abuse.ch/sample/cee4690dbf65dd7af76498a0486ce6ad3541fac4a9f73e8aa8500b10618737f0/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 03:07 | [2b02bf4c5b12…](https://bazaar.abuse.ch/sample/2b02bf4c5b127e2838522dd60481e99eafd667c383807604648618d9a21d6818/) | `exe` | RustyStealer | 81.6 | – | – | 🇺🇸US |
| 02:23 | [9cd6656e9d40…](https://bazaar.abuse.ch/sample/9cd6656e9d40aa6c49c0fa7918837e807676d91c99727f9ad710d99c85b5b5c6/) | `elf` | Mirai | 77.1 | 41.3% | 🟠 MÄSSIG ERKANNT | 🇩🇪DE |
| 02:02 | [4ea545bd4a77…](https://bazaar.abuse.ch/sample/4ea545bd4a77d715f0d67c223165b8558c413215300dd3c7704aa0b5d99e0cae/) | `elf` | unbekannt | 41.8 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.10.2026 03:47 UTC*