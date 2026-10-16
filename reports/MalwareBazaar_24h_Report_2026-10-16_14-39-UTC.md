# MalwareBazaar – 16.10.2026 14:39 UTC

Dieser Run hat **65 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **66** |
| Kritisch (≥75) | **30** |
| Höchster Score | **94.4/100** – 78e25638e490f326… |
| Häufigste Familie | **unbekannt** (33x) |
| Häufigster Typ | **exe** (20x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 25 Samples |
| Ø Dateigröße | 4.11 MB (σ=12.80) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 20 | 30.3%  ██████ |
| `elf` | 18 | 27.3%  █████ |
| `hta` | 8 | 12.1%  ██ |
| `msi` | 4 | 6.1%  █ |
| `sh` | 4 | 6.1%  █ |
| `js` | 3 | 4.5%   |
| `ps1` | 2 | 3.0%   |
| `wsf` | 2 | 3.0%   |
| `apk` | 1 | 1.5%   |
| `zip` | 1 | 1.5%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 33 | 50.0% |
| 2 | Mirai | 14 | 21.2% |
| 3 | RemcosRAT | 3 | 4.5% |
| 4 | Formbook | 3 | 4.5% |
| 5 | AsyncRAT | 2 | 3.0% |
| 6 | RevStealer | 2 | 3.0% |
| 7 | RemusStealer | 1 | 1.5% |
| 8 | VShell | 1 | 1.5% |
| 9 | ValleyRAT | 1 | 1.5% |
| 10 | MassLogger | 1 | 1.5% |
| 11 | WannaCry | 1 | 1.5% |
| 12 | FileRepMalware [Misc] | 1 | 1.5% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 14 | 21.2% | 95% |
| Skript/Dropper | 11 | 16.7% | 35% |
| Windows-Malware | 10 | 15.2% | 35% |
| RAT | 8 | 12.1% | 90% |
| Infostealer | 7 | 10.6% | 82% |
| Andere / Unbekannt | 5 | 7.6% | 20% |
| Loader | 4 | 6.1% | 75% |
| Linux-Malware | 3 | 4.5% | 45% |
| Trojaner | 2 | 3.0% | 70% |
| Cryptominer | 1 | 1.5% | 75% |
| Ransomware | 1 | 1.5% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 30 | 45.5% |
| 🟠 HOCH | 7 | 10.6% |
| 🟡 MITTEL | 24 | 36.4% |
| 🟢 NIEDRIG | 5 | 7.6% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [78e25638e490f3…](https://bazaar.abuse.ch/sample/78e25638e490f326551d803a608c0df0f7e5af2747f124078237301737f63b2b/) | WannaCry | Ransomware | **94.4** | 🔴 KRITISCH | – | – | ? |
| [32dcaf5c4f41db…](https://bazaar.abuse.ch/sample/32dcaf5c4f41dbdaddeee5fd64dacb290f81655a37ea10beaeca1a369a80c7f0/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [ebb2f6d9ee6731…](https://bazaar.abuse.ch/sample/ebb2f6d9ee6731d87d430b7c9114d4fa02ffb5adba565da3ffda7cca0afb2353/) | AsyncRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [079ed8a3888c79…](https://bazaar.abuse.ch/sample/079ed8a3888c7976c6ab214f13bb615205f8c48d33267078089f67bff660180f/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [9416bdf770137a…](https://bazaar.abuse.ch/sample/9416bdf770137a32ac6c37eb44093f37196b773afb3fcc9b88acb14682067f79/) | Formbook | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [caf71ad07536d0…](https://bazaar.abuse.ch/sample/caf71ad07536d045b05008c24a5a70f82b64a1a47040564df40df94499d3883f/) | Formbook | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [b08bff811d20fb…](https://bazaar.abuse.ch/sample/b08bff811d20fb95abbb8a09175f33a749c1dff6967b86e583ba5f5ee08872e5/) | RemcosRAT | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [843cdaf3fd24c4…](https://bazaar.abuse.ch/sample/843cdaf3fd24c4c227f37b0ac5dc69ee66e06b3e346cb45b99c11baf81c36a10/) | AsyncRAT | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [24294bb46842f0…](https://bazaar.abuse.ch/sample/24294bb46842f08d3f37989de1f47d0aef9eaffa1fc9eea3ceda173702978641/) | NetSupport | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [720ab5b6160394…](https://bazaar.abuse.ch/sample/720ab5b61603944d0ab6022de5e531ddc42191f2bcb2d93f6942e17bc892cb51/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5999/7416 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5999/7416 |
| 3 | ESET-NOD32 | 77.4% | 5743/7416 |
| 4 | Kaspersky | 76.3% | 5661/7415 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5302/7413 |
| 8 | Rising | 68.7% | 5098/7416 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4925/7412 |
| 11 | Tencent | 65.3% | 4697/7190 |
| 12 | Avast | 65.1% | 4827/7412 |
| 13 | AVG | 65.1% | 4827/7411 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4545/7409 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 34 | 51.5% |
| 🐧 Linux | 23 | 34.8% |
| ❓ Unbekannt | 7 | 10.6% |
| 🤖 Android | 1 | 1.5% |
| 📦 Archiv | 1 | 1.5% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 51 | 77.3% |
| C2 / Nachladen | 5 | 7.6% |
| Drive-By / Exploit-Kit | 4 | 6.1% |
| Trojanisierte Software | 4 | 6.1% |
| APK-Sideloading | 1 | 1.5% |
| Exploit / N-Day | 1 | 1.5% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 23 | 34.8% |
| 2 | 🇺🇸 US | 14 | 21.2% |
| 3 | 🇳🇱 NL | 13 | 19.7% |
| 4 | 🇭🇺 HU | 10 | 15.2% |
| 5 | 🇨🇭 CH | 3 | 4.5% |
| 6 | 🇧🇷 BR | 2 | 3.0% |
| 7 | 🌐 Unbekannt | 1 | 1.5% |

## MITRE ATT&CK

> 25 von 66 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Collection | 7 |
| Command and Control | 6 |
| Execution | 3 |
| Credential Access | 3 |
| Impact | 1 |
| Persistence | 1 |

<details><summary>32dcaf5c4f41dbdaddee… – RemcosRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>ebb2f6d9ee6731d87d43… – AsyncRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>079ed8a3888c7976c6ab… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>9416bdf770137a32ac6c… – Formbook | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4474e4c5b8eac1a198cf…](https://bazaar.abuse.ch/sample/4474e4c5b8eac1a198cf4dc95f48321710a53ba6a91182d91ff8581c05fd9b1d/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.F26A871F` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (high confidence)` |
| Malwarebytes | `Malware.AI.2689162386` |
| McAfeeD | `ti!4474E4C5B8EA` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Webroot | `Win.Trojan.Gen` |

### [39c420634bccc77b6ba9…](https://bazaar.abuse.ch/sample/39c420634bccc77b6ba9cccf6302c171c19fded3ec7491d5ba969809d14b134d/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [4b30b77b7862debf1288…](https://bazaar.abuse.ch/sample/4b30b77b7862debf12885536085528d0f7ca69e2a0a86d7b04c9427bd06c22e0/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [4aa8b661bffc46d90a56…](https://bazaar.abuse.ch/sample/4aa8b661bffc46d90a56bc2da15dda5fc02c97d4c37bf653ff5f08f8804862d8/)

- **Familie:** FormBook
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.FormBook.891
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.FormBook.891`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.FormBook.891` |
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Arcabit | `Trojan.FormBook.891` |
| Avast | `MalwareX-gen [Drp]` |
| BitDefender 🛡️ | `Gen:Variant.FormBook.891` |
| Bkav | `W32.Malware.4A8B43C9` |
| CTX | `exe.unknown.formbook` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.ANRB trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.FormBook.891 (B)` |
| Fortinet | `MSIL/Nekark.TIYVL!tr` |
| GData | `Gen:Variant.FormBook.891` |
| Kaspersky | `UDS:Trojan-Spy.MSIL.Noon.gen` |
| Kingsoft | `MSIL.Trojan-Spy.Noon.gen` |
| Malwarebytes | `Malware.AI.2069472421` |
| McAfeeD | `Real Protect-LS!3F6841E24E20` |
| MicroWorld-eScan | `Gen:Variant.FormBook.891` |
| Microsoft 🛡️ | `Trojan:Win32/Sonbokli.A!cl` |
| Paloalto | `generic.ml` |
| Rising | `Malware.Obfus/MSIL@AI.97 (RDM.MSIL2:iHkLzkqaZlVNok1w7Odabg)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Msil.Trojan.Kryptik.Jqil` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| VIPRE | `Gen:Variant.FormBook.891` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |

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

- **exe** (19×)
- **Mirai** (14×)
- **elf** (12×)
- **hta** (8×)
- **dropped-by-GCleaner** (4×)
- **msi** (4×)
- **signed** (3×)
- **js** (3×)
- **upx-dec** (3×)
- **upx** (3×)
- **U** (3×)
- **UNIQ.file** (3×)
- **Formbook** (3×)
- **RemcosRAT** (2×)
- **AsyncRAT** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +9 (24→33)
- ↓ **Mirai** -1 (15→14)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **Formbook** +1 (2→3)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **RevStealer** (2)
- neu: **VShell** (1)
- neu: **MassLogger** (1)
- weg: **DDoSAgent** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +5 (28→33)
- ↓ **Mirai** -18 (32→14)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **Formbook** +1 (2→3)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **RevStealer** (2)
- neu: **MassLogger** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.111 MB |
| σ Dateigröße | 12.803 MB |
| Ø Risiko-Score | 61.4/100 |
| Ø Klassifikations-Konfidenz | 63.7% |
| Samples mit VT | 5/66 |
| Samples mit MITRE | 25/66 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 5 (7.6%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:37 | [d3ac1e52b34c…](https://bazaar.abuse.ch/sample/d3ac1e52b34c67274f000880489a6318ff771b747e524c66a8766bfc2648f2ea/) | `hta` | unbekannt | 39.1 | – | – | 🇩🇪DE |
| 14:35 | [720ab5b61603…](https://bazaar.abuse.ch/sample/720ab5b61603944d0ab6022de5e531ddc42191f2bcb2d93f6942e17bc892cb51/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 14:23 | [ae60900bdab2…](https://bazaar.abuse.ch/sample/ae60900bdab2138230f1908ca57faa66052de78c3a2f99213662be20dfab44cb/) | `hta` | unbekannt | 38.9 | – | – | 🇩🇪DE |
| 14:19 | [6107eb831d4f…](https://bazaar.abuse.ch/sample/6107eb831d4fe329c38dfd958e0ea66f1439bc6fba9b41914bdda8ad04af0eea/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 14:05 | [e8ffb03941b8…](https://bazaar.abuse.ch/sample/e8ffb03941b8101c814d2e6e1641f14595075ff5f0b481da5ed7f79f0f4813a8/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.10.2026 14:39 UTC*