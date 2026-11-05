# MalwareBazaar – 05.11.2026 05:45 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **52** |
| Höchster Score | **94.2/100** – 092dd2e5365b858d… |
| Häufigste Familie | **unbekannt** (56x) |
| Häufigster Typ | **exe** (60x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 12 Samples |
| Ø Dateigröße | 6.28 MB (σ=11.91) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 60 | 59.4%  ███████████ |
| `macho` | 27 | 26.7%  █████ |
| `zip` | 4 | 4.0%   |
| `msi` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |
| `js` | 1 | 1.0%   |
| `elf` | 1 | 1.0%   |
| `iso` | 1 | 1.0%   |
| `vbs` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 56 | 55.4% |
| 2 | SalatStealer | 21 | 20.8% |
| 3 | Arechclient2 | 4 | 4.0% |
| 4 | WARDENStealer | 3 | 3.0% |
| 5 | VShell | 2 | 2.0% |
| 6 | RemusStealer | 2 | 2.0% |
| 7 | NetSupport | 2 | 2.0% |
| 8 | RemcosRAT | 1 | 1.0% |
| 9 | Mirai | 1 | 1.0% |
| 10 | ConnectWise | 1 | 1.0% |
| 11 | Trojan.GenericKD.82029581 | 1 | 1.0% |
| 12 | CoinMiner | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 39 | 38.6% | 75% |
| Andere / Unbekannt | 23 | 22.8% | 20% |
| Windows-Malware | 14 | 13.9% | 35% |
| Loader | 10 | 9.9% | 75% |
| RAT | 9 | 8.9% | 84% |
| Backdoor | 2 | 2.0% | 75% |
| Trojaner | 2 | 2.0% | 65% |
| Botnet/IoT | 1 | 1.0% | 95% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 52 | 51.5% |
| 🟠 HOCH | 12 | 11.9% |
| 🟡 MITTEL | 14 | 13.9% |
| 🟢 NIEDRIG | 23 | 22.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [092dd2e5365b85…](https://bazaar.abuse.ch/sample/092dd2e5365b858d6bd6b3c16089752e85ee7f79056f95f6ebc4ce085f7f4b62/) | WannaCry | Ransomware | **94.2** | 🔴 KRITISCH | – | – | ? |
| [8561ec7bffde32…](https://bazaar.abuse.ch/sample/8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1/) | RemcosRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [550fe7647faf8d…](https://bazaar.abuse.ch/sample/550fe7647faf8dd9c0c5166c785fdc754ac444ad3f948eafcbe28a55bfca7cab/) | NetSupport | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [bc020b95fc01fa…](https://bazaar.abuse.ch/sample/bc020b95fc01fae40e13f429eaddeac6c08755399d96d06e9dbea22114eb595c/) | NetSupport | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [62a18370ac8531…](https://bazaar.abuse.ch/sample/62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [f7237fdb6fb019…](https://bazaar.abuse.ch/sample/f7237fdb6fb01955ed81c50b3b9d52169fd9dba03f03c14c6ee14f66a92bf34c/) | unbekannt | Backdoor | **82.0** | 🔴 KRITISCH | – | – | ? |
| [ecef5317df8b01…](https://bazaar.abuse.ch/sample/ecef5317df8b014e1581d7a4e819c3290c846fac20a0423846f1081071c7304d/) | unbekannt | Backdoor | **82.0** | 🔴 KRITISCH | – | – | ? |
| [3f8bcc5070ae60…](https://bazaar.abuse.ch/sample/3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f/) | unbekannt | Infostealer | **80.1** | 🔴 KRITISCH | – | – | ? |
| [9478ccb9b54de3…](https://bazaar.abuse.ch/sample/9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a/) | unbekannt | Infostealer | **79.9** | 🔴 KRITISCH | – | – | ? |
| [08f36297e916e1…](https://bazaar.abuse.ch/sample/08f36297e916e15853dcd5c4728f2ad554eda6686e4342867f4653b982d260df/) | unbekannt | Infostealer | **79.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6341/7828 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6341/7828 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.2% | 6047/7828 |
| 6 | Kaspersky | 75.5% | 5907/7827 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5570/7824 |
| 9 | Rising | 68.3% | 5344/7828 |
| 10 | Varist | 66.2% | 5176/7823 |
| 11 | Avast | 65.1% | 5090/7824 |
| 12 | AVG | 65.1% | 5090/7823 |
| 13 | Tencent | 64.9% | 4932/7602 |
| 14 | McAfeeD | 61.3% | 4797/7820 |
| 15 | huorong | 60.8% | 4757/7820 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 64 | 63.4% |
| 🍎 macOS | 27 | 26.7% |
| 🐧 Linux | 5 | 5.0% |
| 📦 Archiv | 4 | 4.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 77 | 76.2% |
| MaaS-Loader | 11 | 10.9% |
| C2 / Nachladen | 7 | 6.9% |
| Trojanisierte Software | 3 | 3.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 50 | 49.5% |
| 2 | 🌐 PT | 20 | 19.8% |
| 3 | 🇫🇷 FR | 14 | 13.9% |
| 4 | 🇳🇱 NL | 13 | 12.9% |
| 5 | 🇩🇪 DE | 1 | 1.0% |
| 6 | 🌐 FI | 1 | 1.0% |
| 7 | 🌐 NO | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 12 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 11 |
| Command and Control | 7 |
| Credential Access | 4 |
| Initial Access | 1 |
| Lateral Movement | 1 |

<details><summary>8561ec7bffde32073dc5… – RemcosRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>550fe7647faf8dd9c0c5… – NetSupport | 🔴 KRITISCH 86.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Collection | [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture |

</details>
<details><summary>bc020b95fc01fae40e13… – NetSupport | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Collection | [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture |

</details>
<details><summary>62a18370ac8531988270… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b06d0eda8ef44bf0846f…](https://bazaar.abuse.ch/sample/b06d0eda8ef44bf0846fd029d90541dbb18af17b845cbdbbf4f4003b3ff6dd62/)

- **Familie:** WARDENStealer
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.E3D925EA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.GenKryptik.C5966127` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.E3D925EA` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Rising | `Trojan.Kryptik@AI.92 (RDML:IHyi1Gt3d0z3CALL+7LmSA)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |

### [8657c9c9326b795d4d9c…](https://bazaar.abuse.ch/sample/8657c9c9326b795d4d9c65f1f1e7a219154d59579cc40709c12fd1fb23a4adcb/)

- **Familie:** Trojan.GenericKD.82029581
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82029581
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82029581`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82029581` |
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Misc]` |
| Alibaba | `Trojan:Win32/Shellcode.fe22b5c8` |
| Antiy-AVL | `Trojan/Win32.ShellCode` |
| Arcabit | `Trojan.Generic.D4E3AC0D` |
| Avast | `MalwareX-gen [Misc]` |
| Avira | `TR/W32.Agent` |
| BitDefender 🛡️ | `Trojan.GenericKD.82029581` |
| Bkav | `W32.Malware.CFEE1738` |
| CAT-QuickHeal | `Trojan.Shellcode` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cynet | `Malicious (score: 100)` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.82029581 (B)` |
| F-Secure | `Trojan.TR/W32.Agent` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Trojan.GenericKD.82029581` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 0050d6d51 )` |
| K7GW | `Trojan ( 0050d6d51 )` |
| Kaspersky | `Trojan.Win32.Shellcode.vbw` |
| Kingsoft | `Win32.Trojan.Shellcode.vbw` |
| Lionic | `Trojan.Win32.Shellcode.4!c` |
| MaxSecure | `Trojan.Malware.730178956.susgen` |
| McAfeeD | `ti!8657C9C9326B` |
| MicroWorld-eScan | `Trojan.GenericKD.82029581` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxIK.A` |
| Rising | `Trojan.Shellcode!8.2FDD (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Artemis!Trojan` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Shellcode.513256` |
| Tencent | `OB:Trojan.Win32.Agent.16008572` |
| TrellixENS | `Artemis!F43B1931EE4A` |
| TrendMicro | `Trojan.Win32.SHELLCODE.USBLK126` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `BScope.Trojan.Shellcode` |
| VIPRE | `Trojan.GenericKD.82029581` |
| Varist | `W32/ABTrojan.UUMA-8637` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |

### [643d7a79d4adffd085c0…](https://bazaar.abuse.ch/sample/643d7a79d4adffd085c09ea4aea6333559e3373388a9fc21b8e553d04707c7b0/)

- **Familie:** Application
- **Erkannt von:** 51 von 75 Engines (68.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Application.Fragtor.40843
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.Fragtor.40843`

**Erkennende Engines (51/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Fragtor.40843` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5508256` |
| Antiy-AVL | `Trojan/Win32.Mikey` |
| Arcabit | `Trojan.Application.Fragtor.D9F8B` |
| Avast | `Win32:MalwareX-gen [Trj]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Application.Fragtor.40843` |
| Bkav | `W32.Malware.650F2E7D` |
| CTX | `exe.unknown.fragtor` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Siggen2.5324` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Application.Fragtor.40843 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `W32/Rozena.ZA!tr` |
| GData | `Gen:Variant.Application.Fragtor.40843` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Win64.Small` |
| K7AntiVirus | `Trojan ( 001203481 )` |
| K7GW | `Trojan ( 001203481 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Kingsoft | `malware.kb.a.932` |
| Malwarebytes | `Malware.AI.1039774085` |
| MaxSecure | `Trojan.Malware.8147765.susgen` |
| McAfeeD | `ti!643D7A79D4AD` |
| MicroWorld-eScan | `Gen:Variant.Application.Fragtor.40843` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Virus.Win32.Gen.ccmw` |
| Rising | `Malware.Undefined!8.C (TFE:3:Va1tsgOetEG)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Mikey` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `VShell-JCAD!F652A20F0EF1` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Rozena.16006312` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `VShell-JCAD!F652A20F0EF1` |
| VBA32 | `BScope.Trojan.Wacatac` |
| VIPRE | `Gen:Variant.Application.Fragtor.40843` |
| Varist | `W32/Rozena.JO.gen!Eldorado` |
| VirIT | `Trojan.Win32.Genus.ZQO` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Backdoor:Win/shellcode.api(dyn)` |
| huorong | `TrojanDownloader/Agent.bri` |

### [da20070812bc969f0460…](https://bazaar.abuse.ch/sample/da20070812bc969f0460a2841c75a7972d0ffc3a1b3a8b1d53d59a496028722e/)

- **Familie:** trojan
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** exe.trojan.astraea
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| CTX | `exe.trojan.astraea` |
| Emsisoft | `QD:Trojan.Astraea.58CA491B01 (B)` |
| GData | `QD:Trojan.Astraea.58CA491B01` |
| Tencent | `Malware.Win32.Gencirc.14baf60f` |

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
| MaxSecure | `Trojan.Malware.300983.susgen` |
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

- **exe** (59×)
- **macho** (27×)
- **SalatStealer** (14×)
- **upx-dec** (12×)
- **upx** (10×)
- **signed** (8×)
- **salatstealer** (7×)
- **NetSupport** (6×)
- **Arechclient2** (5×)
- **SectopRAT** (5×)
- **HijackLoader** (5×)
- **IDATLoader** (5×)
- **RemusStealer** (5×)
- **loader** (5×)
- **zip** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +20 (36→56)
- ↑ **SalatStealer** +20 (1→21)
- neu: **Arechclient2** (4)
- ↑ **VShell** +1 (1→2)
- neu: **RemusStealer** (2)
- neu: **NetSupport** (2)
- ↓ **RemcosRAT** -1 (2→1)
- ↓ **Mirai** -18 (19→1)
- weg: **Formbook** (war 4)
- weg: **AsyncRAT** (war 2)
- weg: **AgentTesla** (war 3)
- weg: **XWorm** (war 2)
- weg: **PureLogsStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +26 (30→56)
- ↑ **SalatStealer** +15 (6→21)
- neu: **Arechclient2** (4)
- ↑ **WARDENStealer** +2 (1→3)
- ↑ **VShell** +1 (1→2)
- neu: **RemusStealer** (2)
- neu: **NetSupport** (2)
- ↓ **RemcosRAT** -1 (2→1)
- ↓ **Mirai** -20 (21→1)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.285 MB |
| σ Dateigröße | 11.910 MB |
| Ø Risiko-Score | 60.9/100 |
| Ø Klassifikations-Konfidenz | 57.9% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 12/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 85 |
| Unbekannte Familien | 23 (22.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:30 | [8561ec7bffde…](https://bazaar.abuse.ch/sample/8561ec7bffde32073dc5edab14f4025009c4941a0683bad0eb33d72b37c9caa1/) | `js` | RemcosRAT | 89.6 | – | – | 🇳🇱NL |
| 04:40 | [62a18370ac85…](https://bazaar.abuse.ch/sample/62a18370ac853198827085fb01a17b56b9d74b13d0b37e9a37f70be1f8c3d616/) | `elf` | Mirai | 83.6 | – | – | 🇩🇪DE |
| 03:16 | [3f8bcc5070ae…](https://bazaar.abuse.ch/sample/3f8bcc5070ae60b49d1dd6e804c2a6bcf24165541d8c35b27e646c83e673f36f/) | `exe` | unbekannt | 80.1 | – | – | 🌐PT |
| 03:04 | [35eb9408b68c…](https://bazaar.abuse.ch/sample/35eb9408b68c3b07a4230db82ea75de1bc70e7f0c2c92250aa7d21a12fc88d53/) | `exe` | VShell | 36.9 | – | – | 🇺🇸US |
| 02:56 | [9478ccb9b54d…](https://bazaar.abuse.ch/sample/9478ccb9b54de30851f10cb2e388edd672ef9d94c5f9b252a01126bafbdf4d4a/) | `ps1` | unbekannt | 79.9 | – | – | 🌐PT |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 05.11.2026 05:45 UTC*