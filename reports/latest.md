# MalwareBazaar – 06.11.2026 02:04 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **11** |
| Höchster Score | **83.5/100** – 086b9625247a2ef5… |
| Häufigste Familie | **unbekannt** (80x) |
| Häufigster Typ | **macho** (68x) |
| Hauptplattform | **macOS** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 5 Samples |
| Ø Dateigröße | 0.95 MB (σ=1.85) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `macho` | 68 | 67.3%  █████████████ |
| `exe` | 26 | 25.7%  █████ |
| `elf` | 4 | 4.0%   |
| `zip` | 2 | 2.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 80 | 79.2% |
| 2 | VShell | 6 | 5.9% |
| 3 | WARDENStealer | 4 | 4.0% |
| 4 | Mirai | 4 | 4.0% |
| 5 | Rozena | 2 | 2.0% |
| 6 | AokigaharaStealer | 2 | 2.0% |
| 7 | GCleaner | 1 | 1.0% |
| 8 | Gafgyt | 1 | 1.0% |
| 9 | NanoCore | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 56 | 55.4% | 20% |
| Windows-Malware | 16 | 15.8% | 35% |
| Loader | 14 | 13.9% | 75% |
| Infostealer | 6 | 5.9% | 75% |
| Botnet/IoT | 5 | 5.0% | 95% |
| Trojaner | 3 | 3.0% | 65% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 11 | 10.9% |
| 🟠 HOCH | 18 | 17.8% |
| 🟡 MITTEL | 16 | 15.8% |
| 🟢 NIEDRIG | 56 | 55.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [086b9625247a2e…](https://bazaar.abuse.ch/sample/086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [96556b8939e1de…](https://bazaar.abuse.ch/sample/96556b8939e1de45a08cf3b97877b27c1c8b6e553ec5968bfb7dff519a93ac0a/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [b41286360f4358…](https://bazaar.abuse.ch/sample/b41286360f43585c2c7e783d0dfcbe4965e8485221035d7f3e6a20fd20c3acd8/) | Gafgyt | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [954c3785a9d9e6…](https://bazaar.abuse.ch/sample/954c3785a9d9e6dd611e05f1dcb18814e4bb7fa9c07da926b5c5be0d6fd4956f/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [2731c2579caa28…](https://bazaar.abuse.ch/sample/2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a/) | WARDENStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [ae22c6a4bc847f…](https://bazaar.abuse.ch/sample/ae22c6a4bc847f2044568d14bf0c1d85350f2b5cdde2fa0e7ab8ee2e33e91d45/) | WARDENStealer | Infostealer | **81.0** | 🔴 KRITISCH | – | – | ? |
| [31810889506dd9…](https://bazaar.abuse.ch/sample/31810889506dd999d37d1622c135ffed2e6f60933e6a29ac1c00e86ed7abe460/) | WARDENStealer | Infostealer | **80.7** | 🔴 KRITISCH | – | – | ? |
| [c0ffaf554a08da…](https://bazaar.abuse.ch/sample/c0ffaf554a08da18e285a2c2d59b51f1b9496b2ac0447620d998718f3172931a/) | AokigaharaStealer | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |
| [01ad296c490b0e…](https://bazaar.abuse.ch/sample/01ad296c490b0e70f63e12f2a676503236cd8f1b1bc68cad2a6e17829ac1350b/) | AokigaharaStealer | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |
| [11cf5c351110d1…](https://bazaar.abuse.ch/sample/11cf5c351110d1ff4c923e673567570a623250fbb7b3e8086a7e894b5a80afda/) | WARDENStealer | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6353/7842 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6353/7842 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6059/7842 |
| 6 | Kaspersky | 75.5% | 5918/7841 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5582/7838 |
| 9 | Rising | 68.3% | 5355/7842 |
| 10 | Varist | 66.2% | 5188/7837 |
| 11 | Avast | 65.1% | 5101/7838 |
| 12 | AVG | 65.1% | 5101/7837 |
| 13 | Tencent | 64.9% | 4944/7616 |
| 14 | McAfeeD | 61.4% | 4810/7834 |
| 15 | huorong | 60.8% | 4766/7834 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🍎 macOS | 68 | 67.3% |
| 🪟 Windows | 20 | 19.8% |
| 🐧 Linux | 11 | 10.9% |
| 📦 Archiv | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 87 | 86.1% |
| MaaS-Loader | 14 | 13.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 86 | 85.1% |
| 2 | 🇫🇷 FR | 8 | 7.9% |
| 3 | 🌐 Unbekannt | 2 | 2.0% |
| 4 | 🇯🇵 JP | 2 | 2.0% |
| 5 | 🌐 CO | 2 | 2.0% |
| 6 | 🇩🇪 DE | 1 | 1.0% |

## MITRE ATT&CK

> 5 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 5 |
| Lateral Movement | 5 |

<details><summary>086b9625247a2ef58a4e… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>96556b8939e1de45a08c… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b41286360f43585c2c7e… – Gafgyt | 🔴 KRITISCH 82.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>954c3785a9d9e6dd611e… – Mirai | 🔴 KRITISCH 82.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [94d7b9615e79407a2917…](https://bazaar.abuse.ch/sample/94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390/)

- **Familie:** Rozena
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Rozena.62
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Rozena.62`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Rozena.62` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Downloader/Win.VShell.R742609` |
| Antiy-AVL | `Trojan/Win32.Mikey` |
| Arcabit | `Trojan.Rozena.62` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Rozena.62` |
| Bkav | `W32.Malware.D1F893C7` |
| CTX | `exe.unknown.rozena` |
| ClamAV | `Win.Trojan.Mikey-10034322-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Packed2.49347` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Rozena.62 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/HelloKitty.PNG!tr.ransom` |
| GData | `Gen:Variant.Rozena.62` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Shelm` |
| K7AntiVirus | `Trojan ( 005c2d751 )` |
| K7GW | `Trojan ( 005c2d751 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Malwarebytes | `Malware.AI.2447105317` |
| MaxSecure | `Trojan.W32.290726.rozena.YR` |
| McAfeeD | `ti!94D7B9615E79` |
| MicroWorld-eScan | `Gen:Variant.Rozena.62` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Trojan.Win64.NetworkShellcodeLoader.lkdmtv` |
| Rising | `Trojan.Loader/x64!1.141AB (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Rozena` |
| Sangfor | `Trojan.Win32.Agent.Ajkn` |
| Skyhigh | `Trojan-JAED!843BBFC2D4A7` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Meterpreter.16007671` |
| TrellixENS | `Trojan-JAED!843BBFC2D4A7` |
| VIPRE | `Gen:Variant.Rozena.62` |
| Varist | `W64/Rozena.JN.gen!Eldorado` |
| VirIT | `Trojan.Win64.Genus.HHM` |
| Webroot | `W32.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Backdoor:Win/shellcode.api(dyn)` |
| huorong | `Trojan/ShellLoader.acv` |

### [801859bdd548e3965de1…](https://bazaar.abuse.ch/sample/801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Application.Generic.37119494
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37119494`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37119494` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D2366606` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37119494` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37119494 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37119494` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37119494` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37119494` |
| huorong | `Trojan/Prometei.c` |

### [db6c7c1d1d690f3e91d3…](https://bazaar.abuse.ch/sample/db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb/)

- **Familie:** Rozena
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Rozena.62
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Rozena.62`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Rozena.62` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Downloader/Win.VShell.R742609` |
| Antiy-AVL | `Trojan/Win32.Mikey` |
| Arcabit | `Trojan.Rozena.62` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Rozena.62` |
| CTX | `exe.unknown.rozena` |
| ClamAV | `Win.Trojan.Mikey-10034322-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Packed2.49347` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Rozena.62 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/HelloKitty.PNG!tr.ransom` |
| GData | `Gen:Variant.Rozena.62` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Shelm` |
| K7AntiVirus | `Trojan ( 005c2d751 )` |
| K7GW | `Trojan ( 005c2d751 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Malwarebytes | `Malware.AI.2447105317` |
| MaxSecure | `Trojan.W32.290726.rozena.YR` |
| McAfeeD | `ti!DB6C7C1D1D69` |
| MicroWorld-eScan | `Gen:Variant.Rozena.62` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Trojan.Win64.NetworkShellcodeLoader.lkdmtv` |
| Rising | `Trojan.Loader/x64!1.141AB (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Rozena` |
| Skyhigh | `Trojan-JAED!EB6AD5CF6584` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Meterpreter.16007671` |
| TrellixENS | `Trojan-JAED!EB6AD5CF6584` |
| VIPRE | `Gen:Variant.Rozena.62` |
| Varist | `W64/Rozena.JN.gen!Eldorado` |
| VirIT | `Trojan.Win64.Genus.HHM` |
| Webroot | `W32.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Backdoor:Win/shellcode.api(dyn)` |
| huorong | `Trojan/ShellLoader.acv` |

### [b642b90a8fb96a8a3346…](https://bazaar.abuse.ch/sample/b642b90a8fb96a8a3346529183a6d43eb9e0db02cd7e83e49a76725d757b2fa0/)

- **Familie:** VShell
- **Erkannt von:** 52 von 75 Engines (69.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Application.Fragtor.40843
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.Fragtor.40843`

**Erkennende Engines (52/75):**

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
| Bkav | `W32.Malware.3EBC1697` |
| CTX | `exe.unknown.fragtor` |
| ClamAV | `Win.Trojan.Mikey-10038331-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen33.25221` |
| ESET-NOD32 | `Win64/Rozena.ZA trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Application.Fragtor.40843 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `W32/Rozena.ZA!tr` |
| GData | `Win32.Trojan.Loader.Q` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Win64.Small` |
| Jiangmin | `Trojan.Generic.hscze` |
| K7AntiVirus | `Trojan ( 001203481 )` |
| K7GW | `Trojan ( 001203481 )` |
| Kaspersky | `HEUR:Trojan.Win32.Generic` |
| Kingsoft | `malware.kb.a.916` |
| MaxSecure | `Downloader.W32.180226.Snowlight.YR` |
| McAfeeD | `ti!B642B90A8FB9` |
| MicroWorld-eScan | `Gen:Variant.Application.Fragtor.40843` |
| Microsoft 🛡️ | `Trojan:Win32/Mikey.HNC!MTB` |
| NANO-Antivirus | `Virus.Win32.Gen.ccmw` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Backdoor.VShell!1.13126 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Mikey` |
| Sophos | `Troj/Loader-IY` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Rozena.hj` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `VShell-JCAC!5A72CBD87423` |
| VBA32 | `BScope.Trojan.Wacatac` |
| VIPRE | `Gen:Variant.Application.Fragtor.40843` |
| Varist | `W32/Rozena.JO.gen!Eldorado` |
| VirIT | `Trojan.Win32.Genus.ZQO` |
| Webroot | `W32.Trojan.Gen` |
| ZoneAlarm | `Troj/Loader-IY` |
| alibabacloud | `Backdoor:Win/shellcode.api(dyn)` |
| huorong | `Trojan/Fake.ao` |

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

- **macho** (68×)
- **exe** (25×)
- **ClickFix** (14×)
- **Foxveil** (14×)
- **loader** (14×)
- **Mach-O** (14×)
- **macOS** (14×)
- **VShell** (6×)
- **WARDENStealer** (4×)
- **elf** (4×)
- **Mirai** (3×)
- **Prometei** (2×)
- **mirai** (2×)
- **zip** (2×)
- **AokigaharaStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +32 (48→80)
- ↑ **VShell** +5 (1→6)
- ↑ **WARDENStealer** +3 (1→4)
- neu: **Rozena** (2)
- neu: **AokigaharaStealer** (2)
- neu: **GCleaner** (1)
- neu: **Gafgyt** (1)
- ↓ **NanoCore** -1 (2→1)
- weg: **SalatStealer** (war 7)
- weg: **RemcosRAT** (war 5)
- weg: **AgentTesla** (war 8)
- weg: **XWorm** (war 2)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +47 (33→80)
- ↑ **VShell** +5 (1→6)
- ↑ **WARDENStealer** +3 (1→4)
- ↓ **Mirai** -15 (19→4)
- neu: **Rozena** (2)
- neu: **AokigaharaStealer** (2)
- neu: **GCleaner** (1)
- neu: **Gafgyt** (1)
- weg: **SalatStealer** (war 7)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.955 MB |
| σ Dateigröße | 1.854 MB |
| Ø Risiko-Score | 45.3/100 |
| Ø Klassifikations-Konfidenz | 39.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 5/101 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 32 |
| Unbekannte Familien | 56 (55.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 01:50 | [4cee268790d7…](https://bazaar.abuse.ch/sample/4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 01:49 | [92a8eb4a5952…](https://bazaar.abuse.ch/sample/92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 01:41 | [1dde3ee1a023…](https://bazaar.abuse.ch/sample/1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a/) | `exe` | VShell | 38.8 | – | – | 🇺🇸US |
| 01:39 | [2731c2579caa…](https://bazaar.abuse.ch/sample/2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a/) | `exe` | WARDENStealer | 81.9 | – | – | 🇺🇸US |
| 01:34 | [af4b153c27eb…](https://bazaar.abuse.ch/sample/af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b/) | `macho` | unbekannt | 32.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 06.11.2026 02:04 UTC*