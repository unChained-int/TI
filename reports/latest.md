# MalwareBazaar – 08.11.2026 23:29 UTC

Dieser Run hat **60 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **61** |
| Kritisch (≥75) | **28** |
| Höchster Score | **95.9/100** – 447f3261b187e5a3… |
| Häufigste Familie | **unbekannt** (27x) |
| Häufigster Typ | **elf** (23x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 20 Samples |
| Ø Dateigröße | 3.19 MB (σ=6.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 23 | 37.7%  ███████ |
| `exe` | 16 | 26.2%  █████ |
| `jar` | 8 | 13.1%  ██ |
| `ps1` | 7 | 11.5%  ██ |
| `lnk` | 2 | 3.3%   |
| `apk` | 2 | 3.3%   |
| `cmd` | 1 | 1.6%   |
| `zip` | 1 | 1.6%   |
| `dll` | 1 | 1.6%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 27 | 44.3% |
| 2 | Mirai | 20 | 32.8% |
| 3 | SalatStealer | 5 | 8.2% |
| 4 | SilentNet | 4 | 6.6% |
| 5 | WARDENStealer | 2 | 3.3% |
| 6 | Downloader!gen446 | 1 | 1.6% |
| 7 | WannaCry | 1 | 1.6% |
| 8 | NanoCore | 1 | 1.6% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 20 | 32.8% | 95% |
| Andere / Unbekannt | 11 | 18.0% | 20% |
| Windows-Malware | 8 | 13.1% | 35% |
| Infostealer | 8 | 13.1% | 75% |
| Skript/Dropper | 6 | 9.8% | 35% |
| Linux-Malware | 3 | 4.9% | 45% |
| Android-Malware | 2 | 3.3% | 45% |
| Loader | 1 | 1.6% | 65% |
| Ransomware | 1 | 1.6% | 95% |
| RAT | 1 | 1.6% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 28 | 45.9% |
| 🟠 HOCH | 3 | 4.9% |
| 🟡 MITTEL | 19 | 31.1% |
| 🟢 NIEDRIG | 11 | 18.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [447f3261b187e5…](https://bazaar.abuse.ch/sample/447f3261b187e5a3278417e0eed4281d0a0360f7878bff3e0366e932541ee3c6/) | WannaCry | Ransomware | **95.9** | 🔴 KRITISCH | – | – | ? |
| [1ee7c1ce24fe24…](https://bazaar.abuse.ch/sample/1ee7c1ce24fe24227c173dfe4002d58e4da356398bef504897b27afa6163c5f5/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [6f35e36daba4df…](https://bazaar.abuse.ch/sample/6f35e36daba4df57391e1887e11bc88fd3adc88eb4277e5320b984f3f5eceb10/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [9a38b87066f16f…](https://bazaar.abuse.ch/sample/9a38b87066f16ffb1743407d1dde01b6aa70f1735b52dc538966cc6945408de8/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [c27e32a805ca44…](https://bazaar.abuse.ch/sample/c27e32a805ca44dd54d201fa4dace18a78f36ab25040b746945055c114291bde/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [f60c603ab8b9d3…](https://bazaar.abuse.ch/sample/f60c603ab8b9d309d26694a6018498d750037072df49f2febfc1b58a91611fd5/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [14716776162469…](https://bazaar.abuse.ch/sample/14716776162469751843d566b5230aaa50f7c985bbdff38c134fa3b3d654f705/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [43004ce76423cf…](https://bazaar.abuse.ch/sample/43004ce76423cfa80018b0f318a7f9d285d0fadde2dba87a1f661ad3d78aaf9a/) | WARDENStealer | Infostealer | **82.0** | 🔴 KRITISCH | – | – | ? |
| [06b5d5232b4f95…](https://bazaar.abuse.ch/sample/06b5d5232b4f952e7d2ddd07d6d62552064833c2279fa00c7ba9640acc9dd1ae/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [449eb613274e76…](https://bazaar.abuse.ch/sample/449eb613274e768f794757227c768eefdb32f43561a2854e913b7fcb2dcb6674/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6400/7896 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6400/7896 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6100/7896 |
| 6 | Kaspersky | 75.5% | 5957/7895 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5617/7892 |
| 9 | Rising | 68.4% | 5397/7896 |
| 10 | Varist | 66.1% | 5217/7891 |
| 11 | Avast | 65.2% | 5143/7892 |
| 12 | AVG | 65.2% | 5143/7891 |
| 13 | Tencent | 64.9% | 4981/7670 |
| 14 | McAfeeD | 61.4% | 4844/7888 |
| 15 | huorong | 60.9% | 4806/7888 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 26 | 42.6% |
| 🐧 Linux | 23 | 37.7% |
| ❓ Unbekannt | 9 | 14.8% |
| 🤖 Android | 2 | 3.3% |
| 📦 Archiv | 1 | 1.6% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 58 | 95.1% |
| APK-Sideloading | 2 | 3.3% |
| Exploit / N-Day | 1 | 1.6% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 22 | 36.1% |
| 2 | 🇫🇷 FR | 13 | 21.3% |
| 3 | 🇧🇷 BR | 6 | 9.8% |
| 4 | 🇵🇱 PL | 6 | 9.8% |
| 5 | 🇺🇸 US | 5 | 8.2% |
| 6 | 🇭🇺 HU | 5 | 8.2% |
| 7 | 🇳🇱 NL | 3 | 4.9% |
| 8 | 🌐 Unbekannt | 1 | 1.6% |

## MITRE ATT&CK

> 20 von 61 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |

<details><summary>1ee7c1ce24fe24227c17… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6f35e36daba4df57391e… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9a38b87066f16ffb1743… – Mirai | 🔴 KRITISCH 83.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c27e32a805ca44dd54d2… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [6995e817ab8001aeb8d5…](https://bazaar.abuse.ch/sample/6995e817ab8001aeb8d5cf5de92b832a541780abce60ee007842662a87e57915/)

- **Familie:** Downloader!gen446
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ISB.Downloader!gen446
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Symantec | `ISB.Downloader!gen446` |

### [f7bf8f83edebd03fd25a…](https://bazaar.abuse.ch/sample/f7bf8f83edebd03fd25a010c06d11c391199e1ec1d187f9586540b1d53235d25/)

- **Familie:** SalatStealer
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKDZ.121181
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKDZ.121181`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKDZ.121181` |
| AVG | `Win64:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.WallStealer.R803269` |
| Arcabit | `Trojan.Generic.D1D95D` |
| Avast | `Win64:MalwareX-gen [Pws]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKDZ.121181` |
| Bkav | `W32.Malware.FB66BF76` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Backdoor.LucidRook-10059729-0` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Agent.CJZ trojan` |
| Elastic | `Windows.Exploit.Generic` |
| Emsisoft | `Trojan.GenericKDZ.121181 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/MALD2.4E35!tr` |
| GData | `Trojan.GenericKDZ.121181` |
| Kaspersky | `HEUR:Trojan-PSW.Win64.Coins.pef` |
| Malwarebytes | `Spyware.Stealer` |
| MaxSecure | `Trojan.W32.121225.SalatStealer.YR` |
| McAfeeD | `ti!F7BF8F83EDEB` |
| MicroWorld-eScan | `Trojan.GenericKDZ.121181` |
| Microsoft 🛡️ | `PWS:Win64/WallStealer.CI!MTB` |
| Rising | `Backdoor.Agent!8.C5D (TFE:5:uUuztGE45cU)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Dropper.vh` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `backdoor.win64.agentcjz.16008246` |
| Trapmine | `suspicious.low.ml.score` |
| VIPRE | `Trojan.GenericKDZ.121181` |
| Varist | `W64/Agent.NQZ.gen!Eldorado` |
| huorong | `TrojanSpy/Stealer.gg` |

### [af0598ad6986c10a35fc…](https://bazaar.abuse.ch/sample/af0598ad6986c10a35fcd822c07f2310aea47f883c4a3b19f48252bc66ee14bb/)

- **Familie:** SalatStealer
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Heur.Mint.Zard.39
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.Mint.Zard.39`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R805346` |
| Arcabit | `Trojan.Mint.Zard.39` |
| Avast | `Win32:MalwareX-gen [Pws]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Heur.Mint.Zard.39` |
| Bkav | `W32.Malware.BF5C022` |
| CTX | `exe.unknown.generic` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win32/Agent_AGen.HOB trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.Mint.Zard.39 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| GData | `Gen:Heur.Mint.Zard.39` |
| McAfeeD | `Trojan:Win/Generic.GZFY` |
| MicroWorld-eScan | `Gen:Heur.Mint.Zard.39` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Stealer.Salat!8.1CB5C (TFE:1:po1W570OrSE)` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.high.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `BScope.TrojanPSW.Satal` |
| VIPRE | `Gen:Heur.Mint.Zard.39` |
| Webroot | `W32.Malware.gen` |

### [1d3f3ca955ffc35a381d…](https://bazaar.abuse.ch/sample/1d3f3ca955ffc35a381d559a42ffca08cbe2b3e3a293f994eac5c3d42c5cf011/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Application.Generic.37119494
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37119494`

**Erkennende Engines (29/75):**

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
| Google | `Detected` |
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

- **elf** (22×)
- **Mirai** (20×)
- **exe** (15×)
- **Torii** (9×)
- **ps1** (7×)
- **Prometei** (5×)
- **SilentNet** (5×)
- **jar** (4×)
- **81-168-24-109** (3×)
- **salat** (3×)
- **salatstealer** (3×)
- **WARDENStealer** (2×)
- **lnk** (2×)
- **UKR** (2×)
- **apk** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +1 (26→27)
- ↓ **Mirai** -13 (33→20)
- neu: **SalatStealer** (5)
- neu: **SilentNet** (4)
- ↓ **WARDENStealer** -3 (5→2)
- neu: **Downloader!gen446** (1)
- neu: **WannaCry** (1)
- weg: **VShell** (war 2)
- weg: **Snowlight** (war 4)
- weg: **EchoBot** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -6 (33→27)
- ↑ **SalatStealer** +3 (2→5)
- neu: **SilentNet** (4)
- ↓ **WARDENStealer** -1 (3→2)
- neu: **Downloader!gen446** (1)
- neu: **WannaCry** (1)
- weg: **RemcosRAT** (war 2)
- weg: **VShell** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.195 MB |
| σ Dateigröße | 6.065 MB |
| Ø Risiko-Score | 58.2/100 |
| Ø Klassifikations-Konfidenz | 60.5% |
| Samples mit VT | 5/61 |
| Samples mit MITRE | 20/61 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 31 |
| Unbekannte Familien | 11 (18.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:13 | [f929629da2a6…](https://bazaar.abuse.ch/sample/f929629da2a695ca8832bd5d3ecd7633da1b3f5cab66068da6611f0c9915fe67/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |
| 23:13 | [43004ce76423…](https://bazaar.abuse.ch/sample/43004ce76423cfa80018b0f318a7f9d285d0fadde2dba87a1f661ad3d78aaf9a/) | `exe` | WARDENStealer | 82.0 | – | – | 🇫🇷FR |
| 23:13 | [5d620521cf8d…](https://bazaar.abuse.ch/sample/5d620521cf8d83a81d0f814adabe0ce9ed3af7777f9d122e39fcc2d60ed22d99/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |
| 23:13 | [5470a0ccca30…](https://bazaar.abuse.ch/sample/5470a0ccca30579d435283bcc3ee824e9accf13d6bcb276b36ec1e664a73935b/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |
| 23:13 | [9a71e0b2f5d3…](https://bazaar.abuse.ch/sample/9a71e0b2f5d33b8cab0215aa2c6f46225d94581da7018a692f77952adc1eaa3c/) | `exe` | unbekannt | 38.9 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 08.11.2026 23:29 UTC*