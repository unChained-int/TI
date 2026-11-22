# MalwareBazaar – 22.11.2026 01:58 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **49** |
| Höchster Score | **84.3/100** – 7dd30f2a4bb373d1… |
| Häufigste Familie | **unbekannt** (43x) |
| Häufigster Typ | **elf** (72x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 0.98 MB (σ=2.15) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 72 | 71.3%  ██████████████ |
| `macho` | 16 | 15.8%  ███ |
| `exe` | 13 | 12.9%  ██ |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 43 | 42.6% |
| 2 | Snowlight | 26 | 25.7% |
| 3 | Mirai | 24 | 23.8% |
| 4 | ConnectWise | 3 | 3.0% |
| 5 | WARDENStealer | 3 | 3.0% |
| 6 | SnappyClient | 1 | 1.0% |
| 7 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 29 | 28.7% | 92% |
| Linux-Malware | 29 | 28.7% | 45% |
| RAT | 18 | 17.8% | 76% |
| Andere / Unbekannt | 11 | 10.9% | 20% |
| Windows-Malware | 9 | 8.9% | 35% |
| Infostealer | 3 | 3.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |
| Loader | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 49 | 48.5% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 38 | 37.6% |
| 🟢 NIEDRIG | 11 | 10.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7dd30f2a4bb373…](https://bazaar.abuse.ch/sample/7dd30f2a4bb373d1a059c9b5a402331e2f5fa87a675e753ceb97e33860a084e1/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [9f1e4186bd3ddc…](https://bazaar.abuse.ch/sample/9f1e4186bd3ddcf4fa93ac3590d2bcb9a40e1ffe78900e37b7ecaeda62e0faad/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [e1727ed7417715…](https://bazaar.abuse.ch/sample/e1727ed7417715d4ab251f389f1539a72f59f0e6d20a013b1a5e3bf455e304ad/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [27353979b9017a…](https://bazaar.abuse.ch/sample/27353979b9017a0f6f1f6d409aaaae262ac33a87e7c452c93ca87b24ebf24cc1/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [7c3ce61160cb10…](https://bazaar.abuse.ch/sample/7c3ce61160cb10f6870d5561eb2550ec2ab7192344fe79e62b61a5933674e65c/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [06b53ea369881b…](https://bazaar.abuse.ch/sample/06b53ea369881b21795b8c1b499c3c1b0dc6b17b48ef1f74beaf33f51366ce5b/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [9b991d30f29672…](https://bazaar.abuse.ch/sample/9b991d30f29672e12ab147d22f87919d97198965e090ff1864019d972a60691a/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [85472e543ba64a…](https://bazaar.abuse.ch/sample/85472e543ba64a8c9eebbe40187e7055c0dd98bcc3e0d28ef425c5f45ed9080f/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [a983810368d01e…](https://bazaar.abuse.ch/sample/a983810368d01efd733237d0ccaa5d42cdb09f68b0e7e35c5cbf025450dbb313/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [32f5a34139305d…](https://bazaar.abuse.ch/sample/32f5a34139305d6b8ac2631a131c000eff6ca1ef79ea7c2857257b4bda5eabea/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6568/8093 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6568/8093 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6264/8093 |
| 6 | Kaspersky | 75.6% | 6117/8092 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5769/8089 |
| 9 | Rising | 68.6% | 5548/8093 |
| 10 | Varist | 66.1% | 5346/8088 |
| 11 | Tencent | 65.2% | 5130/7867 |
| 12 | Avast | 65.2% | 5277/8089 |
| 13 | AVG | 65.2% | 5277/8088 |
| 14 | McAfeeD | 61.5% | 4973/8085 |
| 15 | huorong | 61.0% | 4930/8085 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 77 | 76.2% |
| 🪟 Windows | 13 | 12.9% |
| 🍎 macOS | 11 | 10.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 82 | 81.2% |
| 2 | 🇫🇷 FR | 14 | 13.9% |
| 3 | 🇩🇪 DE | 3 | 3.0% |
| 4 | 🇳🇱 NL | 1 | 1.0% |
| 5 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 30 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 29 |
| Lateral Movement | 29 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>7dd30f2a4bb373d1a059… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9f1e4186bd3ddcf4fa93… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e1727ed7417715d4ab25… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>27353979b9017a0f6f1f… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7c3ce61160cb10f6870d… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [700783e4be32e15e69e4…](https://bazaar.abuse.ch/sample/700783e4be32e15e69e43cb0776e69708a0dedb50f5500bb65fb61a67e60a9ed/)

- **Familie:** Snowlight
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!8420649D0B06` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.be46e5af` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [ef16c680389ae089d47c…](https://bazaar.abuse.ch/sample/ef16c680389ae089d47c513ced6dcef84254df07d780999acce1bc7d5f648f9a/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2270` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF64/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.emw` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.AT!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!195C95D14B49` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| VBA32 | `Trojan.Elf64.Agent` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [e67c28668981746dd4f6…](https://bazaar.abuse.ch/sample/e67c28668981746dd4f6fe8ee665a16b2b43808347992cf409f4f87e00784f6a/)

- **Familie:** Snowlight
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Linux/SAgnt.AI!MTB`

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.dws` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| Varist | `E32/Agent.BE.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.ab!crit` |

### [2c3e83aaf71ed95e2bb7…](https://bazaar.abuse.ch/sample/2c3e83aaf71ed95e2bb7424fb80e6eff2c88cea6370a66e7d0f76d8e9baeab8d/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 74 Engines (27.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BR [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BR [Drp]` |
| Antiy-AVL | `Trojan/Linux.Agent` |
| Avast | `ELF:Downloader-BR [Drp]` |
| Avira | `DR/LINUX.Downloade.BR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2961` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Dropper.DR/LINUX.Downloade.BR` |
| Fortinet | `ELF/Agent.2270!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.AT!MTB` |
| Rising | `Downloader.Agent/Linux!1.14466 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| ZoneAlarm | `Linux/Dldr-WW` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **elf** (72×)
- **Mirai** (29×)
- **Snowlight** (26×)
- **EasyShell** (17×)
- **RAT** (17×)
- **Rust** (17×)
- **SnoopyTriage** (17×)
- **macho** (16×)
- **exe** (12×)
- **ConnectWise** (3×)
- **signed** (3×)
- **Torii** (3×)
- **WARDENStealer** (3×)
- **upx-dec** (2×)
- **upx** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -3 (46→43)
- neu: **Snowlight** (26)
- ↓ **Mirai** -6 (30→24)
- ↑ **ConnectWise** +2 (1→3)
- neu: **WARDENStealer** (3)
- neu: **SnappyClient** (1)
- weg: **Prometei** (war 7)
- weg: **CatStorm** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +17 (26→43)
- ↑ **Snowlight** +25 (1→26)
- ↓ **Mirai** -11 (35→24)
- ↑ **ConnectWise** +2 (1→3)
- ↓ **WARDENStealer** -2 (5→3)
- neu: **SnappyClient** (1)
- weg: **SalatStealer** (war 2)
- weg: **RemcosRAT** (war 3)
- weg: **Prometei** (war 5)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.977 MB |
| σ Dateigröße | 2.154 MB |
| Ø Risiko-Score | 60.9/100 |
| Ø Klassifikations-Konfidenz | 61.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 30/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 21 |
| Unbekannte Familien | 11 (10.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 01:47 | [700783e4be32…](https://bazaar.abuse.ch/sample/700783e4be32e15e69e43cb0776e69708a0dedb50f5500bb65fb61a67e60a9ed/) | `elf` | Snowlight | 75.7 | 37.8% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 01:44 | [83733d52f442…](https://bazaar.abuse.ch/sample/83733d52f442159d1fe89665fa8bffe54829902e5d352b613225ba00e3e2c828/) | `macho` | unbekannt | 32.5 | – | – | 🇺🇸US |
| 01:44 | [5dbaa9229e7a…](https://bazaar.abuse.ch/sample/5dbaa9229e7ab2ac3ec5ad44a1f1fa57989f501f341ed97500e8b8fdfe65cd5b/) | `elf` | Snowlight | 75.9 | – | – | 🇺🇸US |
| 01:44 | [36e4651fdfe7…](https://bazaar.abuse.ch/sample/36e4651fdfe7656e8598c8d4c40f95b01062ae27d07e6fb0b37be93db5cb5c25/) | `macho` | unbekannt | 32.5 | – | – | 🇺🇸US |
| 01:44 | [9d0693445549…](https://bazaar.abuse.ch/sample/9d06934455490a64ecfbddaf5d2ad58ad12745f89f3fc91e9f182ee98557eaf1/) | `elf` | Snowlight | 43.2 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.11.2026 01:58 UTC*