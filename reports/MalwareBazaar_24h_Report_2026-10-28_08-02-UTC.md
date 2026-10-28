# MalwareBazaar – 28.10.2026 08:02 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **71** |
| Höchster Score | **89.5/100** – 322e33b688c2b589… |
| Häufigste Familie | **Mirai** (38x) |
| Häufigster Typ | **elf** (56x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 44 Samples |
| Ø Dateigröße | 4.35 MB (σ=7.79) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 56 | 55.4%  ███████████ |
| `exe` | 35 | 34.7%  ██████ |
| `vbs` | 5 | 5.0%   |
| `macho` | 2 | 2.0%   |
| `js` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 38 | 37.6% |
| 2 | SalatStealer | 31 | 30.7% |
| 3 | unbekannt | 25 | 24.8% |
| 4 | CoinMiner | 1 | 1.0% |
| 5 | RemcosRAT | 1 | 1.0% |
| 6 | Phorpiex | 1 | 1.0% |
| 7 | Gafgyt | 1 | 1.0% |
| 8 | AMOS | 1 | 1.0% |
| 9 | ConnectWise | 1 | 1.0% |
| 10 | ELF:ProcHider-C [Trj] | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 43 | 42.6% | 93% |
| Infostealer | 32 | 31.7% | 75% |
| Linux-Malware | 12 | 11.9% | 45% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Loader | 2 | 2.0% | 75% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Windows-Malware | 2 | 2.0% | 35% |
| RAT | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 71 | 70.3% |
| 🟠 HOCH | 8 | 7.9% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [322e33b688c2b5…](https://bazaar.abuse.ch/sample/322e33b688c2b589f5b28fff6ce53a302dcd0d26c8df2bcc4f4831805f1ea9dd/) | RemcosRAT | RAT | **89.5** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [acd2e7872edb96…](https://bazaar.abuse.ch/sample/acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc/) | AMOS | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [e5fb83d9606bc3…](https://bazaar.abuse.ch/sample/e5fb83d9606bc3b1ba7a2f217428d5c55fc28a6aa130696deaa24520335c3d54/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [82765efbca46e7…](https://bazaar.abuse.ch/sample/82765efbca46e722723b9cbd687b941f695bcc0c388246efa7e012a3e050edf1/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [c2cc8fe95f7759…](https://bazaar.abuse.ch/sample/c2cc8fe95f77597872929b909113252167363555b7249477b65b74a557a5e602/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [a2663ec44165c5…](https://bazaar.abuse.ch/sample/a2663ec44165c58e51268114ce71c6ad6f6f2ed227179c80e91e8a630b887c66/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [bcfd24e3080c48…](https://bazaar.abuse.ch/sample/bcfd24e3080c4834f4288812d2b539c30b851008745b945377cd54eb37e467fa/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [858961b25fbcc4…](https://bazaar.abuse.ch/sample/858961b25fbcc4fefe3723c9e1ce8e15563895a6917b273249097a79e9d1ac89/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [fa007e93a6afd3…](https://bazaar.abuse.ch/sample/fa007e93a6afd356bce0a76d18541c5da8c5547b886f9c4198e0230c6835e198/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [4c14c434dd7e6f…](https://bazaar.abuse.ch/sample/4c14c434dd7e6ff2948f40c16eaa803122be09b4d70d20ab45a786fa0be22cd4/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6229/7687 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6229/7687 |
| 3 | ESET-NOD32 | 77.2% | 5935/7687 |
| 4 | Kaspersky | 75.6% | 5807/7686 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5466/7684 |
| 8 | Rising | 68.3% | 5250/7687 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5083/7683 |
| 11 | Avast | 65.1% | 5003/7683 |
| 12 | AVG | 65.1% | 5003/7682 |
| 13 | Tencent | 64.9% | 4842/7461 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4702/7680 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 57 | 56.4% |
| 🪟 Windows | 41 | 40.6% |
| 🍎 macOS | 2 | 2.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 97 | 96.0% |
| C2 / Nachladen | 2 | 2.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇳🇱 NL | 29 | 28.7% |
| 2 | 🇺🇸 US | 25 | 24.8% |
| 3 | 🇩🇪 DE | 23 | 22.8% |
| 4 | 🇪🇸 ES | 11 | 10.9% |
| 5 | 🇫🇷 FR | 6 | 5.9% |
| 6 | 🌐 EG | 4 | 4.0% |
| 7 | 🇨🇦 CA | 2 | 2.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 44 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 43 |
| Lateral Movement | 43 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>322e33b688c2b589f5b2… – RemcosRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>e5fb83d9606bc3b1ba7a… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>82765efbca46e722723b… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c2cc8fe95f7759787292… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [322e33b688c2b589f5b2…](https://bazaar.abuse.ch/sample/322e33b688c2b589f5b28fff6ce53a302dcd0d26c8df2bcc4f4831805f1ea9dd/)

- **Familie:** RemcosRAT
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** win/malicious_confidence_90% (D)
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Elastic | `malicious (high confidence)` |
| Paloalto | `generic.ml` |
| Symantec | `Scr.NSISHeur!gen3` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| huorong | `Trojan/Injector.buk` |

### [4c68701b3af3d5171192…](https://bazaar.abuse.ch/sample/4c68701b3af3d5171192606d5afdfd90b2c9afbf49eae943afe3d989894e6e38/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-DNH [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DNH [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-DNH [Trj]` |
| Avira | `TR/LINUX.Mirai.DNH` |
| ClamAV | `Unix.Trojan.Mirai-10060415-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DNH` |
| Fortinet | `ELF/MALD2.9BA9!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Kingsoft | `Linux.Backdoor.Gafgyt.jp` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| Varist | `E32/Mirai.DM.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.mq` |

### [a4ab01b4d1fc873330ad…](https://bazaar.abuse.ch/sample/a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847/)

- **Familie:** ELF:ProcHider-C [Trj]
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:ProcHider-C [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:ProcHider-C [Trj]` |
| Avast | `ELF:ProcHider-C [Trj]` |
| Avira | `TR/LINUX.ProcHider.C` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Rootkit.Agent.AQ trojan` |
| F-Secure | `Trojan.TR/LINUX.ProcHider.C` |
| Kaspersky | `HEUR:Rootkit.Linux.Processhider.gen` |
| Rising | `Rootkit.Agent/Linux!8.1369A (TFE:1B:xF1UUc5Cet)` |
| Tencent | `Linux.Rootkit.Processhider.Gflw` |

### [0f8704e6b74bf56c42f2…](https://bazaar.abuse.ch/sample/0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7/)

- **Familie:** SalatStealer
- **Erkannt von:** 47 von 74 Engines (63.5%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (47/74):**

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
| Bkav | `W32.Malware.9FC26E2` |
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
| Gridinsoft | `Trojan.Win32.Agent.oa!s1` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!F8BFE165DB0C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!F8BFE165DB0C` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!F8BFE165DB0C` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Zillya | `Trojan.Agent.Win32.4649254` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

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

- **elf** (56×)
- **exe** (34×)
- **upx-dec** (29×)
- **Mirai** (26×)
- **upx** (23×)
- **SalatStealer** (22×)
- **ddos** (11×)
- **mirai** (11×)
- **salatstealer** (8×)
- **jkl** (7×)
- **vbs** (5×)
- **dropped-by-phorpiex** (2×)
- **macho** (2×)
- **Prometei** (2×)
- **enthec** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +4 (34→38)
- ↑ **SalatStealer** +21 (10→31)
- ↓ **unbekannt** -2 (27→25)
- neu: **RemcosRAT** (1)
- neu: **Phorpiex** (1)
- neu: **Gafgyt** (1)
- neu: **AMOS** (1)
- neu: **ELF:ProcHider-C [Trj]** (1)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +18 (20→38)
- ↑ **SalatStealer** +22 (9→31)
- ↓ **unbekannt** -5 (30→25)
- ↓ **CoinMiner** -2 (3→1)
- neu: **Phorpiex** (1)
- neu: **Gafgyt** (1)
- neu: **AMOS** (1)
- neu: **ELF:ProcHider-C [Trj]** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.348 MB |
| σ Dateigröße | 7.792 MB |
| Ø Risiko-Score | 71.5/100 |
| Ø Klassifikations-Konfidenz | 75.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 44/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 29 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 07:40 | [65f9e948f1cc…](https://bazaar.abuse.ch/sample/65f9e948f1ccc026ca9d6a4851fdc850a731af7df1dabaf26eac5fd1884fc052/) | `exe` | CoinMiner | 74.8 | – | – | 🇩🇪DE |
| 07:32 | [014154af3366…](https://bazaar.abuse.ch/sample/014154af33662f55901a20902b9deae23a63fe3817fad44a2718f6e30e7a9cb1/) | `elf` | unbekannt | 42.9 | – | – | 🌐EG |
| 07:25 | [2d2b32c115c6…](https://bazaar.abuse.ch/sample/2d2b32c115c606e33cabd48e0b132e5515fd7bb33827ad17191fb37356a121b9/) | `macho` | unbekannt | 32.2 | – | – | 🌐EG |
| 07:22 | [44f8cb798339…](https://bazaar.abuse.ch/sample/44f8cb7983396bd788bed1d3050536e14b342fbc9533de65192e0d0621d7383e/) | `elf` | unbekannt | 42.8 | – | – | 🌐EG |
| 07:21 | [b441e34c8c1d…](https://bazaar.abuse.ch/sample/b441e34c8c1d724686533b700494e2dfe68b5d1f2bb9d6d5ea6080616c88780d/) | `exe` | unbekannt | 38.5 | – | – | 🌐EG |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.10.2026 08:02 UTC*