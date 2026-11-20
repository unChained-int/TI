# MalwareBazaar – 20.11.2026 03:01 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **74** |
| Höchster Score | **88.7/100** – cacd3bcc5c397d82… |
| Häufigste Familie | **Mirai** (35x) |
| Häufigster Typ | **exe** (57x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 40 Samples |
| Ø Dateigröße | 2.75 MB (σ=4.75) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 57 | 56.4%  ███████████ |
| `elf` | 39 | 38.6%  ███████ |
| `hta` | 2 | 2.0%   |
| `msi` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 35 | 34.7% |
| 2 | SalatStealer | 16 | 15.8% |
| 3 | WARDENStealer | 15 | 14.9% |
| 4 | unbekannt | 14 | 13.9% |
| 5 | VShell | 5 | 5.0% |
| 6 | Prometei | 3 | 3.0% |
| 7 | RemusStealer | 3 | 3.0% |
| 8 | ConnectWise | 2 | 2.0% |
| 9 | RemcosRAT | 2 | 2.0% |
| 10 | JOMANGY | 1 | 1.0% |
| 11 | ValleyRAT | 1 | 1.0% |
| 12 | Vidar | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 35 | 34.7% | 76% |
| Botnet/IoT | 35 | 34.7% | 95% |
| Windows-Malware | 19 | 18.8% | 35% |
| RAT | 5 | 5.0% | 91% |
| Linux-Malware | 4 | 4.0% | 45% |
| Andere / Unbekannt | 1 | 1.0% | 20% |
| Android-Malware | 1 | 1.0% | 45% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 74 | 73.3% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 24 | 23.8% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [cacd3bcc5c397d…](https://bazaar.abuse.ch/sample/cacd3bcc5c397d82545b49c22f8f831aee6976893bd977d8a827a67e9781df9b/) | Vidar | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [2120cd6aae0810…](https://bazaar.abuse.ch/sample/2120cd6aae081063d7f2f3709feaaf9cfc594fb50d3c2cebd431f0b4a03212c4/) | AsyncRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [d1e1b6fd227bc6…](https://bazaar.abuse.ch/sample/d1e1b6fd227bc6ae2c1e078b6daa3398723e0d086df52781226135027897dd7a/) | RemcosRAT | RAT | **87.7** | 🔴 KRITISCH | 10.8% | 🟡 SCHWACH ERKANNT | ✗ |
| [18cad9bd6f9bbc…](https://bazaar.abuse.ch/sample/18cad9bd6f9bbc0e5563a206f8afcef44529a8f294ac20b8eea050704b523cd4/) | RemcosRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [765d78be9c09d3…](https://bazaar.abuse.ch/sample/765d78be9c09d393f6fa2d4360f709dd0d14b8f653f9afa48f0cfba63b9bc402/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [50f92ee9546fc5…](https://bazaar.abuse.ch/sample/50f92ee9546fc51acb4fcfb2131eb6632325b687b4e0adbe42b28eaa1fb89329/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [31ee1518da5c18…](https://bazaar.abuse.ch/sample/31ee1518da5c18060dbcf259b6e19fc4a2821a8ab011f10f5f623ca3f8606bf5/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [050c3478d27d60…](https://bazaar.abuse.ch/sample/050c3478d27d60e75a1d403c32ab1a1d5809c3f77bf9d898799f5aaead083686/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [993bb703534d02…](https://bazaar.abuse.ch/sample/993bb703534d027dfe36933822562a15500d943a4a98582d869a7d6261c2749f/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [41c282a8c13276…](https://bazaar.abuse.ch/sample/41c282a8c13276e670939eaaaa572e45e2607bb62cf2a94bc875963008805909/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6545/8065 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6545/8065 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6242/8065 |
| 6 | Kaspersky | 75.6% | 6094/8064 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5748/8061 |
| 9 | Rising | 68.6% | 5529/8065 |
| 10 | Varist | 66.1% | 5329/8060 |
| 11 | Avast | 65.3% | 5260/8061 |
| 12 | AVG | 65.3% | 5260/8060 |
| 13 | Tencent | 65.2% | 5110/7839 |
| 14 | McAfeeD | 61.6% | 4960/8057 |
| 15 | huorong | 61.0% | 4912/8057 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 55 | 54.5% |
| 🐧 Linux | 45 | 44.6% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Trojanisierte Software | 1 | 1.0% |
| APK-Sideloading | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 35 | 34.7% |
| 2 | 🇫🇷 FR | 27 | 26.7% |
| 3 | 🇺🇸 US | 21 | 20.8% |
| 4 | 🇳🇱 NL | 15 | 14.9% |
| 5 | 🇯🇵 JP | 1 | 1.0% |
| 6 | 🇵🇱 PL | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 40 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 35 |
| Lateral Movement | 35 |
| Collection | 4 |
| Command and Control | 4 |
| Credential Access | 1 |
| Exfiltration | 1 |
| Execution | 1 |

<details><summary>cacd3bcc5c397d82545b… – Vidar | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2120cd6aae081063d7f2… – AsyncRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>d1e1b6fd227bc6ae2c1e… – RemcosRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>18cad9bd6f9bbc0e5563… – RemcosRAT | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>765d78be9c09d393f6fa… – Mirai | 🔴 KRITISCH 82.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d1e1b6fd227bc6ae2c1e…](https://bazaar.abuse.ch/sample/d1e1b6fd227bc6ae2c1e078b6daa3398723e0d086df52781226135027897dd7a/)

- **Familie:** RemcosRAT
- **Erkannt von:** 8 von 74 Engines (10.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** BehavesLike.HTML.Exploit.zr
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `JS/Agent.VMP trojan` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-Downloader.Script.Generic` |
| NANO-Antivirus | `Trojan.Script.Heuristic-js.iacgm` |
| Rising | `Trojan.Agent/JS!8.11351 (TOPIS:E0:zD0ihL4yERP)` |
| Skyhigh | `BehavesLike.HTML.Exploit.zr` |
| Symantec | `ISB.Dropper!gen1` |
| Varist | `HTML/Agent.IU` |

### [f006aaa1017115b9d41f…](https://bazaar.abuse.ch/sample/f006aaa1017115b9d41f28b3187671fabfbdbde131c75732348c4276e2f09373/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [84eb16231866f4630eab…](https://bazaar.abuse.ch/sample/84eb16231866f4630eabb27ba35a9f5cfaf0027b4f53a7ba8065572ab62e55df/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.iosi` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [e7549b8ba65fa99a8df3…](https://bazaar.abuse.ch/sample/e7549b8ba65fa99a8df3a905a1d963e2de1fae688b7869a94f931335039e4e44/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

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

- **exe** (54×)
- **elf** (39×)
- **Mirai** (35×)
- **Torii** (34×)
- **upx-dec** (15×)
- **upx** (15×)
- **WARDENStealer** (15×)
- **stealer** (10×)
- **Warden** (10×)
- **SalatStealer** (8×)
- **salatstealer** (8×)
- **signed** (6×)
- **VShell** (5×)
- **RAT** (3×)
- **Prometei** (3×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -23 (58→35)
- neu: **SalatStealer** (16)
- ↑ **WARDENStealer** +13 (2→15)
- ↓ **unbekannt** -12 (26→14)
- neu: **VShell** (5)
- ↓ **Prometei** -3 (6→3)
- neu: **RemusStealer** (3)
- neu: **ConnectWise** (2)
- neu: **RemcosRAT** (2)
- neu: **JOMANGY** (1)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -4 (39→35)
- ↑ **SalatStealer** +15 (1→16)
- ↑ **WARDENStealer** +10 (5→15)
- ↓ **unbekannt** -10 (24→14)
- neu: **VShell** (5)
- ↑ **RemusStealer** +2 (1→3)
- ↑ **ConnectWise** +1 (1→2)
- ↓ **RemcosRAT** -1 (3→2)
- neu: **JOMANGY** (1)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.753 MB |
| σ Dateigröße | 4.747 MB |
| Ø Risiko-Score | 70.3/100 |
| Ø Klassifikations-Konfidenz | 73.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 40/101 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 33 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 02:26 | [b10f8397ef57…](https://bazaar.abuse.ch/sample/b10f8397ef57e03d16f74cc271a020b08c930e35ff3f5a07ef35a6c209df1f6c/) | `exe` | SalatStealer | 81.7 | – | – | 🇳🇱NL |
| 02:26 | [f2741eff6f68…](https://bazaar.abuse.ch/sample/f2741eff6f684b785ffc7af70dbda15e8382f1a46f58dd3c1037fdc2dae5e267/) | `exe` | SalatStealer | 81.7 | – | – | 🇳🇱NL |
| 02:26 | [99acb253a5d5…](https://bazaar.abuse.ch/sample/99acb253a5d5c4640fc0e75b5b1a15d31b78cfaea8c1761445b56eff533c6ad2/) | `exe` | SalatStealer | 81.7 | – | – | 🇳🇱NL |
| 02:26 | [c4ce670cc161…](https://bazaar.abuse.ch/sample/c4ce670cc1619043eb0a5e3557cf00487d892ea7976fc8febf95b0dfb10a2747/) | `exe` | SalatStealer | 81.7 | – | – | 🇳🇱NL |
| 02:26 | [3b47193ffb34…](https://bazaar.abuse.ch/sample/3b47193ffb34de4f7dd3a78eab3bf328705e1148621b014d424104337a161c1d/) | `exe` | SalatStealer | 81.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.11.2026 03:01 UTC*