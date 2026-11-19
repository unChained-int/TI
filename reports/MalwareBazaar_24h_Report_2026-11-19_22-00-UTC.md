# MalwareBazaar – 19.11.2026 22:00 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **69** |
| Höchster Score | **89.5/100** – 62268ab41e16d955… |
| Häufigste Familie | **Mirai** (59x) |
| Häufigster Typ | **elf** (68x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 62 Samples |
| Ø Dateigröße | 2.38 MB (σ=9.53) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 68 | 67.3%  █████████████ |
| `exe` | 12 | 11.9%  ██ |
| `zip` | 6 | 5.9%  █ |
| `js` | 6 | 5.9%  █ |
| `apk` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |
| `xlsm` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |
| `html` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 59 | 58.4% |
| 2 | unbekannt | 23 | 22.8% |
| 3 | Prometei | 6 | 5.9% |
| 4 | WARDENStealer | 3 | 3.0% |
| 5 | RustyStealer | 2 | 2.0% |
| 6 | AsyncRAT | 1 | 1.0% |
| 7 | Formbook | 1 | 1.0% |
| 8 | AdaptixC2 | 1 | 1.0% |
| 9 | Malware | 1 | 1.0% |
| 10 | AgentTesla | 1 | 1.0% |
| 11 | SheetRAT | 1 | 1.0% |
| 12 | Panchan | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 59 | 58.4% | 95% |
| Linux-Malware | 9 | 8.9% | 45% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Infostealer | 6 | 5.9% | 78% |
| Skript/Dropper | 6 | 5.9% | 35% |
| RAT | 4 | 4.0% | 82% |
| Android-Malware | 3 | 3.0% | 45% |
| Loader | 3 | 3.0% | 75% |
| Windows-Malware | 2 | 2.0% | 35% |
| Maldoc | 1 | 1.0% | 35% |
| Post-Exploitation | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 69 | 68.3% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [62268ab41e16d9…](https://bazaar.abuse.ch/sample/62268ab41e16d955af34beb2801c61c2542d1004fb163fd090228f29df69ce24/) | AsyncRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [14f32f3f913b13…](https://bazaar.abuse.ch/sample/14f32f3f913b13ef6e30d8981f1519d99e6e48ed430a70de8a854fab127c2561/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [916fe1e211d032…](https://bazaar.abuse.ch/sample/916fe1e211d03231ce5588c408317ea110baf55a1cfb2940083e490b235de3bf/) | AdaptixC2 | Post-Exploitat | **85.3** | 🔴 KRITISCH | – | – | ? |
| [99647ec802196c…](https://bazaar.abuse.ch/sample/99647ec802196c42f57b8f8518028592e68c832e081b504cdfad9de69c868fc6/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [58479001308c20…](https://bazaar.abuse.ch/sample/58479001308c208550c828ec58114e208a6876e69010296f8ac8d05e64f6f6b3/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [1202486ea139e1…](https://bazaar.abuse.ch/sample/1202486ea139e1f3b8f4add4b4a8e3d016c32c2f219523f2330d02ac7061ba27/) | WARDENStealer | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [7ba10a314348d6…](https://bazaar.abuse.ch/sample/7ba10a314348d6d7567a3b3697820d99fbb6d118dd5542a29d5ee97b7888a5fc/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [81cb70cc47fba5…](https://bazaar.abuse.ch/sample/81cb70cc47fba5216f1a9119c1ec91bb0bc1f4c75cc795df909258d3dc1ddd02/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [e8268ab28ef0df…](https://bazaar.abuse.ch/sample/e8268ab28ef0df7294bf043091d1e14dcd2153286df9321d35eb4aa2196de0d5/) | Mirai | Botnet/IoT | **81.9** | 🔴 KRITISCH | – | – | ? |
| [c5d71b6f49ebd4…](https://bazaar.abuse.ch/sample/c5d71b6f49ebd4ce138e8720814bbfd39c608ec3c435496090ee8c94b911b387/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6541/8060 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6541/8060 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6237/8060 |
| 6 | Kaspersky | 75.6% | 6089/8059 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5743/8056 |
| 9 | Rising | 68.5% | 5524/8060 |
| 10 | Varist | 66.1% | 5324/8055 |
| 11 | AVG | 65.3% | 5256/8055 |
| 12 | Tencent | 65.2% | 5106/7834 |
| 13 | Avast | 65.2% | 5256/8056 |
| 14 | McAfeeD | 61.5% | 4956/8052 |
| 15 | huorong | 61.0% | 4908/8052 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 72 | 71.3% |
| 🪟 Windows | 13 | 12.9% |
| 📦 Archiv | 6 | 5.9% |
| ❓ Unbekannt | 6 | 5.9% |
| 🤖 Android | 3 | 3.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 86 | 85.1% |
| Drive-By / Exploit-Kit | 7 | 6.9% |
| MaaS-Loader | 4 | 4.0% |
| APK-Sideloading | 3 | 3.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 69 | 68.3% |
| 2 | 🇭🇺 HU | 11 | 10.9% |
| 3 | 🇪🇸 ES | 4 | 4.0% |
| 4 | 🇺🇸 US | 3 | 3.0% |
| 5 | 🌐 CL | 3 | 3.0% |
| 6 | 🇫🇷 FR | 3 | 3.0% |
| 7 | 🇨🇿 CZ | 2 | 2.0% |
| 8 | 🇸🇪 SE | 2 | 2.0% |
| 9 | 🇧🇪 BE | 2 | 2.0% |
| 10 | 🇳🇱 NL | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 62 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 59 |
| Lateral Movement | 59 |
| Command and Control | 2 |
| Collection | 2 |
| Execution | 1 |
| Credential Access | 1 |

<details><summary>62268ab41e16d955af34… – AsyncRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>14f32f3f913b13ef6e30… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>99647ec802196c42f57b… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>58479001308c208550c8… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [16354c21171dd32d13ac…](https://bazaar.abuse.ch/sample/16354c21171dd32d13ac0ba63bf0470801c80f03f5fb097ce3cdba7a20c7000c/)

- **Familie:** Malware
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.B7CABB26
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.B7CABB26` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| Gridinsoft | `Trojan.Heur!.0231A0A2` |
| Malwarebytes | `Malware.Heuristic.2102` |
| Trapmine | `malicious.moderate.ml.score` |

### [850e7bac14e1af622da3…](https://bazaar.abuse.ch/sample/850e7bac14e1af622da3a7f548a231e2918480d16d1314a290231895e4366929/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Kingsoft | `Linux.Backdoor.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Trojan.Linux.Mirai.nn` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [5d376099a48d713f40c9…](https://bazaar.abuse.ch/sample/5d376099a48d713f40c9de66c15655da664034a582ba84a069a35a82de629b6f/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [40109e704b4b2ff399a9…](https://bazaar.abuse.ch/sample/40109e704b4b2ff399a9b6bbd93c535c430f69a9fd80b6566b2acaad3b56b3e3/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
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

- **elf** (67×)
- **Mirai** (59×)
- **Torii** (54×)
- **exe** (13×)
- **js** (7×)
- **zip** (6×)
- **Prometei** (6×)
- **apk** (3×)
- **ClickFix** (3×)
- **dll** (3×)
- **VIGIA** (3×)
- **loader** (3×)
- **WARDENStealer** (2×)
- **ps1** (2×)
- **RustyStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +17 (42→59)
- ↓ **unbekannt** -13 (36→23)
- ↑ **Prometei** +2 (4→6)
- neu: **RustyStealer** (2)
- ↓ **AsyncRAT** -1 (2→1)
- neu: **Formbook** (1)
- neu: **AdaptixC2** (1)
- neu: **Malware** (1)
- neu: **AgentTesla** (1)
- weg: **Snowlight** (war 4)
- weg: **ConnectWise** (war 4)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +22 (37→59)
- ↓ **unbekannt** -1 (24→23)
- ↑ **Prometei** +3 (3→6)
- ↓ **WARDENStealer** -3 (6→3)
- ↑ **RustyStealer** +1 (1→2)
- neu: **AdaptixC2** (1)
- neu: **Malware** (1)
- ↓ **AgentTesla** -1 (2→1)
- weg: **RemcosRAT** (war 3)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.384 MB |
| σ Dateigröße | 9.532 MB |
| Ø Risiko-Score | 68.7/100 |
| Ø Klassifikations-Konfidenz | 76.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 62/101 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 54 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:50 | [1202486ea139…](https://bazaar.abuse.ch/sample/1202486ea139e1f3b8f4add4b4a8e3d016c32c2f219523f2330d02ac7061ba27/) | `exe` | WARDENStealer | 82.1 | – | – | 🌐CZ |
| 21:50 | [afd1ba88447d…](https://bazaar.abuse.ch/sample/afd1ba88447d99dcb17e72d357116546666dfc2cfa108adb3f3932bf5bd1a452/) | `zip` | unbekannt | 32.6 | – | – | 🌐HU |
| 21:42 | [62268ab41e16…](https://bazaar.abuse.ch/sample/62268ab41e16d955af34beb2801c61c2542d1004fb163fd090228f29df69ce24/) | `js` | AsyncRAT | 89.5 | – | – | 🇺🇸US |
| 21:42 | [2bdd74a995a3…](https://bazaar.abuse.ch/sample/2bdd74a995a3c5545eca1d8da28697f356b987b0af582ce6a38fa70c2016b021/) | `js` | unbekannt | 38.8 | – | – | 🌐HU |
| 21:38 | [82d3718c9afd…](https://bazaar.abuse.ch/sample/82d3718c9afd821aa8202f85ad694f0c008c6dffdb8d5e4bd34c1c2344cee366/) | `js` | unbekannt | 38.8 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.11.2026 22:00 UTC*