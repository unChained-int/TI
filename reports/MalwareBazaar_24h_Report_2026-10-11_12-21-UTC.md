# MalwareBazaar – 11.10.2026 12:21 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ba0f697bbdbabdcb48c3…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **64** |
| Höchster Score | **87.2/100** – 0fdf8b638918ac7a… |
| Häufigste Familie | **Mirai** (60x) |
| Häufigster Typ | **elf** (82x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 64 Samples |
| Ø Dateigröße | 1.53 MB (σ=4.06) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 82 | 81.2%  ████████████████ |
| `exe` | 7 | 6.9%  █ |
| `apk` | 5 | 5.0%   |
| `sh` | 4 | 4.0%   |
| `jar` | 1 | 1.0%   |
| `pdf` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 60 | 59.4% |
| 2 | unbekannt | 34 | 33.7% |
| 3 | QuasarRAT | 2 | 2.0% |
| 4 | FileRepMalware [Misc] | 1 | 1.0% |
| 5 | WannaCry | 1 | 1.0% |
| 6 | ChiselClient | 1 | 1.0% |
| 7 | AsyncRAT | 1 | 1.0% |
| 8 | ConnectWise | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 60 | 59.4% | 95% |
| Linux-Malware | 23 | 22.8% | 45% |
| Android-Malware | 5 | 5.0% | 45% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| RAT | 3 | 3.0% | 95% |
| Trojaner | 2 | 2.0% | 70% |
| Windows-Malware | 1 | 1.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |
| Loader | 1 | 1.0% | 75% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 64 | 63.4% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 29 | 28.7% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [0fdf8b638918ac…](https://bazaar.abuse.ch/sample/0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3/) | QuasarRAT | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [c11464f548d271…](https://bazaar.abuse.ch/sample/c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb/) | AsyncRAT | RAT | **85.1** | 🔴 KRITISCH | – | – | ? |
| [f1376b1e04deff…](https://bazaar.abuse.ch/sample/f1376b1e04deff8446c519063e390a8de951e3e4074f1b60b182da2bb5fc807c/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [7f8844fed77616…](https://bazaar.abuse.ch/sample/7f8844fed77616b081d20219cc7e59ebcf0ab44333e5c4b635a161a3f5c412ff/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [685d91b7880c68…](https://bazaar.abuse.ch/sample/685d91b7880c6877fc0b5ab0430c503373b4280eca139cb5db2b1d50c176bc85/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [eaf9a32f13fb73…](https://bazaar.abuse.ch/sample/eaf9a32f13fb73cbde90a492c015e6e70dd6134edbf1d114d1a759818f715985/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [dc12d239064621…](https://bazaar.abuse.ch/sample/dc12d2390646217fcccb0c448f5c654e8dbb4cdd83f3096148a86013bfcebbd2/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [fb89553bb9a085…](https://bazaar.abuse.ch/sample/fb89553bb9a0859703235338f23888e182abcae177b6d4687406981f9ed9c580/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [788254aef022ee…](https://bazaar.abuse.ch/sample/788254aef022ee04419d9838cc1b7d3e5b1629c70d7cb58352670e150baa1061/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [dbee7860f24ece…](https://bazaar.abuse.ch/sample/dbee7860f24ecea5d96cff39678ced298b068f9a175c071e54a8d65efd9ecb2a/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5918/7317 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5918/7317 |
| 3 | ESET-NOD32 | 77.4% | 5660/7317 |
| 4 | Kaspersky | 76.3% | 5581/7316 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5237/7314 |
| 8 | Rising | 68.7% | 5026/7317 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4862/7313 |
| 11 | Tencent | 65.2% | 4622/7091 |
| 12 | Avast | 65.0% | 4756/7313 |
| 13 | AVG | 65.0% | 4756/7312 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4487/7310 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 86 | 85.1% |
| 🪟 Windows | 8 | 7.9% |
| 🤖 Android | 5 | 5.0% |
| ❓ Unbekannt | 1 | 1.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 92 | 91.1% |
| APK-Sideloading | 5 | 5.0% |
| Exploit / N-Day | 1 | 1.0% |
| C2 / Nachladen | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 69 | 68.3% |
| 2 | 🇳🇱 NL | 14 | 13.9% |
| 3 | 🇺🇸 US | 8 | 7.9% |
| 4 | 🇨🇦 CA | 6 | 5.9% |
| 5 | 🇨🇭 CH | 2 | 2.0% |
| 6 | 🌐 PE | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 64 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 60 |
| Lateral Movement | 60 |
| Command and Control | 3 |
| Exfiltration | 2 |
| Execution | 2 |
| Persistence | 1 |

<details><summary>0fdf8b638918ac7a04c3… – QuasarRAT | 🔴 KRITISCH 87.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>c11464f548d27189b733… – AsyncRAT | 🔴 KRITISCH 85.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>f1376b1e04deff8446c5… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7f8844fed77616b081d2… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>685d91b7880c6877fc0b… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [8bda1aaaa3f5bfc58f66…](https://bazaar.abuse.ch/sample/8bda1aaaa3f5bfc58f668d02bd6561665523abfd13488d66e8531e3c2f8dfd68/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Agent.6
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Agent.6`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Agent.6` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.Gafgyt.SE180` |
| Arcabit | `Trojan.Linux.Agent.6` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `EXP/ELF.Mirai.D` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Agent.6` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Gafgyt-6981160-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| ESET-NOD32 | `Linux/Mirai.FKU trojan` |
| Emsisoft | `Gen:Variant.Linux.Agent.6 (B)` |
| F-Secure | `Trojan:Linux/MiraiRbot.A` |
| Fortinet | `ELF/Fodcha.080F!tr` |
| GData | `Gen:Variant.Linux.Agent.6` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ns` |
| Kingsoft | `Linux.Backdoor.elf.2023761` |
| MicroWorld-eScan | `Gen:Variant.Linux.Agent.6` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.DE80 (CLASSIC)` |
| Tencent | `Backdoor.Linux.Zhtrap.dhyra` |
| VIPRE | `Gen:Variant.Linux.Agent.6` |
| Varist | `E64/Gafgyt.C.gen!Camelot` |
| alibabacloud | `DDoS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.q` |

### [b46c9ddeb0478d52d744…](https://bazaar.abuse.ch/sample/b46c9ddeb0478d52d74426f8bdf6689ba6a5cab410ea52513ac4d969989e1a08/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -1
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.921C3BFA` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!B46C9DDEB047` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.95 (RDML:23V7ODLZSCkA5OKCG5WLZA)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |

### [c77785269a54df0173e9…](https://bazaar.abuse.ch/sample/c77785269a54df0173e98b8a53a22594a104e701a5132bd53d03f4cb0f285c21/)

- **Familie:** WannaCry
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0147`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0147` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Antiy-AVL | `Trojan[Exploit]/Win64.CVE-2017-0147` |
| Arcabit | `Exploit.CVE-2017-0147` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `EXP/W32.CVE-2017-01.B` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0147` |
| Bkav | `W32.Malware.B4F785DC` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.generic` |
| ClamAV | `Win.Ransomware.Wanna-9769986-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win64/Exploit.CVE-2017-0147.A trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Exploit.CVE-2017-0147 (B)` |
| F-Secure | `Exploit.EXP/W32.CVE-2017-01.B` |
| Fortinet | `W64/Wanna.AK!tr` |
| GData | `Exploit.CVE-2017-0147` |
| Gridinsoft | `Trojan.Win64.Downloader.oa!s1` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan.Win32.Eb.s` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!C77785269A54` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Panda | `Trj/GdSda.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Ransom-WannaCry!BD4A59EEEA77` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5298176` |
| Tencent | `Trojan.Win64.Wanna.a` |
| TrellixENS | `Ransom-WannaCry!BD4A59EEEA77` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-e4f863f0!Eldorado` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| Zillya | `Trojan.Wanna.Win32.27` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `Exploit/EquationDrug.a` |

### [329706c148a26631625f…](https://bazaar.abuse.ch/sample/329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde/)

- **Familie:** QuasarRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Application.Fca.3927
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Application.Fca.3927`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Application.Fca.3927` |
| APEX | `Malicious` |
| AVG | `MSIL:Quasar-A [Rat]` |
| AhnLab-V3 | `Backdoor/Win32.QuasarRAT.R341693` |
| Alibaba | `Backdoor:MSIL/Quasar.e1f7f473` |
| Antiy-AVL | `Trojan/MSIL.Quasar` |
| Arcabit | `Trojan.Application.Fca.DF57` |
| Avast | `MSIL:Quasar-A [Rat]` |
| Avira | `TR/Quasar.A` |
| BitDefender 🛡️ | `Gen:Variant.Application.Fca.3927` |
| Bkav | `W32.Malware.BD2DF64C` |
| CAT-QuickHeal | `Trojan.Generic.TRFH927` |
| CTX | `exe.unknown.generic` |
| ClamAV | `Win.Malware.Generic-9883083-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Quasar.299` |
| ESET-NOD32 | `MSIL/Agent.CLQ trojan` |
| Elastic | `Windows.Generic.Threat` |
| Emsisoft | `Trojan.Agent (A)` |
| F-Secure | `Trojan.TR/Quasar.A` |
| Fortinet | `MSIL/QuasarRat.BPH!tr` |
| GData | `MSIL.Backdoor.Quasar.A` |
| Google | `Detected` |
| Gridinsoft | `Spy.Win32.Keylogger.dd!n` |
| Ikarus | `Backdoor.QuasarRat` |
| Jiangmin | `Trojan.MSIL.aogzw` |
| K7AntiVirus | `Trojan ( 005b1c021 )` |
| K7GW | `Trojan ( 005690671 )` |
| Kaspersky | `HEUR:Trojan.MSIL.Quasar.gen` |
| Kingsoft | `MSIL.Trojan.Quasar.gen` |
| Malwarebytes | `Backdoor.Quasar` |
| MaxSecure | `Trojan.Malware.325358113.susgen` |
| McAfeeD | `Trojan:Win/QuasarRAT.AA` |
| MicroWorld-eScan | `Gen:Variant.Application.Fca.3927` |
| Microsoft 🛡️ | `Backdoor:MSIL/Quasar!atmn` |
| NANO-Antivirus | `Trojan.Win32.Quasar.lelzaq` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Quasar!1.E5F1 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Quasar!6AF89B4A89BE` |
| Sophos | `Troj/Quasar-AF` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Backdoor/W32.DN-Agent.3266048.E` |
| Tencent | `Trojan.MSIL.Quasar.ka` |
| TrellixENS | `GenericRXLX-DS!6AF89B4A89BE` |
| TrendMicro | `Backdoor.MSIL.QUASAR.SMTPTPI` |
| TrendMicro-HouseCall | `Backdoor.MSIL.QUASAR.SMTPTPI` |
| VBA32 | `Trojan.MSIL.Quasar.Heur` |
| VIPRE | `Gen:Variant.Application.Fca.3927` |
| Varist | `W32/MSIL_Troj.BTX.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.B` |
| Webroot | `W32.Trojan.Quasar` |
| Yandex | `Trojan.Agent!sOb3JuaPiQk` |
| Zillya | `Trojan.Agent.Win32.3788330` |
| ZoneAlarm | `Troj/Quasar-AF` |
| alibabacloud | `Backdoor:MSIL/Quasar.server` |
| huorong | `Trojan/MSIL.Obfuscated.g!crit` |

### [ba0f697bbdbabdcb48c3…](https://bazaar.abuse.ch/sample/ba0f697bbdbabdcb48c377aec31dd6c9e09041e952f9903a23a06866cdcdbb88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81674645
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81674645`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81674645` |
| Arcabit | `Trojan.Generic.D4DE4195` |
| BitDefender 🛡️ | `Trojan.GenericKD.81674645` |
| CTX | `msi.remote-access-trojan.connectwise` |
| DrWeb | `Program.RemoteAdmin.975` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.V potentially unsafe application` |
| Emsisoft | `Trojan.GenericKD.81674645 (B)` |
| Fortinet | `Riskware/RemoteAdmin_ConnectWiseControl` |
| GData | `Trojan.GenericKD.81674645` |
| Google | `Detected` |
| Ikarus | `PUA.ConnectWise` |
| Kaspersky | `not-a-virus:UDS:RemoteAdmin.MSIL.ConnectWise.gen` |
| Lionic | `Riskware.Win32.ConnectWise.1!c` |
| McAfeeD | `ti!BA0F697BBDBA` |
| MicroWorld-eScan | `Trojan.GenericKD.81674645` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| NANO-Antivirus | `Riskware.Win32.RemoteAdmin.ljylbz` |
| Rising | `Hacktool.ConnectWise!8.13A88 (CLOUD)` |
| Skyhigh | `ConnectWise` |
| Symantec | `PUA.Gen.2` |
| Tencent | `Msil.Trojan.Connectwise.Nsmw` |
| TrellixENS | `ConnectWise` |
| VBA32 | `Riskware.MSIL.ScreenConnect.Heur` |
| VIPRE | `Trojan.GenericKD.81674645` |
| Varist | `W32/ConnectWise.X.gen!Eldorado` |
| alibabacloud | `Backdoor[rat]:Win/RemoteAdmin.CafpcxiOBisDuBBYsU` |


## Top Tags

- **elf** (82×)
- **Mirai** (59×)
- **upx-dec** (13×)
- **upx** (13×)
- **exe** (7×)
- **enthec** (6×)
- **apk** (5×)
- **sh** (4×)
- **signed** (4×)
- **Gafgyt** (3×)
- **QuasarRAT** (2×)
- **jar** (1×)
- **java** (1×)
- **python** (1×)
- **silentnet** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +16 (44→60)
- ↑ **unbekannt** +12 (22→34)
- neu: **QuasarRAT** (2)
- neu: **FileRepMalware [Misc]** (1)
- neu: **ChiselClient** (1)
- neu: **AsyncRAT** (1)
- ↓ **ConnectWise** -1 (2→1)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +22 (38→60)
- ↑ **unbekannt** +5 (29→34)
- neu: **QuasarRAT** (2)
- neu: **FileRepMalware [Misc]** (1)
- neu: **WannaCry** (1)
- neu: **ChiselClient** (1)
- ↓ **ConnectWise** -1 (2→1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.525 MB |
| σ Dateigröße | 4.059 MB |
| Ø Risiko-Score | 66.6/100 |
| Ø Klassifikations-Konfidenz | 76.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 64/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 33 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:17 | [f1376b1e04de…](https://bazaar.abuse.ch/sample/f1376b1e04deff8446c519063e390a8de951e3e4074f1b60b182da2bb5fc807c/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 12:05 | [7f8844fed776…](https://bazaar.abuse.ch/sample/7f8844fed77616b081d20219cc7e59ebcf0ab44333e5c4b635a161a3f5c412ff/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 12:05 | [685d91b7880c…](https://bazaar.abuse.ch/sample/685d91b7880c6877fc0b5ab0430c503373b4280eca139cb5db2b1d50c176bc85/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 12:01 | [eaf9a32f13fb…](https://bazaar.abuse.ch/sample/eaf9a32f13fb73cbde90a492c015e6e70dd6134edbf1d114d1a759818f715985/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 12:01 | [7bf62dcbc8c2…](https://bazaar.abuse.ch/sample/7bf62dcbc8c23a9d2962dd875da533f61c4e27259dc494466b51c81cb6e2476e/) | `jar` | unbekannt | 32.4 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.10.2026 12:21 UTC*