# MalwareBazaar – 21.10.2026 18:29 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **57** |
| Höchster Score | **89.4/100** – 06aa951ad5384f9a… |
| Häufigste Familie | **Mirai** (52x) |
| Häufigster Typ | **elf** (80x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 53 Samples |
| Ø Dateigröße | 0.79 MB (σ=1.91) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 80 | 79.2%  ███████████████ |
| `sh` | 7 | 6.9%  █ |
| `exe` | 5 | 5.0%   |
| `js` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `bat` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 52 | 51.5% |
| 2 | unbekannt | 42 | 41.6% |
| 3 | DDoSAgent | 3 | 3.0% |
| 4 | ELF:Agent-ETO [Trj] | 1 | 1.0% |
| 5 | ConnectWise | 1 | 1.0% |
| 6 | NetSupport | 1 | 1.0% |
| 7 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 56 | 55.4% | 93% |
| Linux-Malware | 27 | 26.7% | 45% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Skript/Dropper | 5 | 5.0% | 35% |
| Windows-Malware | 4 | 4.0% | 35% |
| Infostealer | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |
| RAT | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 57 | 56.4% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 35 | 34.7% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [06aa951ad5384f…](https://bazaar.abuse.ch/sample/06aa951ad5384f9af7cbfa10692181cf622effa8d3840d62e3c1f37072465c04/) | NetSupport | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [ee3daaf459b2e9…](https://bazaar.abuse.ch/sample/ee3daaf459b2e9168f8701dbc23b6927c70623de97884c3ae43b53ca06ef3b8d/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [edf351f12fa7d3…](https://bazaar.abuse.ch/sample/edf351f12fa7d3299ef99abf60bb75efd5d53d7984f87302df86d46c03752be6/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [92af213632499a…](https://bazaar.abuse.ch/sample/92af213632499ac45568289e53075013615bf44ff93bbe7f131807a02866334a/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [74f0dd12db39cf…](https://bazaar.abuse.ch/sample/74f0dd12db39cfe876d961d629df4eea463d2499cddc1b12c57d036f53dc7206/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [b1110c6835b562…](https://bazaar.abuse.ch/sample/b1110c6835b5620df7f3feb754ff5e83e3349e2112dc33c439743ae9e3aebbfc/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [894f8812b92a1b…](https://bazaar.abuse.ch/sample/894f8812b92a1b3fffff5ac2686c75db677180387edd41af6aea60c5ebf76e95/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [0be273779ab4cc…](https://bazaar.abuse.ch/sample/0be273779ab4cc6cebd141822b211480e1769bc8bb3b66e8b9c94a2b511687d2/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [b7bef9028eff17…](https://bazaar.abuse.ch/sample/b7bef9028eff17a5fabb56a1885de02e2706caee5af28d7f816983518c1c730b/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [94b731c3731bbd…](https://bazaar.abuse.ch/sample/94b731c3731bbd2468eac5844a045ce03831e689f6487939b8d96e8a60d30a9a/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6098/7532 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6098/7532 |
| 3 | ESET-NOD32 | 77.3% | 5823/7532 |
| 4 | Kaspersky | 76.2% | 5735/7531 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5374/7529 |
| 8 | Rising | 68.6% | 5170/7532 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4986/7528 |
| 11 | Avast | 65.2% | 4911/7528 |
| 12 | AVG | 65.2% | 4911/7527 |
| 13 | Tencent | 65.1% | 4757/7306 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4614/7525 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 87 | 86.1% |
| 🪟 Windows | 7 | 6.9% |
| ❓ Unbekannt | 4 | 4.0% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 97 | 96.0% |
| Drive-By / Exploit-Kit | 3 | 3.0% |
| C2 / Nachladen | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇦🇹 AT | 43 | 42.6% |
| 2 | 🇺🇸 US | 37 | 36.6% |
| 3 | 🇳🇱 NL | 10 | 9.9% |
| 4 | 🇪🇸 ES | 7 | 6.9% |
| 5 | 🇩🇪 DE | 2 | 2.0% |
| 6 | 🌐 DK | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 53 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 52 |
| Lateral Movement | 52 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>06aa951ad5384f9af7cb… – NetSupport | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Collection | [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture |

</details>
<details><summary>ee3daaf459b2e9168f87… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>edf351f12fa7d3299ef9… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>92af213632499ac45568… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>74f0dd12db39cfe876d9… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [201061c0e5cceec82737…](https://bazaar.abuse.ch/sample/201061c0e5cceec82737dc417c0cafed8fb29378e7623344ff3055681d5b098d/)

- **Familie:** ELF:Agent-ETO [Trj]
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Agent-ETO [Trj]` |
| ClamAV | `Unix.Trojan.Mirai-10056451-0` |
| DrWeb | `Linux.DDoS.2725` |
| ESET-NOD32 | `Linux/DDoS.Agent.JH trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.DDoS` |
| Kaspersky | `HEUR:Trojan-DDoS.Linux.Agent.av` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.DDOS/Linux!1.14316 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.DDoS.ml` |
| huorong | `Trojan/Linux.DDos.bv` |

### [50f87e2f85a39bfbff1c…](https://bazaar.abuse.ch/sample/50f87e2f85a39bfbff1cbee7d6b648075f010ea6a8738bf001d75a3210ac7128/)

- **Familie:** ConnectWise
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

### [45d984cbf5d105df00c4…](https://bazaar.abuse.ch/sample/45d984cbf5d105df00c45042a0fb00aae45b491e3af9bf09fd1b0cc7b7b3a25a/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-DZ [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-DZ [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.iran.SE356` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avast | `ELF:Gafgyt-DZ [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-8041698-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9874` |
| ESET-NOD32 | `Linux/Gafgyt.BST trojan` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.B!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.bj` |
| Kingsoft | `Script.Troj.Shell.2052936` |
| McAfeeD | `Trojan:Script/Mirai.EET` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13313 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Gafgyt.mbxra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.jx` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **Mirai** (50×)
- **elf** (10×)
- **upx-dec** (10×)
- **upx** (10×)
- **ContagiousInterview** (7×)
- **DPRK** (7×)
- **EtherHiding** (7×)
- **fake-interview** (7×)
- **DDoSAgent** (4×)
- **js** (3×)
- **js.ottercandy** (3×)
- **signed** (2×)
- **exe** (2×)
- **zip** (2×)
- **sh** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +38 (14→52)
- ↓ **unbekannt** -17 (59→42)
- neu: **DDoSAgent** (3)
- neu: **ELF:Agent-ETO [Trj]** (1)
- neu: **ConnectWise** (1)
- neu: **NetSupport** (1)
- weg: **SalatStealer** (war 3)
- weg: **CoinMiner** (war 5)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +30 (22→52)
- ↑ **unbekannt** +8 (34→42)
- neu: **DDoSAgent** (3)
- neu: **ELF:Agent-ETO [Trj]** (1)
- neu: **ConnectWise** (1)
- neu: **NetSupport** (1)
- neu: **PythonStealer** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.791 MB |
| σ Dateigröße | 1.905 MB |
| Ø Risiko-Score | 66.3/100 |
| Ø Klassifikations-Konfidenz | 71.0% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 53/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 28 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:26 | [0c86add553de…](https://bazaar.abuse.ch/sample/0c86add553de8e07ebd4e29d830623f9cbe1c6a25dba0faca22464704b7c400f/) | `elf` | unbekannt | 43.3 | – | – | 🌐AT |
| 18:26 | [f52e8860984b…](https://bazaar.abuse.ch/sample/f52e8860984b0073f335d2268c67e0211a79ad478a7902ee3b6dcd4d55c88f3b/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 18:26 | [8c0cbf3a25cb…](https://bazaar.abuse.ch/sample/8c0cbf3a25cbad99c18b4bcdb78e4f01c094aca50a253bb59bf32c5c9781a593/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 18:26 | [87adaadbd026…](https://bazaar.abuse.ch/sample/87adaadbd026e041e88c5f963b149e09673b883b7e7b85270b69225530489c9f/) | `elf` | unbekannt | 43.3 | – | – | 🌐AT |
| 18:26 | [336dac709d99…](https://bazaar.abuse.ch/sample/336dac709d99f9c3f74905da3e1470dc8e4867d647f68db2cfdb5f8f0d00b58e/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.10.2026 18:29 UTC*