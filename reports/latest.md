# MalwareBazaar – 14.11.2026 00:46 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **74** |
| Höchster Score | **89.1/100** – 0c93e7fdddca0d2b… |
| Häufigste Familie | **Mirai** (38x) |
| Häufigster Typ | **exe** (46x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 42 Samples |
| Ø Dateigröße | 2.40 MB (σ=5.13) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 46 | 45.5%  █████████ |
| `elf` | 41 | 40.6%  ████████ |
| `sh` | 4 | 4.0%   |
| `ps1` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `py` | 2 | 2.0%   |
| `msi` | 1 | 1.0%   |
| `rtf` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 38 | 37.6% |
| 2 | unbekannt | 23 | 22.8% |
| 3 | WARDENStealer | 15 | 14.9% |
| 4 | RevStealer | 8 | 7.9% |
| 5 | CoinMiner | 3 | 3.0% |
| 6 | RemusStealer | 3 | 3.0% |
| 7 | ConnectWise | 2 | 2.0% |
| 8 | RustyStealer | 1 | 1.0% |
| 9 | AdaptixC2 | 1 | 1.0% |
| 10 | ValleyRAT | 1 | 1.0% |
| 11 | njrat | 1 | 1.0% |
| 12 | VShell | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 38 | 37.6% | 95% |
| Infostealer | 28 | 27.7% | 76% |
| Windows-Malware | 10 | 9.9% | 35% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| RAT | 6 | 5.9% | 85% |
| Cryptominer | 3 | 3.0% | 75% |
| Android-Malware | 2 | 2.0% | 45% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Post-Exploitation | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |
| Maldoc | 1 | 1.0% | 35% |
| Backdoor | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 74 | 73.3% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 15 | 14.9% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [0c93e7fdddca0d…](https://bazaar.abuse.ch/sample/0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be/) | njrat | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [4e59bfbaec7888…](https://bazaar.abuse.ch/sample/4e59bfbaec788854ed1a2429c5c828fce0436012f0970a5c6a3c9449ef067075/) | Vidar | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [ced186a8664f5e…](https://bazaar.abuse.ch/sample/ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900/) | AdaptixC2 | Post-Exploitat | **86.7** | 🔴 KRITISCH | – | – | ? |
| [7dd12910e5f009…](https://bazaar.abuse.ch/sample/7dd12910e5f009c04e26eab8ef4c5a95e021922b40407140dd4325e81c3b4a60/) | QuasarRAT | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [2683747e3aa55b…](https://bazaar.abuse.ch/sample/2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [5999831c9aabcf…](https://bazaar.abuse.ch/sample/5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [7993520ebfdedb…](https://bazaar.abuse.ch/sample/7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [77a51a49cae68e…](https://bazaar.abuse.ch/sample/77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [12bc981ef4da1f…](https://bazaar.abuse.ch/sample/12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [89eb05e0de1d4b…](https://bazaar.abuse.ch/sample/89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6472/7975 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6472/7975 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6166/7975 |
| 6 | Kaspersky | 75.5% | 6021/7974 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5680/7971 |
| 9 | Rising | 68.4% | 5457/7975 |
| 10 | Varist | 66.1% | 5267/7970 |
| 11 | Avast | 65.2% | 5195/7971 |
| 12 | AVG | 65.2% | 5195/7970 |
| 13 | Tencent | 65.0% | 5037/7749 |
| 14 | McAfeeD | 61.4% | 4895/7967 |
| 15 | huorong | 60.9% | 4850/7967 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 49 | 48.5% |
| 🐧 Linux | 46 | 45.5% |
| ❓ Unbekannt | 3 | 3.0% |
| 🤖 Android | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 96 | 95.0% |
| APK-Sideloading | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 41 | 40.6% |
| 2 | 🇺🇸 US | 25 | 24.8% |
| 3 | 🇫🇷 FR | 23 | 22.8% |
| 4 | 🇨🇿 CZ | 3 | 3.0% |
| 5 | 🇯🇵 JP | 2 | 2.0% |
| 6 | 🇳🇱 NL | 2 | 2.0% |
| 7 | 🇬🇧 GB | 2 | 2.0% |
| 8 | 🌐 PT | 1 | 1.0% |
| 9 | 🇧🇷 BR | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 42 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 38 |
| Lateral Movement | 38 |
| Command and Control | 3 |
| Collection | 3 |
| Exfiltration | 2 |
| Credential Access | 1 |

<details><summary>0c93e7fdddca0d2bb2e9… – njrat | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>4e59bfbaec788854ed1a… – Vidar | 🔴 KRITISCH 87.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>7dd12910e5f009c04e26… – QuasarRAT | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2683747e3aa55b68c8ed… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [8605176d7b9e62388acf…](https://bazaar.abuse.ch/sample/8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5/)

- **Familie:** ConnectWise
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ConnectWise
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Program.RemoteAdmin.975` |
| Google | `Detected` |
| Ikarus | `PUA.ScreenConnect` |
| Kaspersky | `not-a-virus:HEUR:RemoteAdmin.Win32.ConnectWise.gen` |
| NANO-Antivirus | `Riskware.Win32.RemoteAdmin.ljylbz` |
| Rising | `Hacktool.ConnectWiseControl!8.17790 (CLOUD)` |
| Skyhigh | `ConnectWise` |
| Tencent | `OB:Backdoor.Win32.ScreenConnect.16009294` |
| VBA32 | `Riskware.MSIL.ScreenConnect.Heur` |
| Varist | `W32/ConnectWise.O.gen!Eldorado` |
| VirIT | `Trojan.MSI.Agent.JMG` |
| Zillya | `Tool.ConnectWise.Win32.234` |
| huorong | `TrojanDropper/HTML.Agent.v!crit` |

### [ac12b28cadd1e8822927…](https://bazaar.abuse.ch/sample/ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39502263` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39502263 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39502263` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [349a204218ee8afdeff6…](https://bazaar.abuse.ch/sample/349a204218ee8afdeff6c11b802c80310da5b7ea0c71ec90a2ed0e4ad9677ec5/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `Linux/Mirai.REAL!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [33dcf137bba16f0bcad0…](https://bazaar.abuse.ch/sample/33dcf137bba16f0bcad004377f3a08f6d1597f58c36ecbec42d9e7a2b6c386c0/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-8041698-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14339 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| alibabacloud | `DDoS:Linux/Mirai.CGY` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (45×)
- **elf** (41×)
- **Mirai** (38×)
- **Torii** (26×)
- **WARDENStealer** (15×)
- **Prometei** (9×)
- **stealer** (9×)
- **RevStealer** (8×)
- **Warden** (6×)
- **cowrie** (4×)
- **honeypot** (4×)
- **upx-dec** (4×)
- **upx** (4×)
- **signed** (3×)
- **CoinMiner** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +16 (22→38)
- ↓ **unbekannt** -5 (28→23)
- ↑ **WARDENStealer** +7 (8→15)
- ↑ **RevStealer** +3 (5→8)
- ↑ **CoinMiner** +2 (1→3)
- neu: **RemusStealer** (3)
- ↓ **ConnectWise** -1 (3→2)
- ↓ **RustyStealer** -1 (2→1)
- neu: **AdaptixC2** (1)
- neu: **ValleyRAT** (1)
- weg: **GuLoader** (war 3)
- weg: **AgentTesla** (war 3)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +8 (30→38)
- ↓ **unbekannt** -3 (26→23)
- ↑ **WARDENStealer** +11 (4→15)
- ↑ **RevStealer** +7 (1→8)
- ↑ **CoinMiner** +2 (1→3)
- neu: **RemusStealer** (3)
- ↑ **ConnectWise** +1 (1→2)
- neu: **RustyStealer** (1)
- neu: **AdaptixC2** (1)
- neu: **ValleyRAT** (1)
- weg: **Snowlight** (war 3)
- weg: **SalatStealer** (war 6)
- weg: **Formbook** (war 2)
- weg: **AgentTesla** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.401 MB |
| σ Dateigröße | 5.131 MB |
| Ø Risiko-Score | 71.3/100 |
| Ø Klassifikations-Konfidenz | 73.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 42/101 |
| Eindeutige Familien | 16 |
| Eindeutige Tags | 47 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:41 | [394b2b404ecd…](https://bazaar.abuse.ch/sample/394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9/) | `sh` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 00:38 | [4cb918bdd53f…](https://bazaar.abuse.ch/sample/4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 00:37 | [cf690ffe7647…](https://bazaar.abuse.ch/sample/cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 00:37 | [ffbb2d190c87…](https://bazaar.abuse.ch/sample/ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69/) | `exe` | WARDENStealer | 82.1 | – | – | 🇺🇸US |
| 00:36 | [a7f0dd6c6c8c…](https://bazaar.abuse.ch/sample/a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.11.2026 00:46 UTC*