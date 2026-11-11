# MalwareBazaar – 11.11.2026 13:47 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **70** |
| Höchster Score | **93.2/100** – 607b43b4c726a7c2… |
| Häufigste Familie | **Mirai** (48x) |
| Häufigster Typ | **elf** (56x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 60 Samples |
| Ø Dateigröße | 2.15 MB (σ=6.82) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 56 | 55.4%  ███████████ |
| `exe` | 19 | 18.8%  ███ |
| `sh` | 8 | 7.9%  █ |
| `js` | 8 | 7.9%  █ |
| `zip` | 3 | 3.0%   |
| `vbs` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `wsf` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 48 | 47.5% |
| 2 | unbekannt | 20 | 19.8% |
| 3 | AgentTesla | 5 | 5.0% |
| 4 | Formbook | 5 | 5.0% |
| 5 | WARDENStealer | 4 | 4.0% |
| 6 | RemcosRAT | 4 | 4.0% |
| 7 | CoinMiner | 2 | 2.0% |
| 8 | PureLogsStealer | 2 | 2.0% |
| 9 | GuLoader | 2 | 2.0% |
| 10 | Hajime | 1 | 1.0% |
| 11 | Panchan | 1 | 1.0% |
| 12 | Prometei | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 49 | 48.5% | 95% |
| Infostealer | 12 | 11.9% | 83% |
| Linux-Malware | 9 | 8.9% | 45% |
| Windows-Malware | 8 | 7.9% | 35% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| RAT | 6 | 5.9% | 92% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Cryptominer | 2 | 2.0% | 75% |
| Loader | 2 | 2.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |
| Android-Malware | 1 | 1.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 70 | 69.3% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 17 | 16.8% |
| 🟢 NIEDRIG | 11 | 10.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [607b43b4c726a7…](https://bazaar.abuse.ch/sample/607b43b4c726a7c2b19cf80dff0d9b65586d830a3cb6aeab7515042726fffc6b/) | WannaCry | Ransomware | **93.2** | 🔴 KRITISCH | – | – | ? |
| [f06f83a2ad264d…](https://bazaar.abuse.ch/sample/f06f83a2ad264dcf87934d804873e176b5fa75a896a756d9c69faded7d8d3552/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [a87dab608fa308…](https://bazaar.abuse.ch/sample/a87dab608fa308d8dee66602aa85eb7bb486c28f0d667d4cef9a77e9437f63ec/) | Formbook | Infostealer | **86.5** | 🔴 KRITISCH | – | – | ? |
| [0496d2903b7f29…](https://bazaar.abuse.ch/sample/0496d2903b7f29fe260dee3cdaf20e872c188bd93d28d3a4f5665297c152c496/) | Formbook | Infostealer | **86.5** | 🔴 KRITISCH | – | – | ? |
| [5c61714e8627e6…](https://bazaar.abuse.ch/sample/5c61714e8627e6b739b9a5dc3f5efc751ec56ad91f030cf83880c89793a90330/) | Formbook | Infostealer | **86.1** | 🔴 KRITISCH | – | – | ? |
| [8da846137ba086…](https://bazaar.abuse.ch/sample/8da846137ba0865659a08186092779fe59adf9ac524e26d6a803a264fa06244f/) | Formbook | Infostealer | **86.0** | 🔴 KRITISCH | – | – | ? |
| [70397f327b246f…](https://bazaar.abuse.ch/sample/70397f327b246f58b7b8457ff31d0646d5ab037ac522299283592047a58d4711/) | RemcosRAT | RAT | **85.9** | 🔴 KRITISCH | – | – | ? |
| [ae52bf45261050…](https://bazaar.abuse.ch/sample/ae52bf45261050cb6a69adec5e46bd29253c4bea9d0d0777fc0db2841b43e296/) | RemcosRAT | RAT | **85.9** | 🔴 KRITISCH | – | – | ? |
| [d497027812a587…](https://bazaar.abuse.ch/sample/d497027812a5877711b678936be2c99585cda5640688199314ecb87712598915/) | XWorm | RAT | **85.0** | 🔴 KRITISCH | – | – | ? |
| [809e667d67a568…](https://bazaar.abuse.ch/sample/809e667d67a568e3078df2c1e8a82a3ba0c1b78b6aca48ce567d939ae88f6d99/) | RemcosRAT | RAT | **85.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6438/7936 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6438/7936 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6135/7936 |
| 6 | Kaspersky | 75.5% | 5990/7935 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5653/7932 |
| 9 | Rising | 68.4% | 5428/7936 |
| 10 | Varist | 66.1% | 5243/7931 |
| 11 | Avast | 65.2% | 5170/7932 |
| 12 | AVG | 65.2% | 5170/7931 |
| 13 | Tencent | 65.0% | 5009/7710 |
| 14 | McAfeeD | 61.4% | 4867/7928 |
| 15 | huorong | 60.9% | 4830/7928 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 64 | 63.4% |
| 🪟 Windows | 23 | 22.8% |
| ❓ Unbekannt | 9 | 8.9% |
| 📦 Archiv | 3 | 3.0% |
| 🤖 Android | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 84.2% |
| Drive-By / Exploit-Kit | 10 | 9.9% |
| APK-Sideloading | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 42 | 41.6% |
| 2 | 🇺🇸 US | 14 | 13.9% |
| 3 | 🇫🇷 FR | 7 | 6.9% |
| 4 | 🇦🇹 AT | 7 | 6.9% |
| 5 | 🇨🇭 CH | 6 | 5.9% |
| 6 | 🇳🇱 NL | 5 | 5.0% |
| 7 | 🇭🇺 HU | 4 | 4.0% |
| 8 | 🇪🇸 ES | 4 | 4.0% |
| 9 | 🌐 EG | 3 | 3.0% |
| 10 | 🇸🇪 SE | 3 | 3.0% |
| 11 | 🌐 Unbekannt | 2 | 2.0% |
| 12 | 🌐 PT | 2 | 2.0% |
| 13 | 🇨🇦 CA | 1 | 1.0% |
| 14 | 🇯🇵 JP | 1 | 1.0% |

## MITRE ATT&CK

> 60 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 49 |
| Lateral Movement | 49 |
| Collection | 9 |
| Credential Access | 5 |
| Command and Control | 4 |
| Defense Evasion | 2 |
| Execution | 2 |

<details><summary>f06f83a2ad264dcf8793… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a87dab608fa308d8dee6… – Formbook | 🔴 KRITISCH 86.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>0496d2903b7f29fe260d… – Formbook | 🔴 KRITISCH 86.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>5c61714e8627e6b739b9… – Formbook | 🔴 KRITISCH 86.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [e1413be26bb7fa26ea7f…](https://bazaar.abuse.ch/sample/e1413be26bb7fa26ea7f6589e7643287a9f9997d6bb40ee36cd7219fd85d6778/)

- **Familie:** Mirai
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-DDO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DDO [Trj]` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-DDO [Trj]` |
| Avira | `TR/LINUX.Mirai.DDO` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DDO` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.Y!MTB` |
| Sangfor | `Suspicious.Linux.Save.a` |

### [062125925c51454d7783…](https://bazaar.abuse.ch/sample/062125925c51454d77832af2d3236221b5cbdd6e1b2b2d78d15b792577d340ac/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Hajime-R [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Hajime-R [Trj]` |
| Avast | `ELF:Hajime-R [Trj]` |
| Avast-Mobile | `ELF:Hajime-Q [Trj]` |
| Avira | `TR/LINUX.Hajime.R` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Trojan.TR/LINUX.Hajime.R` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2018-10561.a` |
| McAfeeD | `Trojan:Linux/Mirai.ERM` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner.C12` |
| Rising | `Backdoor.Mirai/Linux!1.BAFE (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| huorong | `Trojan/Linux.Mirai.q` |

### [237e97f32505a8b226f1…](https://bazaar.abuse.ch/sample/237e97f32505a8b226f1ce873642cfe85c9ab32760682a2a57e606ebdedcde5d/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-COW [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-COW [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-COW [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `TR/LINUX.Mirai.COW` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.COW` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Varist | `E32/Mirai.DK.gen!Eldorado` |
| huorong | `Backdoor/Linux.Mirai.fo` |

### [372f48cfe2a859acc997…](https://bazaar.abuse.ch/sample/372f48cfe2a859acc997c784cb56ae4786a72eb399dd283cbfc15417dd36f979/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 59 von 75 Engines (78.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (59/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
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
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.DR5DOL` |
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
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Ve5q` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (55×)
- **Mirai** (49×)
- **Torii** (25×)
- **exe** (18×)
- **cowrie** (17×)
- **honeypot** (17×)
- **sh** (8×)
- **js** (8×)
- **arm** (7×)
- **upx** (6×)
- **AgentTesla** (5×)
- **Prometei** (5×)
- **upx-dec** (5×)
- **Formbook** (5×)
- **Hajime** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +34 (14→48)
- ↓ **unbekannt** -11 (31→20)
- ↑ **AgentTesla** +4 (1→5)
- ↑ **Formbook** +4 (1→5)
- ↑ **WARDENStealer** +2 (2→4)
- ↑ **RemcosRAT** +1 (3→4)
- ↑ **CoinMiner** +1 (1→2)
- neu: **PureLogsStealer** (2)
- neu: **Hajime** (1)
- weg: **SilentNet** (war 5)
- weg: **SalatStealer** (war 17)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +27 (21→48)
- ↓ **unbekannt** -12 (32→20)
- ↑ **AgentTesla** +2 (3→5)
- ↑ **Formbook** +3 (2→5)
- ↑ **WARDENStealer** +1 (3→4)
- ↑ **RemcosRAT** +2 (2→4)
- ↑ **CoinMiner** +1 (1→2)
- neu: **PureLogsStealer** (2)
- neu: **GuLoader** (2)
- neu: **Hajime** (1)
- weg: **SalatStealer** (war 4)
- weg: **VShell** (war 2)
- weg: **RevStealer** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.146 MB |
| σ Dateigröße | 6.816 MB |
| Ø Risiko-Score | 69.1/100 |
| Ø Klassifikations-Konfidenz | 75.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 60/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 46 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:40 | [0d3782e22842…](https://bazaar.abuse.ch/sample/0d3782e228425031ded3f3979145a565976f76458884655f3cf0c0ebf9657d87/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 13:15 | [6b7288d121c5…](https://bazaar.abuse.ch/sample/6b7288d121c5632d9e1388ff4c5a96b4d212032bad66cda9a389ca4c6f187d5b/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 13:13 | [e1413be26bb7…](https://bazaar.abuse.ch/sample/e1413be26bb7fa26ea7f6589e7643287a9f9997d6bb40ee36cd7219fd85d6778/) | `elf` | Mirai | 84.2 | 16.0% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 13:08 | [58253d3775b7…](https://bazaar.abuse.ch/sample/58253d3775b7cbb5fc65acf6cced3d3690b0db26cb52ecb7cf3d0da3c4451e24/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 13:05 | [3b71fa7bd09b…](https://bazaar.abuse.ch/sample/3b71fa7bd09b62b79aa4becbcfe4de7dac3cf3b29bdc04351a0b2400024d5bd7/) | `elf` | Mirai | 83.9 | – | – | 🌐CH |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.11.2026 13:47 UTC*