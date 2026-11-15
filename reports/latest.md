# MalwareBazaar – 15.11.2026 19:38 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **81** |
| Höchster Score | **87.8/100** – b7db8b116f3b023b… |
| Häufigste Familie | **Mirai** (70x) |
| Häufigster Typ | **elf** (72x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 72 Samples |
| Ø Dateigröße | 4.77 MB (σ=17.10) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 72 | 71.3%  ██████████████ |
| `exe` | 17 | 16.8%  ███ |
| `jar` | 6 | 5.9%  █ |
| `msi` | 3 | 3.0%   |
| `zip` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 70 | 69.3% |
| 2 | unbekannt | 14 | 13.9% |
| 3 | WARDENStealer | 6 | 5.9% |
| 4 | SilentNet | 5 | 5.0% |
| 5 | RustyStealer | 2 | 2.0% |
| 6 | Prometei | 2 | 2.0% |
| 7 | njrat | 1 | 1.0% |
| 8 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 70 | 69.3% | 95% |
| Windows-Malware | 11 | 10.9% | 35% |
| Infostealer | 9 | 8.9% | 75% |
| Andere / Unbekannt | 6 | 5.9% | 20% |
| RAT | 2 | 2.0% | 95% |
| Linux-Malware | 2 | 2.0% | 45% |
| Backdoor | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 81 | 80.2% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 13 | 12.9% |
| 🟢 NIEDRIG | 6 | 5.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b7db8b116f3b02…](https://bazaar.abuse.ch/sample/b7db8b116f3b023b2756d4628c0af9b3d2b1286a9729b0cfe975cefe8a3f06d4/) | njrat | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [708a6f89f3c1ae…](https://bazaar.abuse.ch/sample/708a6f89f3c1aef35cabfad0e06a1dc273f5677e76c885d28321d05d6127015e/) | unbekannt | Backdoor | **84.5** | 🔴 KRITISCH | – | – | ? |
| [a2161204017e45…](https://bazaar.abuse.ch/sample/a2161204017e4533d41c1ee214756be3f4c1060bb5b67b6ebecfd00a474fb87d/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [cab661ad894801…](https://bazaar.abuse.ch/sample/cab661ad894801938f1392b1e44200780099e9568b73fa052ff2abfe9521cc0d/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [0aa093ae2f2e5c…](https://bazaar.abuse.ch/sample/0aa093ae2f2e5c3438da6b9b4f7f70eec5e4b115fb20f1f769b05df540959e8c/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [3647305116e2d1…](https://bazaar.abuse.ch/sample/3647305116e2d127f8de85a648245f3e55800b084a5a6797789165810c69539f/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [14420e42cbf835…](https://bazaar.abuse.ch/sample/14420e42cbf835f594deab40fdeea5b06cc8d5c4285d5a630b0479890538c184/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [100b6666b703ee…](https://bazaar.abuse.ch/sample/100b6666b703ee1df0fe809dfe12d562e6f2ab7fb775fbf590e3dcaa69a8fa90/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [3a273fdcee7c90…](https://bazaar.abuse.ch/sample/3a273fdcee7c907407b7fbd7b00fa9c9b8d8959d5dd2644c7fafabedb81cd7b6/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [37993161fa3bb5…](https://bazaar.abuse.ch/sample/37993161fa3bb50db62a4f6d343ba17626f8b17dfe88aaeada5b72d7b680293f/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6496/8004 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6496/8004 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6189/8004 |
| 6 | Kaspersky | 75.5% | 6042/8003 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5701/8000 |
| 9 | Rising | 68.4% | 5478/8004 |
| 10 | Varist | 66.1% | 5285/7999 |
| 11 | Avast | 65.2% | 5213/8000 |
| 12 | AVG | 65.2% | 5213/7999 |
| 13 | Tencent | 65.0% | 5059/7778 |
| 14 | McAfeeD | 61.5% | 4915/7996 |
| 15 | huorong | 60.8% | 4864/7996 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 73 | 72.3% |
| 🪟 Windows | 21 | 20.8% |
| ❓ Unbekannt | 6 | 5.9% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| Trojanisierte Software | 3 | 3.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 71 | 70.3% |
| 2 | 🇺🇸 US | 13 | 12.9% |
| 3 | 🇧🇷 BR | 8 | 7.9% |
| 4 | 🇳🇱 NL | 3 | 3.0% |
| 5 | 🇫🇷 FR | 3 | 3.0% |
| 6 | 🇨🇭 CH | 2 | 2.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 72 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 70 |
| Lateral Movement | 70 |
| Command and Control | 2 |
| Collection | 2 |

<details><summary>b7db8b116f3b023b2756… – njrat | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>a2161204017e4533d41c… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>cab661ad894801938f13… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>0aa093ae2f2e5c3438da… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [2ebaa12598cdd8f4dce5…](https://bazaar.abuse.ch/sample/2ebaa12598cdd8f4dce59b309c13fe0c2b849f1a60a079686a36068eeb97d0ee/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.hxrf` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.P!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B75 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.Sh0ra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [a2e5c8bdf9d9bcea6b7a…](https://bazaar.abuse.ch/sample/a2e5c8bdf9d9bcea6b7ad5e3347837ff9382ca168f1ead5b0fb39ebbb612be70/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9806` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FS!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B75 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [2136e9a68ddf468767fd…](https://bazaar.abuse.ch/sample/2136e9a68ddf468767fd63950a0c2d5acc309256c0f7a6f0b844e7b9a5796662/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B75 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [dc5c23a8fc6ddbfead93…](https://bazaar.abuse.ch/sample/dc5c23a8fc6ddbfead93e10c315326754e3f57ef2cd2aec38b72807134441c7a/)

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
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9806` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B75 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
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

- **elf** (72×)
- **Mirai** (70×)
- **Torii** (63×)
- **exe** (16×)
- **Prometei** (8×)
- **SilentNet** (8×)
- **jar** (7×)
- **WARDENStealer** (6×)
- **stealer** (5×)
- **Warden** (4×)
- **signed** (4×)
- **msi** (3×)
- **upx-dec** (2×)
- **upx** (2×)
- **HYPERFINEX** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +21 (49→70)
- ↓ **unbekannt** -19 (33→14)
- ↑ **WARDENStealer** +3 (3→6)
- neu: **SilentNet** (5)
- neu: **RustyStealer** (2)
- neu: **Prometei** (2)
- weg: **ValleyRAT** (war 2)
- weg: **RevStealer** (war 2)
- weg: **ConnectWise** (war 2)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +34 (36→70)
- ↓ **unbekannt** -12 (26→14)
- ↑ **WARDENStealer** +2 (4→6)
- ↑ **SilentNet** +4 (1→5)
- neu: **RustyStealer** (2)
- neu: **Prometei** (2)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **SalatStealer** (war 7)
- weg: **Snowlight** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.775 MB |
| σ Dateigröße | 17.101 MB |
| Ø Risiko-Score | 73.4/100 |
| Ø Klassifikations-Konfidenz | 81.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 72/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 6 (5.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:31 | [708a6f89f3c1…](https://bazaar.abuse.ch/sample/708a6f89f3c1aef35cabfad0e06a1dc273f5677e76c885d28321d05d6127015e/) | `exe` | unbekannt | 84.5 | – | – | 🌐CH |
| 19:25 | [a2161204017e…](https://bazaar.abuse.ch/sample/a2161204017e4533d41c1ee214756be3f4c1060bb5b67b6ebecfd00a474fb87d/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 19:20 | [297a33e3cafb…](https://bazaar.abuse.ch/sample/297a33e3cafba806b70e3f0cf9b1310374075f0ba4a27089ef903e1c4d4435c0/) | `exe` | WARDENStealer | 82.0 | – | – | 🇳🇱NL |
| 19:19 | [c553b06361e5…](https://bazaar.abuse.ch/sample/c553b06361e5161092f9e4bdbc0ea2521133e520620852daf76242a961492ab6/) | `exe` | WARDENStealer | 81.9 | – | – | 🇺🇸US |
| 19:18 | [4ea58e7c2b13…](https://bazaar.abuse.ch/sample/4ea58e7c2b134e7ddc0a7c4013c50544eeb27644c2affbdd30d37439a23e30b7/) | `exe` | WARDENStealer | 81.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.11.2026 19:38 UTC*