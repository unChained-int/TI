# MalwareBazaar – 12.10.2026 05:02 UTC

Dieser Run hat **80 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **81** |
| Kritisch (≥75) | **55** |
| Höchster Score | **97.2/100** – 9213b83aa454f4c4… |
| Häufigste Familie | **Mirai** (40x) |
| Häufigster Typ | **elf** (51x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 46 Samples |
| Ø Dateigröße | 3.37 MB (σ=11.48) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 51 | 63.0%  ████████████ |
| `exe` | 21 | 25.9%  █████ |
| `sh` | 4 | 4.9%   |
| `zip` | 2 | 2.5%   |
| `js` | 1 | 1.2%   |
| `macho` | 1 | 1.2%   |
| `ps1` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 40 | 49.4% |
| 2 | unbekannt | 26 | 32.1% |
| 3 | Formbook | 3 | 3.7% |
| 4 | NanoCore | 2 | 2.5% |
| 5 | WannaCry | 1 | 1.2% |
| 6 | MimiKatz | 1 | 1.2% |
| 7 | AMOS | 1 | 1.2% |
| 8 | BlankGrabber | 1 | 1.2% |
| 9 | PythonStealer | 1 | 1.2% |
| 10 | Gafgyt | 1 | 1.2% |
| 11 | RustyStealer | 1 | 1.2% |
| 12 | ELF:Flooder-ADS [Trj] | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 41 | 50.6% | 95% |
| Linux-Malware | 10 | 12.3% | 45% |
| Infostealer | 9 | 11.1% | 84% |
| Windows-Malware | 5 | 6.2% | 35% |
| Loader | 4 | 4.9% | 75% |
| RAT | 4 | 4.9% | 90% |
| Andere / Unbekannt | 4 | 4.9% | 20% |
| Skript/Dropper | 2 | 2.5% | 35% |
| Ransomware | 1 | 1.2% | 95% |
| Trojaner | 1 | 1.2% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 55 | 67.9% |
| 🟠 HOCH | 5 | 6.2% |
| 🟡 MITTEL | 17 | 21.0% |
| 🟢 NIEDRIG | 4 | 4.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [9213b83aa454f4…](https://bazaar.abuse.ch/sample/9213b83aa454f4c45e0d764042ac1a3d6f2f37d22aa95b660c81b8009e0d4b06/) | WannaCry | Ransomware | **97.2** | 🔴 KRITISCH | – | – | ? |
| [0404070ceb269b…](https://bazaar.abuse.ch/sample/0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26/) | Formbook | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [d9e039206aab0d…](https://bazaar.abuse.ch/sample/d9e039206aab0dffab3ffd6f5f37f2547ce6093bacafada63fc1e0de9a3b72da/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [17b6b0db4462db…](https://bazaar.abuse.ch/sample/17b6b0db4462dbb0ae69fa5aeeee59ca82347760354b9e61ffa1d4f24f002931/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [1d90627d5213dc…](https://bazaar.abuse.ch/sample/1d90627d5213dc9fef971a7c945e1aa4c9c84a5bf14a69cf0f14775908843b10/) | AMOS | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [5eb6513070383d…](https://bazaar.abuse.ch/sample/5eb6513070383d331f1d7690bf0cec69be82786cda4c2e65ac0d938fcbc36cb8/) | NanoCore | RAT | **86.0** | 🔴 KRITISCH | – | – | ? |
| [6084d04942d79a…](https://bazaar.abuse.ch/sample/6084d04942d79a30e426b464f2e88f5f7a69365f8b9b6429c7a1c7bcdf61a1cc/) | NanoCore | RAT | **86.0** | 🔴 KRITISCH | – | – | ? |
| [1c932818d46883…](https://bazaar.abuse.ch/sample/1c932818d468835c5bdb9277bdbddee4d9acef206a1da5cfd6600cae6ff3926a/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [ff5ab417d41ff6…](https://bazaar.abuse.ch/sample/ff5ab417d41ff6ab5fdfd03daea132cc11f5707ad3e801166748a1da3383443e/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [889f9f66e43430…](https://bazaar.abuse.ch/sample/889f9f66e43430fa4fe696dd50912f555eb0b8e998942e7918b0561e01883dbe/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5931/7331 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5931/7331 |
| 3 | ESET-NOD32 | 77.4% | 5674/7331 |
| 4 | Kaspersky | 76.3% | 5595/7330 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5248/7328 |
| 8 | Rising | 68.7% | 5038/7331 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4870/7327 |
| 11 | Tencent | 65.2% | 4635/7105 |
| 12 | Avast | 65.1% | 4767/7327 |
| 13 | AVG | 65.1% | 4767/7326 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4494/7324 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 55 | 67.9% |
| 🪟 Windows | 22 | 27.2% |
| 📦 Archiv | 2 | 2.5% |
| ❓ Unbekannt | 1 | 1.2% |
| 🍎 macOS | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 73 | 90.1% |
| MaaS-Loader | 3 | 3.7% |
| C2 / Nachladen | 3 | 3.7% |
| Drive-By / Exploit-Kit | 1 | 1.2% |
| Exploit / N-Day | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 41 | 50.6% |
| 2 | 🇳🇱 NL | 16 | 19.8% |
| 3 | 🇺🇸 US | 12 | 14.8% |
| 4 | 🇨🇭 CH | 4 | 4.9% |
| 5 | 🌐 Unbekannt | 3 | 3.7% |
| 6 | 🇧🇷 BR | 3 | 3.7% |
| 7 | 🌐 TH | 2 | 2.5% |

## MITRE ATT&CK

> 46 von 81 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 40 |
| Lateral Movement | 40 |
| Collection | 7 |
| Credential Access | 4 |
| Command and Control | 2 |
| Exfiltration | 2 |

<details><summary>0404070ceb269b1590a7… – Formbook | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>d9e039206aab0dffab3f… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>17b6b0db4462dbb0ae69… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9372674060b0b5a68083…](https://bazaar.abuse.ch/sample/9372674060b0b5a68083f1159e95d228be271f4dae6faeadb2c034d28fe6cf57/)

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
| AhnLab-V3 | `Trojan/Linux.Mirai.SE302` |
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
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ns` |
| Kingsoft | `Linux.Backdoor.elf.2023761` |
| MicroWorld-eScan | `Gen:Variant.Linux.Agent.6` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.DE80 (CLASSIC)` |
| Skyhigh | `LINUX/Mirai-FRY!718410934F00` |
| Tencent | `Backdoor.Linux.Zhtrap.dhyra` |
| TrellixENS | `LINUX/Mirai-FRY!718410934F00` |
| VIPRE | `Gen:Variant.Linux.Agent.6` |
| alibabacloud | `DDoS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.q` |

### [28bbd5353459848870e1…](https://bazaar.abuse.ch/sample/28bbd5353459848870e10e2696a85ff9fa67c33e5e98e6097de88965993b1ac0/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10760` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Exploit.Linux.DirtyFrag` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Trojan/Linux.Mirai.f` |

### [d535179fb5d5cd892cdc…](https://bazaar.abuse.ch/sample/d535179fb5d5cd892cdce91c28f4df1ca932ef7f2ef20d70b632cfff44d61bbe/)

- **Familie:** ELF:Flooder-ADS [Trj]
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Flooder-ADS [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Flooder-ADS [Trj]` |
| Antiy-AVL | `Trojan[Miner]/Linux.CoinMiner` |
| Avast | `ELF:Flooder-ADS [Trj]` |
| DrWeb | `Linux.Siggen.12973` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.wo` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| Tencent | `OB:Trojan.Linux.Catstorm.Catra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/CoinMiner.dm` |

### [2dbacf84101591035901…](https://bazaar.abuse.ch/sample/2dbacf84101591035901a40fa9adf5e2b6ed98d9831bf14b2fe6f3ce94169db0/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2021-36260-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2021-36260-A [Expl]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:CVE-2021-36260-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2021-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10760` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2021-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Trojan/Linux.Mirai.f` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 57 von 75 Engines (76.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (57/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.unknown.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.Remcos!1.147CC (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusT.FMPU` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| Zillya | `Trojan.Rescoms.Win32.2903` |
| ZoneAlarm | `Troj/Remcos-APM` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (43×)
- **Mirai** (37×)
- **exe** (20×)
- **ClickFix** (5×)
- **upx-dec** (4×)
- **Gafgyt** (4×)
- **upx** (4×)
- **FakeCaptcha** (4×)
- **Formbook** (3×)
- **signed** (3×)
- **sideloading** (3×)
- **zip** (2×)
- **cowrie** (2×)
- **honeypot** (2×)
- **sh** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +3 (37→40)
- ↓ **unbekannt** -4 (30→26)
- ↑ **Formbook** +2 (1→3)
- neu: **NanoCore** (2)
- neu: **MimiKatz** (1)
- neu: **AMOS** (1)
- neu: **BlankGrabber** (1)
- neu: **PythonStealer** (1)
- ↓ **Gafgyt** -1 (2→1)
- weg: **AsyncRAT** (war 2)
- weg: **LxBaseRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +1 (39→40)
- ↓ **unbekannt** -5 (31→26)
- ↑ **Formbook** +2 (1→3)
- neu: **NanoCore** (2)
- neu: **MimiKatz** (1)
- neu: **AMOS** (1)
- neu: **BlankGrabber** (1)
- neu: **PythonStealer** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.368 MB |
| σ Dateigröße | 11.485 MB |
| Ø Risiko-Score | 69.5/100 |
| Ø Klassifikations-Konfidenz | 77.1% |
| Samples mit VT | 5/81 |
| Samples mit MITRE | 46/81 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 51 |
| Unbekannte Familien | 4 (4.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:53 | [1c932818d468…](https://bazaar.abuse.ch/sample/1c932818d468835c5bdb9277bdbddee4d9acef206a1da5cfd6600cae6ff3926a/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 04:50 | [9372674060b0…](https://bazaar.abuse.ch/sample/9372674060b0b5a68083f1159e95d228be271f4dae6faeadb2c034d28fe6cf57/) | `elf` | Mirai | 79.2 | 37.3% | 🟡 SCHWACH ERKANNT | 🇳🇱NL |
| 04:49 | [ff5ab417d41f…](https://bazaar.abuse.ch/sample/ff5ab417d41ff6ab5fdfd03daea132cc11f5707ad3e801166748a1da3383443e/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 04:40 | [2b9eaacac67f…](https://bazaar.abuse.ch/sample/2b9eaacac67f1bb69042d4618e7a2e56385e2032726f7f3547b34378b47a70d0/) | `js` | unbekannt | 38.8 | – | – | 🌐TH |
| 04:40 | [7e2ad0ec1f15…](https://bazaar.abuse.ch/sample/7e2ad0ec1f150f9dd7b933d817eeadd7ef42219f1bbd8f26d722dc5ee4e8260f/) | `zip` | unbekannt | 74.8 | – | – | 🌐TH |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.10.2026 05:02 UTC*