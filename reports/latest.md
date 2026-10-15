# MalwareBazaar – 15.10.2026 08:59 UTC

Dieser Run hat **66 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **67** |
| Kritisch (≥75) | **46** |
| Höchster Score | **90.4/100** – a111ea501acb04ac… |
| Häufigste Familie | **unbekannt** (15x) |
| Häufigster Typ | **exe** (39x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 27 Samples |
| Ø Dateigröße | 2.98 MB (σ=5.16) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 39 | 58.2%  ███████████ |
| `js` | 10 | 14.9%  ██ |
| `elf` | 7 | 10.4%  ██ |
| `zip` | 3 | 4.5%   |
| `bat` | 2 | 3.0%   |
| `wsf` | 2 | 3.0%   |
| `jar` | 1 | 1.5%   |
| `xlsx` | 1 | 1.5%   |
| `vbs` | 1 | 1.5%   |
| `ps1` | 1 | 1.5%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 15 | 22.4% |
| 2 | Formbook | 7 | 10.4% |
| 3 | Mirai | 4 | 6.0% |
| 4 | RemcosRAT | 4 | 6.0% |
| 5 | ValleyRAT | 4 | 6.0% |
| 6 | XWorm | 3 | 4.5% |
| 7 | njrat | 3 | 4.5% |
| 8 | Vidar | 3 | 4.5% |
| 9 | AsyncRAT | 2 | 3.0% |
| 10 | RemusStealer | 1 | 1.5% |
| 11 | MalwareX-gen [Drp] | 1 | 1.5% |
| 12 | CoinMiner | 1 | 1.5% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 22 | 32.8% | 86% |
| Infostealer | 18 | 26.9% | 88% |
| Windows-Malware | 5 | 7.5% | 35% |
| Skript/Dropper | 4 | 6.0% | 35% |
| Botnet/IoT | 4 | 6.0% | 95% |
| Andere / Unbekannt | 3 | 4.5% | 20% |
| Linux-Malware | 3 | 4.5% | 45% |
| Trojaner | 2 | 3.0% | 65% |
| Loader | 2 | 3.0% | 75% |
| Cryptominer | 1 | 1.5% | 75% |
| Maldoc | 1 | 1.5% | 35% |
| Ransomware | 1 | 1.5% | 95% |
| Spyware | 1 | 1.5% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 46 | 68.7% |
| 🟠 HOCH | 5 | 7.5% |
| 🟡 MITTEL | 12 | 17.9% |
| 🟢 NIEDRIG | 4 | 6.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a111ea501acb04…](https://bazaar.abuse.ch/sample/a111ea501acb04ac3bcf83da91e1fd0b0a62a839f8f7069e4647a29eb956252a/) | Formbook | Infostealer | **90.4** | 🔴 KRITISCH | – | – | ? |
| [8aeff0c7ac9eab…](https://bazaar.abuse.ch/sample/8aeff0c7ac9eab60e3eb8038d0a6bcd6c1a3fd6de70faef0721cf6fe2223e92d/) | LummaStealer | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [30a27eaf23cbec…](https://bazaar.abuse.ch/sample/30a27eaf23cbec3ad0817f339ac43655aed23c96d047d0791d5d8a5db1fba2a5/) | Formbook | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [a223ae354f57f2…](https://bazaar.abuse.ch/sample/a223ae354f57f22446c59714459293e09e3316b5bbbee653aa268f216318771e/) | Formbook | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [af919251deffa6…](https://bazaar.abuse.ch/sample/af919251deffa6c7a9ff6f2f88a38ae982b365823e13f814a4c73cbb67a30de3/) | XWorm | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [3504635b77e25e…](https://bazaar.abuse.ch/sample/3504635b77e25e9ed7e8082bb264c4ce8cc4bb3424fbf4bc44277f4946a37db7/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [7c1cbb86a75846…](https://bazaar.abuse.ch/sample/7c1cbb86a7584608ba9c04069ddbbef287b9fb3cf439ec4e7fccafbfb168c428/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [09d980d295bc92…](https://bazaar.abuse.ch/sample/09d980d295bc92df536ea2e2d6b37fb8eda7b1ea87a05bd97415c8d6dbe40bd2/) | Stealc | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [5825ebe05704f9…](https://bazaar.abuse.ch/sample/5825ebe05704f9c16b2aff3fb567fcb86dcb6474660793c5e267a6e49b9282f7/) | XWorm | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [5ab3e835eef27d…](https://bazaar.abuse.ch/sample/5ab3e835eef27d5927c72320af184d1e49125dcaf61f7188bb4ae67758da909a/) | Vidar | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5976/7386 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5976/7386 |
| 3 | ESET-NOD32 | 77.4% | 5720/7386 |
| 4 | Kaspersky | 76.4% | 5641/7385 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5286/7383 |
| 8 | Rising | 68.8% | 5078/7386 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4908/7382 |
| 11 | Tencent | 65.3% | 4678/7160 |
| 12 | Avast | 65.1% | 4804/7382 |
| 13 | AVG | 65.1% | 4804/7381 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4528/7379 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 41 | 61.2% |
| ❓ Unbekannt | 13 | 19.4% |
| 🐧 Linux | 9 | 13.4% |
| 📦 Archiv | 3 | 4.5% |
| 📄 Dokument | 1 | 1.5% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 48 | 71.6% |
| Drive-By / Exploit-Kit | 10 | 14.9% |
| MaaS-Loader | 3 | 4.5% |
| C2 / Nachladen | 3 | 4.5% |
| Phishing / E-Mail-Anhang | 1 | 1.5% |
| Exploit / N-Day | 1 | 1.5% |
| USB / Wechselmedium | 1 | 1.5% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 22 | 32.8% |
| 2 | 🇳🇱 NL | 14 | 20.9% |
| 3 | 🇺🇸 US | 13 | 19.4% |
| 4 | 🇨🇭 CH | 8 | 11.9% |
| 5 | 🌐 PT | 3 | 4.5% |
| 6 | 🇭🇺 HU | 3 | 4.5% |
| 7 | 🌐 EE | 1 | 1.5% |
| 8 | 🌐 EG | 1 | 1.5% |
| 9 | 🇨🇦 CA | 1 | 1.5% |
| 10 | 🌐 Unbekannt | 1 | 1.5% |

## MITRE ATT&CK

> 27 von 67 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 20 |
| Credential Access | 12 |
| Command and Control | 10 |
| Exfiltration | 5 |
| Initial Access | 4 |
| Lateral Movement | 4 |
| Execution | 2 |
| Impact | 1 |

<details><summary>a111ea501acb04ac3bcf… – Formbook | 🔴 KRITISCH 90.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>8aeff0c7ac9eab60e3eb… – LummaStealer | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>30a27eaf23cbec3ad081… – Formbook | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a223ae354f57f22446c5… – Formbook | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5ae667a2ffce6864964f…](https://bazaar.abuse.ch/sample/5ae667a2ffce6864964f906c2ec7049b342a534ebb8e38a8d0640e6656e0de7a/)

- **Familie:** MalwareX-gen [Drp]
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Alibaba | `Trojan:MSIL/Kryptik.35480e31` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.7025EBE7` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.ARDP trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `MSIL/GetType.AB!tr` |
| Google | `Detected` |
| Kaspersky | `UDS:Trojan-PSW.MSIL.Agensla.gen` |
| Kingsoft | `MSIL.Trojan-PSW.Agensla.gen` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| McAfeeD | `Trojan:Win/GenericPack.BMP` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Malware.Obfus/MSIL@AI.92 (RDM.MSIL2:v+xHRDKDyKcpkQnU8LIV0A)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Msil.Trojan.Kryptik.Fajl` |
| Trapmine | `malicious.moderate.ml.score` |
| Varist | `W32/MSIL_Kryptik.MUC1.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |

### [caa74155a24da662ebe4…](https://bazaar.abuse.ch/sample/caa74155a24da662ebe423ba7d53ff54f3d34f3c405a2c9a9f047d0cc1edb46b/)

- **Familie:** WannaCry
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0147
- **VT-Reputation:** -11
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
| Bkav | `W32.Malware.7653A97E` |
| CAT-QuickHeal | `Ransom.WcryG.S28363974` |
| CTX | `dll.exploit-kit.generic` |
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
| Ikarus | `Exploit.CVE-2017-0147` |
| Jiangmin | `Trojan.Wanna.e` |
| K7AntiVirus | `Trojan ( 0058feba1 )` |
| K7GW | `Trojan ( 0058feba1 )` |
| Kaspersky | `Trojan.Win32.Eb.s` |
| Malwarebytes | `CVE20170147.Trojan.Exploit.DDS` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!CAA74155A24D` |
| MicroWorld-eScan | `Exploit.CVE-2017-0147` |
| Microsoft 🛡️ | `Ransom:Win32/WannaCrypt!pz` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epclsl` |
| Panda | `Trj/GdSda.A` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Ransom.Win32.Save.WannaCry` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5298176` |
| Tencent | `Trojan.Win64.Wanna.a` |
| TrellixENS | `Ransom-WannaCry!72EF20C8BF9C` |
| VBA32 | `TrojanRansom.Win64.Wanna` |
| VIPRE | `Exploit.CVE-2017-0147` |
| Varist | `W64/S-e4f863f0!Eldorado` |
| VirIT | `Trojan.Win32.Genus.LWU` |
| Webroot | `W32.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!DtE/ovQwFGg` |
| Zillya | `Trojan.Wanna.Win32.27` |
| ZoneAlarm | `Mal/Wanna-A` |
| alibabacloud | `RansomWare:Win/Wannacryptor.6d8dbf74` |
| huorong | `Exploit/EquationDrug.a` |

### [971e3cbbef20c1c3d24d…](https://bazaar.abuse.ch/sample/971e3cbbef20c1c3d24df20dc98db532bb46b04ba0132c219dc5999c07bf4069/)

- **Familie:** Trojan.GenericKD.80617815
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.80617815
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.80617815`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.80617815` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R773315` |
| Alibaba | `Backdoor:Win64/Vidar.4013a4b7` |
| Antiy-AVL | `Trojan[Backdoor]/Win64.Gsb` |
| Arcabit | `Trojan.Generic.D4CE2157` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| BitDefender 🛡️ | `Trojan.GenericKD.80617815` |
| CTX | `dll.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Kryptik.UF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.80617815 (B)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.3301!tr` |
| GData | `Trojan.GenericKD.80617815` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| K7AntiVirus | `Backdoor ( 006dd9cd1 )` |
| K7GW | `Backdoor ( 006dd9cd1 )` |
| Kaspersky | `HEUR:Trojan.Win32.Agent.pef` |
| Kingsoft | `Win64.Backdoor.Gsb.gen` |
| Lionic | `Trojan.Win32.Gsb.m!c` |
| Malwarebytes | `Trojan.Loader` |
| McAfeeD | `Trojan:Win/Dllhijack.EAT` |
| MicroWorld-eScan | `Trojan.GenericKD.80617815` |
| Microsoft 🛡️ | `Trojan:Win64/AveMariaRat.BDA!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Trojan.Kryptik!8.8 (TFE:6:nlUeWyQgXpI)` |
| Sangfor | `Backdoor.Win64.Kryptik.Vx8y` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Backdoor.Win64.Gsb.16004167` |
| TrellixENS | `Artemis!84430433D756` |
| VBA32 | `Backdoor.Win64.Gsb` |
| VIPRE | `Trojan.GenericKD.80617815` |
| Varist | `W64/Agent.MMK.gen!Eldorado` |
| Zillya | `Backdoor.Gsb.Win64.143` |
| alibabacloud | `Backdoor:Win/Wacatac.B9nj` |
| huorong | `Trojan/W64.Agent.bs!crit` |

### [4f958c91c539101a78cf…](https://bazaar.abuse.ch/sample/4f958c91c539101a78cf76056e305152049fe52e5febb80686e6b0e17f5a84d0/)

- **Familie:** Vidar
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Pws]` |
| Avast | `FileRepMalware [Pws]` |
| Bkav | `W32.Malware.65ADE1E4` |
| ESET-NOD32 | `WinGo/GenKryptik.HVTH trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Vidar.YI!tr` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| Lionic | `Trojan.Win32.Vidar.4!c` |
| McAfeeD | `ti!4F958C91C539` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
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
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **exe** (38×)
- **RAT** (11×)
- **js** (10×)
- **Formbook** (7×)
- **elf** (6×)
- **signed** (5×)
- **ValleyRAT** (4×)
- **Vidar** (4×)
- **dropped-by-OffLoader** (3×)
- **XWorm** (3×)
- **Mirai** (3×)
- **stealer** (3×)
- **rat** (3×)
- **RemcosRAT** (3×)
- **njrat** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -16 (31→15)
- ↑ **Formbook** +3 (4→7)
- ↓ **Mirai** -22 (26→4)
- ↑ **RemcosRAT** +2 (2→4)
- neu: **ValleyRAT** (4)
- neu: **XWorm** (3)
- neu: **njrat** (3)
- ↑ **Vidar** +2 (1→3)
- ↓ **RemusStealer** -1 (2→1)
- weg: **AMOS** (war 2)
- weg: **DCRat** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -14 (29→15)
- ↑ **Formbook** +5 (2→7)
- ↓ **Mirai** -33 (37→4)
- ↑ **RemcosRAT** +2 (2→4)
- ↑ **ValleyRAT** +3 (1→4)
- ↑ **XWorm** +2 (1→3)
- neu: **njrat** (3)
- ↑ **Vidar** +2 (1→3)
- ↑ **AsyncRAT** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.982 MB |
| σ Dateigröße | 5.157 MB |
| Ø Risiko-Score | 71.6/100 |
| Ø Klassifikations-Konfidenz | 73.6% |
| Samples mit VT | 5/67 |
| Samples mit MITRE | 27/67 |
| Eindeutige Familien | 31 |
| Eindeutige Tags | 66 |
| Unbekannte Familien | 3 (4.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:52 | [65a9dc5c5c47…](https://bazaar.abuse.ch/sample/65a9dc5c5c47a3dce3e6cf283ed8836f02f3dc07f45b7bba71be953d7cec05ec/) | `exe` | RemusStealer | 82.1 | – | – | 🌐PT |
| 08:51 | [d59d912c5666…](https://bazaar.abuse.ch/sample/d59d912c566606f981ab61932858017fbb450fc0aa82e9c47101e1cc3ace3046/) | `js` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 08:51 | [7eb8fc545493…](https://bazaar.abuse.ch/sample/7eb8fc5454938505305cf577cb9936f328b1cdb8d74e8b470377a27834d10e00/) | `bat` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 08:50 | [4aae15627103…](https://bazaar.abuse.ch/sample/4aae156271039997062de8029d54ab346696d29e92dbd52ddd54a0f800801ec1/) | `exe` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 08:49 | [78c8ec578418…](https://bazaar.abuse.ch/sample/78c8ec578418690b427b7617babfdfcc388e286e0325b1cf2f61fa61c588cf05/) | `zip` | unbekannt | 32.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.10.2026 08:59 UTC*