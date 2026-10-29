# MalwareBazaar – 29.10.2026 04:55 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **71** |
| Höchster Score | **87.2/100** – d590b52661f31fa0… |
| Häufigste Familie | **SalatStealer** (68x) |
| Häufigster Typ | **exe** (75x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 10 Samples |
| Ø Dateigröße | 6.71 MB (σ=6.01) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 75 | 74.3%  ██████████████ |
| `macho` | 12 | 11.9%  ██ |
| `elf` | 11 | 10.9%  ██ |
| `sh` | 2 | 2.0%   |
| `rar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 68 | 67.3% |
| 2 | unbekannt | 23 | 22.8% |
| 3 | Mirai | 9 | 8.9% |
| 4 | njrat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 65 | 64.4% | 75% |
| Loader | 12 | 11.9% | 75% |
| Botnet/IoT | 9 | 8.9% | 95% |
| Windows-Malware | 8 | 7.9% | 35% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| RAT | 2 | 2.0% | 85% |
| Cryptominer | 1 | 1.0% | 75% |
| Linux-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 71 | 70.3% |
| 🟠 HOCH | 18 | 17.8% |
| 🟡 MITTEL | 9 | 8.9% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [d590b52661f31f…](https://bazaar.abuse.ch/sample/d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9/) | njrat | RAT | **87.2** | 🔴 KRITISCH | – | – | ? |
| [c14491979811b9…](https://bazaar.abuse.ch/sample/c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [6e79e890c649ef…](https://bazaar.abuse.ch/sample/6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [1382088ffa6ee9…](https://bazaar.abuse.ch/sample/1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [9daea98c0ef4a9…](https://bazaar.abuse.ch/sample/9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [eec3f1975eb721…](https://bazaar.abuse.ch/sample/eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [1589043c3092d9…](https://bazaar.abuse.ch/sample/1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [bca63a1f5c50cf…](https://bazaar.abuse.ch/sample/bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [7f64ed4a05d8be…](https://bazaar.abuse.ch/sample/7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [18cc64b5520b72…](https://bazaar.abuse.ch/sample/18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a/) | SalatStealer | Infostealer | **81.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6243/7701 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6243/7701 |
| 3 | ESET-NOD32 | 77.2% | 5947/7701 |
| 4 | Kaspersky | 75.5% | 5816/7700 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5480/7698 |
| 8 | Rising | 68.3% | 5262/7701 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5094/7697 |
| 11 | Avast | 65.1% | 5013/7697 |
| 12 | AVG | 65.1% | 5013/7696 |
| 13 | Tencent | 64.9% | 4853/7475 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4714/7694 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 75 | 74.3% |
| 🐧 Linux | 13 | 12.9% |
| 🍎 macOS | 12 | 11.9% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 89 | 88.1% |
| MaaS-Loader | 12 | 11.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 47 | 46.5% |
| 2 | 🇳🇱 NL | 35 | 34.7% |
| 3 | 🇩🇪 DE | 10 | 9.9% |
| 4 | 🇫🇷 FR | 6 | 5.9% |
| 5 | 🌐 Unbekannt | 2 | 2.0% |
| 6 | 🇨🇭 CH | 1 | 1.0% |

## MITRE ATT&CK

> 10 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 9 |
| Lateral Movement | 9 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>d590b52661f31fa0234e… – njrat | 🔴 KRITISCH 87.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c14491979811b95f025b… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6e79e890c649ef6f0cd2… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1382088ffa6ee9bb02c4… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9daea98c0ef4a998a9c8… – Mirai | 🔴 KRITISCH 82.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [021e04edfe50d0172ec0…](https://bazaar.abuse.ch/sample/021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a/)

- **Familie:** SalatStealer
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (48/75):**

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
| Bkav | `W32.Malware.A29B6A0C` |
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
| Gridinsoft | `Trojan.Win32.Agent.oa!s1` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| McAfeeD | `Real Protect-LS!56425359A822` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!56425359A822` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570890` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!56425359A822` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Zillya | `Trojan.Agent.Win32.4649254` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [d36b6e6c034d47ac22ed…](https://bazaar.abuse.ch/sample/d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c/)

- **Familie:** SalatStealer
- **Erkannt von:** 45 von 74 Engines (60.8%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (45/74):**

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
| Bkav | `W32.Malware.5403848C` |
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
| McAfeeD | `Real Protect-LS!6D911DEA5A98` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!6D911DEA5A98` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!6D911DEA5A98` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [05cfac8008d88e131e7e…](https://bazaar.abuse.ch/sample/05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004/)

- **Familie:** SalatStealer
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Dump:Generic.Dacic.18086.04764999
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Dump:Generic.Dacic.18086.04764999`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Dump:Generic.Dacic.18086.04764999` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R763881` |
| Arcabit | `Dump:Generic.Dacic.18086.04764999` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| BitDefender 🛡️ | `Dump:Generic.Dacic.18086.04764999` |
| Bkav | `W32.Malware.8B1158DE` |
| CTX | `exe.unknown.dacic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Dump:Generic.Dacic.18086.04764999 (B)` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Dump:Generic.Dacic.18086.04764999` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!566259371135` |
| MicroWorld-eScan | `Dump:Generic.Dacic.18086.04764999` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!02510061B8E2` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Banker/W32.Agent.12570112.B` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!02510061B8E2` |
| VIPRE | `Dump:Generic.Dacic.18086.04764999` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [d24016826df7ae508b90…](https://bazaar.abuse.ch/sample/d24016826df7ae508b90fdb6c9e7b6e8305245595ecfc2b506513f2f971cebd0/)

- **Familie:** SalatStealer
- **Erkannt von:** 57 von 75 Engines (76.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (57/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Alibaba | `TrojanBanker:Win32/SalatStealer.0f5af39b` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.F2C18E6B` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Win32.Trojan-Downloader.Salat.QP2QYB` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Lionic | `Trojan.Win32.Salat.4!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!EA977AF4B311` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Stealer.Salat!1.13A22 (CLOUD)` |
| Sangfor | `Infostealer.Win32.Agent.Vlli` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!243BD5C5A26D` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570871` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!EA977AF4B311` |
| TrendMicro | `Trojan.Win32.AGENTAGEN.USBLJQ26` |
| TrendMicro-HouseCall | `Trojan.Win32.AGENTAGEN.USBLJQ26` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/ABTrojan.BDOG-8671` |
| ViRobot | `Trojan.Win.Z.Draftor.3592951.D` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
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

- **exe** (75×)
- **SalatStealer** (49×)
- **upx-dec** (35×)
- **upx** (35×)
- **salatstealer** (15×)
- **ClickFix** (12×)
- **Foxveil** (12×)
- **loader** (12×)
- **Mach-O** (12×)
- **macho** (12×)
- **macOS** (12×)
- **elf** (11×)
- **Mirai** (9×)
- **honeypot** (2×)
- **Torii** (2×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +55 (13→68)
- ↓ **Mirai** -42 (51→9)
- neu: **njrat** (1)
- weg: **RemcosRAT** (war 2)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +58 (10→68)
- ↓ **unbekannt** -2 (25→23)
- ↓ **Mirai** -14 (23→9)
- neu: **njrat** (1)
- weg: **CoinMiner** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.710 MB |
| σ Dateigröße | 6.013 MB |
| Ø Risiko-Score | 73.0/100 |
| Ø Klassifikations-Konfidenz | 71.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 10/101 |
| Eindeutige Familien | 4 |
| Eindeutige Tags | 25 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:35 | [6b5afe506c5b…](https://bazaar.abuse.ch/sample/6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7/) | `elf` | unbekannt | 67.7 | – | – | 🌐CH |
| 04:26 | [c14491979811…](https://bazaar.abuse.ch/sample/c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 04:25 | [18cc64b5520b…](https://bazaar.abuse.ch/sample/18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a/) | `exe` | SalatStealer | 81.8 | – | – | 🇳🇱NL |
| 04:25 | [11308a0ae356…](https://bazaar.abuse.ch/sample/11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa/) | `exe` | SalatStealer | 81.8 | – | – | 🇳🇱NL |
| 04:24 | [f2c4da25934b…](https://bazaar.abuse.ch/sample/f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba/) | `exe` | SalatStealer | 81.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 29.10.2026 04:55 UTC*