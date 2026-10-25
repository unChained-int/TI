# MalwareBazaar – 25.10.2026 17:29 UTC

Dieser Run hat **56 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **57** |
| Kritisch (≥75) | **37** |
| Höchster Score | **89.9/100** – 37e4943b8094583d… |
| Häufigste Familie | **unbekannt** (18x) |
| Häufigster Typ | **exe** (30x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 22 Samples |
| Ø Dateigröße | 3.24 MB (σ=4.71) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 30 | 52.6%  ██████████ |
| `elf` | 16 | 28.1%  █████ |
| `xls` | 6 | 10.5%  ██ |
| `zsh` | 1 | 1.8%   |
| `js` | 1 | 1.8%   |
| `sh` | 1 | 1.8%   |
| `msi` | 1 | 1.8%   |
| `applescript` | 1 | 1.8%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 18 | 31.6% |
| 2 | Mirai | 16 | 28.1% |
| 3 | SalatStealer | 7 | 12.3% |
| 4 | AveMariaRAT | 6 | 10.5% |
| 5 | Vidar | 2 | 3.5% |
| 6 | AokigaharaStealer | 1 | 1.8% |
| 7 | AgentTesla | 1 | 1.8% |
| 8 | Amadey | 1 | 1.8% |
| 9 | njrat | 1 | 1.8% |
| 10 | ConnectWise | 1 | 1.8% |
| 11 | Gh0stRAT | 1 | 1.8% |
| 12 | AMOS | 1 | 1.8% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 16 | 28.1% | 95% |
| Infostealer | 14 | 24.6% | 79% |
| Windows-Malware | 12 | 21.1% | 35% |
| RAT | 7 | 12.3% | 78% |
| Loader | 4 | 7.0% | 80% |
| Skript/Dropper | 1 | 1.8% | 35% |
| Backdoor | 1 | 1.8% | 95% |
| Linux-Malware | 1 | 1.8% | 45% |
| Trojaner | 1 | 1.8% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 37 | 64.9% |
| 🟠 HOCH | 6 | 10.5% |
| 🟡 MITTEL | 14 | 24.6% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [37e4943b809458…](https://bazaar.abuse.ch/sample/37e4943b8094583de174578e66c5754a693f711fcbe5c95bd1bd6d90f5b95099/) | Gh0stRAT | Backdoor | **89.9** | 🔴 KRITISCH | – | – | ? |
| [24c6c2c865319c…](https://bazaar.abuse.ch/sample/24c6c2c865319cb27ceadd7fef97f944785341e909359815aeca9ddb3c948a45/) | Vidar | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [8abdd20fea637c…](https://bazaar.abuse.ch/sample/8abdd20fea637c76086d603a63390539fda513c024528d2c920dd3d090d0762c/) | Vidar | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [0d01e3d312a444…](https://bazaar.abuse.ch/sample/0d01e3d312a444a855dc98c6783b18243a81e15b41b340a7b5a37c2ed89aafe2/) | AMOS | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [fbd4db896bb05f…](https://bazaar.abuse.ch/sample/fbd4db896bb05fdd2e25a28e7c19885d4f559268f0fef0c944739c255c7455bb/) | njrat | RAT | **86.7** | 🔴 KRITISCH | – | – | ? |
| [fb16a7b6bac257…](https://bazaar.abuse.ch/sample/fb16a7b6bac257b6f3e5bca7ccc0ebf083efc5aa8fd8e736521b81220a3f0e94/) | Mirai | Botnet/IoT | **86.2** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [83a47cf5f37588…](https://bazaar.abuse.ch/sample/83a47cf5f37588bc0de8c79c71a4fbadff36b4fce4955c32f662dbf7cee0307d/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [49a0506751b4bf…](https://bazaar.abuse.ch/sample/49a0506751b4bfac7e26fcc256bf6f1bc86c0d5db55df5c2c9c2588bdcf582dc/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [160b29be7a24aa…](https://bazaar.abuse.ch/sample/160b29be7a24aa625887ac0da57e974fbce4b5dc7066d548517b5af6b4656832/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [0f7df63cb33760…](https://bazaar.abuse.ch/sample/0f7df63cb33760ecfc28a0528f1063565c321547a5aa5a3252289cecf3ea65a7/) | SalatStealer | Infostealer | **82.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6182/7630 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6182/7630 |
| 3 | ESET-NOD32 | 77.2% | 5888/7630 |
| 4 | Kaspersky | 75.8% | 5785/7629 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5421/7627 |
| 8 | Rising | 68.3% | 5208/7630 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5045/7626 |
| 11 | Avast | 65.1% | 4963/7626 |
| 12 | AVG | 65.1% | 4963/7625 |
| 13 | Tencent | 64.8% | 4797/7404 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4668/7623 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 32 | 56.1% |
| 🐧 Linux | 18 | 31.6% |
| 📄 Dokument | 6 | 10.5% |
| ❓ Unbekannt | 1 | 1.8% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 46 | 80.7% |
| Phishing / E-Mail-Anhang | 6 | 10.5% |
| MaaS-Loader | 3 | 5.3% |
| Drive-By / Exploit-Kit | 1 | 1.8% |
| Trojanisierte Software | 1 | 1.8% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 15 | 26.3% |
| 2 | 🇺🇸 US | 13 | 22.8% |
| 3 | 🇩🇪 DE | 10 | 17.5% |
| 4 | 🇳🇱 NL | 7 | 12.3% |
| 5 | 🇸🇪 SE | 7 | 12.3% |
| 6 | 🇦🇹 AT | 2 | 3.5% |
| 7 | 🇨🇭 CH | 1 | 1.8% |
| 8 | 🌐 PT | 1 | 1.8% |
| 9 | 🌐 Unbekannt | 1 | 1.8% |

## MITRE ATT&CK

> 22 von 57 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 16 |
| Lateral Movement | 16 |
| Collection | 5 |
| Credential Access | 4 |
| Exfiltration | 4 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |

<details><summary>24c6c2c865319cb27cea… – Vidar | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>8abdd20fea637c76086d… – Vidar | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>fbd4db896bb05fdd2e25… – njrat | 🔴 KRITISCH 86.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [fb16a7b6bac257b6f3e5…](https://bazaar.abuse.ch/sample/fb16a7b6bac257b6f3e5bca7ccc0ebf083efc5aa8fd8e736521b81220a3f0e94/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -12
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| alibabacloud | `Trojan:Linux/Flooder.Akgpp` |
| huorong | `Trojan/Linux.Flooder.ac` |

### [ccd8c73dc516f01fc039…](https://bazaar.abuse.ch/sample/ccd8c73dc516f01fc03978265e62025415550ad423d7cfe8fbc16f4417467c39/)

- **Familie:** AokigaharaStealer
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:Evo-gen [Trj]` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.2243D707` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/GenKryptik.HVTH trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/Vidar.YI!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Spy.Win64.Agent` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Agent.gen` |
| Malwarebytes | `Malware.AI.2957342724` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!CCD8C73DC516` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [d8d2d49845fe8dcec949…](https://bazaar.abuse.ch/sample/d8d2d49845fe8dcec9491daa1d40c746b1332ea51645c44ed79d854b2433aa8a/)

- **Familie:** AveMariaRAT
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** VB:Trojan.Downloader.4637
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `VB:Trojan.Downloader.4637`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `VB:Trojan.Downloader.4637` |
| AVG | `Script:SNH-gen [Drp]` |
| Acronis | `suspicious` |
| Arcabit | `HEUR.VBA.Trojan.d` |
| Avast | `Script:SNH-gen [Drp]` |
| Avira | `DR/SNH` |
| BitDefender 🛡️ | `VB:Trojan.Downloader.4637` |
| Bkav | `X97M.EmoDldr.Macro` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `VBA/TrojanDownloader.Agent.DWR trojan` |
| Emsisoft | `VB:Trojan.Downloader.4637 (B)` |
| F-Secure | `Dropper.DR/SNH` |
| Fortinet | `VBA/Agent.1873!tr.dldr` |
| GData | `Macro.Trojan.Agent.YJ` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.VBA.Agent` |
| Kaspersky | `HEUR:Trojan-Downloader.Script.Generic` |
| MicroWorld-eScan | `VB:Trojan.Downloader.4637` |
| Microsoft 🛡️ | `Trojan:O97M/Sonbokli.A!cl` |
| NANO-Antivirus | `Trojan.Ole2.Vbs-heuristic.druvzi` |
| Panda | `O97M/Downloader` |
| Rising | `Malware.Obfus/VBA@AI.97 (VBA)` |
| Sangfor | `VBA.Sus.Obf` |
| SentinelOne | `Static AI - Malicious OLE` |
| Skyhigh | `BehavesLike.OLE2.Bad-VBA.db` |
| Sophos | `Troj/DocDl-AHPF` |
| Symantec | `ISB.Downloader!gen60` |
| TACHYON | `Suspicious/X97M.DNL.Gen` |
| TrellixENS | `W97M/Downloader.djz` |
| TrendMicro | `HEUR_MLVBA.ARGO1` |
| TrendMicro-HouseCall | `HEUR_MLVBA.ARGO1` |
| VIPRE | `VB:Trojan.Downloader.4637` |
| Varist | `X97M/Agent.BA.gen!Eldorado` |
| VirIT | `Office.VBA_Macro_Heur` |
| ZoneAlarm | `Troj/DocDl-AHPF` |
| huorong | `OMacro/Downloader.apo` |

### [accfca5192b6395b28db…](https://bazaar.abuse.ch/sample/accfca5192b6395b28db6266a51e4ebd08284b2344f451a8d0f10d058b56a1c3/)

- **Familie:** SalatStealer
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Dump:Generic.Dacic.18086.3573094E
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Dump:Generic.Dacic.18086.3573094E`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Dump:Generic.Dacic.18086.3573094E` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R743754` |
| Arcabit | `Dump:Generic.Dacic.18086.3573094E` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| BitDefender 🛡️ | `Dump:Generic.Dacic.18086.3573094E` |
| Bkav | `W32.Malware.19CD0CA7` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Dump:Generic.Dacic.18086.3573094E (B)` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Dump:Generic.Dacic.18086.3573094E` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kingsoft | `malware.kb.b.830` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!6C8C40744230` |
| MicroWorld-eScan | `Dump:Generic.Dacic.18086.3573094E` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!183F61B0934E` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Banker/W32.Agent.12570112` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!183F61B0934E` |
| VIPRE | `Dump:Generic.Dacic.18086.3573094E` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7AntiVirus | `Trojan ( 0001140e1 )` |
| K7GW | `Hacktool ( a007e0071 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **exe** (29×)
- **elf** (16×)
- **Mirai** (15×)
- **stealer** (7×)
- **AveMariaRAT** (6×)
- **xls** (6×)
- **upx-dec** (5×)
- **upx** (5×)
- **signed** (5×)
- **SalatStealer** (4×)
- **vidar** (4×)
- **Warden** (2×)
- **WARDENStealer** (2×)
- **Yap** (2×)
- **YapStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +3 (15→18)
- ↑ **SalatStealer** +1 (6→7)
- neu: **AveMariaRAT** (6)
- neu: **Vidar** (2)
- neu: **AokigaharaStealer** (1)
- neu: **AgentTesla** (1)
- neu: **Amadey** (1)
- neu: **ConnectWise** (1)
- weg: **CoinMiner** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -19 (37→18)
- ↓ **Mirai** -3 (19→16)
- ↑ **SalatStealer** +5 (2→7)
- neu: **AveMariaRAT** (6)
- neu: **Vidar** (2)
- neu: **AokigaharaStealer** (1)
- neu: **AgentTesla** (1)
- neu: **Amadey** (1)
- neu: **njrat** (1)
- neu: **ConnectWise** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.244 MB |
| σ Dateigröße | 4.712 MB |
| Ø Risiko-Score | 70.1/100 |
| Ø Klassifikations-Konfidenz | 72.9% |
| Samples mit VT | 5/57 |
| Samples mit MITRE | 22/57 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 50 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:28 | [ed267508f076…](https://bazaar.abuse.ch/sample/ed267508f076d8f0ae1e77b13cbdc359ce25d9345407367f8af991194a052019/) | `exe` | unbekannt | 39.1 | – | – | 🇳🇱NL |
| 17:27 | [19be9a2a6d5c…](https://bazaar.abuse.ch/sample/19be9a2a6d5cc73e036dc52c02234b79584482600f92244077ff6eb03122019b/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 17:23 | [0f7df63cb337…](https://bazaar.abuse.ch/sample/0f7df63cb33760ecfc28a0528f1063565c321547a5aa5a3252289cecf3ea65a7/) | `exe` | SalatStealer | 82.2 | – | – | 🇳🇱NL |
| 17:23 | [802479118edb…](https://bazaar.abuse.ch/sample/802479118edbe27d31a7d1ae2b16e6a3dc78ba32f34737a4940028060719787d/) | `exe` | unbekannt | 39.0 | – | – | 🇳🇱NL |
| 17:23 | [a1aafc1c9c85…](https://bazaar.abuse.ch/sample/a1aafc1c9c85a77b366d242c2dbd77d7a6de95107a474919ad04dee6cca636b4/) | `exe` | SalatStealer | 39.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 17:29 UTC*