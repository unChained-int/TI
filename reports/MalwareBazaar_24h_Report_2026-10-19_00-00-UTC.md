# MalwareBazaar – 19.10.2026 00:00 UTC

Dieser Run hat **35 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **36** |
| Kritisch (≥75) | **24** |
| Höchster Score | **84.5/100** – 1410244e815eabf7… |
| Häufigste Familie | **Mirai** (20x) |
| Häufigster Typ | **elf** (20x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 20 Samples |
| Ø Dateigröße | 0.91 MB (σ=2.26) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 20 | 55.6%  ███████████ |
| `exe` | 9 | 25.0%  █████ |
| `sh` | 3 | 8.3%  █ |
| `macho` | 2 | 5.6%  █ |
| `zsh` | 2 | 5.6%  █ |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 20 | 55.6% |
| 2 | unbekannt | 10 | 27.8% |
| 3 | SalatStealer | 2 | 5.6% |
| 4 | PureLogsStealer | 1 | 2.8% |
| 5 | MacSync | 1 | 2.8% |
| 6 | MalwareX-gen [Pws] | 1 | 2.8% |
| 7 | PythonStealer | 1 | 2.8% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 20 | 55.6% | 95% |
| Andere / Unbekannt | 6 | 16.7% | 20% |
| Infostealer | 5 | 13.9% | 75% |
| Windows-Malware | 4 | 11.1% | 35% |
| Loader | 1 | 2.8% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 24 | 66.7% |
| 🟠 HOCH | 2 | 5.6% |
| 🟡 MITTEL | 4 | 11.1% |
| 🟢 NIEDRIG | 6 | 16.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1410244e815eab…](https://bazaar.abuse.ch/sample/1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [3ed85e9cd1b68a…](https://bazaar.abuse.ch/sample/3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [671574f7454bbe…](https://bazaar.abuse.ch/sample/671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [03e2f6194b0252…](https://bazaar.abuse.ch/sample/03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [ece8528fe3f27d…](https://bazaar.abuse.ch/sample/ece8528fe3f27d206dbe159c78f315cfc191fb7415ca8cf0112086150d4120b3/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [4efb335bc6357d…](https://bazaar.abuse.ch/sample/4efb335bc6357df3b48ed5e73db1fe454c926f6015bd4447b9386eb8f13fb7cc/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [51d17edc97d157…](https://bazaar.abuse.ch/sample/51d17edc97d157620defeb37c7b3aa6516869ae0e4c9564781cde51ea59628d6/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [9a05910fedc8ea…](https://bazaar.abuse.ch/sample/9a05910fedc8ea2f92e3f223740d147e3a731dfdc2b697432d9c1ee2142fd803/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [90d265704bba45…](https://bazaar.abuse.ch/sample/90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [341df173a5a6bb…](https://bazaar.abuse.ch/sample/341df173a5a6bb6c29fc10b5e711cfac5137441db164fbf47408cd1ed9c0e5f6/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6051/7481 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6051/7481 |
| 3 | ESET-NOD32 | 77.4% | 5791/7481 |
| 4 | Kaspersky | 76.3% | 5708/7480 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5344/7478 |
| 8 | Rising | 68.7% | 5140/7481 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4956/7477 |
| 11 | Tencent | 65.2% | 4733/7255 |
| 12 | Avast | 65.2% | 4873/7477 |
| 13 | AVG | 65.2% | 4873/7476 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4580/7474 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 25 | 69.4% |
| 🪟 Windows | 9 | 25.0% |
| 🍎 macOS | 2 | 5.6% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 35 | 97.2% |
| C2 / Nachladen | 1 | 2.8% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 19 | 52.8% |
| 2 | 🇺🇸 US | 11 | 30.6% |
| 3 | 🇳🇱 NL | 3 | 8.3% |
| 4 | 🇫🇷 FR | 1 | 2.8% |
| 5 | 🇬🇧 GB | 1 | 2.8% |
| 6 | 🌐 Unbekannt | 1 | 2.8% |

## MITRE ATT&CK

> 20 von 36 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |

<details><summary>1410244e815eabf714a9… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3ed85e9cd1b68ad52510… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>671574f7454bbe4cc277… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>03e2f6194b0252b1e157… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ece8528fe3f27d206dbe… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [34b1590817537f05bfa8…](https://bazaar.abuse.ch/sample/34b1590817537f05bfa8ce5fc071287780f798e5aa301aaff1a7eadd6569b265/)

- **Familie:** PureLogsStealer
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Benin.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Benin.5`

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Drp]` |
| Antiy-AVL | `Trojan[Dropper]/MSIL.Dapato` |
| Arcabit | `Trojan.MSIL.Benin.5` |
| Avast | `Win32:MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Benin.5` |
| Bkav | `W32.Malware.33CB7DD9` |
| CTX | `exe.unknown.benin` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.APRJ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Benin.5 (B)` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| GData | `Gen:Heur.MSIL.Benin.5` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-Dropper.MSIL.Dapato.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Malwarebytes | `Trojan.Crypt` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D3ADBE59A410` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Benin.5` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Obfus/MSIL@AI.97 (RDM.MSIL2:oalf5zPQlhQKeMbjjqDNXg)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `ML/PE-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CA3` |
| VIPRE | `Gen:Heur.MSIL.Benin.5` |
| Varist | `W32/MSIL_Kryptik.MYG.gen!Eldorado` |
| huorong | `Trojan/MSIL.Loader.bc` |
| tehtris | `Generic.Malware` |

### [62f65b335e3a7d4cf806…](https://bazaar.abuse.ch/sample/62f65b335e3a7d4cf806440134105f533ce5f639856a2edaea03013217bf6ec4/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!8E99DCF31FEE
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.EKB trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.BO!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.jw` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14331 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!8E99DCF31FEE` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.PPCra` |
| TrellixENS | `LINUX/Mirai-FQU!8E99DCF31FEE` |
| Varist | `E32/Mirai.EN.gen!Camelot` |

### [598d8e60da3039e42c7f…](https://bazaar.abuse.ch/sample/598d8e60da3039e42c7f50aa015bb4536053152dd108bb2ad8ddebb8a9ae7249/)

- **Familie:** MalwareX-gen [Pws]
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.BC5562F4` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!598D8E60DA30` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Rising | `Trojan.Kryptik@AI.95 (RDML:7Mg4i8Zt9tn+Ls6yl5PwsQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |

### [bd90fa0a64f8482a0a1a…](https://bazaar.abuse.ch/sample/bd90fa0a64f8482a0a1a56b85daf11129b5ea373e0df93260a2da096fd011f7d/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!C936B535AC2E
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-6981989-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.jw` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GB!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14331 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!C936B535AC2E` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Linux.Backdoor.Mirai.Qsmw` |
| TrellixENS | `LINUX/Mirai-FQU!C936B535AC2E` |
| Varist | `E32/Mirai.EN.gen!Camelot` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.7053573B
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |


## Top Tags

- **elf** (20×)
- **Mirai** (20×)
- **exe** (8×)
- **ClickFix** (4×)
- **macOS** (4×)
- **AMOS** (3×)
- **Foxveil** (3×)
- **Mach-O** (2×)
- **macho** (2×)
- **zsh** (2×)
- **stealer** (2×)
- **SalatStealer** (2×)
- **PureLogsStealer** (1×)
- **MacSync** (1×)
- **DvnX** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -4 (24→20)
- ↓ **unbekannt** -14 (24→10)
- neu: **SalatStealer** (2)
- neu: **PureLogsStealer** (1)
- neu: **MacSync** (1)
- neu: **MalwareX-gen [Pws]** (1)
- neu: **PythonStealer** (1)
- weg: **AMOS** (war 2)
- weg: **RemcosRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -6 (26→20)
- ↓ **unbekannt** -17 (27→10)
- neu: **SalatStealer** (2)
- neu: **PureLogsStealer** (1)
- neu: **MacSync** (1)
- neu: **MalwareX-gen [Pws]** (1)
- neu: **PythonStealer** (1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.908 MB |
| σ Dateigröße | 2.256 MB |
| Ø Risiko-Score | 68.5/100 |
| Ø Klassifikations-Konfidenz | 72.5% |
| Samples mit VT | 5/36 |
| Samples mit MITRE | 20/36 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 28 |
| Unbekannte Familien | 6 (16.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:54 | [1410244e815e…](https://bazaar.abuse.ch/sample/1410244e815eabf714a977ab9b20372c270046ec5bd90c8e05e94bf62386d9b5/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 23:51 | [3ed85e9cd1b6…](https://bazaar.abuse.ch/sample/3ed85e9cd1b68ad525101e63ab867fc5b3a31e195b88ef82b7a1096bdde68841/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 23:51 | [671574f7454b…](https://bazaar.abuse.ch/sample/671574f7454bbe4cc277d9caa4c513d2ccc11073f46f9a3f5998136fe0ef9927/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 23:48 | [03e2f6194b02…](https://bazaar.abuse.ch/sample/03e2f6194b0252b1e157f33a4f673973fbeab3a95604181fb0fcb064a815ba60/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 23:44 | [93de911f3ec5…](https://bazaar.abuse.ch/sample/93de911f3ec5cb14664ade2b7885b1d643ac951c564f1453e795eec9e3ba7129/) | `sh` | unbekannt | 32.5 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.10.2026 00:00 UTC*