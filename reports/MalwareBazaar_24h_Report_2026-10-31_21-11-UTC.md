# MalwareBazaar – 31.10.2026 21:11 UTC

Dieser Run hat **23 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **24** |
| Kritisch (≥75) | **13** |
| Höchster Score | **94.6/100** – 87adc00cc7aa18d8… |
| Häufigste Familie | **unbekannt** (14x) |
| Häufigster Typ | **exe** (13x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 4 Samples |
| Ø Dateigröße | 4.05 MB (σ=6.54) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 13 | 54.2%  ██████████ |
| `elf` | 7 | 29.2%  █████ |
| `msi` | 1 | 4.2%   |
| `zip` | 1 | 4.2%   |
| `hta` | 1 | 4.2%   |
| `dll` | 1 | 4.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 14 | 58.3% |
| 2 | Mirai | 3 | 12.5% |
| 3 | BRB trojan | 1 | 4.2% |
| 4 | AokigaharaStealer | 1 | 4.2% |
| 5 | RustyStealer | 1 | 4.2% |
| 6 | ValleyRAT | 1 | 4.2% |
| 7 | FileRepMalware [Misc] | 1 | 4.2% |
| 8 | WannaCry | 1 | 4.2% |
| 9 | SalatStealer | 1 | 4.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 8 | 33.3% | 74% |
| Loader | 4 | 16.7% | 75% |
| Botnet/IoT | 3 | 12.5% | 95% |
| Linux-Malware | 3 | 12.5% | 45% |
| Windows-Malware | 2 | 8.3% | 35% |
| Trojaner | 1 | 4.2% | 65% |
| RAT | 1 | 4.2% | 75% |
| Skript/Dropper | 1 | 4.2% | 35% |
| Ransomware | 1 | 4.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 13 | 54.2% |
| 🟠 HOCH | 5 | 20.8% |
| 🟡 MITTEL | 6 | 25.0% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [87adc00cc7aa18…](https://bazaar.abuse.ch/sample/87adc00cc7aa18d84c0b047bc186b34e48715b89f8d2f40278f7eb3a01d05223/) | WannaCry | Ransomware | **94.6** | 🔴 KRITISCH | – | – | ? |
| [ccfd73a74d8830…](https://bazaar.abuse.ch/sample/ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91/) | Mirai | Botnet/IoT | **85.8** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [449162c0118749…](https://bazaar.abuse.ch/sample/449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [4ea4f6dd439a54…](https://bazaar.abuse.ch/sample/4ea4f6dd439a54cd36d8194c14c1673c6e935b1a493f27bf4df83a2b96ceedb6/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [05fafc00e36eba…](https://bazaar.abuse.ch/sample/05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3/) | BRB trojan | Trojaner | **82.5** | 🔴 KRITISCH | 2.7% | ⚠️ KAUM ERKANNT | ✗ |
| [e34efe9b7001f4…](https://bazaar.abuse.ch/sample/e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [7cd4c78e136257…](https://bazaar.abuse.ch/sample/7cd4c78e13625706f3012bb236b48afcab8f4ef1ec4e9b7fc4c13a87a3cced02/) | unbekannt | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |
| [4a0b3f9aaf8214…](https://bazaar.abuse.ch/sample/4a0b3f9aaf8214e7b3a4ea6784fb9960ac0aeca67ff1c35d418d0bcced56697c/) | unbekannt | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |
| [edbb2619827bab…](https://bazaar.abuse.ch/sample/edbb2619827bab21ed33fdd1c9ebe83f07c6db7ce92598eca7fb0aa2cd85a639/) | unbekannt | Infostealer | **80.2** | 🔴 KRITISCH | – | – | ? |
| [1370f67acce699…](https://bazaar.abuse.ch/sample/1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483/) | AokigaharaStealer | Infostealer | **80.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6287/7755 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6287/7755 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 5995/7755 |
| 6 | Kaspersky | 75.5% | 5855/7754 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5519/7751 |
| 9 | Rising | 68.3% | 5296/7755 |
| 10 | Varist | 66.2% | 5128/7750 |
| 11 | Avast | 65.1% | 5048/7751 |
| 12 | AVG | 65.1% | 5048/7750 |
| 13 | Tencent | 64.9% | 4889/7529 |
| 14 | McAfeeD | 61.3% | 4750/7747 |
| 15 | huorong | 60.8% | 4713/7747 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 16 | 66.7% |
| 🐧 Linux | 7 | 29.2% |
| 📦 Archiv | 1 | 4.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 18 | 75.0% |
| MaaS-Loader | 4 | 16.7% |
| Trojanisierte Software | 1 | 4.2% |
| Exploit / N-Day | 1 | 4.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 7 | 29.2% |
| 2 | 🇫🇷 FR | 6 | 25.0% |
| 3 | 🇩🇪 DE | 4 | 16.7% |
| 4 | 🌐 PT | 2 | 8.3% |
| 5 | 🌐 Unbekannt | 2 | 8.3% |
| 6 | 🇨🇦 CA | 1 | 4.2% |
| 7 | 🌐 TH | 1 | 4.2% |
| 8 | 🇳🇱 NL | 1 | 4.2% |

## MITRE ATT&CK

> 4 von 24 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 3 |
| Lateral Movement | 3 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |

<details><summary>ccfd73a74d8830d845b2… – Mirai | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>449162c0118749eb2c83… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4ea4f6dd439a54cd36d8… – Mirai | 🔴 KRITISCH 82.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b25a752117a9f7072929…](https://bazaar.abuse.ch/sample/b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [05fafc00e36ebaec146e…](https://bazaar.abuse.ch/sample/05fafc00e36ebaec146e64c9ad7bb3bc7a733c2dd99fff954e8ef1736b1e04a3/)

- **Familie:** BRB trojan
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BRB trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BRB trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [ccfd73a74d8830d845b2…](https://bazaar.abuse.ch/sample/ccfd73a74d8830d845b25ab416295c531e1476b9a89f2b07e77346468f13bd91/)

- **Familie:** Mirai
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Dirtydecrypt.EAA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| McAfeeD | `Trojan:Script/Dirtydecrypt.EAA` |

### [ea3b82d9a70295c74edd…](https://bazaar.abuse.ch/sample/ea3b82d9a70295c74edd17b90c549a84ca05a31f07c9a398b0c945493fb0dc5c/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.A4E2A55C` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Vidar.HUHV!tr` |
| GData | `Win64.Trojan.Agent.C6Y41H` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| Kaspersky | `VHO:Trojan-Downloader.Win32.Remus.gen` |
| McAfeeD | `ti!EA3B82D9A702` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Downloader.Remus!8.1E06E (CLOUD)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!52ECFE174F1C` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

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

- **exe** (12×)
- **elf** (7×)
- **stealer** (5×)
- **Warden** (3×)
- **WARDENStealer** (3×)
- **Mirai** (3×)
- **unpacked** (3×)
- **DIVINEX** (2×)
- **dropped-by-OffLoader** (2×)
- **Torii** (2×)
- **signed** (2×)
- **wraith** (2×)
- **DvnX** (2×)
- **loader** (2×)
- **Lold** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -8 (22→14)
- ↓ **Mirai** -30 (33→3)
- neu: **BRB trojan** (1)
- neu: **AokigaharaStealer** (1)
- ↓ **RustyStealer** -3 (4→1)
- neu: **ValleyRAT** (1)
- neu: **FileRepMalware [Misc]** (1)
- ↓ **WannaCry** -1 (2→1)
- ↓ **SalatStealer** -13 (14→1)
- weg: **XWorm** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -10 (24→14)
- ↓ **Mirai** -22 (25→3)
- neu: **BRB trojan** (1)
- neu: **AokigaharaStealer** (1)
- neu: **ValleyRAT** (1)
- neu: **FileRepMalware [Misc]** (1)
- ↓ **SalatStealer** -16 (17→1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.046 MB |
| σ Dateigröße | 6.545 MB |
| Ø Risiko-Score | 69.6/100 |
| Ø Klassifikations-Konfidenz | 68.8% |
| Samples mit VT | 5/24 |
| Samples mit MITRE | 4/24 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:01 | [e34efe9b7001…](https://bazaar.abuse.ch/sample/e34efe9b7001f45cbf03764eb9658c3c3e4889b1c81454758df799fa7dc40e9e/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 20:52 | [42b9001bc3cb…](https://bazaar.abuse.ch/sample/42b9001bc3cba3459607da359512d20adf4453f74d7ed793d39d77be465ee9c2/) | `exe` | unbekannt | 74.8 | – | – | 🌐PT |
| 20:52 | [e3b3d631cba7…](https://bazaar.abuse.ch/sample/e3b3d631cba7f3ff41d6dcc207a52bc84e096facec79953684849564d85d40e3/) | `exe` | unbekannt | 74.8 | – | – | 🌐PT |
| 20:27 | [449162c01187…](https://bazaar.abuse.ch/sample/449162c0118749eb2c836d1c8af26976f010a1842e04743694d6d5479a7542d9/) | `elf` | Mirai | 83.9 | – | – | 🇩🇪DE |
| 19:29 | [b25a752117a9…](https://bazaar.abuse.ch/sample/b25a752117a9f7072929b88771a281fc7a412a2955b087ef6b3741e8a2434343/) | `msi` | unbekannt | 54.5 | 0.0% | ⚠️ KAUM ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 31.10.2026 21:11 UTC*