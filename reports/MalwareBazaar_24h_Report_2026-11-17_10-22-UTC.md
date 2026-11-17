# MalwareBazaar – 17.11.2026 10:22 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **60** |
| Höchster Score | **92.1/100** – c8130d8d73dec5f4… |
| Häufigste Familie | **RemcosRAT** (21x) |
| Häufigster Typ | **js** (38x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 44 Samples |
| Ø Dateigröße | 2.44 MB (σ=10.87) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 38 | 37.6%  ███████ |
| `exe` | 30 | 29.7%  █████ |
| `vbs` | 8 | 7.9%  █ |
| `hta` | 8 | 7.9%  █ |
| `elf` | 6 | 5.9%  █ |
| `xls` | 6 | 5.9%  █ |
| `bat` | 3 | 3.0%   |
| `vbe` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | RemcosRAT | 21 | 20.8% |
| 2 | unbekannt | 16 | 15.8% |
| 3 | AgentTesla | 12 | 11.9% |
| 4 | Formbook | 8 | 7.9% |
| 5 | MassLogger | 5 | 5.0% |
| 6 | GuLoader | 4 | 4.0% |
| 7 | Prometei | 3 | 3.0% |
| 8 | AsyncRAT | 3 | 3.0% |
| 9 | VIPKeylogger | 3 | 3.0% |
| 10 | njrat | 3 | 3.0% |
| 11 | LxBaseRAT | 3 | 3.0% |
| 12 | WARDENStealer | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 36 | 35.6% | 92% |
| Skript/Dropper | 18 | 17.8% | 35% |
| Infostealer | 15 | 14.9% | 87% |
| Windows-Malware | 12 | 11.9% | 35% |
| Linux-Malware | 4 | 4.0% | 45% |
| Loader | 4 | 4.0% | 95% |
| Spyware | 3 | 3.0% | 75% |
| Maldoc | 3 | 3.0% | 35% |
| Botnet/IoT | 2 | 2.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |
| Exploit | 1 | 1.0% | 65% |
| Trojaner | 1 | 1.0% | 65% |
| Andere / Unbekannt | 1 | 1.0% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 60 | 59.4% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 37 | 36.6% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c8130d8d73dec5…](https://bazaar.abuse.ch/sample/c8130d8d73dec5f4b03d7eb3e54f68f04531e8537a53703d5207fe0319955e22/) | Gh0stRAT | Backdoor | **92.1** | 🔴 KRITISCH | – | – | ? |
| [793031b66d60eb…](https://bazaar.abuse.ch/sample/793031b66d60eb463e32172961dea273d68d000e5c2122d9a5ac5f26048a4a32/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [a0f1e6089494ff…](https://bazaar.abuse.ch/sample/a0f1e6089494ffdd70d293a085a8be74539270c79b4d92d08dd83692e8f7d8f1/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [000a219ec381c8…](https://bazaar.abuse.ch/sample/000a219ec381c86b6a1b2cb18f11d66f0a545749ac515335d772266d0720946a/) | FormBook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [90bd651d418dac…](https://bazaar.abuse.ch/sample/90bd651d418dac48c5dc2983a82fb51cf6b7ee0c26ef6b9fcdd642850ba6bfe7/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [e855c7be40af26…](https://bazaar.abuse.ch/sample/e855c7be40af26d6ce5143911dfa17bc22a9100193005ef2485319558aa22925/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [8e2ba6ee55fe7c…](https://bazaar.abuse.ch/sample/8e2ba6ee55fe7c5250fd39ecc82d27d0c2db5c7e11ba592cb29bde36f6bec29d/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [0730a5a6e67a43…](https://bazaar.abuse.ch/sample/0730a5a6e67a43979f924c02b9f090869bec2aa51cf019e0777327bb2f0468ac/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [d0344adf817bc2…](https://bazaar.abuse.ch/sample/d0344adf817bc25427991180fc2cf8185570950b1667690af54fa9213624928e/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [aa6037d16044f7…](https://bazaar.abuse.ch/sample/aa6037d16044f7e65ea39a0bebe84eccfec335bcaef4a0edc89e5b4516ce9efa/) | AsyncRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6514/8027 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6514/8027 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6207/8027 |
| 6 | Kaspersky | 75.5% | 6062/8026 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5716/8023 |
| 9 | Rising | 68.5% | 5496/8027 |
| 10 | Varist | 66.1% | 5300/8022 |
| 11 | Avast | 65.2% | 5229/8023 |
| 12 | AVG | 65.2% | 5229/8022 |
| 13 | Tencent | 65.1% | 5078/7801 |
| 14 | McAfeeD | 61.5% | 4930/8019 |
| 15 | huorong | 60.8% | 4878/8019 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 48 | 47.5% |
| ❓ Unbekannt | 38 | 37.6% |
| 🐧 Linux | 6 | 5.9% |
| 📄 Dokument | 6 | 5.9% |
| 🤖 Android | 2 | 2.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 53 | 52.5% |
| Drive-By / Exploit-Kit | 40 | 39.6% |
| Phishing / E-Mail-Anhang | 6 | 5.9% |
| USB / Wechselmedium | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 52 | 51.5% |
| 2 | 🇦🇹 AT | 28 | 27.7% |
| 3 | 🇩🇪 DE | 9 | 8.9% |
| 4 | 🇳🇱 NL | 3 | 3.0% |
| 5 | 🇫🇷 FR | 3 | 3.0% |
| 6 | 🇺🇸 US | 2 | 2.0% |
| 7 | 🇨🇭 CH | 2 | 2.0% |
| 8 | 🌐 EG | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 44 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 33 |
| Command and Control | 29 |
| Credential Access | 9 |
| Execution | 8 |
| Defense Evasion | 4 |
| Initial Access | 2 |
| Lateral Movement | 2 |
| Exfiltration | 1 |

<details><summary>793031b66d60eb463e32… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a0f1e6089494ffdd70d2… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>000a219ec381c86b6a1b… – FormBook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>90bd651d418dac48c5dc… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d92650b88bc72fc759f2…](https://bazaar.abuse.ch/sample/d92650b88bc72fc759f2ebcbf402f4d25ac8fb11e8287c6fc027edd3ad865327/)

- **Familie:** RemcosRAT
- **Erkannt von:** 20 von 74 Engines (27.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** GT:VB.Asthma.2.1B12F652
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `GT:VB.Asthma.2.1B12F652`

**Erkennende Engines (20/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `GT:VB.Asthma.2.1B12F652` |
| Arcabit | `GT:VB.Asthma.2.1B12F652` |
| Avira | `DR/SNH` |
| BitDefender 🛡️ | `GT:VB.Asthma.2.1B12F652` |
| CTX | `html.unknown.asthma` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `VBS/Obfuscated.AO trojan` |
| Emsisoft | `GT:VB.Asthma.2.1B12F652 (B)` |
| F-Secure | `Dropper.DR/SNH` |
| Fortinet | `VBS/Obfuscated.AO!tr` |
| GData | `GT:VB.Asthma.2.1B12F652` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan-Downloader.Script.Generic` |
| MicroWorld-eScan | `GT:VB.Asthma.2.1B12F652` |
| NANO-Antivirus | `Trojan.Script.Vbs-heuristic.druvzi` |
| Symantec | `ISB.Downloader!gen80` |
| TrendMicro | `HEUR_EMBVBS.EE1` |
| TrendMicro-HouseCall | `HEUR_EMBVBS.EE1` |
| VIPRE | `GT:VB.Asthma.2.1B12F652` |
| Varist | `JS/Agent.CMC3.gen!Eldorado` |

### [66a1e5ffd7ff5d8f5170…](https://bazaar.abuse.ch/sample/66a1e5ffd7ff5d8f5170bf57db0e0a058e43ed853647adf7a3b216748f9fad68/)

- **Familie:** CVE-2017-0199
- **Erkannt von:** 19 von 74 Engines (25.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Exploit.CVE-2017-0199.04.Gen
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Exploit.CVE-2017-0199.04.Gen`

**Erkennende Engines (19/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Exploit.CVE-2017-0199.04.Gen` |
| Arcabit | `Exploit.CVE-2017-0199.04.Gen` |
| BitDefender 🛡️ | `Exploit.CVE-2017-0199.04.Gen` |
| CTX | `xls.exploit-kit.cve-2017-0199` |
| ESET-NOD32 | `probably Win32/Exploit.CVE-2017-0199.C trojan` |
| Emsisoft | `Exploit.CVE-2017-0199.04.Gen (B)` |
| Fortinet | `MSOffice/Phishing.8C4D!tr` |
| GData | `Exploit.CVE-2017-0199.04.Gen` |
| Kaspersky | `HEUR:Trojan.OLE2.UrcBadur.genw` |
| MicroWorld-eScan | `Exploit.CVE-2017-0199.04.Gen` |
| Rising | `Exploit.CVE-2017-0199!1.E43C (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious OLE` |
| TACHYON | `Downloader/W97.CVE-2017-0199` |
| Tencent | `Win32.Trojan.Urcbadur.Sgil` |
| TrendMicro | `HEUR_CVE170199.L` |
| TrendMicro-HouseCall | `HEUR_CVE170199.L` |
| VIPRE | `Exploit.CVE-2017-0199.04.Gen` |
| Varist | `CVE-2017-0199.A.gen!Camelot` |
| huorong | `Exploit/CVE-2017-0199.t` |

### [c57f91b6379d1bd04419…](https://bazaar.abuse.ch/sample/c57f91b6379d1bd044192e13ecf02e5c85f0624680a27aff369e016fdf4a70fa/)

- **Familie:** Barys
- **Erkannt von:** 42 von 74 Engines (56.8%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Barys.522025
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Barys.522025`

**Erkennende Engines (42/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.23831` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Trj]` |
| Antiy-AVL | `Trojan[Spy]/Win32.Bobik` |
| Arcabit | `Trojan.Barys.D7F729` |
| Avast | `Win32:MalwareX-gen [Trj]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Barys.522025` |
| Bkav | `W32.Malware.3EA709D4` |
| CTX | `exe.unknown.generic` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop44.51117` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Barys.522025 (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| GData | `Gen:Variant.Barys.522025` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Gen.sa` |
| Ikarus | `Trojan.Win32.MalwareX` |
| Kaspersky | `Trojan-Spy.Win32.Bobik.dyki` |
| Kingsoft | `Win32.Trojan-Spy.Bobik.dyki` |
| Lionic | `Trojan.Win32.Bobik.l!c` |
| McAfeeD | `ti!C57F91B6379D` |
| MicroWorld-eScan | `Gen:Variant.Barys.522025` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Spyware.Bobik!8.108FF (CLOUD)` |
| Sangfor | `Trojan.Win32.Agent.Vbx1` |
| Skyhigh | `BehavesLike.Win32.Dropper.cm` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan-Spy.Bobik.Zylw` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Artemis!232C0450415A` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H09KG26` |
| VBA32 | `BScope.Trojan.Shellcode` |
| VIPRE | `Gen:Variant.Draftor.23831` |
| Varist | `W32/ABTrojan.XJAN-1707` |
| alibabacloud | `Trojan[spy]:Win/Bobik.dgzV` |

### [7ca0d9b533effed8c750…](https://bazaar.abuse.ch/sample/7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971/)

- **Familie:** AgentTesla
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| AhnLab-V3 | `Trojan/Win.SpyNoon.C5959689` |
| Avast | `MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| Bkav | `W32.Malware.F6442A85` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.ARGQ trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| Fortinet | `MSIL/AgentTesla.ALLB!tr` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.Noon.gen` |
| McAfeeD | `ti!7CA0D9B533EF` |
| Microsoft 🛡️ | `Trojan:MSIL/XWorm.AV!MTB` |
| Rising | `Malware.Obfus/MSIL@AI.98 (RDM.MSIL2:ZfywNMNewjD2Nhh+1Gkcyg)` |
| Sangfor | `Virus.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `Scr.Malcode!gdn34` |
| Tencent | `Msil.Trojan.Kryptik.Ztjl` |
| Trapmine | `suspicious.low.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| Varist | `W32/MSIL_Kryptik.MUC.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **js** (38×)
- **exe** (29×)
- **RemcosRAT** (21×)
- **RAT** (13×)
- **AgentTesla** (12×)
- **vbs** (8×)
- **Formbook** (8×)
- **hta** (8×)
- **xls** (6×)
- **elf** (5×)
- **MassLogger** (5×)
- **GuLoader** (4×)
- **AsyncRAT** (4×)
- **CVE-2017-0199** (4×)
- **Prometei** (3×)

## Änderungen – 24h-Vergleich

- ↑ **RemcosRAT** +19 (2→21)
- ↓ **unbekannt** -14 (30→16)
- ↑ **AgentTesla** +10 (2→12)
- ↑ **Formbook** +6 (2→8)
- ↑ **MassLogger** +4 (1→5)
- neu: **GuLoader** (4)
- ↓ **Prometei** -5 (8→3)
- neu: **AsyncRAT** (3)
- neu: **VIPKeylogger** (3)
- ↑ **njrat** +1 (2→3)
- weg: **FunStealer** (war 14)
- weg: **RemusStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **RemcosRAT** +19 (2→21)
- ↓ **unbekannt** -9 (25→16)
- ↑ **AgentTesla** +11 (1→12)
- ↑ **Formbook** +7 (1→8)
- neu: **MassLogger** (5)
- ↑ **GuLoader** +3 (1→4)
- ↑ **Prometei** +2 (1→3)
- neu: **AsyncRAT** (3)
- neu: **VIPKeylogger** (3)
- ↑ **njrat** +2 (1→3)
- weg: **SalatStealer** (war 6)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.443 MB |
| σ Dateigröße | 10.866 MB |
| Ø Risiko-Score | 67.3/100 |
| Ø Klassifikations-Konfidenz | 69.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 44/101 |
| Eindeutige Familien | 27 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 10:10 | [15314144f737…](https://bazaar.abuse.ch/sample/15314144f73741b3e31921da6580bf87662db370a1ed8f1f93e72762358182c1/) | `elf` | Prometei | 43.2 | – | – | 🇺🇸US |
| 09:58 | [fd5343c627c0…](https://bazaar.abuse.ch/sample/fd5343c627c0670b2f99c3c24bb11d3f0548009d2cabe0ac8042e46d1d8795ef/) | `exe` | AndyDesk | 38.7 | – | – | 🇺🇸US |
| 09:52 | [ec005ccbbc83…](https://bazaar.abuse.ch/sample/ec005ccbbc83c0b4f9e232dfe96c8293caa4552d2ac7a91bb3705c13106af6e3/) | `elf` | unbekannt | 42.9 | – | – | 🌐EG |
| 09:31 | [2d89184a566d…](https://bazaar.abuse.ch/sample/2d89184a566d2cae6d3e7c78dad0f9e1a44c5e64a44d19bacfc9cfc0366e7d0a/) | `vbs` | DarkCoreRAT | 80.5 | – | – | 🌐SE |
| 09:31 | [8e2ba6ee55fe…](https://bazaar.abuse.ch/sample/8e2ba6ee55fe7c5250fd39ecc82d27d0c2db5c7e11ba592cb29bde36f6bec29d/) | `vbs` | RemcosRAT | 89.0 | – | – | 🌐SE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.11.2026 10:22 UTC*