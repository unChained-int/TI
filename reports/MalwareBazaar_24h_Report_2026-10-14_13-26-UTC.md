# MalwareBazaar – 14.10.2026 13:26 UTC

Dieser Run hat **96 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **97** |
| Kritisch (≥75) | **46** |
| Höchster Score | **90.3/100** – 2c478b9fd4089b21… |
| Häufigste Familie | **unbekannt** (47x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 37 Samples |
| Ø Dateigröße | 5.83 MB (σ=14.00) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 54.6%  ██████████ |
| `exe` | 18 | 18.6%  ███ |
| `js` | 5 | 5.2%  █ |
| `zip` | 4 | 4.1%   |
| `macho` | 3 | 3.1%   |
| `lnk` | 3 | 3.1%   |
| `jar` | 2 | 2.1%   |
| `vhdx` | 2 | 2.1%   |
| `ps1` | 2 | 2.1%   |
| `iso` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 47 | 48.5% |
| 2 | Mirai | 20 | 20.6% |
| 3 | Formbook | 7 | 7.2% |
| 4 | AsyncRAT | 3 | 3.1% |
| 5 | RemcosRAT | 3 | 3.1% |
| 6 | AMOS | 3 | 3.1% |
| 7 | CoinMiner | 2 | 2.1% |
| 8 | ValleyRAT | 2 | 2.1% |
| 9 | Vidar | 2 | 2.1% |
| 10 | Agent | 1 | 1.0% |
| 11 | BridgeAgent | 1 | 1.0% |
| 12 | XWorm | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 27 | 27.8% | 45% |
| Botnet/IoT | 21 | 21.6% | 94% |
| Infostealer | 15 | 15.5% | 91% |
| RAT | 10 | 10.3% | 89% |
| Andere / Unbekannt | 10 | 10.3% | 20% |
| Loader | 4 | 4.1% | 75% |
| Windows-Malware | 4 | 4.1% | 35% |
| Trojaner | 3 | 3.1% | 72% |
| Cryptominer | 2 | 2.1% | 75% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 46 | 47.4% |
| 🟠 HOCH | 9 | 9.3% |
| 🟡 MITTEL | 32 | 33.0% |
| 🟢 NIEDRIG | 10 | 10.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2c478b9fd4089b…](https://bazaar.abuse.ch/sample/2c478b9fd4089b21e0bf8ee5682c652a9ee0ac545432576a0691bdea5ee11338/) | Formbook | Infostealer | **90.3** | 🔴 KRITISCH | – | – | ? |
| [ff113135f91e73…](https://bazaar.abuse.ch/sample/ff113135f91e732050a8cba3281dd73926f356d6021e55019c3b3fa2ee5d9b60/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [1c4a7fa5a9ab10…](https://bazaar.abuse.ch/sample/1c4a7fa5a9ab10facde4dabbffe32d5bf9903f930f3c63d83c5c21dad346e931/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [e9ae2f17b2926e…](https://bazaar.abuse.ch/sample/e9ae2f17b2926e49768e787b1802282a32625244746713c32c7d6d32c225cf0e/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [137ac2a2bc790a…](https://bazaar.abuse.ch/sample/137ac2a2bc790a7ed9769f900fd5cdedac90d3e937a6b2bad8cd8cfff0b55ffd/) | XWorm | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [4d5f1c0ba9e03f…](https://bazaar.abuse.ch/sample/4d5f1c0ba9e03f82ed543d43ff77c1d94345f2ed05480c89b4b3ca3f71e86ee8/) | Formbook | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [956b3514f38e62…](https://bazaar.abuse.ch/sample/956b3514f38e62f398f2b62fb7f6a11199e127ed5a1517211285056e62d2e3a6/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [79965c365c3cc4…](https://bazaar.abuse.ch/sample/79965c365c3cc4422bfbb808d7e36d50f631d68552601d85ebeabb8c887320fe/) | Formbook | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [d0c440f72378bf…](https://bazaar.abuse.ch/sample/d0c440f72378bfe693207e2ce49e504828a881d132b20e5ce3b3443e82d9f06f/) | Vidar | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [61449e2aff0663…](https://bazaar.abuse.ch/sample/61449e2aff06633a1add0461027d7e40b2c4b07ba96043b2ce99646b3f8d62ab/) | Vidar | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5957/7366 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5957/7366 |
| 3 | ESET-NOD32 | 77.4% | 5701/7366 |
| 4 | Kaspersky | 76.3% | 5623/7365 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5269/7363 |
| 8 | Rising | 68.7% | 5061/7366 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4890/7362 |
| 11 | Tencent | 65.3% | 4661/7140 |
| 12 | Avast | 65.0% | 4786/7362 |
| 13 | AVG | 65.0% | 4786/7361 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4512/7359 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 54 | 55.7% |
| 🪟 Windows | 24 | 24.7% |
| ❓ Unbekannt | 9 | 9.3% |
| 📦 Archiv | 6 | 6.2% |
| 🍎 macOS | 3 | 3.1% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 87.6% |
| Drive-By / Exploit-Kit | 5 | 5.2% |
| MaaS-Loader | 3 | 3.1% |
| C2 / Nachladen | 2 | 2.1% |
| Trojanisierte Software | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 46 | 47.4% |
| 2 | 🇺🇸 US | 14 | 14.4% |
| 3 | 🇭🇺 HU | 11 | 11.3% |
| 4 | 🇨🇭 CH | 7 | 7.2% |
| 5 | 🇫🇷 FR | 6 | 6.2% |
| 6 | 🇳🇱 NL | 5 | 5.2% |
| 7 | 🇦🇹 AT | 2 | 2.1% |
| 8 | 🇦🇺 AU | 2 | 2.1% |
| 9 | 🇸🇪 SE | 1 | 1.0% |
| 10 | 🇨🇿 CZ | 1 | 1.0% |
| 11 | 🇷🇺 RU | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 37 von 97 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |
| Collection | 14 |
| Credential Access | 9 |
| Command and Control | 8 |
| Execution | 3 |
| Exfiltration | 2 |

<details><summary>2c478b9fd4089b21e0bf… – Formbook | 🔴 KRITISCH 90.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ff113135f91e732050a8… – AsyncRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>1c4a7fa5a9ab10facde4… – RemcosRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>e9ae2f17b2926e49768e… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [acd33492caa5b601813e…](https://bazaar.abuse.ch/sample/acd33492caa5b601813eccad568b1a85e66f671e5255f64fc0338e3001c82a6c/)

- **Familie:** Agent
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/HackTool.Agent.GM trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/HackTool.Agent.GM trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [87130e2f3d6f0c6f22a2…](https://bazaar.abuse.ch/sample/87130e2f3d6f0c6f22a2a52d188fdadfe3a1d8ddff589238eb614a892a932371/)

- **Familie:** AsyncRAT
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Generic.AsyncRAT.Marte.B.7E8423CC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.AsyncRAT.Marte.B.7E8423CC`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.AsyncRAT.Marte.B.7E8423CC` |
| APEX | `Malicious` |
| AVG | `MSIL:AsyncRat-E [Pws]` |
| AhnLab-V3 | `Trojan/Win32.RL_Generic.R358277` |
| Antiy-AVL | `Trojan[Backdoor]/MSIL.Crysan` |
| Arcabit | `Generic.AsyncRAT.Marte.B.7E8423CC` |
| Avast | `MSIL:AsyncRat-E [Pws]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Generic.AsyncRAT.Marte.B.7E8423CC` |
| Bkav | `W32.Malware.6F3C9BC1` |
| CAT-QuickHeal | `Trojan.IgenericFC.S14890850` |
| CTX | `exe.unknown.asyncrat` |
| ClamAV | `Win.Packed.Razy-9625918-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.AsyncRAT.115` |
| ESET-NOD32 | `MSIL/AsyncRAT.A trojan` |
| Elastic | `Windows.Generic.Threat` |
| Emsisoft | `Trojan.Agent (A)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/AsyncRAT.A!tr` |
| GData | `MSIL.Backdoor.DCRat.D` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.AsyncRAT` |
| Jiangmin | `Backdoor.MSIL.gguk` |
| K7AntiVirus | `Trojan ( 005c228f1 )` |
| K7GW | `Trojan ( 005c228f1 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.Crysan.gen` |
| Malwarebytes | `Generic.Trojan.MSIL.DDS` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!87130E2F3D6F` |
| MicroWorld-eScan | `Generic.AsyncRAT.Marte.B.7E8423CC` |
| Microsoft 🛡️ | `Backdoor:MSIL/AsyncRat!atmn` |
| NANO-Antivirus | `Trojan.Win32.AsyncRAT.lhhviy` |
| Rising | `Trojan.AntiVM!1.CF63 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Kryptik` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Fareit-FZT!4120583579B2` |
| Sophos | `Troj/AsyncRat-B` |
| Symantec | `Backdoor.ASync!g2` |
| Tencent | `Trojan.Msil.Agent.zap` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Fareit-FZT!4120583579B2` |
| TrendMicro | `Backdoor.MSIL.ASYNCRAT.SMXSR` |
| TrendMicro-HouseCall | `Backdoor.MSIL.ASYNCRAT.SMXSR` |
| VBA32 | `OScope.Backdoor.MSIL.Crysan` |
| VIPRE | `Generic.AsyncRAT.Marte.B.7E8423CC` |
| Varist | `W32/Samas.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Yandex | `Trojan.AsyncRAT!LgMSjHRYcEo` |
| Zillya | `Trojan.Agent.Win32.1334603` |
| ZoneAlarm | `Troj/AsyncRat-B` |
| huorong | `Backdoor/MSIL.DcRat.a` |

### [3d480c449a433f133a11…](https://bazaar.abuse.ch/sample/3d480c449a433f133a1135e699de8e86310c073723c5e7c60b52d8d8c212079d/)

- **Familie:** ELF:CVE-2021-36260-A [Expl]
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2021-36260-A [Expl]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2021-36260-A [Expl]` |
| Avast | `ELF:CVE-2021-36260-A [Expl]` |
| Avira | `EXP/LINUX.CVE-2021-.A` |
| ClamAV | `Unix.Trojan.Mirai-10004218-0` |
| Cynet | `Malicious (score: 99)` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2021-.A` |
| Kaspersky | `HEUR:Exploit.Linux.Netgear.a` |
| Microsoft 🛡️ | `DDoS:Linux/Mirai.PA!MTB` |
| Tencent | `Linux.Exploit.Netgear.Qgil` |
| huorong | `Trojan/Linux.DDoS.t` |

### [c869584f3e17fdde01a2…](https://bazaar.abuse.ch/sample/c869584f3e17fdde01a26bdf58d92837d8f396aad9944dffb08627c1f7e1323f/)

- **Familie:** Mirai
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Ikarus | `Backdoor.Linux.Gafgyt` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Rising | `Trojan.Agent/Linux!8.13268 (CLOUD)` |
| Tencent | `Malware.Linux.Generic.1c0aa20b` |
| TrendMicro-HouseCall | `Trojan.Linux.Gen.TL0101HS26Z5` |
| alibabacloud | `Trojan:Linux/Agent.gyf` |

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

- **elf** (53×)
- **Mirai** (20×)
- **exe** (15×)
- **Formbook** (7×)
- **upx-dec** (5×)
- **upx** (5×)
- **js** (5×)
- **diicot** (4×)
- **arm** (4×)
- **cowrie** (4×)
- **honeypot** (4×)
- **ClickFix** (4×)
- **Foxveil** (4×)
- **macOS** (4×)
- **AsyncRAT** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +17 (30→47)
- ↓ **Mirai** -10 (30→20)
- ↑ **Formbook** +5 (2→7)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **AMOS** +1 (2→3)
- ↑ **ValleyRAT** +1 (1→2)
- ↑ **Vidar** +1 (1→2)
- neu: **Agent** (1)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +19 (28→47)
- ↓ **Mirai** -19 (39→20)
- ↑ **Formbook** +5 (2→7)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **AMOS** +2 (1→3)
- ↑ **CoinMiner** +1 (1→2)
- ↑ **ValleyRAT** +1 (1→2)
- ↑ **Vidar** +1 (1→2)
- neu: **Agent** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.828 MB |
| σ Dateigröße | 13.997 MB |
| Ø Risiko-Score | 62.9/100 |
| Ø Klassifikations-Konfidenz | 66.8% |
| Samples mit VT | 5/97 |
| Samples mit MITRE | 37/97 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 66 |
| Unbekannte Familien | 10 (10.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:15 | [ff113135f91e…](https://bazaar.abuse.ch/sample/ff113135f91e732050a8cba3281dd73926f356d6021e55019c3b3fa2ee5d9b60/) | `exe` | AsyncRAT | 89.6 | – | – | 🇺🇸US |
| 13:14 | [c30f26965154…](https://bazaar.abuse.ch/sample/c30f26965154e7794969d7273099ae6e502758e8e0698fca32a8442d239b39f4/) | `elf` | unbekannt | 43.2 | – | – | 🇳🇱NL |
| 13:14 | [7f5405336173…](https://bazaar.abuse.ch/sample/7f54053361738ebabcb0981f39a342a32682f954544b4a36a7724f26599b8dd1/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 13:13 | [ce198f1a6613…](https://bazaar.abuse.ch/sample/ce198f1a6613760407d8035588a5b197cad5fdb5d8b887f5b9ac62b8d8b133e9/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 13:13 | [00e7101582c9…](https://bazaar.abuse.ch/sample/00e7101582c9f2c894199a7e638fb04d48e6fa81c791d71a120cdd079dd1293c/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.10.2026 13:26 UTC*