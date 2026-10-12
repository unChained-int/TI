# MalwareBazaar – 12.10.2026 14:47 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **61** |
| Höchster Score | **90.3/100** – b9a20f675edf5f51… |
| Häufigste Familie | **Mirai** (52x) |
| Häufigster Typ | **elf** (60x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 62 Samples |
| Ø Dateigröße | 1.25 MB (σ=3.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 60 | 59.4%  ███████████ |
| `sh` | 12 | 11.9%  ██ |
| `exe` | 11 | 10.9%  ██ |
| `macho` | 5 | 5.0%   |
| `vbs` | 3 | 3.0%   |
| `js` | 3 | 3.0%   |
| `py` | 3 | 3.0%   |
| `iso` | 2 | 2.0%   |
| `bat` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 52 | 51.5% |
| 2 | unbekannt | 34 | 33.7% |
| 3 | ValleyRAT | 2 | 2.0% |
| 4 | RemcosRAT | 2 | 2.0% |
| 5 | Vidar | 2 | 2.0% |
| 6 | GuLoader | 2 | 2.0% |
| 7 | Phorphiex | 1 | 1.0% |
| 8 | Prometei | 1 | 1.0% |
| 9 | GCleaner | 1 | 1.0% |
| 10 | Phorpiex | 1 | 1.0% |
| 11 | Formbook | 1 | 1.0% |
| 12 | MacOS:Agent-BTB [Drp] | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 52 | 51.5% | 95% |
| Andere / Unbekannt | 21 | 20.8% | 20% |
| Loader | 8 | 7.9% | 80% |
| Linux-Malware | 8 | 7.9% | 45% |
| RAT | 4 | 4.0% | 85% |
| Windows-Malware | 3 | 3.0% | 35% |
| Infostealer | 3 | 3.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 61 | 60.4% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 21 | 20.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b9a20f675edf5f…](https://bazaar.abuse.ch/sample/b9a20f675edf5f5115af87aa2ff6cf1dce745948e106f624a125f0cb98e34fd5/) | RemcosRAT | RAT | **90.3** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [0ce8c3af6e7265…](https://bazaar.abuse.ch/sample/0ce8c3af6e72657af3ee76ad397d8d3e5ae4b7aacc26b0ec058a21d6a444849d/) | Vidar | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [dbc072476f4688…](https://bazaar.abuse.ch/sample/dbc072476f46888a6e32fbd6a143d202ac9091d130501d5b9cd95586c47219ac/) | Formbook | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [4b525f710b5946…](https://bazaar.abuse.ch/sample/4b525f710b59464a67ea50c171c358afbe2b4afd22d1388af4aefcb8358d76ca/) | Vidar | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [298b2d2cf81f64…](https://bazaar.abuse.ch/sample/298b2d2cf81f6435744a15d6c83d9dfdcb4d854d6e5d6f4ca96380a1a4bb15b8/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [0c5820c39d9f6c…](https://bazaar.abuse.ch/sample/0c5820c39d9f6c04554753974a60d2961f9ca01c223325921bfd9a73140c4787/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [aecdcc76b8e9f2…](https://bazaar.abuse.ch/sample/aecdcc76b8e9f24d39fd380fcd8d9c96a35414708ccef56b7818e95365fb6327/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [d7c06d01dcebef…](https://bazaar.abuse.ch/sample/d7c06d01dcebef5fdefa8ee774737763dc26bf9fbee3a7924f1fe9b4411f6f86/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [694a029e35ed8c…](https://bazaar.abuse.ch/sample/694a029e35ed8ce359a3c783ee305cd913a83db57e5635ca649118a83787ebf3/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [8b4c1663484633…](https://bazaar.abuse.ch/sample/8b4c166348463321fb9d395faf41965ac403c0f73ccc7129af052f295a23ad34/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5934/7335 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5934/7335 |
| 3 | ESET-NOD32 | 77.4% | 5677/7335 |
| 4 | Kaspersky | 76.3% | 5597/7334 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5251/7332 |
| 8 | Rising | 68.7% | 5040/7335 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4872/7331 |
| 11 | Tencent | 65.2% | 4637/7109 |
| 12 | Avast | 65.1% | 4770/7331 |
| 13 | AVG | 65.1% | 4770/7330 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4495/7328 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 72 | 71.3% |
| 🪟 Windows | 15 | 14.9% |
| ❓ Unbekannt | 6 | 5.9% |
| 🍎 macOS | 5 | 5.0% |
| 📦 Archiv | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 92 | 91.1% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| C2 / Nachladen | 3 | 3.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 58 | 57.4% |
| 2 | 🇳🇱 NL | 18 | 17.8% |
| 3 | 🇺🇸 US | 13 | 12.9% |
| 4 | 🌐 EG | 4 | 4.0% |
| 5 | 🇭🇺 HU | 3 | 3.0% |
| 6 | 🇨🇭 CH | 2 | 2.0% |
| 7 | 🇫🇷 FR | 1 | 1.0% |
| 8 | 🇪🇸 ES | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 62 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 52 |
| Lateral Movement | 52 |
| Collection | 7 |
| Command and Control | 4 |
| Execution | 3 |
| Credential Access | 3 |
| Exfiltration | 2 |
| Defense Evasion | 2 |
| Persistence | 1 |

<details><summary>b9a20f675edf5f5115af… – RemcosRAT | 🔴 KRITISCH 90.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>0ce8c3af6e72657af3ee… – Vidar | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>dbc072476f46888a6e32… – Formbook | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4b525f710b59464a67ea… – Vidar | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>298b2d2cf81f6435744a… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b9a20f675edf5f5115af…](https://bazaar.abuse.ch/sample/b9a20f675edf5f5115af87aa2ff6cf1dce745948e106f624a125f0cb98e34fd5/)

- **Familie:** RemcosRAT
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Scr.Guloader!gen3
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/CloudEye.NI trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Symantec | `Scr.Guloader!gen3` |
| Varist | `JS/Agent.FER` |

### [33e3857559497d9106b1…](https://bazaar.abuse.ch/sample/33e3857559497d9106b1de5c95592988c34771eb00d7df8dd9c5b5e7fd264c31/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Coinminer.Linux.MALXMR.SMDSL64
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CSV [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avast | `ELF:Mirai-CSV [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.fz` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BF!MTB` |
| SentinelOne | `Static AI - Malicious ELF` |
| TrendMicro | `Coinminer.Linux.MALXMR.SMDSL64` |
| TrendMicro-HouseCall | `Coinminer.Linux.MALXMR.SMDSL64` |
| huorong | `Trojan/Linux.Mirai.mq` |

### [6917505bbdc8efa01ea1…](https://bazaar.abuse.ch/sample/6917505bbdc8efa01ea1a0298eae62a93a57a8c98d3712a69d822dca4a667f05/)

- **Familie:** MacOS:Agent-BTB [Drp]
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MacOS:Agent-BTB [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `MacOS:Agent-BTB [Drp]` |
| Avast | `MacOS:Agent-BTB [Drp]` |
| Avira | `DR/OSX.Agent.BTB` |
| CAT-QuickHeal | `Script.Trojan.A27880158` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `OSX/TrojanDownloader.Agent.DJ trojan` |
| F-Secure | `Dropper.DR/OSX.Agent.BTB` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Downloader.Agent/OSX!9.835E7 (XSE:WFNFX0JBVDr0rVZeVNdsaHli7//z/lZE)` |
| Tencent | `Osx.Trojan.Osx.Vgil` |

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

- **elf** (60×)
- **Mirai** (52×)
- **ICMacOS** (17×)
- **STRU** (17×)
- **exe** (12×)
- **sh** (11×)
- **macho** (5×)
- **vbs** (3×)
- **js** (3×)
- **py** (3×)
- **dropped-by-phorpiex** (2×)
- **ValleyRAT** (2×)
- **iso** (2×)
- **dropped-by-remcos** (2×)
- **NoTls** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +22 (30→52)
- ↑ **unbekannt** +7 (27→34)
- neu: **ValleyRAT** (2)
- ↑ **RemcosRAT** +1 (1→2)
- neu: **Vidar** (2)
- ↑ **GuLoader** +1 (1→2)
- neu: **Phorphiex** (1)
- neu: **Prometei** (1)
- neu: **GCleaner** (1)
- neu: **Phorpiex** (1)
- weg: **LxBaseRAT** (war 2)
- weg: **Gafgyt** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +13 (39→52)
- ↑ **unbekannt** +4 (30→34)
- neu: **ValleyRAT** (2)
- ↑ **RemcosRAT** +1 (1→2)
- ↑ **Vidar** +1 (1→2)
- neu: **GuLoader** (2)
- neu: **Phorphiex** (1)
- neu: **Prometei** (1)
- neu: **GCleaner** (1)
- neu: **Phorpiex** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.251 MB |
| σ Dateigröße | 3.067 MB |
| Ø Risiko-Score | 66.5/100 |
| Ø Klassifikations-Konfidenz | 71.2% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 62/101 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 32 |
| Unbekannte Familien | 21 (20.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:32 | [298b2d2cf81f…](https://bazaar.abuse.ch/sample/298b2d2cf81f6435744a15d6c83d9dfdcb4d854d6e5d6f4ca96380a1a4bb15b8/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 14:27 | [0c5820c39d9f…](https://bazaar.abuse.ch/sample/0c5820c39d9f6c04554753974a60d2961f9ca01c223325921bfd9a73140c4787/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 14:27 | [aecdcc76b8e9…](https://bazaar.abuse.ch/sample/aecdcc76b8e9f24d39fd380fcd8d9c96a35414708ccef56b7818e95365fb6327/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 14:22 | [d7c06d01dceb…](https://bazaar.abuse.ch/sample/d7c06d01dcebef5fdefa8ee774737763dc26bf9fbee3a7924f1fe9b4411f6f86/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 14:18 | [d93e944d4e2f…](https://bazaar.abuse.ch/sample/d93e944d4e2f6174ed9fbaa326a8220efbc45e30fe957c796a1177d6c322ae20/) | `exe` | Phorphiex | 74.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.10.2026 14:47 UTC*