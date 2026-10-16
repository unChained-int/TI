# MalwareBazaar – 16.10.2026 19:26 UTC

Dieser Run hat **59 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **60** |
| Kritisch (≥75) | **20** |
| Höchster Score | **89.0/100** – 9d64e52708ab78bf… |
| Häufigste Familie | **unbekannt** (40x) |
| Häufigster Typ | **elf** (23x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 13 Samples |
| Ø Dateigröße | 10.51 MB (σ=16.57) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 23 | 38.3%  ███████ |
| `exe` | 20 | 33.3%  ██████ |
| `jar` | 9 | 15.0%  ███ |
| `sh` | 3 | 5.0%  █ |
| `zip` | 3 | 5.0%  █ |
| `js` | 1 | 1.7%   |
| `macho` | 1 | 1.7%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 40 | 66.7% |
| 2 | Mirai | 9 | 15.0% |
| 3 | RemcosRAT | 2 | 3.3% |
| 4 | RemusStealer | 2 | 3.3% |
| 5 | ConnectWise | 2 | 3.3% |
| 6 | SMLBO1 | 1 | 1.7% |
| 7 | Linux | 1 | 1.7% |
| 8 | LummaStealer | 1 | 1.7% |
| 9 | AMOS | 1 | 1.7% |
| 10 | VShell | 1 | 1.7% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 13 | 21.7% | 20% |
| Linux-Malware | 13 | 21.7% | 45% |
| Botnet/IoT | 9 | 15.0% | 95% |
| Loader | 6 | 10.0% | 73% |
| Infostealer | 6 | 10.0% | 82% |
| Windows-Malware | 6 | 10.0% | 35% |
| RAT | 3 | 5.0% | 88% |
| Trojaner | 2 | 3.3% | 75% |
| Exploit | 1 | 1.7% | 65% |
| Skript/Dropper | 1 | 1.7% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 20 | 33.3% |
| 🟠 HOCH | 7 | 11.7% |
| 🟡 MITTEL | 20 | 33.3% |
| 🟢 NIEDRIG | 13 | 21.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [9d64e52708ab78…](https://bazaar.abuse.ch/sample/9d64e52708ab78bf5e93b06d40cb08392ef8918987c2ce9ac2f0511ede89d4aa/) | LummaStealer | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [ae6e815981ca4e…](https://bazaar.abuse.ch/sample/ae6e815981ca4ef79e01a1bbaf3927bfc557192c288cb31436ffb9366ef03077/) | RemcosRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [cefb465886bc81…](https://bazaar.abuse.ch/sample/cefb465886bc813ac91e9ad5b1835eefe9828f251b58eb0da012ee4022ff6d98/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [65f4813d45b7a5…](https://bazaar.abuse.ch/sample/65f4813d45b7a5009dc552ea28635da725bd0d50c43dc9ac5fd25aa96fcad196/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [4054396ee1fb4c…](https://bazaar.abuse.ch/sample/4054396ee1fb4c0e1714eafdf6919cf223cbaa4324a61b51597bc0dca717ffc6/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [4dab5bbf6968a9…](https://bazaar.abuse.ch/sample/4dab5bbf6968a919390ca9aee96dc7f2b87031b0938111050ea1f79610d01016/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [4fa2ee264589b3…](https://bazaar.abuse.ch/sample/4fa2ee264589b30338945388ab871181c500db00843c319b6890b38d07f9d16f/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [1340c831dbd27a…](https://bazaar.abuse.ch/sample/1340c831dbd27a87cca8c80feb90a3e98071e4d33793192467eee9cfe0343b21/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [00bd2dec0ae7ac…](https://bazaar.abuse.ch/sample/00bd2dec0ae7acd5240da4146f4a7681e2b1c6e1af775e77efeccd742dca09e0/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [463f56104d5b94…](https://bazaar.abuse.ch/sample/463f56104d5b9459918a39fd23d28937c1c7a1f88d8c3b6e48d6755fc0bbb7c7/) | unbekannt | Infostealer | **82.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6001/7420 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6001/7420 |
| 3 | ESET-NOD32 | 77.4% | 5745/7420 |
| 4 | Kaspersky | 76.3% | 5664/7419 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5305/7417 |
| 8 | Rising | 68.7% | 5100/7420 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4928/7416 |
| 11 | Tencent | 65.3% | 4699/7194 |
| 12 | Avast | 65.1% | 4828/7416 |
| 13 | AVG | 65.1% | 4828/7415 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4546/7413 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 27 | 45.0% |
| 🪟 Windows | 19 | 31.7% |
| ❓ Unbekannt | 10 | 16.7% |
| 📦 Archiv | 3 | 5.0% |
| 🍎 macOS | 1 | 1.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 54 | 90.0% |
| C2 / Nachladen | 5 | 8.3% |
| Drive-By / Exploit-Kit | 1 | 1.7% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 23 | 38.3% |
| 2 | 🇩🇪 DE | 16 | 26.7% |
| 3 | 🇦🇹 AT | 9 | 15.0% |
| 4 | 🇨🇿 CZ | 5 | 8.3% |
| 5 | 🇳🇱 NL | 4 | 6.7% |
| 6 | 🇨🇭 CH | 2 | 3.3% |
| 7 | 🌐 Unbekannt | 1 | 1.7% |

## MITRE ATT&CK

> 13 von 60 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 9 |
| Lateral Movement | 9 |
| Collection | 3 |
| Command and Control | 2 |
| Credential Access | 2 |
| Exfiltration | 2 |

<details><summary>9d64e52708ab78bf5e93… – LummaStealer | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>ae6e815981ca4ef79e01… – RemcosRAT | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>65f4813d45b7a5009dc5… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>4054396ee1fb4c0e1714… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [72d835f767c8ced23530…](https://bazaar.abuse.ch/sample/72d835f767c8ced23530f2a80db15ebc60716d280badac96ece9185e3c89e118/)

- **Familie:** SMLBO1
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_BASHDLOD.SMLBO1
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Downloader/Shell.Generic.S2477` |
| Avira | `HTML/ExpKit.Gen2` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2427` |
| Fortinet | `BASH/Mirai.AEH!tr.dldr` |
| Google | `Detected` |
| Ikarus | `HTML.ExploitKit` |
| Symantec | `CL.Downloader!gen277` |
| TrendMicro | `Possible_BASHDLOD.SMLBO1` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBO1` |
| Varist | `SH/Mirai.D.gen!Camelot` |
| huorong | `TrojanDownloader/Linux.Shell.cd` |

### [eae4750fa11a822dc8fb…](https://bazaar.abuse.ch/sample/eae4750fa11a822dc8fba35c9fb4bedeeebb4b9463564c8ff51557e6ebfe2b91/)

- **Familie:** Linux
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** HEUR:Exploit.Linux.CVE-2014-8361.a
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Supershell` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2014-8361.a` |
| huorong | `Trojan/Linux.Mirai.f` |

### [30111b7934f147d113db…](https://bazaar.abuse.ch/sample/30111b7934f147d113db7f8be5aa6fc36646cb9236008d03b2538d090ea3f49e/)

- **Familie:** Mirai
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Crypt` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Linux.Backdoor.Gafgyt.Ychl` |
| Varist | `E64/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.l` |

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

- **exe** (17×)
- **elf** (14×)
- **Mirai** (9×)
- **jar** (9×)
- **java** (9×)
- **python** (9×)
- **silentnet** (9×)
- **dropped-by-GCleaner** (5×)
- **signed** (4×)
- **A** (3×)
- **zip** (3×)
- **SilverFox** (3×)
- **ValleyRAT** (3×)
- **sh** (2×)
- **Stealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +12 (28→40)
- ↓ **Mirai** -6 (15→9)
- ↑ **RemusStealer** +1 (1→2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **SMLBO1** (1)
- neu: **Linux** (1)
- neu: **LummaStealer** (1)
- neu: **VShell** (1)
- weg: **DDoSAgent** (war 2)
- weg: **Formbook** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +12 (28→40)
- ↓ **Mirai** -22 (31→9)
- ↑ **RemusStealer** +1 (1→2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **SMLBO1** (1)
- neu: **Linux** (1)
- neu: **LummaStealer** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 10.514 MB |
| σ Dateigröße | 16.565 MB |
| Ø Risiko-Score | 55.9/100 |
| Ø Klassifikations-Konfidenz | 55.9% |
| Samples mit VT | 4/60 |
| Samples mit MITRE | 13/60 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 13 (21.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:24 | [e06be431a8d4…](https://bazaar.abuse.ch/sample/e06be431a8d427579fec15f84bb152326953a7be7a4d20060c6317614ca27843/) | `sh` | unbekannt | 32.7 | – | – | 🇩🇪DE |
| 19:24 | [72d835f767c8…](https://bazaar.abuse.ch/sample/72d835f767c8ced23530f2a80db15ebc60716d280badac96ece9185e3c89e118/) | `sh` | SMLBO1 | 75.0 | 16.0% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 19:24 | [51221b8ce9f3…](https://bazaar.abuse.ch/sample/51221b8ce9f3a3ac4454b1a576e9bb07783f1dc124822a2edda8839731b69f7f/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 19:24 | [04e76666216c…](https://bazaar.abuse.ch/sample/04e76666216c060a7c8b57c08aabc66c82a3c245f29546c2bc6e2b21c20987f0/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 19:24 | [9fcda81900bd…](https://bazaar.abuse.ch/sample/9fcda81900bd14fde27df6ea9de5da9dd92ed7c670f6b7249b06228be259c8c1/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.10.2026 19:26 UTC*