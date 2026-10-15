# MalwareBazaar – 15.10.2026 19:46 UTC

Dieser Run hat **81 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **82** |
| Kritisch (≥75) | **55** |
| Höchster Score | **91.0/100** – c0ac6e8d2256d9bd… |
| Häufigste Familie | **Mirai** (30x) |
| Häufigster Typ | **elf** (43x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 37 Samples |
| Ø Dateigröße | 6.63 MB (σ=19.07) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 43 | 52.4%  ██████████ |
| `exe` | 20 | 24.4%  ████ |
| `hta` | 4 | 4.9%   |
| `dll` | 3 | 3.7%   |
| `sh` | 2 | 2.4%   |
| `jar` | 2 | 2.4%   |
| `iso` | 1 | 1.2%   |
| `zsh` | 1 | 1.2%   |
| `cab` | 1 | 1.2%   |
| `vbs` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 30 | 36.6% |
| 2 | unbekannt | 20 | 24.4% |
| 3 | DDoSAgent | 9 | 11.0% |
| 4 | RemusStealer | 3 | 3.7% |
| 5 | ValleyRAT | 3 | 3.7% |
| 6 | Amadey | 3 | 3.7% |
| 7 | SilentNet | 2 | 2.4% |
| 8 | HijackLoader | 2 | 2.4% |
| 9 | AsyncRAT | 1 | 1.2% |
| 10 | MacSync | 1 | 1.2% |
| 11 | PythonStealer | 1 | 1.2% |
| 12 | LummaStealer | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 39 | 47.6% | 90% |
| Loader | 8 | 9.8% | 82% |
| Infostealer | 6 | 7.3% | 78% |
| RAT | 6 | 7.3% | 85% |
| Linux-Malware | 5 | 6.1% | 45% |
| Windows-Malware | 5 | 6.1% | 35% |
| Andere / Unbekannt | 5 | 6.1% | 20% |
| Skript/Dropper | 5 | 6.1% | 35% |
| Trojaner | 2 | 2.4% | 75% |
| Backdoor | 1 | 1.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 55 | 67.1% |
| 🟠 HOCH | 7 | 8.5% |
| 🟡 MITTEL | 15 | 18.3% |
| 🟢 NIEDRIG | 5 | 6.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c0ac6e8d2256d9…](https://bazaar.abuse.ch/sample/c0ac6e8d2256d9bddec91edb5e66f2b574af109978072717eb985d8cd17d0fad/) | Gh0stRAT | Backdoor | **91.0** | 🔴 KRITISCH | – | – | ? |
| [c25ead077458ff…](https://bazaar.abuse.ch/sample/c25ead077458ff215c8ef109b2c86e9b8a3c2a63f6d229b721382b035816633e/) | AsyncRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [83d2faf575026b…](https://bazaar.abuse.ch/sample/83d2faf575026b3f75446a6337f004f5d81e66d5e2bfa19c44c6ef369fd1ec1a/) | LummaStealer | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [7fc40c0ee79175…](https://bazaar.abuse.ch/sample/7fc40c0ee7917566f59bb45e2deb94f88b4b1da077fa7c1fda3ceca29b967574/) | XWorm | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [bf39877283bb8b…](https://bazaar.abuse.ch/sample/bf39877283bb8b3ac50ad7f8981b8e54282cf0c41a60b47196de36158bc95f1d/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [170697c480f713…](https://bazaar.abuse.ch/sample/170697c480f713006c0fe0ca6e28508ff56e15afbfe7a93eea78c9eac8bca7f0/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [c22f0ec655f621…](https://bazaar.abuse.ch/sample/c22f0ec655f62108e934dde12dd4bf32c0d632074b63220c8a361a6a85d79324/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [21ad4490d4e235…](https://bazaar.abuse.ch/sample/21ad4490d4e2353d349f2fb75f48b151c45c65dbd09df4a279c682599bbb3879/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [ad200f6f61e273…](https://bazaar.abuse.ch/sample/ad200f6f61e27313e9590a88a20f3f6fc6fc0022839f318bee9f0b8291bb1eb6/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [bfc4b11462bf55…](https://bazaar.abuse.ch/sample/bfc4b11462bf550358591aef4bfb1879053815416e15e2cf0ac3240e2ee52cd7/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5984/7396 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5984/7396 |
| 3 | ESET-NOD32 | 77.5% | 5729/7396 |
| 4 | Kaspersky | 76.4% | 5648/7395 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5292/7393 |
| 8 | Rising | 68.8% | 5086/7396 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4915/7392 |
| 11 | Tencent | 65.4% | 4686/7170 |
| 12 | Avast | 65.1% | 4811/7392 |
| 13 | AVG | 65.1% | 4811/7391 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4532/7389 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 47 | 57.3% |
| 🪟 Windows | 27 | 32.9% |
| ❓ Unbekannt | 5 | 6.1% |
| 📦 Archiv | 2 | 2.4% |
| 🤖 Android | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 69 | 84.1% |
| C2 / Nachladen | 7 | 8.5% |
| MaaS-Loader | 3 | 3.7% |
| USB / Wechselmedium | 1 | 1.2% |
| APK-Sideloading | 1 | 1.2% |
| Drive-By / Exploit-Kit | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 24 | 29.3% |
| 2 | 🇺🇸 US | 17 | 20.7% |
| 3 | 🇬🇧 GB | 13 | 15.9% |
| 4 | 🇳🇱 NL | 11 | 13.4% |
| 5 | 🇭🇺 HU | 5 | 6.1% |
| 6 | 🇵🇱 PL | 2 | 2.4% |
| 7 | 🇦🇹 AT | 2 | 2.4% |
| 8 | 🇧🇬 BG | 2 | 2.4% |
| 9 | 🇫🇷 FR | 2 | 2.4% |
| 10 | 🇸🇬 SG | 1 | 1.2% |
| 11 | 🇷🇴 RO | 1 | 1.2% |
| 12 | 🌐 LT | 1 | 1.2% |
| 13 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 37 von 82 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 30 |
| Lateral Movement | 30 |
| Execution | 5 |
| Persistence | 4 |
| Command and Control | 2 |
| Credential Access | 1 |
| Exfiltration | 1 |
| Collection | 1 |

<details><summary>c25ead077458ff215c8e… – AsyncRAT | 🔴 KRITISCH 89.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>83d2faf575026b3f7544… – LummaStealer | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>bf39877283bb8b3ac50a… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5357ad92b918c67fe124…](https://bazaar.abuse.ch/sample/5357ad92b918c67fe1241ea2156a5ad996f0a18639ff853bbb067f6f80b9da0b/)

- **Familie:** DDoSAgent
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:DDOSAgent-ES [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:DDOSAgent-ES [Trj]` |
| Avast | `ELF:DDOSAgent-ES [Trj]` |
| ESET-NOD32 | `Linux/DDoS.Agent.ID trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| SentinelOne | `Static AI - Suspicious ELF` |
| huorong | `Trojan/Linux.DDos.bg` |

### [e22a8fa512acf18ebf1f…](https://bazaar.abuse.ch/sample/e22a8fa512acf18ebf1fd4940e0eeedd64f15460713750729c3762230d10546a/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Svirtu-AA [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Svirtu-AA [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Svirtu-AA [Trj]` |
| Avast-Mobile | `ELF:Svirtu-AA [Trj]` |
| Avira | `TR/LINUX.Svirtu.AA` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| F-Secure | `Trojan.TR/LINUX.Svirtu.AA` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| Google | `Detected` |
| Ikarus | `AVE.AndroidOS.Svirtu` |
| Jiangmin | `Backdoor.Linux.jiju` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.r` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.waw` |
| Varist | `E32/Mirai.BMN` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [75b204fd3c2fd89692b9…](https://bazaar.abuse.ch/sample/75b204fd3c2fd89692b9afde17263afb681efff8179e13dc8c4b049ccba30017/)

- **Familie:** Mirai
- **Erkannt von:** 32 von 75 Engines (42.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.328
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.328`

**Erkennende Engines (32/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.328` |
| AVG | `ELF:Mirai-GH [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.328` |
| Avast | `ELF:Mirai-GH [Trj]` |
| Avast-Mobile | `ELF:Mirai-GH [Trj]` |
| Avira | `TR/LINUX.Mirai.GH` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.328` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-10041434-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Siggen.9999` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Emsisoft | `Trojan.Linux.Mirai.328 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.GH` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Trojan.Linux.Mirai.328` |
| Google | `Detected` |
| Ikarus | `AVE.AndroidOS.Mirai` |
| Jiangmin | `Backdoor.Linux.jijx` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.r` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.328` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| VIPRE | `Trojan.Linux.Mirai.328` |
| Varist | `E32/Mirai5.CCT` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [e897f0c0bc381f9e0b93…](https://bazaar.abuse.ch/sample/e897f0c0bc381f9e0b93af0e689114eb862698e512ef7cfaed97b1a65da5bfbf/)

- **Familie:** Mirai
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.332
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.332`

**Erkennende Engines (44/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.332` |
| AVG | `ELF:Mirai-AAJ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.332` |
| Avast | `ELF:Mirai-AAJ [Trj]` |
| Avast-Mobile | `ELF:Mirai-FY [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.332` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-7100807-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.DCF trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Trojan.Linux.Mirai.332 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF/Mirai.A!tr` |
| GData | `Trojan.Linux.Mirai.332` |
| Google | `Detected` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Jiangmin | `LINUX.Mirai.ak` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| Kingsoft | `Linux.Backdoor.Mirai.cw` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.332` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.BJ!MTB` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Lnx/Mirai-FEBO!15AF35C06322` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.cb` |
| TrellixENS | `Lnx/Mirai-FEBO!15AF35C06322` |
| VBA32 | `Trojan.Linux.Mirai.L96.25e950` |
| VIPRE | `Trojan.Linux.Mirai.332` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.fk` |

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

- **elf** (43×)
- **Mirai** (30×)
- **exe** (16×)
- **5-83-136-39** (13×)
- **opendir** (13×)
- **upx-dec** (10×)
- **upx** (10×)
- **DDoSAgent** (9×)
- **hta** (4×)
- **dropper** (4×)
- **SilverFox** (4×)
- **ValleyRAT** (4×)
- **dropped-by-Amadey** (4×)
- **signed** (3×)
- **RemusStealer** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +9 (21→30)
- ↑ **unbekannt** +3 (17→20)
- neu: **DDoSAgent** (9)
- ↑ **RemusStealer** +2 (1→3)
- ↑ **ValleyRAT** +2 (1→3)
- neu: **Amadey** (3)
- neu: **SilentNet** (2)
- neu: **HijackLoader** (2)
- ↓ **AsyncRAT** -1 (2→1)
- neu: **MacSync** (1)
- weg: **Formbook** (war 2)
- weg: **Prometei** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -5 (35→30)
- ↓ **unbekannt** -8 (28→20)
- neu: **DDoSAgent** (9)
- ↑ **RemusStealer** +2 (1→3)
- ↑ **ValleyRAT** +2 (1→3)
- neu: **Amadey** (3)
- ↑ **SilentNet** +1 (1→2)
- neu: **HijackLoader** (2)
- neu: **MacSync** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.626 MB |
| σ Dateigröße | 19.068 MB |
| Ø Risiko-Score | 70.0/100 |
| Ø Klassifikations-Konfidenz | 74.2% |
| Samples mit VT | 5/82 |
| Samples mit MITRE | 37/82 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 76 |
| Unbekannte Familien | 5 (6.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:44 | [0d8cdcb2d71a…](https://bazaar.abuse.ch/sample/0d8cdcb2d71adf2c3dab3475154b40c4388eb8d54fea4544de0218d94b714513/) | `elf` | unbekannt | 43.4 | – | – | 🇩🇪DE |
| 19:30 | [f5136464cb75…](https://bazaar.abuse.ch/sample/f5136464cb754604970cf5b3ac0ad4207dcdc99e1793ac51da06d377c30a5dde/) | `elf` | DDoSAgent | 75.8 | – | – | 🇬🇧GB |
| 19:29 | [a82fecba7b2b…](https://bazaar.abuse.ch/sample/a82fecba7b2b0d449d1e425fc34e3075e0363979a68603e362d999474a8453ef/) | `elf` | DDoSAgent | 75.8 | – | – | 🇬🇧GB |
| 19:28 | [dc40e88edb58…](https://bazaar.abuse.ch/sample/dc40e88edb58184a541239820611776ca02ccbd25939e67174181157f119ff40/) | `elf` | unbekannt | 43.1 | – | – | 🇬🇧GB |
| 19:28 | [410f08e78b7b…](https://bazaar.abuse.ch/sample/410f08e78b7b0135a5f76ee2ef0e00f2445eee09071714c4fc5edb4e78a1ba76/) | `elf` | unbekannt | 43.1 | – | – | 🇬🇧GB |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.10.2026 19:46 UTC*