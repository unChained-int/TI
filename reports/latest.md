# MalwareBazaar – 11.10.2026 23:30 UTC

Dieser Run hat **57 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **57** |
| Kritisch (≥75) | **42** |
| Höchster Score | **96.7/100** – a5f0ad9e85500f92… |
| Häufigste Familie | **Mirai** (29x) |
| Häufigster Typ | **elf** (39x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 32 Samples |
| Ø Dateigröße | 3.33 MB (σ=18.33) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 39 | 68.4%  █████████████ |
| `exe` | 14 | 24.6%  ████ |
| `sh` | 2 | 3.5%   |
| `vbs` | 1 | 1.8%   |
| `ps1` | 1 | 1.8%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 29 | 50.9% |
| 2 | unbekannt | 15 | 26.3% |
| 3 | Gafgyt | 5 | 8.8% |
| 4 | AsyncRAT | 2 | 3.5% |
| 5 | WannaCry | 2 | 3.5% |
| 6 | AokigaharaStealer | 1 | 1.8% |
| 7 | OverlordRAT | 1 | 1.8% |
| 8 | Prometei | 1 | 1.8% |
| 9 | RemcosRAT | 1 | 1.8% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 34 | 59.6% | 95% |
| Linux-Malware | 5 | 8.8% | 45% |
| Windows-Malware | 4 | 7.0% | 35% |
| RAT | 4 | 7.0% | 90% |
| Infostealer | 2 | 3.5% | 75% |
| Ransomware | 2 | 3.5% | 95% |
| Loader | 2 | 3.5% | 75% |
| Andere / Unbekannt | 1 | 1.8% | 20% |
| Skript/Dropper | 1 | 1.8% | 35% |
| Backdoor | 1 | 1.8% | 75% |
| Trojaner | 1 | 1.8% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 42 | 73.7% |
| 🟠 HOCH | 4 | 7.0% |
| 🟡 MITTEL | 10 | 17.5% |
| 🟢 NIEDRIG | 1 | 1.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a5f0ad9e85500f…](https://bazaar.abuse.ch/sample/a5f0ad9e85500f92821f8c22cafa0e294ec514f876af0881f59a3891e63251d5/) | WannaCry | Ransomware | **96.7** | 🔴 KRITISCH | – | – | ? |
| [7e8209a4bad679…](https://bazaar.abuse.ch/sample/7e8209a4bad67901c826655b61e66c3d0569d3fdd85da77634050d3018b3dc29/) | WannaCry | Ransomware | **95.9** | 🔴 KRITISCH | – | – | ? |
| [4ef6c9f88c03e3…](https://bazaar.abuse.ch/sample/4ef6c9f88c03e3ef71a6402d93b41a437cbecd632f06ed78116ac68bfe09abe4/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [8054026c22d6f8…](https://bazaar.abuse.ch/sample/8054026c22d6f84e6d6040d704a8f759e8364575df5ad03ef72d3f981262bee3/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [565422e182c8dd…](https://bazaar.abuse.ch/sample/565422e182c8dd4d799257eb053248b8ff9ed052a7729b56ec04722f95057328/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [281cdbb7d1f655…](https://bazaar.abuse.ch/sample/281cdbb7d1f655808e2748311bc002ec86238d91013a7c2dd088faea6e6fd548/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [805e6e6c170e6a…](https://bazaar.abuse.ch/sample/805e6e6c170e6a35e062ea85d1a5f63b3b022359d27fa55537a54eb376db8094/) | unbekannt | Backdoor | **84.0** | 🔴 KRITISCH | – | – | ? |
| [86da7b5aff9100…](https://bazaar.abuse.ch/sample/86da7b5aff91009a26074d06fa3acd5fc36a991e55f59cdd44e56a51e40d7836/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [276f6a22215488…](https://bazaar.abuse.ch/sample/276f6a2221548827416b019aa336f44c395c7efdf512ec2286bc089672832e4b/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [25e110e05a59b8…](https://bazaar.abuse.ch/sample/25e110e05a59b8b67b38911318b77a5951dc613eb3105e600e638bc122f4b94a/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5926/7326 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5926/7326 |
| 3 | ESET-NOD32 | 77.4% | 5669/7326 |
| 4 | Kaspersky | 76.3% | 5590/7325 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5245/7323 |
| 8 | Rising | 68.7% | 5033/7326 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4869/7322 |
| 11 | Tencent | 65.2% | 4630/7100 |
| 12 | Avast | 65.0% | 4762/7322 |
| 13 | AVG | 65.0% | 4762/7321 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4491/7319 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 42 | 73.7% |
| 🪟 Windows | 15 | 26.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 49 | 86.0% |
| C2 / Nachladen | 3 | 5.3% |
| Exploit / N-Day | 2 | 3.5% |
| MaaS-Loader | 2 | 3.5% |
| Drive-By / Exploit-Kit | 1 | 1.8% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 29 | 50.9% |
| 2 | 🇺🇸 US | 16 | 28.1% |
| 3 | 🇳🇱 NL | 7 | 12.3% |
| 4 | 🇨🇦 CA | 2 | 3.5% |
| 5 | 🌐 Unbekannt | 1 | 1.8% |
| 6 | 🇨🇭 CH | 1 | 1.8% |
| 7 | 🇧🇷 BR | 1 | 1.8% |

## MITRE ATT&CK

> 32 von 57 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 29 |
| Lateral Movement | 29 |
| Command and Control | 3 |
| Execution | 2 |
| Collection | 1 |

<details><summary>4ef6c9f88c03e3ef71a6… – AsyncRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>8054026c22d6f84e6d60… – AsyncRAT | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>565422e182c8dd4d7992… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ffa8d7d6a31ed9e71284…](https://bazaar.abuse.ch/sample/ffa8d7d6a31ed9e712844e2aeac58e2f5ff1722bb70b141eabc6f7c824458768/)

- **Familie:** Prometei
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.5`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.5` |
| AVG | `ELF:Prometei-E [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.5` |
| Avast | `ELF:Prometei-E [Trj]` |
| Avira | `TR/LINUX.Prometei.E` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.5` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045451-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Trojan.Linux.Prometei.5 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.E` |
| Fortinet | `ELF/Prometei.12!tr` |
| GData | `Trojan.Linux.Prometei.5` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.5` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.5` |
| huorong | `Trojan/Prometei.c` |

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

### [1f482338d8f7b20de834…](https://bazaar.abuse.ch/sample/1f482338d8f7b20de834e3b6998fbef3ea8bc8b23d4010bd79aa1da5a3742da3/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux.Generic.Threat
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| ClamAV | `Unix.Trojan.Mirai-10060415-0` |
| DrWeb | `Linux.Rootkit.420` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| Elastic | `Linux.Generic.Threat` |
| Fortinet | `ELF/MALD2.9BA9!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Kingsoft | `Linux.Backdoor.Gafgyt.jp` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FO!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| Varist | `E32/Mirai.DM.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.mq` |

### [9fa0f34132937a54ad25…](https://bazaar.abuse.ch/sample/9fa0f34132937a54ad25210a0c4c6ce23aeda27dc90572a67c3cbe147fc8fbea/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Svirtu-AA [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Svirtu-AA [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Svirtu-AA [Trj]` |
| Avast-Mobile | `ELF:Svirtu-AA [Trj]` |
| Avira | `TR/LINUX.Svirtu.AA` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Rootkit.420` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| F-Secure | `Trojan.TR/LINUX.Svirtu.AA` |
| Fortinet | `ELF/MALD2.9BA9!tr` |
| Google | `Detected` |
| Ikarus | `LINUX.Siggen` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| Varist | `E32/Mirai.BMN` |
| huorong | `Trojan/Linux.Mirai.mq` |


## Top Tags

- **elf** (39×)
- **Mirai** (26×)
- **exe** (14×)
- **upx-dec** (6×)
- **upx** (6×)
- **cowrie** (5×)
- **Gafgyt** (5×)
- **honeypot** (5×)
- **dropped-by-GCleaner** (3×)
- **sh** (2×)
- **AsyncRAT** (2×)
- **stealer** (2×)
- **dionaea** (2×)
- **WannaCry** (2×)
- **A** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -11 (40→29)
- ↓ **unbekannt** -12 (27→15)
- neu: **Gafgyt** (5)
- ↑ **AsyncRAT** +1 (1→2)
- ↑ **WannaCry** +1 (1→2)
- neu: **AokigaharaStealer** (1)
- neu: **OverlordRAT** (1)
- neu: **Prometei** (1)
- weg: **ConnectWise** (war 2)
- weg: **LxBaseRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -10 (39→29)
- ↓ **unbekannt** -16 (31→15)
- ↑ **Gafgyt** +4 (1→5)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **WannaCry** (2)
- neu: **AokigaharaStealer** (1)
- neu: **OverlordRAT** (1)
- neu: **Prometei** (1)
- weg: **ConnectWise** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.325 MB |
| σ Dateigröße | 18.332 MB |
| Ø Risiko-Score | 73.4/100 |
| Ø Klassifikations-Konfidenz | 81.4% |
| Samples mit VT | 4/57 |
| Samples mit MITRE | 32/57 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 39 |
| Unbekannte Familien | 1 (1.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:28 | [da14487a4000…](https://bazaar.abuse.ch/sample/da14487a40009ea319c375f2e08ec1711aa0461133c535779d68921433e4747a/) | `exe` | unbekannt | 39.1 | – | – | 🌐unknown |
| 23:26 | [74b8b95d4153…](https://bazaar.abuse.ch/sample/74b8b95d4153009990ca3645f317ce76399f1892d38f79340920449a396bffcc/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 23:26 | [565422e182c8…](https://bazaar.abuse.ch/sample/565422e182c8dd4d799257eb053248b8ff9ed052a7729b56ec04722f95057328/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 23:22 | [0835fa1a0f6d…](https://bazaar.abuse.ch/sample/0835fa1a0f6dee5fbdb9df15bc389f8d396b8c36f388c30e2cd189f5b4eed9d2/) | `sh` | unbekannt | 32.6 | – | – | 🇩🇪DE |
| 23:22 | [281cdbb7d1f6…](https://bazaar.abuse.ch/sample/281cdbb7d1f655808e2748311bc002ec86238d91013a7c2dd088faea6e6fd548/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.10.2026 23:30 UTC*