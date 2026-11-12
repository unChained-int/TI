# MalwareBazaar – 12.11.2026 12:20 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **78** |
| Höchster Score | **90.5/100** – 9248c4d3cdf28743… |
| Häufigste Familie | **Mirai** (73x) |
| Häufigster Typ | **elf** (80x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 80 Samples |
| Ø Dateigröße | 2.04 MB (σ=6.28) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 80 | 79.2%  ███████████████ |
| `exe` | 20 | 19.8%  ███ |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 73 | 72.3% |
| 2 | unbekannt | 20 | 19.8% |
| 3 | Formbook | 3 | 3.0% |
| 4 | AgentTesla | 1 | 1.0% |
| 5 | AsyncRAT | 1 | 1.0% |
| 6 | ELF:Mirai-BOK [Trj] | 1 | 1.0% |
| 7 | njrat | 1 | 1.0% |
| 8 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 74 | 73.3% | 95% |
| Windows-Malware | 14 | 13.9% | 35% |
| Linux-Malware | 6 | 5.9% | 45% |
| Infostealer | 3 | 3.0% | 95% |
| RAT | 3 | 3.0% | 95% |
| Andere / Unbekannt | 1 | 1.0% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 78 | 77.2% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [9248c4d3cdf287…](https://bazaar.abuse.ch/sample/9248c4d3cdf28743ac672169926b2ddd6606f2ec09dc0decc0c9756d0671820c/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [fffd069b093202…](https://bazaar.abuse.ch/sample/fffd069b093202819bb84ab5274acc4051b5cee2ded5286201b2342b260c4524/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [79e0bb6ae09083…](https://bazaar.abuse.ch/sample/79e0bb6ae090838c0e44763b43dfde23021fe6c9cee4b53efa8672cac6425a88/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [0a5cf9655d2470…](https://bazaar.abuse.ch/sample/0a5cf9655d2470d95e76190534efdda021e43c43b0fcc7c340860b4e5ddc2cfc/) | AsyncRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [c4d5b70ab25395…](https://bazaar.abuse.ch/sample/c4d5b70ab253952bfb0e1039eb2a07ac5686e742306195319043447840ef21d9/) | njrat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [f016995ef17974…](https://bazaar.abuse.ch/sample/f016995ef17974fd01df8f16976b69822c7b8007c23742cbbe2c44131666b1f9/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | 14.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [0086accc9aaa50…](https://bazaar.abuse.ch/sample/0086accc9aaa503326d566536c3810327c151204ed71bddf968f5f4d2b3c7fd5/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [a91d9c5c13dbaf…](https://bazaar.abuse.ch/sample/a91d9c5c13dbaff1c871705fe9107110486c4a5d0eb24029c98503b1cdf66621/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [04f6b353537ab8…](https://bazaar.abuse.ch/sample/04f6b353537ab83560d614607ab5683e302d3acd73961dd934f5ea0b5729b3ea/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [2f5bae47236813…](https://bazaar.abuse.ch/sample/2f5bae4723681326d80a093a8909a6e7514a0cc83df6593f6c750197fc52f43b/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6451/7950 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6451/7950 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6146/7950 |
| 6 | Kaspersky | 75.5% | 6000/7949 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5662/7946 |
| 9 | Rising | 68.4% | 5437/7950 |
| 10 | Varist | 66.1% | 5251/7945 |
| 11 | Avast | 65.2% | 5178/7946 |
| 12 | AVG | 65.2% | 5178/7945 |
| 13 | Tencent | 65.0% | 5017/7724 |
| 14 | McAfeeD | 61.4% | 4877/7942 |
| 15 | huorong | 60.9% | 4837/7942 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 81 | 80.2% |
| 🪟 Windows | 20 | 19.8% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 80 | 79.2% |
| 2 | 🇦🇹 AT | 18 | 17.8% |
| 3 | 🇯🇵 JP | 1 | 1.0% |
| 4 | 🇺🇸 US | 1 | 1.0% |
| 5 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 80 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 74 |
| Lateral Movement | 74 |
| Collection | 5 |
| Credential Access | 3 |
| Command and Control | 3 |
| Execution | 1 |

<details><summary>9248c4d3cdf28743ac67… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>fffd069b093202819bb8… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>79e0bb6ae090838c0e44… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>0a5cf9655d2470d95e76… – AsyncRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>c4d5b70ab253952bfb0e… – njrat | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [930ede8e6bd06ad66543…](https://bazaar.abuse.ch/sample/930ede8e6bd06ad665433e277c3e27d9c9b4c399885da340fc6464b7232ae4f4/)

- **Familie:** ELF:Mirai-BOK [Trj]
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BOK [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BOK [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.XE228` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-BOK [Trj]` |
| Avast-Mobile | `ELF:Mirai-CKT [Trj]` |
| Avira | `EXP/ELF.Agent.J.8` |
| ClamAV | `Unix.Trojan.Mirai-9441505-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.BPP trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Exploit.EXP/ELF.Agent.J.8` |
| Fortinet | `ELF/Mirai.H!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FE!MTB` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wao` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [f016995ef17974fd01df…](https://bazaar.abuse.ch/sample/f016995ef17974fd01df8f16976b69822c7b8007c23742cbbe2c44131666b1f9/)

- **Familie:** Mirai
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-DDO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DDO [Trj]` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-DDO [Trj]` |
| Avira | `TR/LINUX.Mirai.DDO` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FPN trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DDO` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.Y!MTB` |
| Sangfor | `Suspicious.Linux.Save.a` |

### [e4754700e3b7c4e2b7d7…](https://bazaar.abuse.ch/sample/e4754700e3b7c4e2b7d75f4eb7d0fdec0dddcea750ce94ef20af308ea84bef84/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.10` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39502263` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39502263 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39502263` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.10` |
| huorong | `Trojan/Prometei.c` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (63/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vmf1` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (80×)
- **Mirai** (73×)
- **Torii** (65×)
- **exe** (19×)
- **Prometei** (7×)
- **signed** (4×)
- **Formbook** (3×)
- **AgentTesla** (1×)
- **AsyncRAT** (1×)
- **ddos** (1×)
- **gafgyt** (1×)
- **mips** (1×)
- **mirai** (1×)
- **njrat** (1×)
- **sh** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +36 (37→73)
- ↑ **unbekannt** +1 (19→20)
- ↓ **AgentTesla** -1 (2→1)
- neu: **AsyncRAT** (1)
- neu: **ELF:Mirai-BOK [Trj]** (1)
- ↓ **RemcosRAT** -4 (5→1)
- weg: **WARDENStealer** (war 3)
- weg: **GuLoader** (war 3)
- weg: **SalatStealer** (war 15)
- weg: **RevStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +49 (24→73)
- ↓ **unbekannt** -10 (30→20)
- ↑ **Formbook** +1 (2→3)
- ↓ **AgentTesla** -2 (3→1)
- neu: **ELF:Mirai-BOK [Trj]** (1)
- neu: **njrat** (1)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **RevStealer** (war 2)
- weg: **WARDENStealer** (war 3)
- weg: **Snowlight** (war 3)
- weg: **SalatStealer** (war 5)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.042 MB |
| σ Dateigröße | 6.283 MB |
| Ø Risiko-Score | 74.3/100 |
| Ø Klassifikations-Konfidenz | 82.8% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 80/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 15 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:01 | [dc4c5a05b3b3…](https://bazaar.abuse.ch/sample/dc4c5a05b3b37dcca1ecd390f539c8fd6878e6c9d184beedf11943f10b494d77/) | `exe` | unbekannt | 38.8 | – | – | 🌐AT |
| 12:01 | [2f1aedbfa0a4…](https://bazaar.abuse.ch/sample/2f1aedbfa0a446c2e57925fa79ab0c923d830f2238ecac07c61ca3929a50c8c8/) | `exe` | unbekannt | 38.8 | – | – | 🌐AT |
| 12:01 | [6025cc6c8a9d…](https://bazaar.abuse.ch/sample/6025cc6c8a9d28d181d85978c7059bce526f25611aa53a63a4f1c1fe386157f4/) | `exe` | unbekannt | 38.8 | – | – | 🌐AT |
| 12:01 | [9248c4d3cdf2…](https://bazaar.abuse.ch/sample/9248c4d3cdf28743ac672169926b2ddd6606f2ec09dc0decc0c9756d0671820c/) | `exe` | Formbook | 90.5 | – | – | 🌐AT |
| 12:01 | [fffd069b0932…](https://bazaar.abuse.ch/sample/fffd069b093202819bb84ab5274acc4051b5cee2ded5286201b2342b260c4524/) | `exe` | Formbook | 90.5 | – | – | 🌐AT |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.11.2026 12:20 UTC*