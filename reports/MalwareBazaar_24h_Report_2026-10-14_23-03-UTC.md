# MalwareBazaar – 14.10.2026 23:03 UTC

Dieser Run hat **81 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **82** |
| Kritisch (≥75) | **63** |
| Höchster Score | **89.9/100** – 976aff8d066d0066… |
| Häufigste Familie | **Mirai** (44x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 51 Samples |
| Ø Dateigröße | 5.19 MB (σ=14.09) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 64.6%  ████████████ |
| `exe` | 25 | 30.5%  ██████ |
| `zip` | 1 | 1.2%   |
| `js` | 1 | 1.2%   |
| `macho` | 1 | 1.2%   |
| `sh` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 44 | 53.7% |
| 2 | unbekannt | 25 | 30.5% |
| 3 | Gafgyt | 2 | 2.4% |
| 4 | RemusStealer | 2 | 2.4% |
| 5 | Vidar | 1 | 1.2% |
| 6 | BlankGrabber | 1 | 1.2% |
| 7 | Obfuscated | 1 | 1.2% |
| 8 | SalatStealer | 1 | 1.2% |
| 9 | LummaStealer | 1 | 1.2% |
| 10 | Hajime | 1 | 1.2% |
| 11 | AMOS | 1 | 1.2% |
| 12 | RustyStealer | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 47 | 57.3% | 95% |
| Infostealer | 13 | 15.9% | 80% |
| Linux-Malware | 6 | 7.3% | 45% |
| Loader | 5 | 6.1% | 75% |
| Windows-Malware | 4 | 4.9% | 35% |
| RAT | 4 | 4.9% | 80% |
| Worm | 2 | 2.4% | 75% |
| Trojaner | 1 | 1.2% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 63 | 76.8% |
| 🟠 HOCH | 9 | 11.0% |
| 🟡 MITTEL | 10 | 12.2% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [976aff8d066d00…](https://bazaar.abuse.ch/sample/976aff8d066d00667f9ebeea846c87fb0f7a6d86aaca725ae06242a6b43ef6d9/) | Vidar | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [2fe60b18bb97ad…](https://bazaar.abuse.ch/sample/2fe60b18bb97ad7ea8bc8f746be851205e59ed68cd2244784ef0d052758e4346/) | LummaStealer | Infostealer | **87.5** | 🔴 KRITISCH | – | – | ? |
| [7997b84c10941d…](https://bazaar.abuse.ch/sample/7997b84c10941d97069dd9dff12fb3b6678564c4356e7f749c7179071d59ee11/) | AMOS | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [00d0db4d3dbc46…](https://bazaar.abuse.ch/sample/00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [e05e7370ae270f…](https://bazaar.abuse.ch/sample/e05e7370ae270f112c1e99addae6454d97f39cef3518009e779ddd6c36d1c0ef/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [645787c5c824a7…](https://bazaar.abuse.ch/sample/645787c5c824a7bfdf2af27a9043db20f1a0d139c28fc55d613f083d720f5707/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [e80a844331873e…](https://bazaar.abuse.ch/sample/e80a844331873eeb234ee346b87e08f7382d5d4f447a09a21ef3a36cfa65d9ef/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [ea8cd9401645ad…](https://bazaar.abuse.ch/sample/ea8cd9401645ad87160e713669c3c95e7f8c819516bce3284b66eb2411478c22/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [8ec6460f4ed87e…](https://bazaar.abuse.ch/sample/8ec6460f4ed87ed848146816e0685d370977a56ca5404ce1efadb3848e17e269/) | Gafgyt | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [b6d0c1a67695dc…](https://bazaar.abuse.ch/sample/b6d0c1a67695dc38db3bf9cbe6b8e8becaaccff0c8619c0df60de57269547a66/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5966/7376 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5966/7376 |
| 3 | ESET-NOD32 | 77.4% | 5710/7376 |
| 4 | Kaspersky | 76.4% | 5631/7375 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5277/7373 |
| 8 | Rising | 68.7% | 5069/7376 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4898/7372 |
| 11 | Tencent | 65.3% | 4669/7150 |
| 12 | Avast | 65.0% | 4794/7372 |
| 13 | AVG | 65.0% | 4794/7371 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4520/7369 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 54 | 65.9% |
| 🪟 Windows | 25 | 30.5% |
| 📦 Archiv | 1 | 1.2% |
| ❓ Unbekannt | 1 | 1.2% |
| 🍎 macOS | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 74 | 90.2% |
| C2 / Nachladen | 6 | 7.3% |
| USB / Wechselmedium | 1 | 1.2% |
| Drive-By / Exploit-Kit | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 44 | 53.7% |
| 2 | 🇺🇸 US | 20 | 24.4% |
| 3 | 🇳🇱 NL | 9 | 11.0% |
| 4 | 🇧🇷 BR | 6 | 7.3% |
| 5 | 🌐 CO | 2 | 2.4% |
| 6 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 51 von 82 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 46 |
| Lateral Movement | 46 |
| Credential Access | 3 |
| Collection | 3 |
| Exfiltration | 3 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |

<details><summary>976aff8d066d00667f9e… – Vidar | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2fe60b18bb97ad7ea8bc… – LummaStealer | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>00d0db4d3dbc46ce64f4… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e05e7370ae270f112c1e… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d18632440bba55c0cc63…](https://bazaar.abuse.ch/sample/d18632440bba55c0cc63e43ee0146b3c30fd94c541df504e8c62637196a4ab75/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Malware.GJIRF!prn!g.7EEFBFBA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Malware.GJIRF!prn!g.7EEFBFBA`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Malware.GJIRF!prn!g.7EEFBFBA` |
| AVG | `ELF:DDoS-Y [Trj]` |
| AhnLab-V3 | `Linux/Tsunami.Gen` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Arcabit | `Generic.Malware.GJIRF!prn!g.7EEFBFBA` |
| Avast | `ELF:DDoS-Y [Trj]` |
| Avast-Mobile | `ELF:DDoS-S [Trj]` |
| Avira | `TR/LINUX.DDoS.Y` |
| BitDefender 🛡️ | `Generic.Malware.GJIRF!prn!g.7EEFBFBA` |
| CAT-QuickHeal | `Backdoor.Linux.Tsunami.A` |
| CTX | `elf.unknown.gjirf` |
| ClamAV | `Unix.Trojan.Gafgyt-6981154-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Tsunami.NCD trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Generic.Malware.GJIRF!prn!g.7EEFBFBA (B)` |
| F-Secure | `Trojan.TR/LINUX.DDoS.Y` |
| Fortinet | `ELF/Gafgyt.WN!tr` |
| GData | `Linux.Trojan.Gafgyt.A` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Gafgyt` |
| Jiangmin | `Backdoor.Linux.gfii` |
| Kaspersky | `HEUR:Backdoor.Linux.Tsunami.bh` |
| McAfeeD | `Trojan:Linux/Mirai.ERC` |
| MicroWorld-eScan | `Generic.Malware.GJIRF!prn!g.7EEFBFBA` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.AX!xp` |
| Rising | `Backdoor.Tsunami/Linux!1.10564 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Gafgyt.r` |
| Sophos | `Linux/Tsunami-A` |
| Tencent | `Backdoor.Linux.Tsunami.ad` |
| TrellixENS | `Linux/Gafgyt.r` |
| TrendMicro | `ELF_KAITEN.SM` |
| TrendMicro-HouseCall | `ELF_KAITEN.SM` |
| VIPRE | `Generic.Malware.GJIRF!prn!g.7EEFBFBA` |
| Varist | `E32/Gafgyt.D.gen!Camelot` |
| VirIT | `Linux.BackDoor.Tsunami.` |
| ZoneAlarm | `Linux/Tsunami-A` |
| alibabacloud | `DDOS:Linux/Gafgyt` |
| huorong | `Trojan/Linux.Mirai.q` |

### [5119d8aaa35dffc9752c…](https://bazaar.abuse.ch/sample/5119d8aaa35dffc9752c377a3ecd8104e1eacade88d94f7fe452717cd7a14f29/)

- **Familie:** Mirai
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Malware.GJIRF!prn!g.5236EC8E
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Malware.GJIRF!prn!g.5236EC8E`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Malware.GJIRF!prn!g.5236EC8E` |
| AVG | `ELF:DDoS-S [Trj]` |
| AhnLab-V3 | `Linux/Tsunami.Gen` |
| Antiy-AVL | `Trojan/Linux.Gafgyt` |
| Arcabit | `Generic.Malware.GJIRF!prn!g.5236EC8E` |
| Avast | `ELF:DDoS-S [Trj]` |
| Avast-Mobile | `ELF:Tsunami-CR [Trj]` |
| Avira | `TR/LINUX.DDoS.S` |
| BitDefender 🛡️ | `Generic.Malware.GJIRF!prn!g.5236EC8E` |
| CAT-QuickHeal | `Backdoor.Linux.Tsunami.A` |
| CTX | `elf.unknown.gjirf` |
| ClamAV | `Unix.Trojan.Gafgyt-6981154-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Tsunami.NCD trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| Emsisoft | `Generic.Malware.GJIRF!prn!g.5236EC8E (B)` |
| F-Secure | `Trojan.TR/LINUX.DDoS.S` |
| Fortinet | `ELF/Gafgyt.WN!tr` |
| GData | `Linux.Trojan.Gafgyt.A` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Tsunami` |
| Kaspersky | `HEUR:Backdoor.Linux.Tsunami.bh` |
| McAfeeD | `Trojan:Linux/Mirai.EQY` |
| MicroWorld-eScan | `Generic.Malware.GJIRF!prn!g.5236EC8E` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.AX!xp` |
| Rising | `Backdoor.Tsunami/Linux!1.10564 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Gafgyt.r` |
| Sophos | `Linux/Tsunami-A` |
| Tencent | `Trojan.Linux.Mirai.zm` |
| TrellixENS | `Linux/Gafgyt.r` |
| TrendMicro | `ELF_KAITEN.SM` |
| TrendMicro-HouseCall | `ELF_KAITEN.SM` |
| VIPRE | `Generic.Malware.GJIRF!prn!g.5236EC8E` |
| Varist | `E32/Gafgyt.D.gen!Camelot` |
| VirIT | `Linux.BackDoor.Tsunami.` |
| ZoneAlarm | `Linux/Tsunami-A` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.q` |

### [e63e4e17e5c30b244534…](https://bazaar.abuse.ch/sample/e63e4e17e5c30b244534c4ecf453367fc7485a3838987d1520d351365a6c284d/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-MV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-MV [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-MV [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.A!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Kingsoft | `Linux.Backdoor.Mirai.b` |
| McAfeeD | `Trojan:Linux/Mirai.EQY` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.bktra` |
| Varist | `E32/Gafgyt.C.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [44272f1f153709662b3b…](https://bazaar.abuse.ch/sample/44272f1f153709662b3b973e7b4a601df852e7eae3dd9a22661860394889b1eb/)

- **Familie:** Obfuscated
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Packed.Obfuscated.B suspicious application
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Packed.Obfuscated.B suspicious application` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| SentinelOne | `Static AI - Suspicious ELF` |

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

- **elf** (52×)
- **Mirai** (46×)
- **exe** (24×)
- **Gafgyt** (13×)
- **Stealer** (8×)
- **upx-dec** (5×)
- **upx** (5×)
- **Warden** (5×)
- **WardenStealer** (5×)
- **dropped-by-GCleaner** (5×)
- **wraith** (4×)
- **xworm** (2×)
- **RemusStealer** (2×)
- **signed** (2×)
- **Vidar** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +24 (20→44)
- ↓ **unbekannt** -5 (30→25)
- neu: **Gafgyt** (2)
- ↑ **RemusStealer** +1 (1→2)
- neu: **BlankGrabber** (1)
- neu: **Obfuscated** (1)
- neu: **SalatStealer** (1)
- neu: **LummaStealer** (1)
- neu: **Hajime** (1)
- weg: **Formbook** (war 4)
- weg: **DCRat** (war 2)
- weg: **AgentTesla** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +6 (38→44)
- ↓ **unbekannt** -4 (29→25)
- ↑ **Gafgyt** +1 (1→2)
- neu: **RemusStealer** (2)
- neu: **BlankGrabber** (1)
- neu: **Obfuscated** (1)
- neu: **SalatStealer** (1)
- neu: **LummaStealer** (1)
- neu: **Hajime** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.187 MB |
| σ Dateigröße | 14.092 MB |
| Ø Risiko-Score | 75.8/100 |
| Ø Klassifikations-Konfidenz | 82.9% |
| Samples mit VT | 5/82 |
| Samples mit MITRE | 51/82 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 48 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:53 | [81c4b388d33f…](https://bazaar.abuse.ch/sample/81c4b388d33f3e0e271181bcedf828f937dde39c30e2a860272aa0c20bf96367/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 22:48 | [27954ed3c844…](https://bazaar.abuse.ch/sample/27954ed3c8444ce4f5105a57af680c4f9d10c0c25bfb566fb2eed67046ae967a/) | `zip` | unbekannt | 77.3 | – | – | 🌐CO |
| 22:46 | [61a109f09e50…](https://bazaar.abuse.ch/sample/61a109f09e500c89219d0d32fb05ea48f43afdf3ad0683fc00e41cabd1b74dd0/) | `js` | unbekannt | 77.2 | – | – | 🌐CO |
| 22:29 | [00d0db4d3dbc…](https://bazaar.abuse.ch/sample/00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 22:20 | [e05e7370ae27…](https://bazaar.abuse.ch/sample/e05e7370ae270f112c1e99addae6454d97f39cef3518009e779ddd6c36d1c0ef/) | `elf` | Mirai | 83.9 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.10.2026 23:03 UTC*