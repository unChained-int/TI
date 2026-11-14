# MalwareBazaar – 14.11.2026 22:06 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **49** |
| Höchster Score | **84.8/100** – ac4b600243dfd90a… |
| Häufigste Familie | **unbekannt** (55x) |
| Häufigster Typ | **elf** (46x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 61 Samples |
| Ø Dateigröße | 5.10 MB (σ=13.71) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 46 | 45.5%  █████████ |
| `sh` | 25 | 24.8%  ████ |
| `exe` | 11 | 10.9%  ██ |
| `gz` | 8 | 7.9%  █ |
| `apk` | 5 | 5.0%   |
| `ps1` | 3 | 3.0%   |
| `js` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 55 | 54.5% |
| 2 | Mirai | 36 | 35.6% |
| 3 | ValleyRAT | 6 | 5.9% |
| 4 | WARDENStealer | 3 | 3.0% |
| 5 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 37 | 36.6% | 94% |
| Loader | 22 | 21.8% | 75% |
| Linux-Malware | 9 | 8.9% | 45% |
| RAT | 9 | 8.9% | 77% |
| Cryptominer | 5 | 5.0% | 75% |
| Infostealer | 5 | 5.0% | 75% |
| Android-Malware | 5 | 5.0% | 45% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| Backdoor | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 49 | 48.5% |
| 🟠 HOCH | 30 | 29.7% |
| 🟡 MITTEL | 18 | 17.8% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ac4b600243dfd9…](https://bazaar.abuse.ch/sample/ac4b600243dfd90ab8ceeea89a947d8a035ed740c9cd692696c2a46b378f2c15/) | unbekannt | RAT | **84.8** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ✗ |
| [b1252217508ad6…](https://bazaar.abuse.ch/sample/b1252217508ad6de9ae4889a2b83685b09b827599bfc15ba1496ace87703deeb/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [274180ab59aed5…](https://bazaar.abuse.ch/sample/274180ab59aed5e9061f0f21f9f4f39443ebd891aae4d4bf91af93669232e64d/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [09cb739d8c6e8c…](https://bazaar.abuse.ch/sample/09cb739d8c6e8c060ab72139bcc4a4e9205d6047bfbb1eb3bb3a7bd7fe5a9369/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [34905b9ab594f1…](https://bazaar.abuse.ch/sample/34905b9ab594f184ad400282025ac04c4a5ed5dae09ae490ad7456828a9caaa7/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [50f5f7dcdab42b…](https://bazaar.abuse.ch/sample/50f5f7dcdab42beaafb070776d26963d4804bd2f9a2d9a653d1ce0f53caa483b/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [8b17dfea54290a…](https://bazaar.abuse.ch/sample/8b17dfea54290aa6653d13d81c2577dc9c5485f8cdabe4e7747a91216f88d0e3/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [eb2a93fac0d9d8…](https://bazaar.abuse.ch/sample/eb2a93fac0d9d8b1a3b702747a792e75b4d35382832b657b58fe4ee673f5aefb/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [4f3c65b3746ea0…](https://bazaar.abuse.ch/sample/4f3c65b3746ea0770a57e213b7f24a78701e4d11c25623505291f2325cc85b93/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [42df016cb22abc…](https://bazaar.abuse.ch/sample/42df016cb22abc985a407f6f0dc5f33dbd93ee0692b3e3b1b80e39ef9bfd1813/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6483/7990 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6483/7990 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6176/7990 |
| 6 | Kaspersky | 75.5% | 6030/7989 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5689/7986 |
| 9 | Rising | 68.4% | 5466/7990 |
| 10 | Varist | 66.0% | 5274/7985 |
| 11 | Avast | 65.1% | 5202/7986 |
| 12 | AVG | 65.1% | 5202/7985 |
| 13 | Tencent | 65.0% | 5047/7764 |
| 14 | McAfeeD | 61.4% | 4902/7982 |
| 15 | huorong | 60.8% | 4855/7982 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 72 | 71.3% |
| 🪟 Windows | 14 | 13.9% |
| ❓ Unbekannt | 9 | 8.9% |
| 🤖 Android | 5 | 5.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 87 | 86.1% |
| MaaS-Loader | 7 | 6.9% |
| APK-Sideloading | 5 | 5.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇪🇸 ES | 49 | 48.5% |
| 2 | 🇩🇪 DE | 24 | 23.8% |
| 3 | 🇺🇸 US | 11 | 10.9% |
| 4 | 🇫🇷 FR | 8 | 7.9% |
| 5 | 🌐 CL | 5 | 5.0% |
| 6 | 🇷🇴 RO | 1 | 1.0% |
| 7 | 🇨🇭 CH | 1 | 1.0% |
| 8 | 🇳🇱 NL | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 61 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 36 |
| Lateral Movement | 36 |
| Impact | 24 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>b1252217508ad6de9ae4… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>274180ab59aed5e9061f… – Mirai | 🔴 KRITISCH 83.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>09cb739d8c6e8c060ab7… – Mirai | 🔴 KRITISCH 83.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>34905b9ab594f184ad40… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ac4b600243dfd90ab8ce…](https://bazaar.abuse.ch/sample/ac4b600243dfd90ab8ceeea89a947d8a035ed740c9cd692696c2a46b378f2c15/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [06f3f293bfbd4cde9438…](https://bazaar.abuse.ch/sample/06f3f293bfbd4cde9438c776e3ef85fcbc65d9f03229033261987e05cc22ff70/)

- **Familie:** Mirai
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan/Linux.Mirai.l
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Crypt` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| MaxSecure | `Backdoor.win32.Linux.aa1.Gafgyt.YR` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAZ!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Malware.Linux.Generic.1c0c9117` |
| Varist | `E64/Gafgyt.C.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.l` |

### [061b8c7550a90ff28be8…](https://bazaar.abuse.ch/sample/061b8c7550a90ff28be87ad1d90fd3d2d2c3b6f6bcff5bf1de05413a9d4c0ff6/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B1 (CLASSIC)` |
| Tencent | `Trojan.Linux.Guardian.grdra` |
| huorong | `Trojan/Linux.Mirai.l` |

### [64c57c4c576e6314dcd8…](https://bazaar.abuse.ch/sample/64c57c4c576e6314dcd89530abd9e7ceb613bb8100db9b0e4419612a7ee2ac6b/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39498459
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39498459`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39498459` |
| AVG | `ELF:Mirai-AJO [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.XE228` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.D25AB2DB` |
| Avast | `ELF:Mirai-AJO [Trj]` |
| Avast-Mobile | `ELF:Mirai-AME [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39498459` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135925-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.CJG trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.39498459 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `Linux/Mirai.BWR!tr` |
| GData | `Trojan.Linux.Mirai.39498459` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| Kingsoft | `Linux.Backdoor.Mirai.cw` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Linux/Mirai.EAF` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39498459` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Lnx/Mirai-FECL!A19672F132AE` |
| Sophos | `Linux/DDoS-CIA` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `Lnx/Mirai-FECL!A19672F132AE` |
| VBA32 | `Trojan.Linux.Mirai.L179.df3c7a` |
| VIPRE | `Trojan.Linux.Mirai.39498459` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CIA` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.gm` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

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
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
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
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (45×)
- **Mirai** (26×)
- **sh** (25×)
- **xmrig** (24×)
- **dropper** (23×)
- **cryptojacking** (19×)
- **Torii** (17×)
- **postgresql** (17×)
- **redis** (12×)
- **rediserver** (12×)
- **mirai** (10×)
- **exe** (10×)
- **gafgyt** (9×)
- **gz** (8×)
- **PatchedHostLoader** (6×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +34 (21→55)
- ↓ **Mirai** -20 (56→36)
- neu: **ValleyRAT** (6)
- ↓ **WARDENStealer** -5 (8→3)
- weg: **RevStealer** (war 3)
- weg: **RemusStealer** (war 2)
- weg: **njrat** (war 2)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +30 (25→55)
- ↑ **Mirai** +2 (34→36)
- neu: **ValleyRAT** (6)
- ↓ **WARDENStealer** -1 (4→3)
- ↓ **RemcosRAT** -2 (3→1)
- weg: **Snowlight** (war 3)
- weg: **RevStealer** (war 2)
- weg: **SalatStealer** (war 6)
- weg: **AgentTesla** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.102 MB |
| σ Dateigröße | 13.715 MB |
| Ø Risiko-Score | 69.1/100 |
| Ø Klassifikations-Konfidenz | 74.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 61/101 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 70 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:33 | [b1252217508a…](https://bazaar.abuse.ch/sample/b1252217508ad6de9ae4889a2b83685b09b827599bfc15ba1496ace87703deeb/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 21:28 | [d5070f52262e…](https://bazaar.abuse.ch/sample/d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573/) | `elf` | unbekannt | 42.8 | – | – | 🌐RO |
| 20:40 | [274180ab59ae…](https://bazaar.abuse.ch/sample/274180ab59aed5e9061f0f21f9f4f39443ebd891aae4d4bf91af93669232e64d/) | `elf` | Mirai | 83.3 | – | – | 🇩🇪DE |
| 20:38 | [09cb739d8c6e…](https://bazaar.abuse.ch/sample/09cb739d8c6e8c060ab72139bcc4a4e9205d6047bfbb1eb3bb3a7bd7fe5a9369/) | `elf` | Mirai | 83.3 | – | – | 🇫🇷FR |
| 20:27 | [bfa951b42c38…](https://bazaar.abuse.ch/sample/bfa951b42c386c27c9b9341b37ad89960396b6b2c85fa2283855d1b42312085e/) | `sh` | unbekannt | 73.7 | – | – | 🌐ES |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 14.11.2026 22:06 UTC*