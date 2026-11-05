# MalwareBazaar – 05.11.2026 21:50 UTC

Dieser Run hat **98 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **99** |
| Kritisch (≥75) | **36** |
| Höchster Score | **96.3/100** – f45ed649c6b28cc6… |
| Häufigste Familie | **unbekannt** (46x) |
| Häufigster Typ | **exe** (28x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 4.62 MB (σ=11.30) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 28 | 28.3%  █████ |
| `elf` | 27 | 27.3%  █████ |
| `js` | 22 | 22.2%  ████ |
| `ps1` | 5 | 5.1%  █ |
| `sh` | 4 | 4.0%   |
| `jar` | 4 | 4.0%   |
| `vbs` | 4 | 4.0%   |
| `zip` | 2 | 2.0%   |
| `dll` | 1 | 1.0%   |
| `pdf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 46 | 46.5% |
| 2 | AgentTesla | 11 | 11.1% |
| 3 | Mirai | 8 | 8.1% |
| 4 | Formbook | 4 | 4.0% |
| 5 | RemcosRAT | 4 | 4.0% |
| 6 | Silentnet | 3 | 3.0% |
| 7 | AsyncRAT | 3 | 3.0% |
| 8 | ValleyRAT | 3 | 3.0% |
| 9 | CoinMiner | 2 | 2.0% |
| 10 | XWorm | 2 | 2.0% |
| 11 | NanoCore | 2 | 2.0% |
| 12 | WannaCry | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 20 | 20.2% | 45% |
| Skript/Dropper | 15 | 15.2% | 35% |
| RAT | 15 | 15.2% | 90% |
| Windows-Malware | 12 | 12.1% | 35% |
| Andere / Unbekannt | 10 | 10.1% | 20% |
| Infostealer | 10 | 10.1% | 83% |
| Botnet/IoT | 8 | 8.1% | 95% |
| Cryptominer | 2 | 2.0% | 75% |
| Loader | 2 | 2.0% | 85% |
| Ransomware | 1 | 1.0% | 95% |
| Maldoc | 1 | 1.0% | 35% |
| Spyware | 1 | 1.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 36 | 36.4% |
| 🟠 HOCH | 5 | 5.1% |
| 🟡 MITTEL | 44 | 44.4% |
| 🟢 NIEDRIG | 14 | 14.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f45ed649c6b28c…](https://bazaar.abuse.ch/sample/f45ed649c6b28cc6957d36fd448ae4d9c5eaa4b3c06a2532bc50eed035869f3f/) | WannaCry | Ransomware | **96.3** | 🔴 KRITISCH | – | – | ? |
| [6bfeb99e0aa982…](https://bazaar.abuse.ch/sample/6bfeb99e0aa982a6f6de1515e290e42e0a039decad9335859c85151265aff102/) | Formbook | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [0301de0be419c5…](https://bazaar.abuse.ch/sample/0301de0be419c5bc6dfc019179b9342dd7a481c90300dd8ce4d2366c03bc5c68/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [e350e18fc96aea…](https://bazaar.abuse.ch/sample/e350e18fc96aea8b2ef6450b6399dc906c7fe8ec259c780541f52979c5073dc6/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [2e0bafa5a685be…](https://bazaar.abuse.ch/sample/2e0bafa5a685be2bf8299bade349d0f452b563321972ec0d7717b2ca7ee040f0/) | Formbook | Infostealer | **87.0** | 🔴 KRITISCH | – | – | ? |
| [a5388675f383d4…](https://bazaar.abuse.ch/sample/a5388675f383d4de1fb003c58a77f3aae3709906585e6444e8b6af44b109e316/) | AsyncRAT | RAT | **86.1** | 🔴 KRITISCH | – | – | ? |
| [c8f9f1c4c1d37a…](https://bazaar.abuse.ch/sample/c8f9f1c4c1d37a91f0549efa48035e50c284b7566001df0009195af6b831aebf/) | AsyncRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [4916996a7508c8…](https://bazaar.abuse.ch/sample/4916996a7508c85519a8d952784153ab3b5bbcf4edd13af0ec13a18474622dc2/) | RemcosRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [789db0dc883f1c…](https://bazaar.abuse.ch/sample/789db0dc883f1cc1ac9dca3fd1f43b32aeb062ce99bd92e0135e3d694585743a/) | XWorm | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [d1ea2b3c84e669…](https://bazaar.abuse.ch/sample/d1ea2b3c84e6697a70c65c5f15ae0468e7eb463b22f955d3412b4312d19906ef/) | RemcosRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6348/7837 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6348/7837 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.2% | 6054/7837 |
| 6 | Kaspersky | 75.5% | 5913/7836 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5578/7833 |
| 9 | Rising | 68.3% | 5350/7837 |
| 10 | Varist | 66.2% | 5184/7832 |
| 11 | Avast | 65.1% | 5096/7833 |
| 12 | AVG | 65.1% | 5096/7832 |
| 13 | Tencent | 64.9% | 4939/7611 |
| 14 | McAfeeD | 61.4% | 4805/7829 |
| 15 | huorong | 60.8% | 4761/7829 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 37 | 37.4% |
| 🐧 Linux | 31 | 31.3% |
| ❓ Unbekannt | 27 | 27.3% |
| 📦 Archiv | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 73 | 73.7% |
| Drive-By / Exploit-Kit | 23 | 23.2% |
| Exploit / N-Day | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 27 | 27.3% |
| 2 | 🇩🇪 DE | 18 | 18.2% |
| 3 | 🇭🇺 HU | 15 | 15.2% |
| 4 | 🇺🇸 US | 10 | 10.1% |
| 5 | 🇳🇱 NL | 8 | 8.1% |
| 6 | 🇬🇧 GB | 6 | 6.1% |
| 7 | 🇫🇷 FR | 5 | 5.1% |
| 8 | 🇦🇹 AT | 4 | 4.0% |
| 9 | 🇨🇭 CH | 3 | 3.0% |
| 10 | 🌐 FI | 1 | 1.0% |
| 11 | 🌐 CO | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 21 von 99 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 8 |
| Lateral Movement | 8 |
| Collection | 8 |
| Command and Control | 8 |
| Credential Access | 5 |
| Execution | 4 |
| Defense Evasion | 1 |

<details><summary>6bfeb99e0aa982a6f6de… – Formbook | 🔴 KRITISCH 87.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>0301de0be419c5bc6dfc… – Formbook | 🔴 KRITISCH 87.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e350e18fc96aea8b2ef6… – Formbook | 🔴 KRITISCH 87.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2e0bafa5a685be2bf829… – Formbook | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f3bcfd1c9c0ee9d7c38e…](https://bazaar.abuse.ch/sample/f3bcfd1c9c0ee9d7c38e837e685da218c6b53c0b8d23c141fc6ec63fbf632dfd/)

- **Familie:** Mirai
- **Erkannt von:** 33 von 75 Engines (44.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Linux.Medusa.C.8496C4FB
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Linux.Medusa.C.8496C4FB`

**Erkennende Engines (33/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Linux.Medusa.C.8496C4FB` |
| AVG | `BV:Downloader-AAN [Drp]` |
| AhnLab-V3 | `Downloader/Shell.Generic.S1672` |
| Arcabit | `Generic.Linux.Medusa.C.8496C4FB` |
| Avast | `BV:Downloader-AAN [Drp]` |
| Avira | `HTML/ExpKit.Gen2` |
| BitDefender 🛡️ | `Generic.Linux.Medusa.C.8496C4FB` |
| CTX | `script.unknown.medusa` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.37` |
| Emsisoft | `Generic.Linux.Medusa.C.8496C4FB (B)` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| Fortinet | `BASH/Dloader.P!tr` |
| GData | `Generic.Linux.Medusa.C.8496C4FB` |
| Google | `Detected` |
| K7GW | `Trojan ( 004102a21 )` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| MaxSecure | `Downloader.W32.Shell.Agent.p` |
| MicroWorld-eScan | `Generic.Linux.Medusa.C.8496C4FB` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Script.Downloader.hjbjep` |
| Rising | `Downloader.Mirai/BASH!1.CECE (CLASSIC)` |
| Sangfor | `Virus.Generic-Script.Save.ba1` |
| Skyhigh | `Linux/Downloader.w` |
| Sophos | `Mal/ShellDl-A` |
| Symantec | `CL.Downloader!gen277` |
| TrellixENS | `Linux/Downloader.w` |
| TrendMicro | `Possible_BASHDLOD.SMLBAT3` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBAT3` |
| VIPRE | `Generic.Linux.Medusa.C.8496C4FB` |
| Varist | `SH/Mirai.C.gen!Camelot` |
| ZoneAlarm | `Mal/ShellDl-A` |
| huorong | `Trojan/BAT.Obfuscated.aar!crit` |

### [9f3b14062eba8d8232e4…](https://bazaar.abuse.ch/sample/9f3b14062eba8d8232e409fbc9c2132f39b11c887457538c8e6101ca30f0c230/)

- **Familie:** AsyncRAT
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Script.AsyncRAT.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `VBS/TrojanDropper.Agent.QIC trojan` |
| Fortinet | `VBS/Agent.QIC!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Kingsoft | `Win32.Infected.AutoInfector.a` |
| Lionic | `Trojan.Script.AsyncRAT.4!c` |
| McAfeeD | `ti!9F3B14062EBA` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Symantec | `Trojan.Sagent!ATN` |
| Tencent | `Vbs.Trojan.Sagent.Unkl` |
| Varist | `JS/Agent.FIJ!Eldorado` |
| alibabacloud | `Trojan[dropper]:Win/SAgent.gyf` |

### [9702425024335a042c34…](https://bazaar.abuse.ch/sample/9702425024335a042c348f6b4c106123575c99704b9cc3c6ac03643fd4b2563e/)

- **Familie:** AgentTesla
- **Erkannt von:** 49 von 75 Engines (65.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Soko.1.26370FCA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Soko.1.26370FCA`

**Erkennende Engines (49/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Soko.1.26370FCA` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Malware/Win32.RL_Generic.C4100885` |
| Antiy-AVL | `Trojan/MSIL.Kryptik` |
| Arcabit | `Generic.Soko.1.26370FCA` |
| Avast | `Win32:MalwareX-gen [Pws]` |
| Avira | `TR/W32.MalwareX` |
| BitDefender 🛡️ | `Generic.Soko.1.26370FCA` |
| Bkav | `W32.Malware.8FACC3C` |
| CAT-QuickHeal | `Trojan.YakbeexMSIL.ZZ4` |
| CTX | `exe.unknown.soko` |
| ClamAV | `Win.Packed.Nanocore-10021190-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen9.47097` |
| ESET-NOD32 | `MSIL/Kryptik.VZB trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Generic.Soko.1.26370FCA (B)` |
| F-Secure | `Trojan.TR/W32.MalwareX` |
| Fortinet | `MSIL/GenKryptik.ELKP!tr` |
| GData | `Generic.Soko.1.26370FCA` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 005670301 )` |
| K7GW | `Trojan ( 005670301 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.NanoBot.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Malwarebytes | `Generic.Trojan.Crypt.DDS` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!970242502433` |
| MicroWorld-eScan | `Generic.Soko.1.26370FCA` |
| Microsoft 🛡️ | `TrojanSpy:MSIL/AgentTesla.AP!MTB` |
| Panda | `Trj/CI.A` |
| Rising | `Malware.Obfus/MSIL@AI.100 (RDM.MSIL2:Y1XwZnWG2N5F36EZbgKZvQ)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `PWS-FCSU!DEECAF12938E` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Packed.Generic.570` |
| TrellixENS | `PWS-FCSU!DEECAF12938E` |
| TrendMicro | `Backdoor.MSIL.REMCOS.SM` |
| TrendMicro-HouseCall | `Backdoor.MSIL.REMCOS.SM` |
| VIPRE | `Generic.Soko.1.26370FCA` |
| Varist | `W32/MSIL_Kryptik.ASY.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Webroot | `W32.Malware.gen` |
| huorong | `VirTool/MSIL.Obfuscator.n` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (27×)
- **elf** (27×)
- **js** (22×)
- **AgentTesla** (11×)
- **Mirai** (8×)
- **RAT** (7×)
- **upx-dec** (7×)
- **upx** (7×)
- **ps1** (5×)
- **sh** (4×)
- **jar** (4×)
- **java** (4×)
- **python** (4×)
- **silentnet** (4×)
- **196-251-107-48** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +4 (42→46)
- ↑ **AgentTesla** +6 (5→11)
- ↑ **Formbook** +2 (2→4)
- ↑ **Silentnet** +1 (2→3)
- ↑ **AsyncRAT** +2 (1→3)
- neu: **ValleyRAT** (3)
- ↑ **CoinMiner** +1 (1→2)
- weg: **WARDENStealer** (war 4)
- weg: **SalatStealer** (war 7)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +14 (32→46)
- ↑ **AgentTesla** +9 (2→11)
- ↓ **Mirai** -12 (20→8)
- ↑ **Formbook** +2 (2→4)
- ↑ **RemcosRAT** +2 (2→4)
- ↑ **Silentnet** +2 (1→3)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **ValleyRAT** +2 (1→3)
- ↑ **CoinMiner** +1 (1→2)
- ↑ **XWorm** +1 (1→2)
- weg: **SalatStealer** (war 7)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.623 MB |
| σ Dateigröße | 11.299 MB |
| Ø Risiko-Score | 54.3/100 |
| Ø Klassifikations-Konfidenz | 57.0% |
| Samples mit VT | 4/99 |
| Samples mit MITRE | 21/99 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 10 (10.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:48 | [fdf5d400ec54…](https://bazaar.abuse.ch/sample/fdf5d400ec54f17de0459a1978c49da526e0f7c2b0ef6c54b7d0ebfd9898aea0/) | `zip` | unbekannt | 32.7 | – | – | 🇬🇧GB |
| 21:48 | [cba327b53231…](https://bazaar.abuse.ch/sample/cba327b53231cea8f00986aa816b23514a95a2329ab79f17760ffe24308eb2c7/) | `zip` | unbekannt | 32.7 | – | – | 🇬🇧GB |
| 20:09 | [5051b4b91de8…](https://bazaar.abuse.ch/sample/5051b4b91de8fbebb31884cf3be01fb381ce6e9704fa0272e8a6b1b50b78caf7/) | `exe` | unbekannt | 37.6 | – | – | 🇫🇷FR |
| 20:06 | [f908daa02ae9…](https://bazaar.abuse.ch/sample/f908daa02ae95827255b043c79f89234ab75dde72b845b3a20000613bf40e277/) | `exe` | unbekannt | 37.6 | – | – | 🌐HU |
| 20:04 | [83695d745bb0…](https://bazaar.abuse.ch/sample/83695d745bb02c152b230544a178ffb5ddf53368c05df2b858e28cc20883eba3/) | `elf` | unbekannt | 41.8 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 05.11.2026 21:50 UTC*