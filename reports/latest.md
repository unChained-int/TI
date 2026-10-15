# MalwareBazaar – 15.10.2026 14:45 UTC

Dieser Run hat **43 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **44** |
| Kritisch (≥75) | **22** |
| Höchster Score | **88.5/100** – ee51871b2d52e015… |
| Häufigste Familie | **Mirai** (15x) |
| Häufigster Typ | **elf** (20x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 1.84 MB (σ=3.08) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 20 | 45.5%  █████████ |
| `exe` | 8 | 18.2%  ███ |
| `js` | 6 | 13.6%  ██ |
| `xlsx` | 3 | 6.8%  █ |
| `py` | 3 | 6.8%  █ |
| `hta` | 1 | 2.3%   |
| `sh` | 1 | 2.3%   |
| `xls` | 1 | 2.3%   |
| `7z` | 1 | 2.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 15 | 34.1% |
| 2 | unbekannt | 12 | 27.3% |
| 3 | Prometei | 6 | 13.6% |
| 4 | AgentTesla | 2 | 4.5% |
| 5 | RemcosRAT | 2 | 4.5% |
| 6 | AsyncRAT | 2 | 4.5% |
| 7 | ConnectWise | 1 | 2.3% |
| 8 | XWorm | 1 | 2.3% |
| 9 | GuLoader | 1 | 2.3% |
| 10 | LONGLEASH | 1 | 2.3% |
| 11 | Formbook | 1 | 2.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 15 | 34.1% | 95% |
| RAT | 5 | 11.4% | 95% |
| Linux-Malware | 5 | 11.4% | 45% |
| Skript/Dropper | 4 | 9.1% | 35% |
| Maldoc | 4 | 9.1% | 35% |
| Andere / Unbekannt | 4 | 9.1% | 20% |
| Windows-Malware | 3 | 6.8% | 35% |
| Loader | 2 | 4.5% | 85% |
| Post-Exploitation | 1 | 2.3% | 65% |
| Infostealer | 1 | 2.3% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 22 | 50.0% |
| 🟠 HOCH | 2 | 4.5% |
| 🟡 MITTEL | 16 | 36.4% |
| 🟢 NIEDRIG | 4 | 9.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [ee51871b2d52e0…](https://bazaar.abuse.ch/sample/ee51871b2d52e0152ea0e645bbee33f2adcc070ec233390cb8c8fc324b4dd1df/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [3e4313662c1ef3…](https://bazaar.abuse.ch/sample/3e4313662c1ef316bb7095b4f8f9b47c9d0b2b7050ec6d3a1ac4440d43fb2d1b/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [8f3f94216965f1…](https://bazaar.abuse.ch/sample/8f3f94216965f1a5aab55bf5659cca63488778d20fca357f385ce341219dc498/) | XWorm | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [6b68a1f5df0a2e…](https://bazaar.abuse.ch/sample/6b68a1f5df0a2e64d8d5092dacf355a35bbab4e7d5d6c193234a05bc5037dcbc/) | AsyncRAT | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [ba65072840838f…](https://bazaar.abuse.ch/sample/ba65072840838f65f3aa886ca87894ebd8b3980e060ef993f49ebb62bbbcdf6b/) | Formbook | Infostealer | **86.8** | 🔴 KRITISCH | – | – | ? |
| [f0395d3cbe1ff9…](https://bazaar.abuse.ch/sample/f0395d3cbe1ff9313f14c102db0803b1b8ac4aa7cc8eaf3c26123a6aea75890b/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | 12.0% | 🟡 SCHWACH ERKANNT | ✓ |
| [c9f7807af2d382…](https://bazaar.abuse.ch/sample/c9f7807af2d38267e151356ec38db145f6014e100b134989211321e5737c5ca4/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [081cba4ea90a4e…](https://bazaar.abuse.ch/sample/081cba4ea90a4e82db7476b29906b546d822ccf4a453bbf234a23c73823b255d/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [9faeaa033a5f1a…](https://bazaar.abuse.ch/sample/9faeaa033a5f1a923cb70d81ddfdb885976cef0a58d68c6c9804118a43985d4a/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [55c3a37165d536…](https://bazaar.abuse.ch/sample/55c3a37165d536c7c83af6ed706212924117277c07987c1def6529cbfc19b06d/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5979/7391 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5979/7391 |
| 3 | ESET-NOD32 | 77.4% | 5724/7391 |
| 4 | Kaspersky | 76.4% | 5644/7390 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5288/7388 |
| 8 | Rising | 68.8% | 5082/7391 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4911/7387 |
| 11 | Tencent | 65.3% | 4682/7165 |
| 12 | Avast | 65.1% | 4806/7387 |
| 13 | AVG | 65.1% | 4806/7386 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4530/7384 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 21 | 47.7% |
| 🪟 Windows | 10 | 22.7% |
| ❓ Unbekannt | 8 | 18.2% |
| 📄 Dokument | 4 | 9.1% |
| 📦 Archiv | 1 | 2.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 33 | 75.0% |
| Drive-By / Exploit-Kit | 6 | 13.6% |
| Phishing / E-Mail-Anhang | 4 | 9.1% |
| C2 / Nachladen | 1 | 2.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 24 | 54.5% |
| 2 | 🇺🇸 US | 10 | 22.7% |
| 3 | 🌐 EG | 3 | 6.8% |
| 4 | 🇳🇱 NL | 2 | 4.5% |
| 5 | 🇭🇺 HU | 2 | 4.5% |
| 6 | 🇨🇭 CH | 2 | 4.5% |
| 7 | 🌐 Unbekannt | 1 | 2.3% |

## MITRE ATT&CK

> 21 von 44 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 15 |
| Lateral Movement | 15 |
| Command and Control | 4 |
| Collection | 3 |
| Execution | 3 |
| Defense Evasion | 1 |
| Credential Access | 1 |

<details><summary>ee51871b2d52e0152ea0… – RemcosRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>3e4313662c1ef316bb70… – AsyncRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>6b68a1f5df0a2e64d8d5… – AsyncRAT | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>ba65072840838f65f3aa… – Formbook | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [2f5b9d79715c6738a138…](https://bazaar.abuse.ch/sample/2f5b9d79715c6738a1384db2016270de7c1c503284abb4365a338d6a7aaf8b52/)

- **Familie:** ConnectWise
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Alibaba | `RiskWare:MSIL/ConnectWise.49136667` |
| Bkav | `W32.Malware.69851B1D` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop31.17564` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Riskware.SilentConwi.B` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kaspersky | `not-a-virus:RemoteAdmin.MSIL.ConnectWise.b` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |

### [f0395d3cbe1ff9313f14…](https://bazaar.abuse.ch/sample/f0395d3cbe1ff9313f14c102db0803b1b8ac4aa7cc8eaf3c26123a6aea75890b/)

- **Familie:** Mirai
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Gafgyt-9940653-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Script/Wacatac.C!ml`

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| GData | `Linux.Trojan-DDoS.Lightaidra.A` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.Mirai.l` |

### [d744542a42c4720ad36f…](https://bazaar.abuse.ch/sample/d744542a42c4720ad36f1127ee5af5f013f23ae5822cdaae2ff03345f2839594/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avira | `APPL/AgentLINUX.M.DMQ` |
| ClamAV | `Unix.Trojan.Gafgyt-9940653-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3272` |
| ESET-NOD32 | `Linux/Mirai.FLI trojan` |
| F-Secure | `Program.APPL/AgentLINUX.M.DMQ` |
| GData | `Linux.Trojan-DDoS.Lightaidra.A` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jq` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148B2 (CLASSIC)` |
| Sangfor | `Backdoor.Linux.Mirai.Vouz` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Linux.Backdoor.Gafgyt.Ximw` |
| Varist | `E64/Gafgyt.C.gen!Camelot` |
| alibabacloud | `DDoS:Linux/Mirai.FEE` |
| huorong | `Trojan/Linux.Mirai.l` |

### [42169bf27014012a0123…](https://bazaar.abuse.ch/sample/42169bf27014012a01236104febd2106e54f874d570a2536f30bfc5bbd139283/)

- **Familie:** Prometei
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.ShellCode.Metasploit.Marte.2.42411C0A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.ShellCode.Metasploit.Marte.2.42411C0A`

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| AVG | `Sf:ShellCode-GG [Trj]` |
| Antiy-AVL | `Trojan/Linux.Prometei` |
| Arcabit | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| Avast | `Sf:ShellCode-GG [Trj]` |
| BitDefender 🛡️ | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| CTX | `elf.unknown.marte` |
| ClamAV | `Win.Trojan.MSShellcode-6` |
| DrWeb | `Linux.Prometei.2` |
| ESET-NOD32 | `Linux/Prometei.C trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Generic.ShellCode.Metasploit.Marte.2.42411C0A (B)` |
| GData | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| Google | `Detected` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| Rising | `Trojan.Prometei/Linux!8.132EB (TFE:14:rNR6dALoP5I)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Skyhigh | `ELF/Kaiji!5D577A2F2188` |
| Sophos | `Linux/Bdoor-BIT` |
| Symantec | `Meterpreter` |
| Tencent | `Trojan.Linux.Flooder.qlyra` |
| VIPRE | `Generic.ShellCode.Metasploit.Marte.2.42411C0A` |
| ZoneAlarm | `Linux/Bdoor-BIT` |
| huorong | `Trojan/Prometei.d` |

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

- **elf** (20×)
- **Mirai** (15×)
- **exe** (8×)
- **js** (6×)
- **cowrie** (6×)
- **honeypot** (6×)
- **Prometei** (5×)
- **sticky** (5×)
- **xlsx** (3×)
- **py** (3×)
- **advanced-micro-devices-x86-64** (3×)
- **AgentTesla** (2×)
- **AsyncRAT** (2×)
- **A** (1×)
- **ConnectWise** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -7 (22→15)
- ↓ **unbekannt** -11 (23→12)
- neu: **Prometei** (6)
- ↓ **RemcosRAT** -1 (3→2)
- neu: **ConnectWise** (1)
- neu: **GuLoader** (1)
- neu: **LONGLEASH** (1)
- weg: **DCRat** (war 2)
- weg: **RemusStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -21 (36→15)
- ↓ **unbekannt** -17 (29→12)
- neu: **Prometei** (6)
- ↑ **AgentTesla** +1 (1→2)
- ↑ **AsyncRAT** +1 (1→2)
- neu: **GuLoader** (1)
- neu: **LONGLEASH** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.841 MB |
| σ Dateigröße | 3.079 MB |
| Ø Risiko-Score | 61.5/100 |
| Ø Klassifikations-Konfidenz | 66.4% |
| Samples mit VT | 5/44 |
| Samples mit MITRE | 21/44 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 34 |
| Unbekannte Familien | 4 (9.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:30 | [c9f7807af2d3…](https://bazaar.abuse.ch/sample/c9f7807af2d38267e151356ec38db145f6014e100b134989211321e5737c5ca4/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 14:26 | [2f5b9d79715c…](https://bazaar.abuse.ch/sample/2f5b9d79715c6738a1384db2016270de7c1c503284abb4365a338d6a7aaf8b52/) | `exe` | ConnectWise | 73.7 | 32.0% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 14:22 | [e6d95e84a81b…](https://bazaar.abuse.ch/sample/e6d95e84a81bc18aa024206c6d586af76518366e8ef2c847dcef21342ebd80ea/) | `js` | unbekannt | 38.8 | – | – | 🇩🇪DE |
| 14:06 | [bf7d7adbb389…](https://bazaar.abuse.ch/sample/bf7d7adbb38971b88c0cae07a28ff639b671aaf15a8b31bb08c84b7c1a41ac64/) | `js` | unbekannt | 38.5 | – | – | 🇩🇪DE |
| 13:42 | [081cba4ea90a…](https://bazaar.abuse.ch/sample/081cba4ea90a4e82db7476b29906b546d822ccf4a453bbf234a23c73823b255d/) | `elf` | Mirai | 83.6 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.10.2026 14:45 UTC*