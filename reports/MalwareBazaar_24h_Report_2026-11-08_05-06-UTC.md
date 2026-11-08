# MalwareBazaar – 08.11.2026 05:06 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **55** |
| Höchster Score | **88.8/100** – 57d947fada8f7084… |
| Häufigste Familie | **Mirai** (52x) |
| Häufigster Typ | **elf** (97x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 53 Samples |
| Ø Dateigröße | 0.16 MB (σ=0.80) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 97 | 96.0%  ███████████████████ |
| `exe` | 4 | 4.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 52 | 51.5% |
| 2 | unbekannt | 29 | 28.7% |
| 3 | Snowlight | 16 | 15.8% |
| 4 | ValleyRAT | 1 | 1.0% |
| 5 | ELF:Downloader-BR [Drp] | 1 | 1.0% |
| 6 | AsyncRAT | 1 | 1.0% |
| 7 | NanoCore | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 52 | 51.5% | 95% |
| Linux-Malware | 42 | 41.6% | 45% |
| RAT | 3 | 3.0% | 88% |
| Trojaner | 1 | 1.0% | 65% |
| Loader | 1 | 1.0% | 65% |
| Cryptominer | 1 | 1.0% | 75% |
| Windows-Malware | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 55 | 54.5% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 43 | 42.6% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [57d947fada8f70…](https://bazaar.abuse.ch/sample/57d947fada8f7084bae6f0f622475e2210fd0e531b7d61e9eeb65adeaf70073c/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [35882ccb1adfa5…](https://bazaar.abuse.ch/sample/35882ccb1adfa5d45dd73dd2cebbd63e31e9a63bafbe23aa03fac13c57dc6e3f/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [b2fe11b977bea3…](https://bazaar.abuse.ch/sample/b2fe11b977bea36950dbe7accae8dc38a3e20684ff03cb746453c445717e96b6/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [a895153a59b851…](https://bazaar.abuse.ch/sample/a895153a59b8517022786649a1e5495eef529b20e9bbdaed37756f6505322fe5/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [3a92faf9c364ae…](https://bazaar.abuse.ch/sample/3a92faf9c364ae0349c174df0d1c3810c865170c333b2ed7b5030a4771dc28eb/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [765bebb2f3f863…](https://bazaar.abuse.ch/sample/765bebb2f3f86349e9a250646fed3e679b923d79496a15341efc1e30c297e584/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [535528c8b8cbe1…](https://bazaar.abuse.ch/sample/535528c8b8cbe19eb5d0bd2f8ba308c4347f03f32e42fe917f7ddab6b18cc60d/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [7efbb8ff84a9d9…](https://bazaar.abuse.ch/sample/7efbb8ff84a9d9759360c98c112d337af53630ef83cc39e5a47f18a03ee3cd1b/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [f5d541d99b8db2…](https://bazaar.abuse.ch/sample/f5d541d99b8db2fe713b9284632e08b0791929f9ecbd753cfcab8ca208d85009/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [6d5855a9bd6378…](https://bazaar.abuse.ch/sample/6d5855a9bd637854b6b2d2b2dfe86b152b2ae0eda690d290c7fe0a0d23d4cbfc/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6387/7881 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6387/7881 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6090/7881 |
| 6 | Kaspersky | 75.5% | 5947/7880 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5610/7877 |
| 9 | Rising | 68.3% | 5385/7881 |
| 10 | Varist | 66.1% | 5209/7876 |
| 11 | Avast | 65.1% | 5130/7877 |
| 12 | AVG | 65.1% | 5130/7876 |
| 13 | Tencent | 64.9% | 4971/7655 |
| 14 | McAfeeD | 61.4% | 4833/7873 |
| 15 | huorong | 60.9% | 4796/7873 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 97 | 96.0% |
| 🪟 Windows | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 60 | 59.4% |
| 2 | 🇫🇷 FR | 25 | 24.8% |
| 3 | 🇩🇪 DE | 11 | 10.9% |
| 4 | 🇳🇱 NL | 3 | 3.0% |
| 5 | 🇭🇺 HU | 1 | 1.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 53 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 52 |
| Lateral Movement | 52 |
| Command and Control | 1 |
| Execution | 1 |

<details><summary>57d947fada8f7084bae6… – AsyncRAT | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>35882ccb1adfa5d45dd7… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b2fe11b977bea36950db… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a895153a59b851702278… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3a92faf9c364ae0349c1… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9bf11533b250a32c79d7…](https://bazaar.abuse.ch/sample/9bf11533b250a32c79d7b8734252eee95cbcf29fde23322e4c584854d16bdf68/)

- **Familie:** Snowlight
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!700AD464452C` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [c13a086deb139c739692…](https://bazaar.abuse.ch/sample/c13a086deb139c739692b50ff08b603ac565a30a5917b0e8cb1280bd72e15218/)

- **Familie:** ELF:Downloader-BR [Drp]
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BR [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BR [Drp]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BR [Drp]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `DR/LINUX.Downloade.BR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Dropper.DR/LINUX.Downloade.BR` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Downloader.Agent/Linux!8.13C9D (TFE:14:7f7dlmYAy1C)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| Varist | `E32/Agent.DB.gen!Eldorado` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.7a308702` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [5a3405f94f713af58bfc…](https://bazaar.abuse.ch/sample/5a3405f94f713af58bfcab1ced0ff6de4ed18276908cca666de54913fcb858a4/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2270` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF64/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.emw` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.S!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!AEC862D6A4FB` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| VBA32 | `Trojan.Elf64.Agent` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [3b2e2a4a787e6504f4e7…](https://bazaar.abuse.ch/sample/3b2e2a4a787e6504f4e793f578b9b61ca58910ef64c442fa7531fdb0b76450bb/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2270` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.2270!tr` |
| Google | `Detected` |
| Jiangmin | `Trojan.Linux.emw` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.S!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!4BCDB905ABB9` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| VBA32 | `Trojan.Elf64.Agent` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

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

- **elf** (96×)
- **Mirai** (52×)
- **Snowlight** (17×)
- **exe** (3×)
- **upx-dec** (2×)
- **upx** (2×)
- **RAT** (1×)
- **ValleyRAT** (1×)
- **bot_lin_lucifer_strings** (1×)
- **coinminer_strings** (1×)
- **cowrie** (1×)
- **cp_script_inject_detector** (1×)
- **honeypot** (1×)
- **x86-64** (1×)
- **AsyncRAT** (1×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +22 (30→52)
- ↑ **unbekannt** +5 (24→29)
- ↑ **Snowlight** +14 (2→16)
- neu: **ValleyRAT** (1)
- neu: **ELF:Downloader-BR [Drp]** (1)
- neu: **AsyncRAT** (1)
- weg: **VShell** (war 2)
- weg: **WARDENStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +33 (19→52)
- ↓ **unbekannt** -6 (35→29)
- neu: **Snowlight** (16)
- neu: **ELF:Downloader-BR [Drp]** (1)
- weg: **SalatStealer** (war 3)
- weg: **WARDENStealer** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **VShell** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.155 MB |
| σ Dateigröße | 0.796 MB |
| Ø Risiko-Score | 65.6/100 |
| Ø Klassifikations-Konfidenz | 72.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 53/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 17 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:05 | [117712dcbed6…](https://bazaar.abuse.ch/sample/117712dcbed67dca7e84e13ed4fb7ee2f5042a9d25f6f2d8c0049b45ebddaf95/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 05:05 | [86b1543fbbb4…](https://bazaar.abuse.ch/sample/86b1543fbbb40fb968bb6d9e9ec5a6a8a1f88c24e13d7f39fe480ac2557e8186/) | `exe` | ValleyRAT | 81.3 | – | – | 🇳🇱NL |
| 05:04 | [049eb043c5fa…](https://bazaar.abuse.ch/sample/049eb043c5fa1da7e40e0cd42c1bf01339174651ce8d2b747817800a21ee271b/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 05:04 | [bee68d99561a…](https://bazaar.abuse.ch/sample/bee68d99561a81a1c25b55d8182b05b93f4e1121547123288ceede8871e7a249/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 05:04 | [5d5c8f889b73…](https://bazaar.abuse.ch/sample/5d5c8f889b734f3827eea79187d246e79d6001c5316f26fc043bc15e2eb72f0f/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 08.11.2026 05:06 UTC*