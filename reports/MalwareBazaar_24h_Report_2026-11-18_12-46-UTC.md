# MalwareBazaar – 18.11.2026 12:46 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **63** |
| Höchster Score | **94.0/100** – f798a8b540560b1b… |
| Häufigste Familie | **Mirai** (24x) |
| Häufigster Typ | **js** (39x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 50 Samples |
| Ø Dateigröße | 2.37 MB (σ=5.64) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 39 | 38.6%  ███████ |
| `elf` | 33 | 32.7%  ██████ |
| `exe` | 15 | 14.9%  ██ |
| `sh` | 3 | 3.0%   |
| `ps1` | 3 | 3.0%   |
| `hta` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `zip` | 1 | 1.0%   |
| `xls` | 1 | 1.0%   |
| `rtf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 24 | 23.8% |
| 2 | unbekannt | 14 | 13.9% |
| 3 | AgentTesla | 11 | 10.9% |
| 4 | RemcosRAT | 11 | 10.9% |
| 5 | Formbook | 6 | 5.9% |
| 6 | AsyncRAT | 6 | 5.9% |
| 7 | Prometei | 5 | 5.0% |
| 8 | MassLogger | 5 | 5.0% |
| 9 | XWorm | 3 | 3.0% |
| 10 | CoinMiner | 2 | 2.0% |
| 11 | RatHat | 2 | 2.0% |
| 12 | LxBaseRAT | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 24.8% | 94% |
| RAT | 25 | 24.8% | 92% |
| Skript/Dropper | 16 | 15.8% | 35% |
| Infostealer | 10 | 9.9% | 87% |
| Linux-Malware | 7 | 6.9% | 45% |
| Windows-Malware | 7 | 6.9% | 35% |
| Cryptominer | 3 | 3.0% | 75% |
| Spyware | 2 | 2.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |
| Post-Exploitation | 1 | 1.0% | 95% |
| Andere / Unbekannt | 1 | 1.0% | 20% |
| Android-Malware | 1 | 1.0% | 45% |
| Maldoc | 1 | 1.0% | 35% |
| Loader | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 63 | 62.4% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 32 | 31.7% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f798a8b540560b…](https://bazaar.abuse.ch/sample/f798a8b540560b1bb3dd7c72c45865756332780bfbd3e44ca0054bc0109be557/) | Sliver | Post-Exploitat | **94.0** | 🔴 KRITISCH | – | – | ? |
| [a2929392503b43…](https://bazaar.abuse.ch/sample/a2929392503b43f5cb438f5c6d7cf6c0a16234cfcecbff3df3f02a2ce4edfc10/) | Formbook | Infostealer | **89.6** | 🔴 KRITISCH | – | – | ? |
| [cb0108febaba14…](https://bazaar.abuse.ch/sample/cb0108febaba146bddd677db32774a54542952efd5c09a5eac15e1a1fc9c9bef/) | Formbook | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [d0978cec0e64b6…](https://bazaar.abuse.ch/sample/d0978cec0e64b66891ab4d54d95f6989b7320046306b22e06e7b013292418253/) | Formbook | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [02337e81f9783c…](https://bazaar.abuse.ch/sample/02337e81f9783c0bcf1430680222b1c6d7504a9bab9bce766580b3d08d29fd58/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [e557f5d5bb5f93…](https://bazaar.abuse.ch/sample/e557f5d5bb5f93861323bc50c5f377e7342b37369531d7b3bb9692376f11fa46/) | RemcosRAT | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [1ec2b7f8955238…](https://bazaar.abuse.ch/sample/1ec2b7f895523883339da07104dab84ba8b912399496a0b2f3b20ec1884ad8a7/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [a3c43099f08d8c…](https://bazaar.abuse.ch/sample/a3c43099f08d8c1ec1124c3ba90101f34fd07fc684ba4b8ea394784a2d58bc82/) | Formbook | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [a3c861d4cb4ee9…](https://bazaar.abuse.ch/sample/a3c861d4cb4ee9ed98d58c2d55fc5a54ea32c56ca23e8c24168ca16ffb2a082a/) | Formbook | Infostealer | **87.2** | 🔴 KRITISCH | – | – | ? |
| [ffa10fe7c00376…](https://bazaar.abuse.ch/sample/ffa10fe7c00376d7f72cc21e5673624dbf50350cd393cf7b065056b383726367/) | Formbook | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6525/8042 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6525/8042 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6220/8042 |
| 6 | Kaspersky | 75.5% | 6074/8041 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5727/8038 |
| 9 | Rising | 68.5% | 5507/8042 |
| 10 | Varist | 66.0% | 5308/8037 |
| 11 | Avast | 65.2% | 5240/8038 |
| 12 | AVG | 65.2% | 5240/8037 |
| 13 | Tencent | 65.1% | 5089/7816 |
| 14 | McAfeeD | 61.5% | 4940/8034 |
| 15 | huorong | 60.9% | 4891/8034 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 37 | 36.6% |
| 🐧 Linux | 36 | 35.6% |
| 🪟 Windows | 21 | 20.8% |
| 🤖 Android | 4 | 4.0% |
| 📄 Dokument | 2 | 2.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 55 | 54.5% |
| Drive-By / Exploit-Kit | 39 | 38.6% |
| APK-Sideloading | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |
| USB / Wechselmedium | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 35 | 34.7% |
| 2 | 🇸🇪 SE | 32 | 31.7% |
| 3 | 🇦🇹 AT | 19 | 18.8% |
| 4 | 🇺🇸 US | 9 | 8.9% |
| 5 | 🇳🇱 NL | 1 | 1.0% |
| 6 | 🌐 CL | 1 | 1.0% |
| 7 | 🇯🇵 JP | 1 | 1.0% |
| 8 | 🇫🇷 FR | 1 | 1.0% |
| 9 | 🇪🇸 ES | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 50 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 24 |
| Lateral Movement | 24 |
| Collection | 18 |
| Command and Control | 18 |
| Credential Access | 6 |
| Execution | 6 |
| Impact | 2 |

<details><summary>a2929392503b43f5cb43… – Formbook | 🔴 KRITISCH 89.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>cb0108febaba146bddd6… – Formbook | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>d0978cec0e64b66891ab… – Formbook | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4dc5bb69063c633c6105…](https://bazaar.abuse.ch/sample/4dc5bb69063c633c6105ea7cee9ca46985db5aa0943d4276dc662f10f1135457/)

- **Familie:** Trojan
- **Erkannt von:** 21 von 74 Engines (28.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.Trojan.Inject.8.D7A529A0
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Generic.Trojan.Inject.8.D7A529A0`

**Erkennende Engines (21/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Trojan.Inject.8.D7A529A0` |
| AVG | `BV:Downloader-BPG [Trj]` |
| Arcabit | `Generic.Trojan.Inject.8.D7A529A0` |
| Avast | `BV:Downloader-BPG [Trj]` |
| Avira | `TR/BAT.Downloader.BPG` |
| BitDefender 🛡️ | `Generic.Trojan.Inject.8.D7A529A0` |
| CTX | `unknown.trojan.inject` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.FJS trojan` |
| Emsisoft | `Generic.Trojan.Inject.8.D7A529A0 (B)` |
| F-Secure | `Trojan.TR/BAT.Downloader.BPG` |
| Fortinet | `BASH/Agent.GJS!tr.dldr` |
| GData | `Generic.Trojan.Inject.8.D7A529A0` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Sh` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.gen` |
| Kingsoft | `Linux.TrojDownloader.sh.2060773` |
| MicroWorld-eScan | `Generic.Trojan.Inject.8.D7A529A0` |
| VIPRE | `Generic.Trojan.Inject.8.D7A529A0` |
| Varist | `XML/Agent.IF` |
| huorong | `TrojanDownloader/Linux.Shell.cr` |

### [7ad666462423c68f7182…](https://bazaar.abuse.ch/sample/7ad666462423c68f71829fff8f138b311a15951424f2ed9d66ca05ce37484d78/)

- **Familie:** Prometei
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (28/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
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
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [f9bc8847c6fca49b3270…](https://bazaar.abuse.ch/sample/f9bc8847c6fca49b32704062817a88b64e991fbe0236b8fc9b5e5216d045068a/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-AIN [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-AIN [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Agent-AIN [PUP]` |
| Avira | `PUA/LINUX.Agent.AIN` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FNP trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.AIN` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/Mirai.EQQ` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GF!MTB` |
| Sangfor | `Backdoor.Linux.Mirai.Vchn` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Tencent | `Backdoor.Linux.Mirai.tnog` |
| Varist | `E64/Agent.AW.gen!Eldorado` |
| alibabacloud | `DDoS:Linux/Mirai.FTD` |
| huorong | `Trojan/Linux.Mirai.np` |

### [4eae60dbf6fa784d2a48…](https://bazaar.abuse.ch/sample/4eae60dbf6fa784d2a48b28e7812c39ac779f6a28c8d14c9d28a762e8234c411/)

- **Familie:** WARDENStealer
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.C8D32978` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| Kingsoft | `malware.kb.a.837` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector.RND.Generic` |
| McAfeeD | `ti!4EAE60DBF6FA` |
| Microsoft 🛡️ | `Trojan:Win32/Egairtigado!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:r8KSZl4vutQFwG56YOfWww)` |
| Sangfor | `Trojan.Win64.Agent.Vj51` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| TrellixENS | `Artemis!5B53D1EAEDCF` |
| Varist | `W64/Agent.NRC.gen!Eldorado` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **js** (39×)
- **elf** (33×)
- **Mirai** (24×)
- **Torii** (17×)
- **exe** (14×)
- **RemcosRAT** (11×)
- **RAT** (11×)
- **AgentTesla** (10×)
- **Formbook** (6×)
- **AsyncRAT** (6×)
- **Prometei** (5×)
- **MassLogger** (5×)
- **ps1** (3×)
- **hta** (3×)
- **XWorm** (3×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -15 (39→24)
- ↓ **unbekannt** -2 (16→14)
- neu: **AgentTesla** (11)
- ↑ **RemcosRAT** +10 (1→11)
- neu: **Formbook** (6)
- neu: **AsyncRAT** (6)
- ↓ **Prometei** -1 (6→5)
- neu: **MassLogger** (5)
- neu: **XWorm** (3)
- weg: **FantasyHub** (war 19)
- weg: **SilentNet** (war 2)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -14 (38→24)
- ↓ **unbekannt** -9 (23→14)
- ↑ **AgentTesla** +9 (2→11)
- ↑ **RemcosRAT** +8 (3→11)
- ↑ **Formbook** +4 (2→6)
- neu: **AsyncRAT** (6)
- ↑ **Prometei** +3 (2→5)
- neu: **MassLogger** (5)
- neu: **XWorm** (3)
- ↑ **CoinMiner** +1 (1→2)
- weg: **SalatStealer** (war 3)
- weg: **RevStealer** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.372 MB |
| σ Dateigröße | 5.642 MB |
| Ø Risiko-Score | 67.6/100 |
| Ø Klassifikations-Konfidenz | 72.9% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 50/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:23 | [478397a59db3…](https://bazaar.abuse.ch/sample/478397a59db3b36385a34008f1ce6f7129f5acea129b6e7997665351fed97010/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 12:08 | [52d07284941d…](https://bazaar.abuse.ch/sample/52d07284941d7ab76b5a08bd111664070a17d73824b09dd80b3870cfd76c0e83/) | `exe` | CoinMiner | 67.4 | – | – | 🇩🇪DE |
| 12:08 | [bb4f14d5cfa3…](https://bazaar.abuse.ch/sample/bb4f14d5cfa36ed89242b310eba3990d2b0cd772fc5afd86668f1fb831ffa5cf/) | `elf` | unbekannt | 67.4 | – | – | 🇩🇪DE |
| 11:57 | [1ba5b25dff36…](https://bazaar.abuse.ch/sample/1ba5b25dff3606a16533cc98375a34e020372e2df0a6a06461076e621066d90a/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 11:54 | [4dc5bb69063c…](https://bazaar.abuse.ch/sample/4dc5bb69063c633c6105ea7cee9ca46985db5aa0943d4276dc662f10f1135457/) | `sh` | Trojan | 77.4 | 28.4% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.11.2026 12:46 UTC*