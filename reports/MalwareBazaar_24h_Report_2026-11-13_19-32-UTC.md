# MalwareBazaar – 13.11.2026 19:32 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **64** |
| Höchster Score | **86.9/100** – e84819b199e292ce… |
| Häufigste Familie | **Mirai** (25x) |
| Häufigster Typ | **elf** (29x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 43 Samples |
| Ø Dateigröße | 4.56 MB (σ=15.91) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 29 | 28.7%  █████ |
| `exe` | 25 | 24.8%  ████ |
| `js` | 12 | 11.9%  ██ |
| `ps1` | 10 | 9.9%  █ |
| `jar` | 4 | 4.0%   |
| `sh` | 4 | 4.0%   |
| `vbe` | 3 | 3.0%   |
| `rtf` | 2 | 2.0%   |
| `7z` | 2 | 2.0%   |
| `doc` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 25 | 24.8% |
| 2 | unbekannt | 21 | 20.8% |
| 3 | Formbook | 7 | 6.9% |
| 4 | RemcosRAT | 6 | 5.9% |
| 5 | SilentNet | 4 | 4.0% |
| 6 | AgentTesla | 4 | 4.0% |
| 7 | RevStealer | 4 | 4.0% |
| 8 | MioLabStealer | 3 | 3.0% |
| 9 | XWorm | 3 | 3.0% |
| 10 | Prometei | 2 | 2.0% |
| 11 | AsyncRAT | 2 | 2.0% |
| 12 | MassLogger | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 24.8% | 95% |
| Infostealer | 18 | 17.8% | 83% |
| RAT | 16 | 15.8% | 91% |
| Windows-Malware | 9 | 8.9% | 35% |
| Skript/Dropper | 8 | 7.9% | 35% |
| Andere / Unbekannt | 8 | 7.9% | 20% |
| Linux-Malware | 5 | 5.0% | 45% |
| Maldoc | 5 | 5.0% | 35% |
| Trojaner | 5 | 5.0% | 67% |
| Spyware | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 64 | 63.4% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 13 | 12.9% |
| 🟢 NIEDRIG | 22 | 21.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [e84819b199e292…](https://bazaar.abuse.ch/sample/e84819b199e292ceadd7baf8c759c6f7926140349acbb814f8111df558b98784/) | Formbook | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [e6cd4216e19455…](https://bazaar.abuse.ch/sample/e6cd4216e19455d8c25c2c9361d1f67f2e948656a979b72b11b603e32ee9c77b/) | Formbook | Infostealer | **86.4** | 🔴 KRITISCH | – | – | ? |
| [64f13e94a23454…](https://bazaar.abuse.ch/sample/64f13e94a2345436777eff5cae49d080c3f4c68b6fc2bf2d1e00be5a7a17e07b/) | Formbook | Infostealer | **86.4** | 🔴 KRITISCH | – | – | ? |
| [ea161f24665532…](https://bazaar.abuse.ch/sample/ea161f246655324da6e7d4d1ee6593fe516767e86f3cbd9659194f42ce0f0340/) | Formbook | Infostealer | **86.3** | 🔴 KRITISCH | – | – | ? |
| [9d898208f82f69…](https://bazaar.abuse.ch/sample/9d898208f82f6960dd8cf93cbb5f7d7d1a3402dbd9fab8f3ddbafc80c7f4defa/) | Formbook | Infostealer | **86.0** | 🔴 KRITISCH | – | – | ? |
| [7e1b31fc47812a…](https://bazaar.abuse.ch/sample/7e1b31fc47812a2835a071da86c6ce1aa409ae46d1653256a99716053302b3f2/) | RemcosRAT | RAT | **85.9** | 🔴 KRITISCH | – | – | ? |
| [be7a01d6f7d7af…](https://bazaar.abuse.ch/sample/be7a01d6f7d7af9ebbb26badf21e29a3e64ed93051144cfae20bc31b52d9e8ff/) | QuasarRAT | RAT | **85.9** | 🔴 KRITISCH | – | – | ? |
| [24d3bfeb08afee…](https://bazaar.abuse.ch/sample/24d3bfeb08afeec2b4ded786913df0b30fc08aecabef0544d8f47f61883ae0b1/) | Formbook | Infostealer | **85.7** | 🔴 KRITISCH | – | – | ? |
| [1c0794f74cd052…](https://bazaar.abuse.ch/sample/1c0794f74cd0520dfa1580112d904fa39cb7ae062c10904743f7bd0422384a4a/) | Formbook | Infostealer | **85.7** | 🔴 KRITISCH | – | – | ? |
| [ebde4af5ea0630…](https://bazaar.abuse.ch/sample/ebde4af5ea0630a3f1bdb044c4d8f5aa29a8ed0060452de69756dd3227bf539b/) | AsyncRAT | RAT | **85.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6468/7970 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6468/7970 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6162/7970 |
| 6 | Kaspersky | 75.5% | 6016/7969 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5675/7966 |
| 9 | Rising | 68.4% | 5452/7970 |
| 10 | Varist | 66.1% | 5263/7965 |
| 11 | Avast | 65.2% | 5191/7966 |
| 12 | AVG | 65.2% | 5191/7965 |
| 13 | Tencent | 65.0% | 5032/7744 |
| 14 | McAfeeD | 61.4% | 4891/7962 |
| 15 | huorong | 60.9% | 4846/7962 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 39 | 38.6% |
| 🐧 Linux | 34 | 33.7% |
| ❓ Unbekannt | 19 | 18.8% |
| 📄 Dokument | 5 | 5.0% |
| 📦 Archiv | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 80 | 79.2% |
| Drive-By / Exploit-Kit | 13 | 12.9% |
| Phishing / E-Mail-Anhang | 5 | 5.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 30 | 29.7% |
| 2 | 🇸🇪 SE | 21 | 20.8% |
| 3 | 🇫🇷 FR | 13 | 12.9% |
| 4 | 🇺🇸 US | 11 | 10.9% |
| 5 | 🇭🇺 HU | 10 | 9.9% |
| 6 | 🇪🇸 ES | 4 | 4.0% |
| 7 | 🇧🇷 BR | 3 | 3.0% |
| 8 | 🇬🇧 GB | 3 | 3.0% |
| 9 | 🇦🇹 AT | 2 | 2.0% |
| 10 | 🌐 Unbekannt | 2 | 2.0% |
| 11 | 🌐 CO | 1 | 1.0% |
| 12 | 🇳🇱 NL | 1 | 1.0% |

## MITRE ATT&CK

> 43 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 14 |
| Command and Control | 10 |
| Credential Access | 7 |
| Execution | 3 |
| Exfiltration | 1 |
| Defense Evasion | 1 |

<details><summary>e84819b199e292ceadd7… – Formbook | 🔴 KRITISCH 86.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e6cd4216e19455d8c25c… – Formbook | 🔴 KRITISCH 86.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>64f13e94a2345436777e… – Formbook | 🔴 KRITISCH 86.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ea161f246655324da6e7… – Formbook | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>9d898208f82f6960dd8c… – Formbook | 🔴 KRITISCH 86.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [58a039a2630fe950cbfe…](https://bazaar.abuse.ch/sample/58a039a2630fe950cbfe502d75b22faa40723181d43456b602d856cf8abe6df1/)

- **Familie:** Gen
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Gen.MBT
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DownLoader.3032` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.ASX trojan` |
| GData | `Script.Trojan.Agent.K333OY` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.bc` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win32.Trojan-Downloader.Agent.Ywhl` |
| Varist | `Unix/Agent.ADQ` |
| alibabacloud | `Trojan[downloader]:Linux/Agent.bz` |
| huorong | `TrojanDownloader/Linux.Shell.d` |

### [4c175903945ee687f7a4…](https://bazaar.abuse.ch/sample/4c175903945ee687f7a41935371b6706b8c77dba83ad4ec7a42cbb9ed242ccd3/)

- **Familie:** C!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.C!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [53e861fb4f75677bbc63…](https://bazaar.abuse.ch/sample/53e861fb4f75677bbc63fedd4d2d578dd7281d9891be27faf81ba3cbca0d0ce2/)

- **Familie:** Artemis!Trojan
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Artemis!Trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Skyhigh | `Artemis!Trojan` |
| TrellixENS | `Artemis!FCC2527D0AE4` |
| VirIT | `Trojan.Win32.Genus.ZFM` |
| Webroot | `Win.Hacktool.Remcos` |

### [936f004ac96157828121…](https://bazaar.abuse.ch/sample/936f004ac961578281212bcbc8a2b86174cdfc9ef9ff5130a37339f08bc95fc5/)

- **Familie:** a310Logger
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Avast | `MalwareX-gen [Drp]` |
| Bkav | `W32.Malware.741DBCD7` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Kryptik.ARDK trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Agent` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Trojan:Win/GenericPack.BMP` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Kryptik!8.8 (CLOUD)` |
| Sangfor | `Virus.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `Artemis!Trojan` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Sonbokli!ATN` |
| Tencent | `Msil.Trojan.Kryptik.Dkjl` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!5230CDF8A8C3` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| Varist | `W32/MSIL_Kryptik.MUC.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Software:MSIL/Sonbokli.A9uj` |

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

- **elf** (29×)
- **Mirai** (25×)
- **exe** (24×)
- **js** (12×)
- **ps1** (10×)
- **Prometei** (10×)
- **Formbook** (7×)
- **signed** (5×)
- **honeypot** (5×)
- **RemcosRAT** (5×)
- **RAT** (5×)
- **jar** (4×)
- **sh** (4×)
- **Torii** (4×)
- **RevStealer** (4×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -8 (33→25)
- ↓ **unbekannt** -9 (30→21)
- ↑ **Formbook** +6 (1→7)
- ↑ **RemcosRAT** +5 (1→6)
- ↑ **SilentNet** +3 (1→4)
- ↑ **AgentTesla** +2 (2→4)
- ↑ **RevStealer** +1 (3→4)
- neu: **MioLabStealer** (3)
- neu: **XWorm** (3)
- neu: **Prometei** (2)
- weg: **SalatStealer** (war 3)
- weg: **WARDENStealer** (war 10)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -5 (30→25)
- ↓ **unbekannt** -4 (25→21)
- ↑ **Formbook** +6 (1→7)
- ↑ **RemcosRAT** +4 (2→6)
- ↑ **SilentNet** +3 (1→4)
- ↑ **AgentTesla** +2 (2→4)
- ↑ **RevStealer** +3 (1→4)
- neu: **MioLabStealer** (3)
- neu: **XWorm** (3)
- neu: **Prometei** (2)
- weg: **WARDENStealer** (war 4)
- weg: **Snowlight** (war 3)
- weg: **SalatStealer** (war 6)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.559 MB |
| σ Dateigröße | 15.908 MB |
| Ø Risiko-Score | 64.9/100 |
| Ø Klassifikations-Konfidenz | 69.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 43/101 |
| Eindeutige Familien | 27 |
| Eindeutige Tags | 75 |
| Unbekannte Familien | 8 (7.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:11 | [67196366b80b…](https://bazaar.abuse.ch/sample/67196366b80be16edfd1ce95a9781aaa6dd51a1c07bef7e00d2981f9b0c7e237/) | `ps1` | unbekannt | 38.8 | – | – | 🇺🇸US |
| 18:43 | [70f974075557…](https://bazaar.abuse.ch/sample/70f9740755573ba536c301f344bdc9b9cb89d5757006e2e8771fcc164d4aaf31/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 18:16 | [4004dfdbbc26…](https://bazaar.abuse.ch/sample/4004dfdbbc266351c921fb36a948a03e82c5fd44f70392ce08168869d9814d0c/) | `elf` | Prometei | 42.2 | – | – | 🇺🇸US |
| 17:39 | [981c31461478…](https://bazaar.abuse.ch/sample/981c3146147861b5bcee71606e6f84129a33d0ad428150d74d489e672d408bad/) | `elf` | Mirai | 82.9 | – | – | 🇩🇪DE |
| 17:38 | [410f7dbad89c…](https://bazaar.abuse.ch/sample/410f7dbad89cfb54d04e63c455a4c8d9f7adf7a16f35dcd1f16b2854471d5b13/) | `elf` | Mirai | 82.9 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.11.2026 19:32 UTC*