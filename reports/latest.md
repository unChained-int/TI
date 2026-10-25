# MalwareBazaar – 25.10.2026 00:05 UTC

Dieser Run hat **16 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **17** |
| Kritisch (≥75) | **9** |
| Höchster Score | **95.5/100** – 3cad72ca97f43944… |
| Häufigste Familie | **Mirai** (7x) |
| Häufigster Typ | **elf** (6x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 8 Samples |
| Ø Dateigröße | 5.52 MB (σ=7.20) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 6 | 35.3%  ███████ |
| `exe` | 4 | 23.5%  ████ |
| `iso` | 3 | 17.6%  ███ |
| `macho` | 2 | 11.8%  ██ |
| `zsh` | 1 | 5.9%  █ |
| `apk` | 1 | 5.9%  █ |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 7 | 41.2% |
| 2 | unbekannt | 7 | 41.2% |
| 3 | Amadey | 1 | 5.9% |
| 4 | WannaCry | 1 | 5.9% |
| 5 | PythonStealer | 1 | 5.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 7 | 41.2% | 95% |
| Andere / Unbekannt | 5 | 29.4% | 20% |
| Loader | 2 | 11.8% | 85% |
| Windows-Malware | 1 | 5.9% | 35% |
| Ransomware | 1 | 5.9% | 95% |
| Trojaner | 1 | 5.9% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 9 | 52.9% |
| 🟠 HOCH | 2 | 11.8% |
| 🟡 MITTEL | 1 | 5.9% |
| 🟢 NIEDRIG | 5 | 29.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3cad72ca97f439…](https://bazaar.abuse.ch/sample/3cad72ca97f4394491d63bbcb0c33f79c3871e4b58f2913a7270520a2b6da162/) | WannaCry | Ransomware | **95.5** | 🔴 KRITISCH | – | – | ? |
| [31b246282c688a…](https://bazaar.abuse.ch/sample/31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293/) | Mirai | Botnet/IoT | **86.6** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [6fe3779ca5f37d…](https://bazaar.abuse.ch/sample/6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1/) | Mirai | Botnet/IoT | **86.3** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [5b6458c024a033…](https://bazaar.abuse.ch/sample/5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5/) | Mirai | Botnet/IoT | **84.7** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [c41923f219244f…](https://bazaar.abuse.ch/sample/c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [f791769f0d47f5…](https://bazaar.abuse.ch/sample/f791769f0d47f571f10468938866750301b228422b623307d623f06af81fca5f/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [6e136391f87bea…](https://bazaar.abuse.ch/sample/6e136391f87beac4ae152e4f3f24ad61fb7b06df0fdb39d0005660ea1c5ea55e/) | Mirai | Botnet/IoT | **82.2** | 🔴 KRITISCH | – | – | ? |
| [04ef642ea5f51c…](https://bazaar.abuse.ch/sample/04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94/) | Amadey | Loader | **82.1** | 🔴 KRITISCH | – | – | ? |
| [d42fede1058f62…](https://bazaar.abuse.ch/sample/d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6/) | Mirai | Botnet/IoT | **76.7** | 🔴 KRITISCH | 37.3% | 🟡 SCHWACH ERKANNT | ✓ |
| [7fdb4ed5896bbf…](https://bazaar.abuse.ch/sample/7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc/) | unbekannt | Loader | **74.6** | 🟠 HOCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6167/7615 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6167/7615 |
| 3 | ESET-NOD32 | 77.2% | 5876/7615 |
| 4 | Kaspersky | 75.9% | 5778/7614 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5409/7612 |
| 8 | Rising | 68.3% | 5199/7615 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5036/7611 |
| 11 | Avast | 65.1% | 4953/7611 |
| 12 | AVG | 65.1% | 4953/7610 |
| 13 | Tencent | 64.8% | 4789/7389 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4657/7608 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 7 | 41.2% |
| 🪟 Windows | 4 | 23.5% |
| 📦 Archiv | 3 | 17.6% |
| 🍎 macOS | 2 | 11.8% |
| 🤖 Android | 1 | 5.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 14 | 82.4% |
| MaaS-Loader | 2 | 11.8% |
| Exploit / N-Day | 1 | 5.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 4 | 23.5% |
| 2 | 🇺🇸 US | 4 | 23.5% |
| 3 | 🇭🇺 HU | 3 | 17.6% |
| 4 | 🇨🇭 CH | 2 | 11.8% |
| 5 | 🇨🇦 CA | 1 | 5.9% |
| 6 | 🇳🇱 NL | 1 | 5.9% |
| 7 | 🇪🇸 ES | 1 | 5.9% |
| 8 | 🌐 Unbekannt | 1 | 5.9% |

## MITRE ATT&CK

> 8 von 17 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 7 |
| Lateral Movement | 7 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>31b246282c688ab94e88… – Mirai | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>6fe3779ca5f37dde4f68… – Mirai | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5b6458c024a0333edf77… – Mirai | 🔴 KRITISCH 84.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c41923f219244fb0b288… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [6fe3779ca5f37dde4f68…](https://bazaar.abuse.ch/sample/6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Ikarus | `PUA.Linux.Obfuscated` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.Flooder.ac` |

### [31b246282c688ab94e88…](https://bazaar.abuse.ch/sample/31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293/)

- **Familie:** Mirai
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Ikarus | `PUA.Linux.Obfuscated` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| huorong | `Trojan/Linux.Flooder.ac` |

### [5b6458c024a0333edf77…](https://bazaar.abuse.ch/sample/5b6458c024a0333edf779148aa23e3072fb1508103001f4dd6477f5805e262f5/)

- **Familie:** Mirai
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| DrWeb | `Linux.Siggen.15842` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| huorong | `Trojan/Linux.Flooder.ac` |

### [d42fede1058f62ba45ce…](https://bazaar.abuse.ch/sample/d42fede1058f62ba45ce9eff1923d644fd2cc1ab6ac1994abc58bd1fd6c666e6/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Application.Generic.37111556
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37111556`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D2364704` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37111556` |
| CTX | `elf.unknown.generic` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37111556 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37111556` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37111556` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37111315` |
| huorong | `Trojan/Prometei.c` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (6×)
- **Mirai** (6×)
- **AMOS** (3×)
- **ClickFix** (3×)
- **Foxveil** (3×)
- **macOS** (3×)
- **exe** (3×)
- **cyuop-com** (3×)
- **iso** (3×)
- **honeypot** (2×)
- **trojan.flooder** (2×)
- **Mach-O** (2×)
- **macho** (2×)
- **Prometei** (2×)
- **dropper** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -10 (17→7)
- ↓ **unbekannt** -12 (19→7)
- neu: **Amadey** (1)
- neu: **WannaCry** (1)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -13 (20→7)
- ↓ **unbekannt** -30 (37→7)
- neu: **Amadey** (1)
- neu: **WannaCry** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.515 MB |
| σ Dateigröße | 7.198 MB |
| Ø Risiko-Score | 64.4/100 |
| Ø Klassifikations-Konfidenz | 66.5% |
| Samples mit VT | 5/17 |
| Samples mit MITRE | 8/17 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 26 |
| Unbekannte Familien | 5 (29.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:02 | [6fe3779ca5f3…](https://bazaar.abuse.ch/sample/6fe3779ca5f37dde4f680dbb7fe5ae87af32a6b463d059ba89fa8426963772e1/) | `elf` | Mirai | 86.3 | 9.3% | ⚠️ KAUM ERKANNT | 🌐CH |
| 00:02 | [31b246282c68…](https://bazaar.abuse.ch/sample/31b246282c688ab94e88110ae7b7078d515a6721c14e411b82b8b83eda91f293/) | `elf` | Mirai | 86.6 | 8.0% | ⚠️ KAUM ERKANNT | 🌐CH |
| 23:53 | [c41923f21924…](https://bazaar.abuse.ch/sample/c41923f219244fb0b28882e01c540c35706f19966b5fc070adf8be235b8be008/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 23:32 | [7fdb4ed5896b…](https://bazaar.abuse.ch/sample/7fdb4ed5896bbfd34f05a2aa00aa05b480df97673304f2b2f84122e65e387cbc/) | `zsh` | unbekannt | 74.6 | – | – | 🇺🇸US |
| 23:25 | [e59471dbb08a…](https://bazaar.abuse.ch/sample/e59471dbb08a04c5ec6df736f149919cc5333ef19da2b2de298d4f429d0c3612/) | `macho` | unbekannt | 32.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 00:05 UTC*