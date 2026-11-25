# MalwareBazaar – 25.11.2026 11:09 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **77** |
| Höchster Score | **90.2/100** – 805e003e6a36e9b6… |
| Häufigste Familie | **FunStealer** (55x) |
| Häufigster Typ | **exe** (67x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 13 Samples |
| Ø Dateigröße | 4.11 MB (σ=2.29) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 67 | 66.3%  █████████████ |
| `elf` | 12 | 11.9%  ██ |
| `js` | 12 | 11.9%  ██ |
| `macho` | 4 | 4.0%   |
| `sh` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |
| `rtf` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |
| `jse` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | FunStealer | 55 | 54.5% |
| 2 | unbekannt | 30 | 29.7% |
| 3 | EasyShell | 6 | 5.9% |
| 4 | AsyncRAT | 5 | 5.0% |
| 5 | Vidar | 3 | 3.0% |
| 6 | RemcosRAT | 1 | 1.0% |
| 7 | ConnectWise | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 58 | 57.4% | 76% |
| RAT | 21 | 20.8% | 81% |
| Skript/Dropper | 9 | 8.9% | 35% |
| Windows-Malware | 7 | 6.9% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Maldoc | 1 | 1.0% | 35% |
| Linux-Malware | 1 | 1.0% | 45% |
| Loader | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 77 | 76.2% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 18 | 17.8% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [805e003e6a36e9…](https://bazaar.abuse.ch/sample/805e003e6a36e9b69c5c3baddbe0802a5239b176f379468d62c265b9ef060225/) | Vidar | Infostealer | **90.2** | 🔴 KRITISCH | – | – | ? |
| [435790cafcca06…](https://bazaar.abuse.ch/sample/435790cafcca0650bbb6aede7f22d4ab7c4eda9d8b9f6e7822c6a8b847c1aa35/) | Vidar | Infostealer | **90.2** | 🔴 KRITISCH | – | – | ? |
| [adce8b1fda13f0…](https://bazaar.abuse.ch/sample/adce8b1fda13f0fe7eda44c34de975099770510a71b97e3d878fc20a1b92cd7a/) | Vidar | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [5a5d815ea66097…](https://bazaar.abuse.ch/sample/5a5d815ea66097c21e8999684cb3dea7fe76caf66117e7aa1589920610c16213/) | AsyncRAT | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [0cbd00c52e5879…](https://bazaar.abuse.ch/sample/0cbd00c52e5879b0a3676750551bb1bc9327169da6aade85e57a35379e0588d5/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [85dda08e033c2f…](https://bazaar.abuse.ch/sample/85dda08e033c2f982d2bf12f6d70db27bb61b9190185a2316bb9d8bcd5be8af1/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [1a76929d51ebdf…](https://bazaar.abuse.ch/sample/1a76929d51ebdfaa103fa0f169d38759b8d5d9daf9a8a0474c64076c2606bd37/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [38b9e2f19508a8…](https://bazaar.abuse.ch/sample/38b9e2f19508a8114fa413c153dd3820af5312fbb0b56dee148902c3d4f78a7f/) | AsyncRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [5afa7a7a91b7af…](https://bazaar.abuse.ch/sample/5afa7a7a91b7afa7360a903198bb77dd94d0250d8ddec1791aad7ab8847b1f59/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [9b29d4e4a53951…](https://bazaar.abuse.ch/sample/9b29d4e4a539515b952f7c871a1704880fb26ff84851281ef711b79eeac0f435/) | unbekannt | RAT | **81.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6603/8133 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6603/8133 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6300/8133 |
| 6 | Kaspersky | 75.6% | 6147/8132 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5795/8129 |
| 9 | Rising | 68.6% | 5581/8133 |
| 10 | Varist | 66.1% | 5373/8128 |
| 11 | Tencent | 65.2% | 5158/7907 |
| 12 | Avast | 65.2% | 5302/8129 |
| 13 | AVG | 65.2% | 5302/8128 |
| 14 | McAfeeD | 61.4% | 4990/8125 |
| 15 | huorong | 61.0% | 4957/8125 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 68 | 67.3% |
| 🐧 Linux | 18 | 17.8% |
| ❓ Unbekannt | 14 | 13.9% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 87 | 86.1% |
| Drive-By / Exploit-Kit | 13 | 12.9% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇭🇺 HU | 42 | 41.6% |
| 2 | 🇫🇷 FR | 22 | 21.8% |
| 3 | 🇺🇸 US | 14 | 13.9% |
| 4 | 🇦🇹 AT | 10 | 9.9% |
| 5 | 🇨🇭 CH | 8 | 7.9% |
| 6 | 🇩🇪 DE | 2 | 2.0% |
| 7 | 🇳🇱 NL | 1 | 1.0% |
| 8 | 🌐 PH | 1 | 1.0% |
| 9 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 13 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 8 |
| Credential Access | 7 |
| Exfiltration | 7 |
| Command and Control | 6 |
| Execution | 5 |

<details><summary>805e003e6a36e9b69c5c… – Vidar | 🔴 KRITISCH 90.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>435790cafcca0650bbb6… – Vidar | 🔴 KRITISCH 90.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>adce8b1fda13f0fe7eda… – Vidar | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>5a5d815ea66097c21e89… – AsyncRAT | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>0cbd00c52e5879b0a367… – AsyncRAT | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ef1b9808546ef3b4f81b…](https://bazaar.abuse.ch/sample/ef1b9808546ef3b4f81b798fba35b844f96349ccb17aff61dc8a4153c939dfb6/)

- **Familie:** FunStealer
- **Erkannt von:** 32 von 74 Engines (43.2%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKDZ.121498
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKDZ.121498`

**Erkennende Engines (32/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKDZ.121498` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R800021` |
| Arcabit | `Trojan.Generic.D1DA9A` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKDZ.121498` |
| Bkav | `W32.Malware.44C4927F` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.GZH trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKDZ.121498 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Trojan.GenericKDZ.121498` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kaspersky | `VHO:Trojan.Win32.Inject.gen` |
| Malwarebytes | `Malware.AI.1987645936` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| MicroWorld-eScan | `Trojan.GenericKDZ.121498` |
| Rising | `Trojan.Kryptik@AI.92 (RDML:v7hKa0roEq1ddaochmd1gA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006303` |
| VIPRE | `Trojan.GenericKDZ.121498` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [5ddf84a0f11284fbe81e…](https://bazaar.abuse.ch/sample/5ddf84a0f11284fbe81edaca229adbc3d0f7777e391266d33ab35a5923ca358d/)

- **Familie:** FunStealer
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R799187` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| Bkav | `W32.Malware.4049A90D` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.HHS trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| McAfeeD | `Trojan:Win/Malwarex.EMO` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:yQ61ZC5bKRE8a0K7tHgVEg)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |

### [4fad25514dafd741f43f…](https://bazaar.abuse.ch/sample/4fad25514dafd741f43f4aac0d29b8955e2dd15aeb78d5e4b4f42b80882220c8/)

- **Familie:** FunStealer
- **Erkannt von:** 33 von 74 Engines (44.6%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.3044
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.3044`

**Erkennende Engines (33/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.3044` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R799187` |
| Arcabit | `Trojan.Stealer.DBE4` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.Stealer.3044` |
| Bkav | `W32.Malware.B0124D84` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.51953` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Stealer.3044 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Trojan.Stealer.3044` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Malwarebytes | `Malware.Heuristic.2108` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| MicroWorld-eScan | `Trojan.Stealer.3044` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:UDROfTIgZrxDiu+JeXMCGw)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006303` |
| VIPRE | `Trojan.Stealer.3044` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `W32.Trojan.Gen` |

### [c6194b69e649fd4e0ec9…](https://bazaar.abuse.ch/sample/c6194b69e649fd4e0ec9c503e9433aba63d858bc9285d732f384b4b3396ca4cb/)

- **Familie:** FunStealer
- **Erkannt von:** 35 von 74 Engines (47.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Stealer.2126
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Stealer.2126`

**Erkennende Engines (35/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Stealer.2126` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R807085` |
| Arcabit | `Trojan.Stealer.D84E` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Stealer.2126` |
| Bkav | `W32.Malware.37237B78` |
| CTX | `exe.spyware.generic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Packed2.52029` |
| ESET-NOD32 | `Win64/GenKryptik.HVMO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Stealer.2126 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVMO!tr` |
| GData | `Gen:Variant.Stealer.2126` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kingsoft | `malware.kb.a.752` |
| Malwarebytes | `Malware.AI.1987645936` |
| MaxSecure | `Trojan.W32.051126.Lazy.742399.YR` |
| McAfeeD | `Trojan:Win/Packed2.EBB` |
| MicroWorld-eScan | `Gen:Variant.Stealer.2126` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:BWtNgVdFBzyOfGvhiEDNiQ)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Agent.16006302` |
| VIPRE | `Gen:Variant.Stealer.2126` |
| Varist | `W64/Agent.NNG.gen!Eldorado` |
| Webroot | `W32.Trojan.Gen` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **exe** (66×)
- **FunStealer** (55×)
- **RAT** (16×)
- **EasyShell** (15×)
- **Rust** (15×)
- **SnoopyTriage** (15×)
- **elf** (12×)
- **js** (12×)
- **Vidar** (7×)
- **AsyncRAT** (5×)
- **macho** (4×)
- **sh** (2×)
- **hta** (1×)
- **wraith** (1×)
- **CVE-2017-11882** (1×)

## Änderungen – 24h-Vergleich

- neu: **FunStealer** (55)
- ↓ **unbekannt** -1 (31→30)
- ↓ **EasyShell** -4 (10→6)
- neu: **AsyncRAT** (5)
- neu: **Vidar** (3)
- ↓ **RemcosRAT** -4 (5→1)
- ↓ **ConnectWise** -2 (3→1)
- weg: **CatStorm** (war 6)
- weg: **Formbook** (war 4)
- weg: **Mirai** (war 14)
- weg: **BotenaGo** (war 3)
- weg: **WARDENStealer** (war 2)
- weg: **Prometei** (war 4)
- weg: **Snowlight** (war 10)

## Änderungen – 7d-Vergleich

- neu: **FunStealer** (55)
- ↓ **unbekannt** -6 (36→30)
- ↑ **EasyShell** +2 (4→6)
- ↑ **AsyncRAT** +4 (1→5)
- neu: **Vidar** (3)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Mirai** (war 29)
- weg: **Prometei** (war 5)
- weg: **WARDENStealer** (war 4)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 4)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.106 MB |
| σ Dateigröße | 2.293 MB |
| Ø Risiko-Score | 72.7/100 |
| Ø Klassifikations-Konfidenz | 68.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 13/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 23 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:07 | [6fe7a4eca94d…](https://bazaar.abuse.ch/sample/6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23/) | `exe` | unbekannt | 39.1 | – | – | 🇫🇷FR |
| 11:07 | [127326678d64…](https://bazaar.abuse.ch/sample/127326678d64e698d2c898687a63c4eabda92cc6f22c24a5ca100535cc468ca0/) | `exe` | unbekannt | 39.1 | – | – | 🇫🇷FR |
| 11:07 | [7df8d1db3393…](https://bazaar.abuse.ch/sample/7df8d1db33935c32a2a5cee3d8b895f53801fb08bbda38b38363967a48f76a81/) | `exe` | unbekannt | 39.1 | – | – | 🇫🇷FR |
| 11:07 | [9b29d4e4a539…](https://bazaar.abuse.ch/sample/9b29d4e4a539515b952f7c871a1704880fb26ff84851281ef711b79eeac0f435/) | `elf` | unbekannt | 81.3 | – | – | 🇺🇸US |
| 11:07 | [d444fca48487…](https://bazaar.abuse.ch/sample/d444fca4848759044c7cfdeaaa366599679ba5242437111467c33e4ba2e6c2e7/) | `elf` | unbekannt | 81.3 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.11.2026 11:09 UTC*