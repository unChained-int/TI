# MalwareBazaar – 06.11.2026 11:55 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **54** |
| Höchster Score | **90.1/100** – 52cd3a921f7ffc39… |
| Häufigste Familie | **unbekannt** (42x) |
| Häufigster Typ | **exe** (50x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 22 Samples |
| Ø Dateigröße | 5.64 MB (σ=17.11) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 50 | 49.5%  █████████ |
| `js` | 26 | 25.7%  █████ |
| `vbs` | 6 | 5.9%  █ |
| `elf` | 5 | 5.0%   |
| `hta` | 2 | 2.0%   |
| `zip` | 2 | 2.0%   |
| `vbe` | 2 | 2.0%   |
| `lnk` | 2 | 2.0%   |
| `dll` | 2 | 2.0%   |
| `ps1` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 42 | 41.6% |
| 2 | FunStealer | 14 | 13.9% |
| 3 | RemcosRAT | 9 | 8.9% |
| 4 | XWorm | 6 | 5.9% |
| 5 | Formbook | 4 | 4.0% |
| 6 | AgentTesla | 4 | 4.0% |
| 7 | AsyncRAT | 4 | 4.0% |
| 8 | VIPKeylogger | 2 | 2.0% |
| 9 | RemusStealer | 2 | 2.0% |
| 10 | Mirai | 2 | 2.0% |
| 11 | WARDENStealer | 2 | 2.0% |
| 12 | PureLogsStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 25 | 24.8% | 92% |
| Windows-Malware | 23 | 22.8% | 35% |
| Infostealer | 23 | 22.8% | 78% |
| Skript/Dropper | 14 | 13.9% | 35% |
| Linux-Malware | 3 | 3.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Trojaner | 2 | 2.0% | 65% |
| Spyware | 2 | 2.0% | 75% |
| Maldoc | 2 | 2.0% | 35% |
| Botnet/IoT | 2 | 2.0% | 95% |
| Loader | 2 | 2.0% | 80% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 54 | 53.5% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 42 | 41.6% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [52cd3a921f7ffc…](https://bazaar.abuse.ch/sample/52cd3a921f7ffc39a78eb2b32e5181f3a132ee7be360740dd49e395ed4080587/) | Formbook | Infostealer | **90.1** | 🔴 KRITISCH | – | – | ? |
| [f9840f81e13d61…](https://bazaar.abuse.ch/sample/f9840f81e13d61483c745b2540775bb8db9e68914b76c71666f5848790b7cdb0/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [78aefb94804409…](https://bazaar.abuse.ch/sample/78aefb94804409a469b2f2c5bfc292bff8563fb84b15a872f4925ec28dfe8400/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [4231704bcfe9db…](https://bazaar.abuse.ch/sample/4231704bcfe9dbaff1e4281e672b804bd9548dd9d765c7a49d6fefdf65fc4f34/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [d513ea26f521b4…](https://bazaar.abuse.ch/sample/d513ea26f521b4fc8db05f6d3b90b9a29aa8402c17660fc5291022c966df8444/) | njrat | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [43de6af8cdd13f…](https://bazaar.abuse.ch/sample/43de6af8cdd13f4e8106f4b21c8b9d8a3a84092b93b1b47faa031db86e2dac2b/) | XWorm | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [5e0181dc8356c0…](https://bazaar.abuse.ch/sample/5e0181dc8356c0e529dfec12d2a3645728811d606f240b238804200f0c4ef6dc/) | XWorm | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [d460dc01fdbe4b…](https://bazaar.abuse.ch/sample/d460dc01fdbe4b72019623cbe1e85577f6d37edcd13e8d8cf94c266b9e4a325c/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [f271f6a93cffcc…](https://bazaar.abuse.ch/sample/f271f6a93cffcce36b67a4c0027e249e4c0b70300f9ac7992f7e6594c8c9362d/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |
| [e9b2ecd6bdc0d9…](https://bazaar.abuse.ch/sample/e9b2ecd6bdc0d9648c8dacab13bd852872f969e251c7ec8eb9be8ab0256388a3/) | RemcosRAT | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6357/7847 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6357/7847 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6062/7847 |
| 6 | Kaspersky | 75.5% | 5921/7846 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5585/7843 |
| 9 | Rising | 68.3% | 5359/7847 |
| 10 | Varist | 66.2% | 5191/7842 |
| 11 | Avast | 65.1% | 5104/7843 |
| 12 | AVG | 65.1% | 5104/7842 |
| 13 | Tencent | 64.9% | 4946/7621 |
| 14 | McAfeeD | 61.4% | 4814/7839 |
| 15 | huorong | 60.8% | 4769/7839 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 63 | 62.4% |
| ❓ Unbekannt | 27 | 26.7% |
| 🐧 Linux | 7 | 6.9% |
| 🤖 Android | 2 | 2.0% |
| 📄 Dokument | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 70 | 69.3% |
| Drive-By / Exploit-Kit | 27 | 26.7% |
| USB / Wechselmedium | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 39 | 38.6% |
| 2 | 🇫🇷 FR | 33 | 32.7% |
| 3 | 🇭🇺 HU | 17 | 16.8% |
| 4 | 🇩🇪 DE | 7 | 6.9% |
| 5 | 🇺🇸 US | 4 | 4.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 22 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Command and Control | 15 |
| Collection | 14 |
| Execution | 6 |
| Credential Access | 4 |
| Initial Access | 2 |
| Lateral Movement | 2 |
| Defense Evasion | 1 |

<details><summary>52cd3a921f7ffc39a78e… – Formbook | 🔴 KRITISCH 90.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>f9840f81e13d61483c74… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>78aefb94804409a469b2… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4231704bcfe9dbaff1e4… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>d513ea26f521b4fc8db0… – njrat | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f82d6c9ccc0c3537f8d3…](https://bazaar.abuse.ch/sample/f82d6c9ccc0c3537f8d38238e06329b8b6f04e73dc88e42f9d734529a6503a13/)

- **Familie:** Trojan.GenericKD.81961752
- **Erkannt von:** 37 von 75 Engines (49.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81961752
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81961752`

**Erkennende Engines (37/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81961752` |
| AVG | `Win64:Malware-gen` |
| Alibaba | `Trojan:Win32/Staser.28349992` |
| Arcabit | `Trojan.Generic.D4E2A318` |
| Avast | `Win64:Malware-gen` |
| Avira | `TR/W64.Malware` |
| BitDefender 🛡️ | `Trojan.GenericKD.81961752` |
| Bkav | `W32.Malware.F2662D5A` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.MulDrop43.20998` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81961752 (B)` |
| F-Secure | `Trojan.TR/W64.Malware` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Trojan.GenericKD.81961752` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Agent` |
| Kaspersky | `Trojan.Win32.Staser.fgeq` |
| MaxSecure | `Trojan.Malware.698979280.susgen` |
| McAfeeD | `ti!F82D6C9CCC0C` |
| MicroWorld-eScan | `Trojan.GenericKD.81961752` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win64.Staser.lktpbk` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Staser!8.7FD (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!2665DD244DC4` |
| TrendMicro | `Trojan.Win32.POSSIBLETHREAT.USBLJV26` |
| TrendMicro-HouseCall | `Trojan.Win32.POSSIBLETHREAT.USBLJV26` |
| VIPRE | `Trojan.GenericKD.81961752` |
| Varist | `W64/ABTrojan.ZZVX-5712` |
| ViRobot | `Trojan.Win.Z.Agent.7730372` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |

### [417d69cdb077786cc2c0…](https://bazaar.abuse.ch/sample/417d69cdb077786cc2c0322873657a689640e838254caacfcca3c31bc184b981/)

- **Familie:** Trojan.Generic.40732892
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Generic.40732892
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Wacatac.B!ml`

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40732892` |
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| Arcabit | `Trojan.Generic.D26D88DC` |
| Avast | `FileRepMalware [Misc]` |
| CTX | `exe.trojan.generic` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win32/TrojanDropper.Agent.TGK trojan` |
| Emsisoft | `Trojan.Generic.40732892 (B)` |
| Fortinet | `Malicious_Behavior.SB` |
| GData | `Trojan.Generic.40732892` |
| K7AntiVirus | `Trojan ( 006ea2981 )` |
| K7GW | `Trojan ( 006ea2981 )` |
| Kaspersky | `Trojan.Win64.Agent.smhwqa` |
| McAfeeD | `ti!417D69CDB077` |
| MicroWorld-eScan | `Trojan.Generic.40732892` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Dropper.Agent!8.2F (CLOUD)` |
| Tencent | `Malware.Win32.Gencirc.14ba9027` |
| VIPRE | `Trojan.Generic.40732892` |
| huorong | `Trojan/FakeApp.aqd` |

### [1da2d3c8caa8ed7d7260…](https://bazaar.abuse.ch/sample/1da2d3c8caa8ed7d7260494e2314c8671a9e6a689d87dd6338966baa6286eb66/)

- **Familie:** Malware
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.9D2B0117
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.9D2B0117` |
| McAfeeD | `ti!1DA2D3C8CAA8` |
| Zillya | `Dropper.Agent.Win32.746397` |

### [cf62388164be89edc469…](https://bazaar.abuse.ch/sample/cf62388164be89edc469cd5d1633b52ac622e092806038fde8812852d7c35e65/)

- **Familie:** WARDENStealer
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.F61F9B0A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Wacatac.B!ml`

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Bkav | `W32.Malware.F61F9B0A` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/MALD2.KHQY!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.100 (RDML:SfkwTRqpT9Cj4nan+MdzKw)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| huorong | `Trojan/W64.Injector.y!crit` |

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

- **exe** (49×)
- **js** (26×)
- **FunStealer** (14×)
- **RemcosRAT** (9×)
- **RAT** (8×)
- **vbs** (6×)
- **XWorm** (6×)
- **elf** (5×)
- **AsyncRAT** (5×)
- **signed** (4×)
- **Formbook** (4×)
- **AgentTesla** (4×)
- **hta** (2×)
- **144.31.215.158** (2×)
- **dotnet** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -14 (56→42)
- neu: **FunStealer** (14)
- ↑ **RemcosRAT** +4 (5→9)
- ↑ **XWorm** +4 (2→6)
- ↑ **Formbook** +1 (3→4)
- ↓ **AgentTesla** -4 (8→4)
- ↑ **AsyncRAT** +3 (1→4)
- neu: **VIPKeylogger** (2)
- neu: **RemusStealer** (2)
- ↓ **Mirai** -3 (5→2)
- weg: **VShell** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +8 (34→42)
- neu: **FunStealer** (14)
- ↑ **RemcosRAT** +7 (2→9)
- ↑ **XWorm** +5 (1→6)
- ↑ **Formbook** +1 (3→4)
- ↑ **AgentTesla** +1 (3→4)
- ↑ **AsyncRAT** +3 (1→4)
- neu: **VIPKeylogger** (2)
- neu: **RemusStealer** (2)
- ↓ **Mirai** -17 (19→2)
- weg: **SalatStealer** (war 6)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.638 MB |
| σ Dateigröße | 17.108 MB |
| Ø Risiko-Score | 63.0/100 |
| Ø Klassifikations-Konfidenz | 62.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 22/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 42 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:53 | [3a71c073d8a0…](https://bazaar.abuse.ch/sample/3a71c073d8a01460f7014648eb90cf543d5a1a6ff43115da24f90d1671f67e44/) | `exe` | unbekannt | 39.1 | – | – | 🌐HU |
| 11:53 | [6661a8468fb7…](https://bazaar.abuse.ch/sample/6661a8468fb799e2ffa2b83606f23ff004ebac7de751715d23d0ee1a275b6f01/) | `exe` | unbekannt | 39.1 | – | – | 🌐HU |
| 11:50 | [e146e2e955f3…](https://bazaar.abuse.ch/sample/e146e2e955f3388764596039b2e04eff50524680aa90ceba5640c9ce27123210/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 11:46 | [221b82ea2ab7…](https://bazaar.abuse.ch/sample/221b82ea2ab76f5155a2537bc0c635599663229152c0a21c44d1e5313bd23f7b/) | `hta` | unbekannt | 39.0 | – | – | 🌐HU |
| 11:44 | [3548759f76e6…](https://bazaar.abuse.ch/sample/3548759f76e6964fd49edd47257efbac3396743c95a95d6af06b4463a4189264/) | `exe` | unbekannt | 39.0 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 06.11.2026 11:55 UTC*