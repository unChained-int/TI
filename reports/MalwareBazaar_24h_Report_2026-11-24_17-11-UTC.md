# MalwareBazaar – 24.11.2026 17:11 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **65** |
| Höchster Score | **89.5/100** – 3c8706da6172c8bb… |
| Häufigste Familie | **unbekannt** (26x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 23 Samples |
| Ø Dateigröße | 3.94 MB (σ=12.60) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 52.5%  ██████████ |
| `exe` | 11 | 10.9%  ██ |
| `macho` | 10 | 9.9%  █ |
| `js` | 7 | 6.9%  █ |
| `ps1` | 4 | 4.0%   |
| `xls` | 3 | 3.0%   |
| `jse` | 2 | 2.0%   |
| `hta` | 2 | 2.0%   |
| `vbe` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 26 | 25.7% |
| 2 | EasyShell | 21 | 20.8% |
| 3 | CatStorm | 13 | 12.9% |
| 4 | RemcosRAT | 10 | 9.9% |
| 5 | Formbook | 7 | 6.9% |
| 6 | Mirai | 6 | 5.9% |
| 7 | BotenaGo | 6 | 5.9% |
| 8 | WARDENStealer | 3 | 3.0% |
| 9 | Prometei | 2 | 2.0% |
| 10 | SnappyClient | 1 | 1.0% |
| 11 | DarkCloud | 1 | 1.0% |
| 12 | DarkTortilla | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 46 | 45.5% | 80% |
| Linux-Malware | 21 | 20.8% | 45% |
| Infostealer | 12 | 11.9% | 87% |
| Windows-Malware | 7 | 6.9% | 35% |
| Botnet/IoT | 7 | 6.9% | 95% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Maldoc | 2 | 2.0% | 35% |
| Cryptominer | 1 | 1.0% | 75% |
| Andere / Unbekannt | 1 | 1.0% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 65 | 64.4% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 34 | 33.7% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3c8706da6172c8…](https://bazaar.abuse.ch/sample/3c8706da6172c8bb31a54e68e5a51d1a5d3556ffda5ce51db944b5472599f79b/) | Formbook | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [0e33c76837882d…](https://bazaar.abuse.ch/sample/0e33c76837882dad67128700839bc893b35c6d2cab6ff380776c557cc44ac6e7/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [08cdf0297e9fd7…](https://bazaar.abuse.ch/sample/08cdf0297e9fd7e84ede0cafaebd3aa9d9e38ef961463e18d581d97e6d2443c7/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [8d5701c8bb2f6f…](https://bazaar.abuse.ch/sample/8d5701c8bb2f6feb364e0753b6d22483e80dadac8e11639b09ad5f426671bee7/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [7fc073db2e9477…](https://bazaar.abuse.ch/sample/7fc073db2e9477fe867dc8d3f7f020de2fd8dfac5ce03785b9df3813f754907e/) | RemcosRAT | RAT | **89.2** | 🔴 KRITISCH | 6.9% | ⚠️ KAUM ERKANNT | ✗ |
| [b787f6560a6bc7…](https://bazaar.abuse.ch/sample/b787f6560a6bc7370f63376923e9d8433076655701edb331b95a6e0d35a680c6/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [6a8f9e5911e3e5…](https://bazaar.abuse.ch/sample/6a8f9e5911e3e527089de2e8a63a57d3fc68fd458fd6e303875d4b7bbe8cbf76/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [1eb6da0313f7ae…](https://bazaar.abuse.ch/sample/1eb6da0313f7ae10eb78b4cd59ca6880311db6834acc0fcb4335a130711f8b92/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [c392ba2de6a735…](https://bazaar.abuse.ch/sample/c392ba2de6a7352c12ba018fa711acf749264fee3f99a5777e5c0d526c0d0eb3/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [c32487204bbfa3…](https://bazaar.abuse.ch/sample/c32487204bbfa3b06ec76f46e101da4828a53e432056f0acbf37555b9d1a67d9/) | RemcosRAT | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6595/8123 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6595/8123 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6291/8123 |
| 6 | Kaspersky | 75.6% | 6143/8122 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5788/8119 |
| 9 | Rising | 68.6% | 5572/8123 |
| 10 | Varist | 66.1% | 5367/8118 |
| 11 | Tencent | 65.2% | 5150/7897 |
| 12 | Avast | 65.2% | 5295/8119 |
| 13 | AVG | 65.2% | 5295/8118 |
| 14 | McAfeeD | 61.5% | 4987/8115 |
| 15 | huorong | 61.0% | 4953/8115 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 65 | 64.4% |
| 🪟 Windows | 20 | 19.8% |
| ❓ Unbekannt | 11 | 10.9% |
| 📄 Dokument | 5 | 5.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 86 | 85.1% |
| Drive-By / Exploit-Kit | 9 | 8.9% |
| Phishing / E-Mail-Anhang | 5 | 5.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 41 | 40.6% |
| 2 | 🇫🇷 FR | 28 | 27.7% |
| 3 | 🇩🇪 DE | 20 | 19.8% |
| 4 | 🇳🇱 NL | 8 | 7.9% |
| 5 | 🇪🇸 ES | 1 | 1.0% |
| 6 | 🌐 EG | 1 | 1.0% |
| 7 | 🇸🇬 SG | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 23 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 17 |
| Command and Control | 10 |
| Credential Access | 7 |
| Initial Access | 6 |
| Lateral Movement | 6 |

<details><summary>3c8706da6172c8bb31a5… – Formbook | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>0e33c76837882dad6712… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>08cdf0297e9fd7e84ede… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>8d5701c8bb2f6feb364e… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>7fc073db2e9477fe867d… – RemcosRAT | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [61cba366f3f0338d41d3…](https://bazaar.abuse.ch/sample/61cba366f3f0338d41d3ac139b63680364f8e4b9518e8ba7671f09fd61b7615b/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

### [7fc073db2e9477fe867d…](https://bazaar.abuse.ch/sample/7fc073db2e9477fe867dc8d3f7f020de2fd8dfac5ce03785b9df3813f754907e/)

- **Familie:** RemcosRAT
- **Erkannt von:** 5 von 73 Engines (6.9%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan/PS.Loader.ac
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/73):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `PowerShell.Packed.329` |
| ESET-NOD32 | `PowerShell/Agent.FVZ trojan` |
| Fortinet | `PowerShell/Kryptik.PF!tr` |
| Kingsoft | `Win32.Troj.Undef.2062101` |
| huorong | `Trojan/PS.Loader.ac` |

### [89b09e60cb7b65202d98…](https://bazaar.abuse.ch/sample/89b09e60cb7b65202d98ac387db1bb2e5284acfdf8a887f212820ad6bad569c0/)

- **Familie:** EasyShell
- **Erkannt von:** 5 von 73 Engines (6.9%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/73):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:LukKB9f4rHJ)` |
| Tencent | `Malware.Linux.Generic.1c0ccd3e` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 73 Engines (39.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/73):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop31.17564` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Riskware.Win32.ConnectWise.1!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win32.ScreenConnect.tc` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **elf** (53×)
- **RAT** (39×)
- **EasyShell** (35×)
- **Rust** (35×)
- **SnoopyTriage** (35×)
- **exe** (12×)
- **macho** (10×)
- **RemcosRAT** (10×)
- **upx-dec** (8×)
- **cowrie** (8×)
- **honeypot** (8×)
- **upx** (7×)
- **Formbook** (7×)
- **js** (7×)
- **CatStorm** (7×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -10 (36→26)
- ↑ **EasyShell** +3 (18→21)
- neu: **CatStorm** (13)
- neu: **RemcosRAT** (10)
- neu: **Formbook** (7)
- ↓ **Mirai** -3 (9→6)
- neu: **BotenaGo** (6)
- ↓ **WARDENStealer** -2 (5→3)
- ↓ **Prometei** -2 (4→2)
- neu: **SnappyClient** (1)
- weg: **WSHRat** (war 2)
- weg: **njrat** (war 2)
- weg: **RemusStealer** (war 2)
- weg: **Snowlight** (war 10)
- weg: **VShell** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -8 (34→26)
- ↑ **EasyShell** +18 (3→21)
- neu: **CatStorm** (13)
- ↑ **RemcosRAT** +9 (1→10)
- neu: **Formbook** (7)
- ↓ **Mirai** -25 (31→6)
- neu: **BotenaGo** (6)
- ↓ **WARDENStealer** -2 (5→3)
- ↓ **Prometei** -3 (5→2)
- neu: **SnappyClient** (1)
- weg: **FantasyHub** (war 2)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.937 MB |
| σ Dateigröße | 12.602 MB |
| Ø Risiko-Score | 67.1/100 |
| Ø Klassifikations-Konfidenz | 68.0% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 23/101 |
| Eindeutige Familien | 16 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:06 | [61cba366f3f0…](https://bazaar.abuse.ch/sample/61cba366f3f0338d41d3ac139b63680364f8e4b9518e8ba7671f09fd61b7615b/) | `elf` | unbekannt | 86.5 | 0.0% | ⚠️ KAUM ERKANNT | 🇺🇸US |
| 17:06 | [5160440b0203…](https://bazaar.abuse.ch/sample/5160440b020329f63c4d033d8cfed55e17ca28c9d776f620e698779cfd622936/) | `elf` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 17:06 | [5ff9f1443e2b…](https://bazaar.abuse.ch/sample/5ff9f1443e2b3ef1ee14fc97bafea2eb9d7be37ccdde5da1cd682b4aa505372a/) | `elf` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 17:06 | [33e85ade3921…](https://bazaar.abuse.ch/sample/33e85ade39213cb4c19e12dc2a150d3930e58c385c2e7a550f5b72973b1ea3b9/) | `macho` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 17:05 | [2251504fee66…](https://bazaar.abuse.ch/sample/2251504fee66944bc6b22aa08cc855df3dae760d9f5c8a26928ef1132c0b1829/) | `macho` | unbekannt | 81.2 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.11.2026 17:11 UTC*