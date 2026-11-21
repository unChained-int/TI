# MalwareBazaar – 21.11.2026 03:01 UTC

Dieser Run hat **78 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **79** |
| Kritisch (≥75) | **17** |
| Höchster Score | **86.2/100** – 6ff47af32ef471f8… |
| Häufigste Familie | **unbekannt** (51x) |
| Häufigster Typ | **elf** (56x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 14 Samples |
| Ø Dateigröße | 4.66 MB (σ=9.59) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 56 | 70.9%  ██████████████ |
| `exe` | 13 | 16.5%  ███ |
| `gz` | 4 | 5.1%  █ |
| `bat` | 3 | 3.8%   |
| `sh` | 2 | 2.5%   |
| `msi` | 1 | 1.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 51 | 64.6% |
| 2 | Mirai | 12 | 15.2% |
| 3 | Prometei | 7 | 8.9% |
| 4 | ConnectWise | 2 | 2.5% |
| 5 | Application.Generic.37115250 | 1 | 1.3% |
| 6 | B!ml | 1 | 1.3% |
| 7 | WARDENStealer | 1 | 1.3% |
| 8 | Adware.OfferCore | 1 | 1.3% |
| 9 | Multi | 1 | 1.3% |
| 10 | QuasarRAT | 1 | 1.3% |
| 11 | njrat | 1 | 1.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 41 | 51.9% | 45% |
| Windows-Malware | 12 | 15.2% | 35% |
| Botnet/IoT | 12 | 15.2% | 95% |
| Cryptominer | 5 | 6.3% | 75% |
| Backdoor | 2 | 2.5% | 65% |
| RAT | 2 | 2.5% | 95% |
| Skript/Dropper | 2 | 2.5% | 35% |
| Trojaner | 1 | 1.3% | 65% |
| Infostealer | 1 | 1.3% | 75% |
| Andere / Unbekannt | 1 | 1.3% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 17 | 21.5% |
| 🟠 HOCH | 7 | 8.9% |
| 🟡 MITTEL | 54 | 68.4% |
| 🟢 NIEDRIG | 1 | 1.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [6ff47af32ef471…](https://bazaar.abuse.ch/sample/6ff47af32ef471f8bec1e4022545353eebea3a19f91bd72164561cf2b8e56ce1/) | QuasarRAT | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [5e519e0d47be9b…](https://bazaar.abuse.ch/sample/5e519e0d47be9b7dea386f863f09acc431d89572297d4fc4e96d561c0e5c9dab/) | B!ml | Trojaner | **83.8** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [3f8f9be5f8e8cd…](https://bazaar.abuse.ch/sample/3f8f9be5f8e8cdffc8bf9b3e5b54d0a906217050803b3e1a37112231f019dd25/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [5e387fc4dbe927…](https://bazaar.abuse.ch/sample/5e387fc4dbe927bd0d8a1a1f3a1571cfd1ab6f3f4c19f56780725b70534f957e/) | Multi | Backdoor | **82.5** | 🔴 KRITISCH | 2.7% | ⚠️ KAUM ERKANNT | ✗ |
| [22668e82cb9225…](https://bazaar.abuse.ch/sample/22668e82cb92251f574ad17bfedf10730387d1e4bc05036f19e2fef630c12257/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [2b7531ea09ad0f…](https://bazaar.abuse.ch/sample/2b7531ea09ad0f6c3b73be869cc72c8b4bea8a8287afc12974c5010219a40150/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [b53b35880c3fe8…](https://bazaar.abuse.ch/sample/b53b35880c3fe841bcb4e88725037a29e433855d424f56008cd1b9d65f84a088/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [9721ecc38dd965…](https://bazaar.abuse.ch/sample/9721ecc38dd965790cdbb888a58c2043f84f0adb65154064ddfe640d025c4559/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [c690ee0ea3eb9d…](https://bazaar.abuse.ch/sample/c690ee0ea3eb9dfc7f6e585239cb6237f5d1c48704941c372bb95d2fa9dff48e/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | – | – | ? |
| [3186e2846f071b…](https://bazaar.abuse.ch/sample/3186e2846f071bcb33e818d52623571c30a2f20182b6b9467b560f46deed8bf2/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6555/8079 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6555/8079 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6251/8079 |
| 6 | Kaspersky | 75.6% | 6104/8078 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5758/8075 |
| 9 | Rising | 68.5% | 5536/8079 |
| 10 | Varist | 66.1% | 5338/8074 |
| 11 | Tencent | 65.2% | 5117/7853 |
| 12 | Avast | 65.2% | 5265/8075 |
| 13 | AVG | 65.2% | 5265/8074 |
| 14 | McAfeeD | 61.5% | 4967/8071 |
| 15 | huorong | 60.9% | 4919/8071 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 58 | 73.4% |
| 🪟 Windows | 17 | 21.5% |
| ❓ Unbekannt | 4 | 5.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 78 | 98.7% |
| Trojanisierte Software | 1 | 1.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 37 | 46.8% |
| 2 | 🇺🇸 US | 20 | 25.3% |
| 3 | 🇳🇱 NL | 10 | 12.7% |
| 4 | 🇫🇷 FR | 6 | 7.6% |
| 5 | 🇭🇺 HU | 4 | 5.1% |
| 6 | 🇸🇬 SG | 1 | 1.3% |
| 7 | 🌐 Unbekannt | 1 | 1.3% |

## MITRE ATT&CK

> 14 von 79 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 12 |
| Lateral Movement | 12 |
| Command and Control | 2 |
| Exfiltration | 1 |
| Collection | 1 |

<details><summary>6ff47af32ef471f8bec1… – QuasarRAT | 🔴 KRITISCH 86.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>3f8f9be5f8e8cdffc8bf… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>22668e82cb92251f574a… – Mirai | 🔴 KRITISCH 82.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [e63c506653c1133fcf94…](https://bazaar.abuse.ch/sample/e63c506653c1133fcf94d418ca420e60fe5bff43bc69b5ac8ac9540ebb419694/)

- **Familie:** Application.Generic.37115250
- **Erkannt von:** 31 von 74 Engines (41.9%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Application.Generic.37115250
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37115250`

**Erkennende Engines (31/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37115250` |
| AhnLab-V3 | `HackTool/Linux.Flooder.SE152` |
| Arcabit | `Application.Generic.D2365572` |
| BitDefender 🛡️ | `Application.Generic.37115250` |
| CAT-QuickHeal | `Elf.Hacktool.A29002609` |
| CTX | `elf.unknown.generic` |
| ESET-NOD32 | `Linux/Agent.GF trojan` |
| Emsisoft | `Application.Generic.37115250 (B)` |
| Fortinet | `Linux/Agent.GF!tr` |
| GData | `Application.Generic.37115250` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Agent` |
| Kaspersky | `HEUR:Backdoor.Linux.Ssh.a` |
| Kingsoft | `Linux.Backdoor.Ssh.a` |
| Lionic | `Trojan.Linux.Ssh.m!c` |
| MaxSecure | `Trojan.Malware.344681797.susgen.npe` |
| McAfeeD | `ti!E63C506653C1` |
| MicroWorld-eScan | `Application.Generic.37115250` |
| Microsoft 🛡️ | `Trojan:Linux/Multiverze!rfn` |
| Rising | `Trojan.Agent/Linux!1.C406 (CLOUD)` |
| Sangfor | `Backdoor.Linux.Ssh.Vljq` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Hacktool.Linux.Sshscan.a` |
| TrendMicro | `Backdoor.Linux.SSH.USBLJV26` |
| TrendMicro-HouseCall | `Backdoor.Linux.SSH.USBLJV26` |
| VIPRE | `Application.Generic.37115250` |
| Varist | `E64/ABTrojan.QSCJ-` |
| alibabacloud | `Scanner[scanner]:Linux/OutlawScanner` |
| huorong | `Trojan/Linux.DDos.cb` |

### [5e519e0d47be9b7dea38…](https://bazaar.abuse.ch/sample/5e519e0d47be9b7dea386f863f09acc431d89572297d4fc4e96d561c0e5c9dab/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [5e387fc4dbe927bd0d8a…](https://bazaar.abuse.ch/sample/5e387fc4dbe927bd0d8a1a1f3a1571cfd1ab6f3f4c19f56780725b70534f957e/)

- **Familie:** Multi
- **Erkannt von:** 2 von 74 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Backdoor.Multi.gl
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Jiangmin | `Backdoor.Multi.gl` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [c94b0d2d52651fb54d69…](https://bazaar.abuse.ch/sample/c94b0d2d52651fb54d69c2e72964a1918f56144a6b41e0cee5db36007d51c756/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 74 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

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

- **elf** (55×)
- **dota3** (12×)
- **outlaw** (12×)
- **exe** (12×)
- **Mirai** (12×)
- **upx-dec** (9×)
- **upx** (9×)
- **bruteforce** (7×)
- **Prometei** (7×)
- **coinminer** (5×)
- **gz** (4×)
- **tar-gz** (4×)
- **x86-64** (3×)
- **bat** (3×)
- **signed** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +15 (36→51)
- ↓ **Mirai** -16 (28→12)
- ↑ **Prometei** +1 (6→7)
- neu: **ConnectWise** (2)
- neu: **Application.Generic.37115250** (1)
- neu: **B!ml** (1)
- ↓ **WARDENStealer** -7 (8→1)
- neu: **Adware.OfferCore** (1)
- neu: **Multi** (1)
- neu: **QuasarRAT** (1)
- weg: **AsyncRAT** (war 4)
- weg: **AgentTesla** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **ValleyRAT** (war 2)
- weg: **SalatStealer** (war 2)
- weg: **MopsStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +27 (24→51)
- ↓ **Mirai** -27 (39→12)
- ↑ **Prometei** +3 (4→7)
- ↑ **ConnectWise** +1 (1→2)
- neu: **Application.Generic.37115250** (1)
- neu: **B!ml** (1)
- ↓ **WARDENStealer** -4 (5→1)
- neu: **Adware.OfferCore** (1)
- neu: **Multi** (1)
- neu: **QuasarRAT** (1)
- weg: **RemcosRAT** (war 3)
- weg: **SalatStealer** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.655 MB |
| σ Dateigröße | 9.586 MB |
| Ø Risiko-Score | 51.4/100 |
| Ø Klassifikations-Konfidenz | 54.8% |
| Samples mit VT | 5/79 |
| Samples mit MITRE | 14/79 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 31 |
| Unbekannte Familien | 1 (1.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 02:56 | [d8edbdfdba47…](https://bazaar.abuse.ch/sample/d8edbdfdba4737f2cfe07d7e28a6a4dee1a552fe8dd0aab26b76ae5f0a28eaa7/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 02:56 | [1c90b187888f…](https://bazaar.abuse.ch/sample/1c90b187888febc674412dac7f98e658b4d00935ddad583ef89949c2e5c7d99a/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 02:56 | [4877997837ec…](https://bazaar.abuse.ch/sample/4877997837ec1bb5b45e41c9ab81dcb23832bc8efb6b4547b1b2ce1f23076f58/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 02:56 | [35d46b9b62e6…](https://bazaar.abuse.ch/sample/35d46b9b62e6845302e7daa29a35fd9a0781b5d5b29541821f88cc90d72006bf/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 02:56 | [e63c506653c1…](https://bazaar.abuse.ch/sample/e63c506653c1133fcf94d418ca420e60fe5bff43bc69b5ac8ac9540ebb419694/) | `elf` | Application.Generic.37 | 75.4 | 41.9% | 🟠 MÄSSIG ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.11.2026 03:01 UTC*