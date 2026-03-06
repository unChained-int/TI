# 🦠 MalwareBazaar Threat Intelligence Report  v6
**Erstellt:** 06.03.2026 16:57 UTC  |  **Samples:** 100  |  **VT-Anreicherung:** 5/100

> ⚠️ Ausschließlich für Threat-Intelligence, Forensik und Bildungszwecke.
> Datenquellen: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com)

## 📋 Executive Summary

| Metrik | Wert |
|--------|------|
| Analysierte Samples | **100** |
| 🔴 Kritische Samples | **57** |
| Höchster Risiko-Score | **88.7/100** (`b91ee6b195867a96…`) |
| Dominanter Dateityp | **elf** (45 Samples) |
| Häufigste Familie | **Mirai** |
| Häufigste Kategorie | **Botnet/IoT** |
| Primäre Plattform | **Linux** |
| Samples mit MITRE-Mapping | **60** |
| Ø Dateigröße ± σ | 2.78 MB ± 12.15 MB |

## 📊 Top Dateitypen

| Rang | Dateityp | Anzahl | Anteil | Balken |
|------|----------|--------|--------|--------|
| 1 | `elf` | 45 | 45.0% | █████████████ |
| 2 | `exe` | 44 | 44.0% | █████████████ |
| 3 | `sh` | 6 | 6.0% | █ |
| 4 | `zip` | 3 | 3.0% |  |
| 5 | `img` | 1 | 1.0% |  |
| 6 | `xlsx` | 1 | 1.0% |  |

## 🦠 Top Malware-Familien / Signaturen

| Rang | Familie / Signatur | Anzahl | Anteil |
|------|--------------------|--------|--------|
| 1 | Mirai | 50 | 50.0% |
| 2 | unbekannt / keine Signatur | 28 | 28.0% |
| 3 | GuLoader | 5 | 5.0% |
| 4 | Formbook | 5 | 5.0% |
| 5 | AgentTesla | 3 | 3.0% |
| 6 | RemcosRAT | 2 | 2.0% |
| 7 | PhantomStealer | 2 | 2.0% |
| 8 | SalatStealer | 1 | 1.0% |
| 9 | MassLogger | 1 | 1.0% |
| 10 | Expiro | 1 | 1.0% |
| 11 | a310Logger | 1 | 1.0% |
| 12 | DarkTortilla | 1 | 1.0% |

## 🏷️ Klassifikation

> **Methodik:** 3-Stufen – (1) Signatur-Lookup, (2) Tag-Keywords, (3) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Ø Konfidenz |
|-----------|--------|--------|-------------|
| **Botnet/IoT** | 50 | 50.0% | 95% |
| **Andere / Unbekannt** | 36 | 36.0% | 20% |
| **Loader** | 6 | 6.0% | 92% |
| **Infostealer** | 3 | 3.0% | 75% |
| **RAT** | 2 | 2.0% | 95% |
| **Ransomware** | 1 | 1.0% | 75% |
| **Maldoc** | 1 | 1.0% | 35% |
| **Skript/Dropper** | 1 | 1.0% | 35% |

## ⚠️ Risiko-Score Analyse

> **Formel (mit VT):**  R = (0.35·S_sev + 0.30·S_sig + 0.25·S_det + 0.10·S_age) × 100
> **Formel (ohne VT):** R = (0.475·S_sev + 0.425·S_sig + 0.10·S_age) × 100
> S_age = e^(−0.096·Alter_in_Stunden)  |  Schwelle: 🔴≥75 / 🟠≥55 / 🟡≥35 / 🟢<35

| Level | Anzahl | Anteil |
|-------|--------|--------|
| 🔴 KRITISCH | 57 | 57.0% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 2 | 2.0% |
| 🟢 NIEDRIG | 36 | 36.0% |

**Top 10 nach Risiko-Score:**

| SHA256 | Familie | Kat. | Score | Level | S_sev | S_det | VT? |
|--------|---------|------|-------|-------|-------|-------|-----|
| [b91ee6b195867a…](https://bazaar.abuse.ch/sample/b91ee6b195867a96f22bbcd98cff92fd2347b720e42281ef06c5d7e27c70250b/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | 0.83 | 0.0 | – |
| [1148fa91ce87cc…](https://bazaar.abuse.ch/sample/1148fa91ce87cc06cbd373b0bd40eb1de0ede6e438262dda0ca8bea60b9239f8/) | RemcosRAT | RAT | **88.6** | 🔴 KRITISCH | 0.83 | 0.0 | – |
| [31e527a5040594…](https://bazaar.abuse.ch/sample/31e527a5040594573feaac114ac5f81c8ef46ba2c984f90f4c0c024775b2eea0/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [5aaf6f8c6459ae…](https://bazaar.abuse.ch/sample/5aaf6f8c6459aecb6ec08b8e88e0f7f143dcff69e200e71b58e18e0535c77307/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [aadff1cd1e8f54…](https://bazaar.abuse.ch/sample/aadff1cd1e8f5414201101ebdd063fcb4d2957cf9330ad5469b066d6cc264066/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [28768fed528dab…](https://bazaar.abuse.ch/sample/28768fed528dab06fb800aaf02e62f519a88614004952e170b2de858b0d06e92/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [fe2d31d8e9db56…](https://bazaar.abuse.ch/sample/fe2d31d8e9db5624dd994fb7ccda1e044f6b8645ff7b4106b56f1ca1ac64dae0/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [04457096271432…](https://bazaar.abuse.ch/sample/04457096271432b6c1253bcd11e02fabf97b303f579c299e01d2ef9d9db3520f/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [a4889fcba22bdf…](https://bazaar.abuse.ch/sample/a4889fcba22bdf46d61c86c20f5b8e19d556aaed0056b9ae303ea0e9a7904399/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |
| [078cf00268c2de…](https://bazaar.abuse.ch/sample/078cf00268c2def420f07a3625d1f191f7a97f57b68af6fa590ef12f78365b53/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | 0.72 | 0.0 | – |

## 💻 Betroffene Plattformen
> Jedes Sample wurde genau einer Plattform zugeordnet (Summe = 100 = 100%)

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 **Linux** | 51 | 51.0% |
| 🪟 **Windows** | 44 | 44.0% |
| 📦 **Archiv** | 3 | 3.0% |
| ❓ **Unbekannt** | 1 | 1.0% |
| 📄 **Dokument** | 1 | 1.0% |

## 🎯 Infektionsvektoren
> Primärvektor je Sample (Summe = 100 = 100%)

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 91 | 91.0% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| C2 / Nachladen | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## 🗺️ MITRE ATT&CK Mapping
> 60/100 Samples haben ein MITRE-Mapping (über Signatur + Tags)
> Referenz: https://attack.mitre.org/

**Taktik-Häufigkeit:**

| Taktik | Betroffene Samples |
|--------|--------------------|
| Initial Access | 50 |
| Lateral Movement | 50 |
| Execution | 7 |
| Defense Evasion | 5 |
| Collection | 3 |
| Persistence | 2 |
| Command and Control | 2 |
| Credential Access | 1 |
| Exfiltration | 1 |

<details><summary><code>b91ee6b195867a96f2…</code> – RemcosRAT (🔴 KRITISCH 88.7)</summary>

| Taktik | ID | Technik |
|--------|-----|---------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary><code>1148fa91ce87cc06cb…</code> – RemcosRAT (🔴 KRITISCH 88.6)</summary>

| Taktik | ID | Technik |
|--------|-----|---------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary><code>31e527a5040594573f…</code> – Mirai (🔴 KRITISCH 84.3)</summary>

| Taktik | ID | Technik |
|--------|-----|---------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary><code>5aaf6f8c6459aecb6e…</code> – Mirai (🔴 KRITISCH 84.3)</summary>

| Taktik | ID | Technik |
|--------|-----|---------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary><code>aadff1cd1e8f541420…</code> – Mirai (🔴 KRITISCH 84.3)</summary>

| Taktik | ID | Technik |
|--------|-----|---------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## 🔬 VirusTotal-Anreicherung

| SHA256 | Erkannt | Rate | Top Engine | Reput. |
|--------|---------|------|------------|--------|
| [`b547dc7a77af8022…`](https://bazaar.abuse.ch/sample/b547dc7a77af8022abbf19a7006213342444caea1cede20ea2409ce9bc9790bf/) | 28/75 | 37.3% | Generic.Ransom.WannaCryptor.292E472 | -11 |
| [`0474b0ce5ba46379…`](https://bazaar.abuse.ch/sample/0474b0ce5ba46379553327c202548576b2b3f69d63cd9111e41a5c0fe12f7f0b/) | 26/75 | 34.7% | ELF:Agent-AYQ [Trj] | -11 |
| [`b33bb5abe865f0d0…`](https://bazaar.abuse.ch/sample/b33bb5abe865f0d0ef3667186db0b6f93bb84f449e2edd32bfb4c77b601dfd3b/) | 20/75 | 26.7% | LINUX/Mirai-FPD!FABAE4C565F3 | -11 |
| [`6f0ca1a298424961…`](https://bazaar.abuse.ch/sample/6f0ca1a298424961cca17b6052e52e935c95529049c69410f0478cd02ba6fb67/) | 24/75 | 32.0% | LINUX/Mirai-FPD!57A5A0A348DE | -11 |
| [`fd64ac296d61656e…`](https://bazaar.abuse.ch/sample/fd64ac296d61656e43e0d2ff8c012779b1ec8615fb63af2fa8f952d6cbad9c70/) | 19/75 | 25.3% | ELF:Mirai-CZE [Trj] | -11 |

## 🏷️ Häufigste Tags (Top 15)

- **Mirai** (50×)  ▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪
- **elf** (45×)  ▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪
- **exe** (44×)  ▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪▪
- **signed** (9×)  ▪▪▪▪▪▪▪▪▪
- **sh** (6×)  ▪▪▪▪▪▪
- **GuLoader** (5×)  ▪▪▪▪▪
- **Formbook** (5×)  ▪▪▪▪▪
- **upx-dec** (4×)  ▪▪▪▪
- **zip** (3×)  ▪▪▪
- **upx** (3×)  ▪▪▪
- **dropped-by-Amadey** (2×)  ▪▪
- **fbf543** (2×)  ▪▪
- **AgentTesla** (2×)  ▪▪
- **RemcosRAT** (2×)  ▪▪
- **PhantomStealer** (2×)  ▪▪

## 📈 Trending – Delta zum Vorrun

- Kein Vorrun verfügbar – Baseline wird jetzt angelegt.

## 📐 Statistische Kennzahlen

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.782 MB |
| σ Dateigröße | 12.146 MB |
| Max. Dateigröße | 99.617 MB |
| Min. Dateigröße | 0.000498 MB |
| Ø Risiko-Score | 63.5/100 |
| Ø Klassifikations-Konfidenz | 65.8% |
| Samples mit VT-Daten | 5 / 100 |
| Samples mit MITRE-Mapping | 60 / 100 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 29 |

## 🔗 Neueste 5 Samples

| Zeit | SHA256 | Typ | Familie | Score | Plattform |
|------|--------|-----|---------|-------|-----------|
| 16:48 | [b547dc7a77af…](https://bazaar.abuse.ch/sample/b547dc7a77af8022abbf19a7006213342444caea1cede20ea2409ce9bc9790bf/) | `exe` | unbekannt / keine Sign | 76.7 | Windows |
| 16:39 | [0474b0ce5ba4…](https://bazaar.abuse.ch/sample/0474b0ce5ba46379553327c202548576b2b3f69d63cd9111e41a5c0fe12f7f0b/) | `elf` | Mirai | 72.1 | Linux |
| 16:39 | [b33bb5abe865…](https://bazaar.abuse.ch/sample/b33bb5abe865f0d0ef3667186db0b6f93bb84f449e2edd32bfb4c77b601dfd3b/) | `elf` | Mirai | 70.1 | Linux |
| 16:39 | [6f0ca1a29842…](https://bazaar.abuse.ch/sample/6f0ca1a298424961cca17b6052e52e935c95529049c69410f0478cd02ba6fb67/) | `elf` | Mirai | 71.4 | Linux |
| 16:39 | [fd64ac296d61…](https://bazaar.abuse.ch/sample/fd64ac296d61656e43e0d2ff8c012779b1ec8615fb63af2fa8f952d6cbad9c70/) | `elf` | Mirai | 69.7 | Linux |

---
*Report v6 · 06.03.2026 16:57 UTC · MalwareBazaar (abuse.ch) × VirusTotal · Fixes: Klassifikation, Risiko, Plattform, Vektoren, MITRE, Deduplizierung*