# SIEMForge v2.0.0 — SIEM Detection Rule Builder
**Author:** Dinesh Patel | github.com/dinesh8123/SIEMForge

## Quick Start
```bash
chmod +x siemforge.sh
./siemforge.sh
```
> Requires: bash 4.0+, bc

## Modules
| # | Module | Description |
|---|--------|-------------|
| 1 | Build Rule | Interactive wizard — create custom Sigma rules |
| 2 | Rule Library | Browse & filter 50+ MITRE ATT&CK mapped rules |
| 3 | My Rules | View / delete your custom rules |
| 4 | Export Rules | Convert to Splunk SPL / Sentinel KQL / QRadar AQL |
| 5 | Alert Simulation | Replay events with FP scoring |
| 6 | Stats Dashboard | Coverage breakdown by severity & tactic |

## Rule Library Coverage
| Tactic | Rules | Examples |
|--------|-------|---------|
| Credential Access | 7 | Mimikatz, DCSync, Kerberoasting, WDigest |
| Defense Evasion | 7 | AMSI Bypass, Defender Disabled, UAC Bypass |
| Persistence | 5 | Registry Run Keys, Scheduled Tasks, New Admin |
| Lateral Movement | 5 | PsExec, Pass-the-Hash, WinRM, RDP |
| Exfiltration | 4 | DNS Tunnelling, HTTPS Exfil, S3 Public |
| C2 & Network | 5 | Beaconing, TOR Nodes, ICMP Tunnel, DGA |
| Cloud AWS/Azure | 9 | Root Login, CloudTrail Stopped, MFA Failures |
| Execution | 6 | PowerShell Encoded, WMI, Python Shell |
| Impact | 2 | Shadow Copy Delete, Ransomware |

## Output Files
```
output/splunk_TIMESTAMP.spl    — Splunk SPL queries
output/sentinel_TIMESTAMP.kql  — Microsoft Sentinel KQL
output/qradar_TIMESTAMP.aql    — IBM QRadar AQL
rules/*.yml                    — Your custom Sigma rules
rule_library/*.yml             — Pre-built library rules
```
