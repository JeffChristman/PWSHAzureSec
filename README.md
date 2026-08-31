# Azure Security Assessment Automation

PowerShell and Azure Workbook assets for repeatable Azure security and operational assessments. The collection focuses on network exposure, identity, Key Vault, resource inventory, Defender findings, and governance evidence.

## PowerShell assessments

| Script | Focus |
| --- | --- |
| `FirewallAssesment.ps1` / `FirewallAudit.ps1` | Azure Firewall configuration and control review |
| `FirewallNSG.ps1` / `NSG_Rules.ps1` | Firewall-to-NSG correlation and rule analysis |
| `Firewall_LAW.ps1` | Firewall diagnostic and Log Analytics coverage |
| `AppServiceWithIp.ps1` | App Service public exposure discovery |
| `MSGraph.ps1` | Microsoft Graph application-permission analysis |
| `ManagedIDWithEmassID.ps1` | Managed-identity inventory with governance metadata |

## Azure Workbooks

The `workbooks/` directory contains reusable JSON templates for:

- Azure inventory and compute reliability
- Firewall and network monitoring
- Key Vault posture and public-access checks
- Vulnerability-assessment findings
- Orphaned-resource discovery
- Operational and governance dashboards

## Control trend reporting

The [`control-trend-reporting`](control-trend-reporting/) example compares weekly security-control snapshots and produces CSV, JSON, and HTML management reports. It includes synthetic input data and demonstrates how repeated status reporting can be automated without publishing internal workbooks or assessment results.

## Safety and permissions

- Run with a dedicated read-only identity unless a script explicitly documents another requirement.
- Inspect every script before use and test in a non-production subscription.
- Workbook template GUIDs are layout and control identifiers; do not add tenant IDs, subscription IDs, resource IDs, or exported results.
- Do not commit customer names, screenshots, assessment exports, or credentials.

## Portfolio note

These assets demonstrate the mechanics of turning Azure control checks into evidence and dashboards. Environment-specific versions and generated reports are intentionally excluded from the public portfolio.
