# Security Control Trend Reporting

A generalized PowerShell example for replacing repeated manual weekly control-status reporting. It compares two CSV snapshots, identifies changes, and creates management-ready CSV, JSON, and HTML output.

The included input is synthetic. No customer, tenant, subscription, system, or production-assessment data is included.

## Input schema

Both snapshots require these columns:

| Column | Purpose |
| --- | --- |
| `ControlId` | Stable control identifier |
| `ControlName` | Human-readable control name |
| `Status` | `Compliant`, `NonCompliant`, `NotApplicable`, or another organization-defined state |
| `Severity` | Finding or control priority |
| `Owner` | Responsible role or team |
| `System` | Assessed system or boundary |
| `AssessmentDate` | Snapshot date |

## Run

```powershell
.\Update-ControlTrend.ps1 `
  -CurrentPath .\examples\current-controls.csv `
  -PreviousPath .\examples\previous-controls.csv `
  -OutputDirectory .\output
```

## Transition logic

| Transition | Meaning |
| --- | --- |
| `NewFinding` | Previously compliant, now noncompliant |
| `Resolved` | Previously noncompliant, now compliant |
| `StatusChanged` | Status changed without crossing the compliant boundary |
| `NewControl` | Appears only in the current snapshot |
| `MissingFromCurrent` | Appears only in the previous snapshot and requires review |
| `Unchanged` | Status did not change |

## Safety

The script reads local CSV files and writes local reports. It does not connect to a cloud environment or change control status. Generated reports may still contain sensitive assessment information and are excluded by the repository `.gitignore`.
