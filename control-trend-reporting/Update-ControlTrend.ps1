<#
.SYNOPSIS
    Compares two security-control snapshots and creates management-ready trend output.

.DESCRIPTION
    Imports current and previous CSV snapshots, validates their schema, classifies
    status transitions, exports a detailed transition CSV and JSON summary, and
    creates a self-contained HTML report. The script processes local files only.

.EXAMPLE
    .\Update-ControlTrend.ps1 `
        -CurrentPath .\examples\current-controls.csv `
        -PreviousPath .\examples\previous-controls.csv `
        -OutputDirectory .\output
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CurrentPath,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PreviousPath,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'output')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredColumns = @(
    'ControlId',
    'ControlName',
    'Status',
    'Severity',
    'Owner',
    'System',
    'AssessmentDate'
)

function Import-ControlSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -eq 0) {
        throw "Snapshot is empty: $Path"
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @($requiredColumns | Where-Object { $_ -notin $columns })
    if ($missing.Count -gt 0) {
        throw "Snapshot '$Path' is missing required columns: $($missing -join ', ')"
    }

    $seen = @{}
    foreach ($row in $rows) {
        $controlId = [string]$row.ControlId
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw "Snapshot '$Path' contains a row without ControlId."
        }

        $key = $controlId.Trim().ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            throw "Snapshot '$Path' contains duplicate ControlId '$controlId'."
        }
        $seen[$key] = $true

        [pscustomobject]@{
            ControlId      = $controlId.Trim()
            ControlName    = ([string]$row.ControlName).Trim()
            Status         = ([string]$row.Status).Trim()
            Severity       = ([string]$row.Severity).Trim()
            Owner          = ([string]$row.Owner).Trim()
            System         = ([string]$row.System).Trim()
            AssessmentDate = ([string]$row.AssessmentDate).Trim()
        }
    }
}

function Test-IsCompliant {
    param([string]$Status)

    return $Status -in @('Compliant', 'Passed', 'Pass')
}

function Get-Transition {
    param(
        [AllowNull()][string]$PreviousStatus,
        [AllowNull()][string]$CurrentStatus
    )

    if ($null -eq $PreviousStatus) {
        return 'NewControl'
    }
    if ($null -eq $CurrentStatus) {
        return 'MissingFromCurrent'
    }

    $previousCompliant = Test-IsCompliant -Status $PreviousStatus
    $currentCompliant = Test-IsCompliant -Status $CurrentStatus

    if (-not $previousCompliant -and $currentCompliant) {
        return 'Resolved'
    }
    if ($previousCompliant -and -not $currentCompliant) {
        return 'NewFinding'
    }
    if ($PreviousStatus -eq $CurrentStatus) {
        return 'Unchanged'
    }
    return 'StatusChanged'
}

function New-ControlIndex {
    param([object[]]$Rows)

    $index = @{}
    foreach ($row in $Rows) {
        $index[$row.ControlId.ToLowerInvariant()] = $row
    }
    return $index
}

$current = @(Import-ControlSnapshot -Path $CurrentPath)
$previous = @(Import-ControlSnapshot -Path $PreviousPath)
$currentIndex = New-ControlIndex -Rows $current
$previousIndex = New-ControlIndex -Rows $previous

$allKeys = @($currentIndex.Keys + $previousIndex.Keys | Sort-Object -Unique)
$transitions = foreach ($key in $allKeys) {
    $currentRow = $currentIndex[$key]
    $previousRow = $previousIndex[$key]
    $source = if ($null -ne $currentRow) { $currentRow } else { $previousRow }
    $previousStatus = if ($null -ne $previousRow) { $previousRow.Status } else { $null }
    $currentStatus = if ($null -ne $currentRow) { $currentRow.Status } else { $null }

    [pscustomobject]@{
        ControlId       = $source.ControlId
        ControlName     = $source.ControlName
        Severity        = $source.Severity
        Owner           = $source.Owner
        System          = $source.System
        PreviousStatus  = $previousStatus
        CurrentStatus   = $currentStatus
        Transition      = Get-Transition -PreviousStatus $previousStatus -CurrentStatus $currentStatus
        AssessmentDate  = if ($null -ne $currentRow) { $currentRow.AssessmentDate } else { $previousRow.AssessmentDate }
    }
}

$summary = [ordered]@{
    GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    CurrentSnapshot   = (Resolve-Path -LiteralPath $CurrentPath).Path
    PreviousSnapshot  = (Resolve-Path -LiteralPath $PreviousPath).Path
    TotalControls     = $transitions.Count
    NewFindings       = @($transitions | Where-Object Transition -eq 'NewFinding').Count
    Resolved          = @($transitions | Where-Object Transition -eq 'Resolved').Count
    StatusChanged     = @($transitions | Where-Object Transition -eq 'StatusChanged').Count
    NewControls       = @($transitions | Where-Object Transition -eq 'NewControl').Count
    MissingFromCurrent = @($transitions | Where-Object Transition -eq 'MissingFromCurrent').Count
    Unchanged         = @($transitions | Where-Object Transition -eq 'Unchanged').Count
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transitionPath = Join-Path $OutputDirectory "control-transitions-$timestamp.csv"
$summaryPath = Join-Path $OutputDirectory "control-summary-$timestamp.json"
$htmlPath = Join-Path $OutputDirectory "control-trend-$timestamp.html"

$transitions |
    Sort-Object Transition, Severity, ControlId |
    Export-Csv -LiteralPath $transitionPath -NoTypeInformation -Encoding utf8

$summary |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $summaryPath -Encoding utf8

$summaryTable = [pscustomobject]@{
    'Total Controls'       = $summary.TotalControls
    'New Findings'        = $summary.NewFindings
    'Resolved'            = $summary.Resolved
    'Status Changed'      = $summary.StatusChanged
    'New Controls'        = $summary.NewControls
    'Missing From Current' = $summary.MissingFromCurrent
    'Unchanged'           = $summary.Unchanged
}

$style = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #172033; }
h1, h2 { color: #17365d; }
table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
th { background: #17365d; color: white; text-align: left; }
th, td { border: 1px solid #ccd5e0; padding: .5rem; }
tr:nth-child(even) { background: #f4f7fa; }
.note { color: #4d5b6a; }
</style>
'@

$html = @(
    '<h1>Security Control Trend Report</h1>'
    "<p class='note'>Generated $($summary.GeneratedAtUtc). Validate every transition before remediation or risk acceptance.</p>"
    '<h2>Summary</h2>'
    ($summaryTable | ConvertTo-Html -Fragment)
    '<h2>Transitions</h2>'
    ($transitions | Sort-Object Transition, Severity, ControlId | ConvertTo-Html -Fragment)
) -join [Environment]::NewLine

ConvertTo-Html -Title 'Security Control Trend Report' -Head $style -Body $html |
    Set-Content -LiteralPath $htmlPath -Encoding utf8

[pscustomobject]@{
    TransitionCsv = $transitionPath
    SummaryJson   = $summaryPath
    HtmlReport    = $htmlPath
    Summary       = [pscustomobject]$summary
}
