#requires -Version 7.0

<#
.SYNOPSIS
    CloudLens - Azure Environment Analyzer

.DESCRIPTION
    Read-only Azure environment analysis tool.

    Version 0.8

    Features:
      - Azure Resource Graph discovery with robust paging
      - Azure Advisor recommendations
      - Custom security analysis
      - Workload metric collection
      - 90-day historical analysis
      - 30-day metric windows
      - Metric aggregation
      - Trend analysis
      - Workload classification
      - No DetailedOutput parameter
      - No raw metric data retained after aggregation
      - Excel report generation

.NOTES
    Owner   : Francesco Leuci
    Version : 0.8
    Mode    : READ-ONLY
#>

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$ScriptVersion = "0.8"
$Owner         = "Francesco Leuci"
$Mode          = "READ-ONLY"

$LookbackDays  = 90
$ChunkDays     = 30
$TimeGrain     = [TimeSpan]::FromHours(1)

$OutputDirectory = Join-Path $PSScriptRoot "output"

if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# ============================================================
# MODULE VALIDATION
# ============================================================

$RequiredModules = @(
    "Az.Accounts",
    "Az.ResourceGraph",
    "Az.Monitor",
    "Az.Advisor"
)

foreach ($module in $RequiredModules) {

    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host ""
        Write-Host "ERROR: Required module not installed: $module" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

    Import-Module $module -ErrorAction Stop
}

# ============================================================
# HEADER
# ============================================================

Clear-Host

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CloudLens - Azure Environment Analyzer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Version : $ScriptVersion"
Write-Host "Owner   : $Owner"
Write-Host "Date    : $(Get-Date -Format 'yyyy-MM-dd')"
Write-Host "Mode    : $Mode"
Write-Host ""

# ============================================================
# AZURE LOGIN
# ============================================================

try {

    $context = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $context) {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

}
catch {

    Write-Host ""
    Write-Host "Unable to connect to Azure." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# ============================================================
# SUBSCRIPTION SELECTION
# ============================================================

$subscriptions = @(Get-AzSubscription | Where-Object {
    $_.State -eq "Enabled"
})

if ($subscriptions.Count -eq 0) {

    Write-Host "No enabled Azure subscriptions found." -ForegroundColor Red
    exit 1
}

Write-Host "Available subscriptions:"
Write-Host ""

for ($i = 0; $i -lt $subscriptions.Count; $i++) {

    Write-Host ("[{0}] {1}" -f ($i + 1), $subscriptions[$i].Name)
}

Write-Host ""

do {

    $selection = Read-Host "Select subscription"

    $selectionNumber = 0

    $validSelection = [int]::TryParse(
        $selection,
        [ref]$selectionNumber
    )

}
while (
    -not $validSelection -or
    $selectionNumber -lt 1 -or
    $selectionNumber -gt $subscriptions.Count
)

$subscription = $subscriptions[$selectionNumber - 1]

Set-AzContext `
    -SubscriptionId $subscription.Id `
    -ErrorAction Stop | Out-Null

Write-Host ""
Write-Host "Selected subscription:"
Write-Host "Name : $($subscription.Name)"
Write-Host "ID   : $($subscription.Id)"
Write-Host ""

# ============================================================
# RESOURCE GRAPH DISCOVERY
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Discovering Azure resources..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$resourceQuery = @"
Resources
| project
    id,
    name,
    type,
    resourceGroup,
    location,
    subscriptionId,
    tags
| order by type asc, name asc
"@

# ArrayList avoids the PowerShell argument-type problem
# encountered with the previous implementation.
$resourceList = New-Object System.Collections.ArrayList

$pageSize = 1000
$skipToken = $null
$page = 0

do {

    $page++

    Write-Host "  Resource Graph page $page..."

    try {

        if ($null -eq $skipToken) {

            $response = Search-AzGraph `
                -Query $resourceQuery `
                -Subscription $subscription.Id `
                -First $pageSize `
                -ErrorAction Stop

        }
        else {

            $response = Search-AzGraph `
                -Query $resourceQuery `
                -Subscription $subscription.Id `
                -First $pageSize `
                -SkipToken $skipToken `
                -ErrorAction Stop
        }

    }
    catch {

        Write-Host ""
        Write-Host "Resource Graph query failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }

    $pageItems = @($response)

    Write-Host "  Page $page returned $($pageItems.Count) resources."

    foreach ($item in $pageItems) {

        [void]$resourceList.Add($item)
    }

    $skipToken = $null

    if ($response -and
        $response.PSObject.Properties.Name -contains "SkipToken") {

        $skipToken = $response.SkipToken
    }

}
while (
    $null -ne $skipToken -and
    $skipToken -ne ""
)

$resources = $resourceList.ToArray()

Write-Host ""
Write-Host "Resources found: $($resources.Count)"
Write-Host ""

if ($resources.Count -eq 0) {

    Write-Host "No resources found." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# METRIC PROFILES
# ============================================================

$MetricProfiles = @{

    "microsoft.compute/virtualmachines" = @(
        "Percentage CPU",
        "Network In Total",
        "Network Out Total",
        "Disk Read Bytes",
        "Disk Write Bytes",
        "Disk Read Operations/Sec",
        "Disk Write Operations/Sec"
    )

    "microsoft.network/publicipaddresses" = @(
        "ByteCount",
        "PacketCount"
    )

    "microsoft.storage/storageaccounts" = @(
        "Transactions",
        "Ingress",
        "Egress",
        "UsedCapacity",
        "Availability"
    )

}

# ============================================================
# METRIC COLLECTION FUNCTION
# ============================================================

function Get-MetricAggregates {

    param(
        [Parameter(Mandatory)]
        [string]$ResourceId,

        [Parameter(Mandatory)]
        [string]$ResourceName,

        [Parameter(Mandatory)]
        [string]$ResourceType,

        [Parameter(Mandatory)]
        [string[]]$MetricNames
    )

    $aggregates = New-Object System.Collections.ArrayList

    $endTime = Get-Date

    $startTime = $endTime.AddDays(-$LookbackDays)

    $windows = @()

    $windowStart = $startTime

    while ($windowStart -lt $endTime) {

        $windowEnd = $windowStart.AddDays($ChunkDays)

        if ($windowEnd -gt $endTime) {
            $windowEnd = $endTime
        }

        $windows += [PSCustomObject]@{
            Start = $windowStart
            End   = $windowEnd
        }

        $windowStart = $windowEnd
    }

    foreach ($window in $windows) {

        Write-Host ("        Window: {0} -> {1}" -f `
            $window.Start.ToString("yyyy-MM-dd"),
            $window.End.ToString("yyyy-MM-dd"))

        foreach ($metricName in $MetricNames) {

            try {

                # IMPORTANT:
                # No -DetailedOutput.
                #
                # Aggregation is performed directly by Azure Monitor.
                # This dramatically reduces the amount of data returned.

                $metricResult = Get-AzMetric `
                    -ResourceId $ResourceId `
                    -MetricName $metricName `
                    -TimeGrain $TimeGrain `
                    -StartTime $window.Start `
                    -EndTime $window.End `
                    -AggregationType Average `
                    -ErrorAction Stop `
                    -WarningAction SilentlyContinue

                if ($null -eq $metricResult) {
                    continue
                }

                foreach ($metric in @($metricResult)) {

                    if ($null -eq $metric.Timeseries) {
                        continue
                    }

                    foreach ($series in @($metric.Timeseries)) {

                        if ($null -eq $series.Data) {
                            continue
                        }

                        $values = @(
                            $series.Data |
                            Where-Object {
                                $null -ne $_.Average
                            } |
                            ForEach-Object {
                                [double]$_.Average
                            }
                        )

                        if ($values.Count -eq 0) {
                            continue
                        }

                        $average = ($values | Measure-Object -Average).Average
                        $minimum = ($values | Measure-Object -Minimum).Minimum
                        $maximum = ($values | Measure-Object -Maximum).Maximum

                        $firstValue = $values[0]
                        $lastValue  = $values[$values.Count - 1]

                        $trend = "Stable"

                        if ($firstValue -ne 0) {

                            $changePercent =
                                (($lastValue - $firstValue) /
                                [math]::Abs($firstValue)) * 100

                            if ($changePercent -gt 10) {
                                $trend = "Increasing"
                            }
                            elseif ($changePercent -lt -10) {
                                $trend = "Decreasing"
                            }
                        }

                        [void]$aggregates.Add(
                            [PSCustomObject]@{

                                ResourceName = $ResourceName
                                ResourceType = $ResourceType
                                ResourceId   = $ResourceId
                                MetricName   = $metricName

                                WindowStart  = $window.Start
                                WindowEnd    = $window.End

                                Average      = [math]::Round($average, 4)
                                Minimum      = [math]::Round($minimum, 4)
                                Maximum      = [math]::Round($maximum, 4)

                                FirstValue   = [math]::Round($firstValue, 4)
                                LastValue    = [math]::Round($lastValue, 4)

                                Trend        = $trend
                                SampleCount  = $values.Count
                            }
                        )
                    }
                }

            }
            catch {

                # Do not abort the complete analysis because a metric
                # is unavailable for one resource.

                $message = $_.Exception.Message

                if ($message.Length -gt 180) {
                    $message = $message.Substring(0,180) + "..."
                }

                Write-Host "        Metric unavailable: $metricName" -ForegroundColor DarkYellow
                Write-Host "        Reason: $message" -ForegroundColor DarkYellow
            }
        }
    }

    return $aggregates.ToArray()
}

# ============================================================
# METRIC COLLECTION
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Collecting Azure Monitor workload metrics..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Lookback period : $LookbackDays days"
Write-Host "Time grain      : $($TimeGrain.ToString())"
Write-Host "Chunk size      : $ChunkDays days"
Write-Host ""

$metricResources = @(
    $resources |
    Where-Object {
        $MetricProfiles.ContainsKey(
            $_.type.ToLower()
        )
    }
)

Write-Host "Resources with metric profiles: $($metricResources.Count)"
Write-Host ""

# We deliberately DO NOT retain raw metric datapoints.
# Only aggregated profiles are kept.

$aggregatedMetrics = New-Object System.Collections.ArrayList

foreach ($resource in $metricResources) {

    $resourceType = $resource.type.ToLower()

    $metricNames = $MetricProfiles[$resourceType]

    Write-Host ""
    Write-Host "    Collecting $resourceType metrics: $($resource.name)"

    $result = Get-MetricAggregates `
        -ResourceId $resource.id `
        -ResourceName $resource.name `
        -ResourceType $resourceType `
        -MetricNames $metricNames

    foreach ($record in @($result)) {

        [void]$aggregatedMetrics.Add($record)
    }
}

# Convert once, after aggregation.
$aggregatedMetrics = $aggregatedMetrics.ToArray()

Write-Host ""
Write-Host "Metric aggregation completed."
Write-Host "Aggregated metric profiles: $($aggregatedMetrics.Count)"
Write-Host ""

# ============================================================
# BUILD WORKLOAD PROFILES
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Building workload profiles..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$workloadProfiles = New-Object System.Collections.ArrayList

$metricGroups = @(
    $aggregatedMetrics |
    Group-Object ResourceId
)

foreach ($group in $metricGroups) {

    $records = @($group.Group)

    if ($records.Count -eq 0) {
        continue
    }

    $first = $records[0]

    $metricCount = (
        $records |
        Select-Object -ExpandProperty MetricName -Unique
    ).Count

    $trends = @(
        $records |
        Group-Object Trend |
        Sort-Object Count -Descending
    )

    $overallTrend = "Stable"

    if ($trends.Count -gt 0) {
        $overallTrend = $trends[0].Name
    }

    # --------------------------------------------------------
    # Workload classification
    # --------------------------------------------------------

    $classification = "Metrics Available"

    $avgValues = @(
        $records |
        Where-Object {
            $_.MetricName -match "CPU" -and
            $null -ne $_.Average
        } |
        Select-Object -ExpandProperty Average
    )

    if ($avgValues.Count -gt 0) {

        $avgCpu =
            ($avgValues | Measure-Object -Average).Average

        $maxCpu =
            ($records |
                Where-Object {
                    $_.MetricName -match "CPU"
                } |
                Measure-Object -Property Maximum -Maximum
            ).Maximum

        if ($avgCpu -lt 10 -and $maxCpu -lt 30) {

            $classification = "Low"

        }
        elseif ($avgCpu -gt 70 -or $maxCpu -gt 90) {

            $classification = "High"

        }
        else {

            $classification = "Normal"
        }
    }

    [void]$workloadProfiles.Add(
        [PSCustomObject]@{

            ResourceName           = $first.ResourceName
            ResourceType           = $first.ResourceType
            ResourceId             = $first.ResourceId

            MetricCount            = $metricCount
            WorkloadClassification = $classification
            OverallTrend           = $overallTrend

            LookbackDays           = $LookbackDays
        }
    )
}

$workloadProfiles = $workloadProfiles.ToArray()

Write-Host "Workload profiles generated: $($workloadProfiles.Count)"
Write-Host ""

# ============================================================
# AZURE ADVISOR
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Collecting Azure Advisor recommendations..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$findings = New-Object System.Collections.ArrayList

try {

    $advisorRecommendations = @(
        Get-AzAdvisorRecommendation `
            -ErrorAction Stop
    )

}
catch {

    Write-Host "Unable to retrieve Azure Advisor recommendations." `
        -ForegroundColor Yellow

    $advisorRecommendations = @()
}

Write-Host "Advisor recommendations found: $($advisorRecommendations.Count)"
Write-Host ""

foreach ($recommendation in $advisorRecommendations) {

    $resourceName = ""

    if ($recommendation.PSObject.Properties.Name -contains "ImpactedValue") {
        $resourceName = $recommendation.ImpactedValue
    }

    if ([string]::IsNullOrWhiteSpace($resourceName)) {
        $resourceName = ""
    }

    $description = ""

    if ($recommendation.PSObject.Properties.Name -contains "ShortDescription") {
        $description = $recommendation.ShortDescription
    }

    $category = "Reliability"

    if ($recommendation.PSObject.Properties.Name -contains "Category") {
        $category = [string]$recommendation.Category
    }

    $severity = "Medium"

    if ($recommendation.PSObject.Properties.Name -contains "Impact") {

        switch ([string]$recommendation.Impact) {

            "High" {
                $severity = "High"
            }

            "Medium" {
                $severity = "Medium"
            }

            "Low" {
                $severity = "Low"
            }
        }
    }

    [void]$findings.Add(
        [PSCustomObject]@{

            RuleId          = "AZ-ADVISOR"
            Source          = "Azure Advisor"
            ResourceType    = ""
            ResourceName    = $resourceName
            Category        = $category
            Severity        = $severity
            Description     = $description
            Evidence        = ""
            EstimatedSavings = ""
            Recommendation  = $description
        }
    )
}

# ============================================================
# CUSTOM SECURITY ANALYSIS
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Running custom security rules..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$securityQuery = @"
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| extend
    ruleName = tostring(rules.name),
    access = tostring(rules.properties.access),
    direction = tostring(rules.properties.direction),
    protocol = tostring(rules.properties.protocol),
    source = tostring(rules.properties.sourceAddressPrefix),
    destinationPort = tostring(rules.properties.destinationPortRange)
| where access =~ 'Allow'
| where direction =~ 'Inbound'
| where source == '*'
| where destinationPort in ('22','3389')
| project
    id,
    name,
    type,
    ruleName,
    protocol,
    source,
    destinationPort
"@

try {

    $securityResults = @(
        Search-AzGraph `
            -Query $securityQuery `
            -Subscription $subscription.Id `
            -First 1000 `
            -ErrorAction Stop
    )

}
catch {

    Write-Host "Security analysis failed." -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Yellow

    $securityResults = @()
}

foreach ($finding in $securityResults) {

    $port = $finding.destinationPort

    if ($port -eq "22") {

        $description =
            "SSH management port exposed to unrestricted inbound traffic."

    }
    elseif ($port -eq "3389") {

        $description =
            "RDP management port exposed to unrestricted inbound traffic."

    }
    else {

        $description =
            "Management port exposed to unrestricted inbound traffic."
    }

    $recommendation =
        "Restrict inbound access using trusted source IP ranges, VPN, Bastion or another controlled management path."

    [void]$findings.Add(
        [PSCustomObject]@{

            RuleId           = "CUSTOM-NET-001"
            Source           = "Custom"
            ResourceType     = $finding.type
            ResourceName     = $finding.name

            Category         = "Security"
            Severity         = "Critical"

            Description      = $description
            Evidence         = "NSG rule '$($finding.ruleName)' allows inbound traffic from '$($finding.source)' to port $port."

            EstimatedSavings = ""

            Recommendation   = $recommendation
        }
    )
}

Write-Host "Custom security findings: $($securityResults.Count)"
Write-Host ""

# ============================================================
# ANALYSIS SUMMARY
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Resources analyzed : $($resources.Count)"
Write-Host "Metric profiles    : $($aggregatedMetrics.Count)"
Write-Host "Workload profiles  : $($workloadProfiles.Count)"
Write-Host "Findings generated : $($findings.Count)"
Write-Host ""

if ($findings.Count -gt 0) {

    Write-Host "Findings by category:"
    Write-Host ""

    $findings |
        Group-Object Category |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Findings by severity:"
    Write-Host ""

    $findings |
        Group-Object Severity |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Workload analysis summary:"
Write-Host ""

if ($workloadProfiles.Count -gt 0) {

    $workloadProfiles |
        Select-Object `
            ResourceName,
            ResourceType,
            MetricCount,
            WorkloadClassification,
            OverallTrend |
        Format-Table -AutoSize

}
else {

    Write-Host "No workload metrics available."
}

# ============================================================
# EXCEL REPORT
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Generating Excel report..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {

    Write-Host ""
    Write-Host "ImportExcel module is required." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install with:"
    Write-Host "Install-Module ImportExcel -Scope CurrentUser"
    Write-Host ""

    exit 1
}

Import-Module ImportExcel -ErrorAction Stop

$reportPath = Join-Path `
    $OutputDirectory `
    "CloudLens-$($subscription.Id)-v$ScriptVersion.xlsx"

if (Test-Path $reportPath) {
    Remove-Item $reportPath -Force
}

# ============================================================
# FINDINGS SHEET
# ============================================================

$findingsExport = @(
    $findings |
    Select-Object `
        ResourceType,
        ResourceName,
        Category,
        Severity,
        @{N="Description + Evidence";E={
            if (
                [string]::IsNullOrWhiteSpace($_.Evidence)
            ) {
                $_.Description
            }
            else {
                "$($_.Description) Evidence: $($_.Evidence)"
            }
        }},
        EstimatedSavings,
        Recommendation
)

$findingsExport |
    Export-Excel `
        -Path $reportPath `
        -WorksheetName "Findings" `
        -AutoSize `
        -FreezeTopRow `
        -BoldTopRow `
        -AutoFilter

# ============================================================
# WORKLOAD SHEET
# ============================================================

$workloadProfiles |
    Select-Object `
        ResourceName,
        ResourceType,
        MetricCount,
        WorkloadClassification,
        OverallTrend,
        LookbackDays |
    Export-Excel `
        -Path $reportPath `
        -WorksheetName "Workload Analysis" `
        -AutoSize `
        -FreezeTopRow `
        -BoldTopRow `
        -AutoFilter

# ============================================================
# METRIC PROFILE SHEET
# ============================================================

$metricExport = @(
    $aggregatedMetrics |
    Select-Object `
        ResourceName,
        ResourceType,
        MetricName,
        WindowStart,
        WindowEnd,
        Average,
        Minimum,
        Maximum,
        FirstValue,
        LastValue,
        Trend,
        SampleCount
)

if ($metricExport.Count -gt 0) {

    $metricExport |
        Export-Excel `
            -Path $reportPath `
            -WorksheetName "Metric Profiles" `
            -AutoSize `
            -FreezeTopRow `
            -BoldTopRow `
            -AutoFilter
}

# ============================================================
# RESOURCE INVENTORY SHEET
# ============================================================

$resources |
    Select-Object `
        name,
        type,
        resourceGroup,
        location,
        subscriptionId |
    Export-Excel `
        -Path $reportPath `
        -WorksheetName "Resources" `
        -AutoSize `
        -FreezeTopRow `
        -BoldTopRow `
        -AutoFilter

# ============================================================
# SUMMARY SHEET
# ============================================================

$summary = @(
    [PSCustomObject]@{
        Property = "CloudLens Version"
        Value    = $ScriptVersion
    }

    [PSCustomObject]@{
        Property = "Subscription"
        Value    = $subscription.Name
    }

    [PSCustomObject]@{
        Property = "Subscription ID"
        Value    = $subscription.Id
    }

    [PSCustomObject]@{
        Property = "Analysis Date"
        Value    = Get-Date
    }

    [PSCustomObject]@{
        Property = "Mode"
        Value    = $Mode
    }

    [PSCustomObject]@{
        Property = "Resources Analyzed"
        Value    = $resources.Count
    }

    [PSCustomObject]@{
        Property = "Metric Lookback"
        Value    = "$LookbackDays days"
    }

    [PSCustomObject]@{
        Property = "Metric Time Grain"
        Value    = "1 hour"
    }

    [PSCustomObject]@{
        Property = "Metric Chunk"
        Value    = "$ChunkDays days"
    }

    [PSCustomObject]@{
        Property = "Aggregated Metric Profiles"
        Value    = $aggregatedMetrics.Count
    }

    [PSCustomObject]@{
        Property = "Workload Profiles"
        Value    = $workloadProfiles.Count
    }

    [PSCustomObject]@{
        Property = "Findings"
        Value    = $findings.Count
    }
)

$summary |
    Export-Excel `
        -Path $reportPath `
        -WorksheetName "Summary" `
        -AutoSize `
        -BoldTopRow

# ============================================================
# FINAL OUTPUT
# ============================================================

Write-Host ""
Write-Host "Excel report generated successfully." -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS COMPLETED" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Report saved:"
Write-Host $reportPath

Write-Host ""
Write-Host "Metric lookback : $LookbackDays days"
Write-Host "Metric chunk    : $ChunkDays days"
Write-Host "Metric grain    : 1 hour"
Write-Host "Aggregated      : $($aggregatedMetrics.Count)"
Write-Host "Workload profiles: $($workloadProfiles.Count)"
Write-Host ""

Write-Host "CloudLens V$ScriptVersion completed successfully." -ForegroundColor Green