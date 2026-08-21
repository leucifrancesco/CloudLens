<#
===========================================================================
 CloudLens - Azure Environment Analyzer
===========================================================================

 Owner        : Francesco Leuci
 Version      : 0.7
 Modified     : 2026-08-21
 Mode         : READ-ONLY

 Purpose:
   Azure environment assessment and workload analysis.

 Main capabilities:
   - Azure Resource Graph discovery
   - Resource Graph pagination using SkipToken
   - Azure Monitor metric collection
   - 90-day workload analysis
   - 30-day metric windows
   - 1-hour aggregation
   - Workload classification
   - Trend analysis
   - Azure Advisor recommendations
   - Custom security rules
   - Excel reporting

 Important:
   - This version does NOT modify Azure resources.
   - Raw metric datapoints are NOT included in the final report.
   - Only aggregated workload information is retained.

 Required modules:
   - Az.Accounts
   - Az.ResourceGraph
   - Az.Monitor
   - Az.Advisor
   - ImportExcel

 Tested module versions:
   Az.ResourceGraph : 1.2.1
   Az.Monitor       : 7.0.0

===========================================================================
#>

# -------------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------------

$CloudLensVersion = "0.7"
$CloudLensOwner   = "Francesco Leuci"
$ModifiedDate     = "2026-08-21"

$LookbackDays     = 90
$ChunkDays        = 30
$TimeGrain        = New-TimeSpan -Hours 1

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputPath = Join-Path $ScriptRoot "output"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# -------------------------------------------------------------------------
# MODULE CHECK
# -------------------------------------------------------------------------

$RequiredModules = @(
    "Az.Accounts",
    "Az.ResourceGraph",
    "Az.Monitor",
    "Az.Advisor",
    "ImportExcel"
)

foreach ($Module in $RequiredModules) {

    if (-not (Get-Module -ListAvailable -Name $Module)) {

        Write-Host ""
        Write-Host "ERROR: Required module not found: $Module" -ForegroundColor Red
        Write-Host ""

        if ($Module -eq "ImportExcel") {
            Write-Host "Install with:"
            Write-Host "Install-Module ImportExcel -Scope CurrentUser"
        }
        else {
            Write-Host "Install the required Az module before continuing."
        }

        exit 1
    }
}

Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.ResourceGraph -ErrorAction Stop
Import-Module Az.Monitor -ErrorAction Stop
Import-Module Az.Advisor -ErrorAction Stop
Import-Module ImportExcel -ErrorAction Stop

# -------------------------------------------------------------------------
# HEADER
# -------------------------------------------------------------------------

Clear-Host

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CloudLens - Azure Environment Analyzer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Version : $CloudLensVersion"
Write-Host "Owner   : $CloudLensOwner"
Write-Host "Date    : $ModifiedDate"
Write-Host "Mode    : READ-ONLY"
Write-Host ""

# -------------------------------------------------------------------------
# AZURE LOGIN
# -------------------------------------------------------------------------

try {
    $AzureContext = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $AzureContext) {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Host ""
    Write-Host "Unable to authenticate to Azure." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------------------
# SUBSCRIPTION SELECTION
# -------------------------------------------------------------------------

$Subscriptions = @(Get-AzSubscription | Where-Object {
    $_.State -eq "Enabled"
})

if ($Subscriptions.Count -eq 0) {

    Write-Host ""
    Write-Host "No enabled Azure subscriptions found." -ForegroundColor Red
    exit 1
}

Write-Host "Available subscriptions:"
Write-Host ""

for ($i = 0; $i -lt $Subscriptions.Count; $i++) {
    Write-Host "[$($i + 1)] $($Subscriptions[$i].Name)"
}

Write-Host ""

do {
    $Selection = Read-Host "Select subscription"

    $SelectionValid =
        ($Selection -as [int]) -and
        ([int]$Selection -ge 1) -and
        ([int]$Selection -le $Subscriptions.Count)

}
until ($SelectionValid)

$SelectedSubscription = $Subscriptions[[int]$Selection - 1]

Set-AzContext `
    -SubscriptionId $SelectedSubscription.Id `
    -ErrorAction Stop | Out-Null

$SubscriptionId   = $SelectedSubscription.Id
$SubscriptionName = $SelectedSubscription.Name

Write-Host ""
Write-Host "Selected subscription:"
Write-Host "Name : $SubscriptionName"
Write-Host "ID   : $SubscriptionId"
Write-Host ""

# =========================================================================
# FUNCTION: SEARCH RESOURCE GRAPH
# =========================================================================

function Search-CloudLensResourceGraph {

    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionIds
    )

    $AllResults = @()
    $SkipToken  = $null
    $Page       = 1
    $PageSize   = 1000

    do {

        Write-Host "  Resource Graph page $Page..." -ForegroundColor Gray

        try {

            if ($null -eq $SkipToken) {

                $Response = Search-AzGraph `
                    -Query $Query `
                    -Subscription $SubscriptionIds `
                    -First $PageSize `
                    -ErrorAction Stop

            }
            else {

                $Response = Search-AzGraph `
                    -Query $Query `
                    -Subscription $SubscriptionIds `
                    -First $PageSize `
                    -SkipToken $SkipToken `
                    -ErrorAction Stop
            }

        }
        catch {

            Write-Host ""
            Write-Host "Resource Graph query failed." -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            throw
        }

        # Search-AzGraph may return a response object containing Data
        # or directly return the records depending on module behaviour.

        if ($Response.PSObject.Properties.Name -contains "Data") {

            $PageData = @($Response.Data)

        }
        else {

            $PageData = @($Response)
        }

        if ($PageData.Count -gt 0) {
            $AllResults += $PageData
        }

        Write-Host "  Page $Page returned $($PageData.Count) resources."

        $NextToken = $null

        if ($Response.PSObject.Properties.Name -contains "SkipToken") {
            $NextToken = $Response.SkipToken
        }

        if ($Response.PSObject.Properties.Name -contains "SkipTokenValue") {
            if (-not $NextToken) {
                $NextToken = $Response.SkipTokenValue
            }
        }

        $SkipToken = $NextToken

        $Page++

    }
    while (
        $SkipToken -and
        $PageData.Count -gt 0
    )

    return $AllResults
}

# =========================================================================
# RESOURCE DISCOVERY
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Discovering Azure resources..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ResourceQuery = @"
resources
| project
    id,
    name,
    type,
    resourceGroup,
    location,
    subscriptionId,
    sku,
    kind,
    tags
| order by type asc, name asc
"@

$Resources = @(Search-CloudLensResourceGraph `
    -Query $ResourceQuery `
    -SubscriptionIds @($SubscriptionId))

Write-Host ""
Write-Host "Resources found: $($Resources.Count)"
Write-Host ""

# =========================================================================
# METRIC PROFILE DEFINITIONS
# =========================================================================

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

    "microsoft.storage/storageaccounts" = @(
        "Transactions",
        "Ingress",
        "Egress",
        "UsedCapacity",
        "Availability"
    )

    "microsoft.network/publicipaddresses" = @(
        "ByteCount",
        "PacketCount"
    )
}

# =========================================================================
# FUNCTION: GET METRIC
# =========================================================================

function Get-CloudLensMetric {

    param(
        [Parameter(Mandatory)]
        [string]$ResourceId,

        [Parameter(Mandatory)]
        [string]$MetricName,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [Parameter(Mandatory)]
        [datetime]$EndTime,

        [Parameter(Mandatory)]
        [timespan]$TimeGrain
    )

    try {

        # IMPORTANT:
        # No -DetailedOutput.
        #
        # Az.Monitor 7.0.0 still exposes the parameter for compatibility,
        # but it is deprecated and must not be used.

        $Metric = Get-AzMetric `
            -ResourceId $ResourceId `
            -MetricName $MetricName `
            -StartTime $StartTime `
            -EndTime $EndTime `
            -TimeGrain $TimeGrain `
            -AggregationType Average `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue

        return $Metric
    }
    catch {

        return $null
    }
}

# =========================================================================
# FUNCTION: EXTRACT METRIC VALUES
# =========================================================================

function ConvertTo-CloudLensMetricPoints {

    param(
        [Parameter(Mandatory)]
        $MetricResult,

        [Parameter(Mandatory)]
        [string]$ResourceId,

        [Parameter(Mandatory)]
        [string]$ResourceName,

        [Parameter(Mandatory)]
        [string]$ResourceType,

        [Parameter(Mandatory)]
        [string]$MetricName
    )

    $Points = @()

    if (-not $MetricResult) {
        return $Points
    }

    foreach ($Metric in @($MetricResult)) {

        if (-not $Metric.Timeseries) {
            continue
        }

        foreach ($TimeSeries in $Metric.Timeseries) {

            foreach ($Data in @($TimeSeries.Data)) {

                $Value = $null

                if ($null -ne $Data.Average) {
                    $Value = $Data.Average
                }
                elseif ($null -ne $Data.Total) {
                    $Value = $Data.Total
                }
                elseif ($null -ne $Data.Maximum) {
                    $Value = $Data.Maximum
                }
                elseif ($null -ne $Data.Minimum) {
                    $Value = $Data.Minimum
                }

                if ($null -eq $Value) {
                    continue
                }

                $Timestamp = $Data.TimeStamp

                if (-not $Timestamp) {
                    continue
                }

                $Points += [PSCustomObject]@{
                    ResourceId   = $ResourceId
                    ResourceName = $ResourceName
                    ResourceType = $ResourceType
                    MetricName   = $MetricName
                    Timestamp    = $Timestamp
                    Value        = [double]$Value
                }
            }
        }
    }

    return $Points
}

# =========================================================================
# METRIC COLLECTION
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Collecting Azure Monitor workload metrics..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$EndTime   = Get-Date
$StartTime = $EndTime.AddDays(-$LookbackDays)

Write-Host "Lookback period : $LookbackDays days"
Write-Host "Time grain      : $($TimeGrain.ToString())"
Write-Host "Chunk size      : $ChunkDays days"
Write-Host ""

$MetricResources = @(
    $Resources | Where-Object {
        $MetricProfiles.ContainsKey($_.type.ToLower())
    }
)

Write-Host "Resources with metric profiles: $($MetricResources.Count)"
Write-Host ""

$RawMetricData = @()

foreach ($Resource in $MetricResources) {

    $ResourceType = $Resource.type.ToLower()
    $ResourceId   = $Resource.id
    $ResourceName = $Resource.name

    $Metrics = $MetricProfiles[$ResourceType]

    Write-Host ""
    Write-Host "    Collecting $ResourceType metrics: $ResourceName" `
        -ForegroundColor Gray

    $WindowStart = $StartTime

    while ($WindowStart -lt $EndTime) {

        $WindowEnd = $WindowStart.AddDays($ChunkDays)

        if ($WindowEnd -gt $EndTime) {
            $WindowEnd = $EndTime
        }

        Write-Host "        Window: $($WindowStart.ToString('yyyy-MM-dd')) -> $($WindowEnd.ToString('yyyy-MM-dd'))"

        foreach ($MetricName in $Metrics) {

            $MetricResult = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $MetricName `
                -StartTime $WindowStart `
                -EndTime $WindowEnd `
                -TimeGrain $TimeGrain

            if ($MetricResult) {

                $Points = ConvertTo-CloudLensMetricPoints `
                    -MetricResult $MetricResult `
                    -ResourceId $ResourceId `
                    -ResourceName $ResourceName `
                    -ResourceType $ResourceType `
                    -MetricName $MetricName

                if ($Points.Count -gt 0) {
                    $RawMetricData += $Points
                }
            }
        }

        $WindowStart = $WindowEnd
    }
}

Write-Host ""
Write-Host "Raw metric collection completed."
Write-Host "Raw metric records: $($RawMetricData.Count)"
Write-Host ""

# =========================================================================
# METRIC AGGREGATION
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Aggregating workload metrics..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$AggregatedProfiles = @()

$GroupedMetrics = $RawMetricData |
    Group-Object ResourceId, ResourceName, ResourceType, MetricName

foreach ($Group in $GroupedMetrics) {

    $Rows = @($Group.Group)

    if ($Rows.Count -eq 0) {
        continue
    }

    $Values = @($Rows | ForEach-Object {
        [double]$_.Value
    })

    $Average = ($Values | Measure-Object -Average).Average
    $Minimum = ($Values | Measure-Object -Minimum).Minimum
    $Maximum = ($Values | Measure-Object -Maximum).Maximum

    $SortedValues = @(
        $Values | Sort-Object
    )

    $P95Index = [math]::Floor(($SortedValues.Count - 1) * 0.95)

    if ($P95Index -lt 0) {
        $P95Index = 0
    }

    $P95 = $SortedValues[$P95Index]

    # ---------------------------------------------------------------------
    # Trend
    # ---------------------------------------------------------------------

    $OrderedRows = @(
        $Rows | Sort-Object Timestamp
    )

    $FirstValues = @(
        $OrderedRows |
        Select-Object -First ([math]::Max(1,[math]::Floor($OrderedRows.Count * 0.20))) |
        ForEach-Object { [double]$_.Value }
    )

    $LastValues = @(
        $OrderedRows |
        Select-Object -Last ([math]::Max(1,[math]::Floor($OrderedRows.Count * 0.20))) |
        ForEach-Object { [double]$_.Value }
    )

    $FirstAverage = ($FirstValues | Measure-Object -Average).Average
    $LastAverage  = ($LastValues | Measure-Object -Average).Average

    if ($FirstAverage -eq 0) {

        if ($LastAverage -eq 0) {
            $TrendPercent = 0
        }
        else {
            $TrendPercent = 100
        }
    }
    else {
        $TrendPercent =
            (($LastAverage - $FirstAverage) / $FirstAverage) * 100
    }

    if ($TrendPercent -gt 10) {
        $Trend = "Increasing"
    }
    elseif ($TrendPercent -lt -10) {
        $Trend = "Decreasing"
    }
    else {
        $Trend = "Stable"
    }

    $AggregatedProfiles += [PSCustomObject]@{
        ResourceId       = $Rows[0].ResourceId
        ResourceName     = $Rows[0].ResourceName
        ResourceType     = $Rows[0].ResourceType
        MetricName       = $Rows[0].MetricName
        SampleCount      = $Rows.Count
        Average          = [math]::Round($Average,4)
        Minimum          = [math]::Round($Minimum,4)
        Maximum          = [math]::Round($Maximum,4)
        P95              = [math]::Round($P95,4)
        TrendPercent     = [math]::Round($TrendPercent,2)
        Trend            = $Trend
    }
}

Write-Host "Metric aggregation completed."
Write-Host "Aggregated metric profiles: $($AggregatedProfiles.Count)"
Write-Host ""

# =========================================================================
# WORKLOAD PROFILES
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Building workload profiles..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$WorkloadProfiles = @()

$ResourceMetricGroups =
    $AggregatedProfiles |
    Group-Object ResourceId, ResourceName, ResourceType

foreach ($Group in $ResourceMetricGroups) {

    $Metrics = @($Group.Group)

    $ResourceName = $Metrics[0].ResourceName
    $ResourceType = $Metrics[0].ResourceType
    $ResourceId   = $Metrics[0].ResourceId

    # ---------------------------------------------------------------------
    # Workload classification
    # ---------------------------------------------------------------------

    $Classification = "Metrics Available"

    if ($ResourceType -eq "microsoft.compute/virtualmachines") {

        $CpuMetric = $Metrics |
            Where-Object { $_.MetricName -eq "Percentage CPU" }

        if ($CpuMetric) {

            if ($CpuMetric.P95 -lt 10) {
                $Classification = "Low"
            }
            elseif ($CpuMetric.P95 -lt 40) {
                $Classification = "Moderate"
            }
            elseif ($CpuMetric.P95 -lt 70) {
                $Classification = "High"
            }
            else {
                $Classification = "Very High"
            }
        }
    }

    # ---------------------------------------------------------------------
    # Overall trend
    # ---------------------------------------------------------------------

    $TrendValues = @(
        $Metrics | ForEach-Object {
            [double]$_.TrendPercent
        }
    )

    if ($TrendValues.Count -gt 0) {

        $TrendAverage =
            ($TrendValues | Measure-Object -Average).Average

        if ($TrendAverage -gt 10) {
            $OverallTrend = "Increasing"
        }
        elseif ($TrendAverage -lt -10) {
            $OverallTrend = "Decreasing"
        }
        else {
            $OverallTrend = "Stable"
        }
    }
    else {
        $OverallTrend = "Unknown"
    }

    $WorkloadProfiles += [PSCustomObject]@{
        ResourceId            = $ResourceId
        ResourceName          = $ResourceName
        ResourceType          = $ResourceType
        MetricCount           = $Metrics.Count
        WorkloadClassification = $Classification
        OverallTrend          = $OverallTrend
    }
}

Write-Host "Workload profiles generated: $($WorkloadProfiles.Count)"
Write-Host ""

# =========================================================================
# AZURE ADVISOR
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Collecting Azure Advisor recommendations..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$Findings = @()

try {

    $AdvisorRecommendations =
        @(Get-AzAdvisorRecommendation -ErrorAction Stop)

    Write-Host "Advisor recommendations found: $($AdvisorRecommendations.Count)"

    foreach ($Recommendation in $AdvisorRecommendations) {

        $Category = switch ($Recommendation.Category) {
            "Cost"      { "Cost Optimization" }
            "Security"  { "Security" }
            "Reliability" { "Reliability" }
            "OperationalExcellence" { "Operational Excellence" }
            "Performance" { "Performance Efficiency" }
            default { $Recommendation.Category }
        }

        $Severity = switch ($Recommendation.Impact) {
            "High"   { "High" }
            "Medium" { "Medium" }
            "Low"    { "Low" }
            default  { "Medium" }
        }

        $ResourceName = ""

        if ($Recommendation.ImpactedField) {
            $ResourceName = $Recommendation.ImpactedField
        }

        $Findings += [PSCustomObject]@{
            RuleId          = "AZ-ADVISOR"
            Source          = "Azure Advisor"
            ResourceType    = ""
            ResourceName    = $ResourceName
            Category        = $Category
            Severity        = $Severity
            Description     = $Recommendation.ShortDescription.Problem
            Evidence        = $Recommendation.Description
            EstimatedSavings = ""
            Recommendation  = $Recommendation.ShortDescription.Solution
        }
    }
}
catch {

    Write-Host ""
    Write-Host "Unable to retrieve Azure Advisor recommendations." `
        -ForegroundColor Yellow
}

Write-Host ""

# =========================================================================
# CUSTOM SECURITY RULES
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Running custom security rules..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$SecurityQuery = @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| extend
    access = tostring(rules.properties.access),
    direction = tostring(rules.properties.direction),
    protocol = tostring(rules.properties.protocol),
    source = tostring(rules.properties.sourceAddressPrefix),
    destinationPort = tostring(rules.properties.destinationPortRange),
    priority = toint(rules.properties.priority)
| where direction =~ 'Inbound'
| where access =~ 'Allow'
| where source == '*'
| where destinationPort in ('22','3389')
| project
    id,
    name,
    type,
    resourceGroup,
    destinationPort,
    protocol,
    source
"@

try {

    $SecurityResults = @(
        Search-CloudLensResourceGraph `
            -Query $SecurityQuery `
            -SubscriptionIds @($SubscriptionId)
    )

    foreach ($Security in $SecurityResults) {

        $Port = $Security.destinationPort

        if ($Port -eq "22") {
            $ProtocolName = "SSH"
        }
        else {
            $ProtocolName = "RDP"
        }

        $Findings += [PSCustomObject]@{
            RuleId           = "CUSTOM-NET-001"
            Source           = "Custom"
            ResourceType     = $Security.type
            ResourceName     = $Security.name
            Category         = "Security"
            Severity         = "Critical"
            Description      = "$ProtocolName management port exposed to unrestricted inbound traffic."
            Evidence         = "Inbound Allow rule from source '*' on destination port $Port."
            EstimatedSavings = ""
            Recommendation   = "Restrict management access using private connectivity, Azure Bastion, VPN or an explicitly allowed source range."
        }
    }

    Write-Host "Custom security findings: $($SecurityResults.Count)"
}
catch {

    Write-Host "Custom security analysis failed." -ForegroundColor Yellow
}

Write-Host ""

# =========================================================================
# ANALYSIS SUMMARY
# =========================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Resources analyzed : $($Resources.Count)"
Write-Host "Metric records      : $($RawMetricData.Count)"
Write-Host "Metric profiles     : $($AggregatedProfiles.Count)"
Write-Host "Workload profiles   : $($WorkloadProfiles.Count)"
Write-Host "Findings generated  : $($Findings.Count)"
Write-Host ""

if ($Findings.Count -gt 0) {

    Write-Host "Findings by category:"
    Write-Host ""

    $Findings |
        Group-Object Category |
        Select-Object Count, Name |
        Sort-Object Count -Descending |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Findings by severity:"
    Write-Host ""

    $Findings |
        Group-Object Severity |
        Select-Object Count, Name |
        Sort-Object Count -Descending |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Workload analysis summary:"
Write-Host ""

if ($WorkloadProfiles.Count -gt 0) {

    $WorkloadProfiles |
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

# =========================================================================
# EXCEL REPORT
# =========================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Generating Excel report..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ReportFile = Join-Path `
    $OutputPath `
    "CloudLens-$SubscriptionId-v$CloudLensVersion.xlsx"

# -------------------------------------------------------------------------
# Findings report
# -------------------------------------------------------------------------

$FindingsReport = @(
    $Findings | ForEach-Object {

        [PSCustomObject]@{
            "Resource Type" =
                $_.ResourceType

            "Resource Name" =
                $_.ResourceName

            "Category" =
                $_.Category

            "Severity" =
                $_.Severity

            "Description + Evidence" =
                "$($_.Description)`n`nEvidence: $($_.Evidence)"

            "Estimated Savings" =
                $_.EstimatedSavings

            "Recommendation" =
                $_.Recommendation
        }
    }
)

# -------------------------------------------------------------------------
# Workload report
# -------------------------------------------------------------------------

$WorkloadReport = @(
    $WorkloadProfiles | ForEach-Object {

        [PSCustomObject]@{
            "Resource Name" =
                $_.ResourceName

            "Resource Type" =
                $_.ResourceType

            "Metric Count" =
                $_.MetricCount

            "Workload Classification" =
                $_.WorkloadClassification

            "Overall Trend" =
                $_.OverallTrend
        }
    }
)

# -------------------------------------------------------------------------
# Aggregated metric report
#
# NOTE:
# This is NOT raw telemetry.
# Only statistical information required for future AI analysis is retained.
# -------------------------------------------------------------------------

$MetricProfileReport = @(
    $AggregatedProfiles | ForEach-Object {

        [PSCustomObject]@{
            "Resource Name" =
                $_.ResourceName

            "Resource Type" =
                $_.ResourceType

            "Metric" =
                $_.MetricName

            "Samples" =
                $_.SampleCount

            "Average" =
                $_.Average

            "Minimum" =
                $_.Minimum

            "Maximum" =
                $_.Maximum

            "P95" =
                $_.P95

            "Trend %" =
                $_.TrendPercent

            "Trend" =
                $_.Trend
        }
    }
)

# -------------------------------------------------------------------------
# Resource inventory
# -------------------------------------------------------------------------

$ResourceReport = @(
    $Resources | ForEach-Object {

        [PSCustomObject]@{
            "Resource Name" =
                $_.name

            "Resource Type" =
                $_.type

            "Resource Group" =
                $_.resourceGroup

            "Location" =
                $_.location

            "Subscription ID" =
                $_.subscriptionId
        }
    }
)

# -------------------------------------------------------------------------
# Excel generation
# -------------------------------------------------------------------------

try {

    $FindingsReport |
        Export-Excel `
            -Path $ReportFile `
            -WorksheetName "Findings" `
            -AutoSize `
            -FreezeTopRow `
            -BoldTopRow `
            -AutoFilter

    if ($WorkloadReport.Count -gt 0) {

        $WorkloadReport |
            Export-Excel `
                -Path $ReportFile `
                -WorksheetName "Workload" `
                -AutoSize `
                -FreezeTopRow `
                -BoldTopRow `
                -AutoFilter
    }

    if ($MetricProfileReport.Count -gt 0) {

        $MetricProfileReport |
            Export-Excel `
                -Path $ReportFile `
                -WorksheetName "Metric Profiles" `
                -AutoSize `
                -FreezeTopRow `
                -BoldTopRow `
                -AutoFilter
    }

    $ResourceReport |
        Export-Excel `
            -Path $ReportFile `
            -WorksheetName "Resources" `
            -AutoSize `
            -FreezeTopRow `
            -BoldTopRow `
            -AutoFilter

    # ---------------------------------------------------------------------
    # Summary worksheet
    # ---------------------------------------------------------------------

    $Summary = @(
        [PSCustomObject]@{
            Property = "CloudLens Version"
            Value    = $CloudLensVersion
        }

        [PSCustomObject]@{
            Property = "Owner"
            Value    = $CloudLensOwner
        }

        [PSCustomObject]@{
            Property = "Analysis Date"
            Value    = $ModifiedDate
        }

        [PSCustomObject]@{
            Property = "Subscription"
            Value    = $SubscriptionName
        }

        [PSCustomObject]@{
            Property = "Subscription ID"
            Value    = $SubscriptionId
        }

        [PSCustomObject]@{
            Property = "Resources Analyzed"
            Value    = $Resources.Count
        }

        [PSCustomObject]@{
            Property = "Lookback Days"
            Value    = $LookbackDays
        }

        [PSCustomObject]@{
            Property = "Metric Chunk Days"
            Value    = $ChunkDays
        }

        [PSCustomObject]@{
            Property = "Metric Time Grain"
            Value    = "1 hour"
        }

        [PSCustomObject]@{
            Property = "Raw Metric Records"
            Value    = $RawMetricData.Count
        }

        [PSCustomObject]@{
            Property = "Aggregated Metric Profiles"
            Value    = $AggregatedProfiles.Count
        }

        [PSCustomObject]@{
            Property = "Workload Profiles"
            Value    = $WorkloadProfiles.Count
        }

        [PSCustomObject]@{
            Property = "Findings"
            Value    = $Findings.Count
        }

        [PSCustomObject]@{
            Property = "Mode"
            Value    = "READ-ONLY"
        }
    )

    $Summary |
        Export-Excel `
            -Path $ReportFile `
            -WorksheetName "Summary" `
            -AutoSize `
            -FreezeTopRow `
            -BoldTopRow

}
catch {

    Write-Host ""
    Write-Host "Excel report generation failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# =========================================================================
# RAW DATA CLEANUP
# =========================================================================

# The raw metric data exists only in memory during analysis.
# It is deliberately not exported.

$RawMetricData = $null
$GroupedMetrics = $null

[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# =========================================================================
# COMPLETION
# =========================================================================

Write-Host ""
Write-Host "Excel report generated successfully." -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS COMPLETED" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Report saved:"
Write-Host $ReportFile
Write-Host ""

Write-Host "Metric lookback : $LookbackDays days"
Write-Host "Metric chunk    : $ChunkDays days"
Write-Host "Metric grain    : 1 hour"
Write-Host "Raw records     : $($AggregatedProfiles.Count - 0)"
Write-Host "Aggregated      : $($AggregatedProfiles.Count)"
Write-Host "Workload profiles: $($WorkloadProfiles.Count)"
Write-Host ""

Write-Host "CloudLens V$CloudLensVersion completed successfully." `
    -ForegroundColor Green

Write-Host ""