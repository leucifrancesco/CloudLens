#Requires -Modules Az.Accounts, Az.ResourceGraph, Az.Advisor, Az.Monitor

$ErrorActionPreference = "Stop"

# ============================================================
# CloudLens - Azure Environment Analyzer
#
# Owner          : Francesco Leuci
# Last Modified  : 2026-08-21
# Version        : 0.6
# Mode           : READ-ONLY
#
# V0.6
# - Azure Resource Graph pagination
# - Azure Advisor recommendations
# - Custom security rules
# - Azure Monitor metric collection
# - 90-day historical analysis
# - 30-day metric collection chunks
# - Metric aggregation
# - P50 / P95 / P99 / Min / Max
# - 30 / 60 / 90 day trend analysis
# - Threshold analysis where applicable
# - Workload profiles per resource
# - Raw metric records excluded from final report
# - Excel output
# ============================================================

$AnalyzerVersion = "0.6"

$MetricLookbackDays = 90
$MetricChunkDays     = 30
$MetricTimeGrain     = New-TimeSpan -Hours 1

# ============================================================
# OUTPUT
# ============================================================

$outputDirectory = Join-Path $PSScriptRoot "output"

if (-not (Test-Path $outputDirectory)) {

    New-Item `
        -Path $outputDirectory `
        -ItemType Directory |
        Out-Null
}

# ============================================================
# HELPER - WRITE SECTION
# ============================================================

function Write-Section {
    param(
        [string]$Title
    )

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
# HELPER - PERCENTILE
# ============================================================

function Get-Percentile {

    param(
        [double[]]$Values,
        [double]$Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }

    $sorted = @(
        $Values |
        Sort-Object
    )

    if ($sorted.Count -eq 1) {
        return [double]$sorted[0]
    }

    $position = ($sorted.Count - 1) * $Percentile

    $lower = [math]::Floor($position)
    $upper = [math]::Ceiling($position)

    if ($lower -eq $upper) {
        return [double]$sorted[$lower]
    }

    $weight = $position - $lower

    return (
        [double]$sorted[$lower] +
        (
            ([double]$sorted[$upper] - [double]$sorted[$lower]) *
            $weight
        )
    )
}

# ============================================================
# HELPER - SAFE NUMBER
# ============================================================

function Get-SafeDouble {

    param(
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [double]$Value
    }
    catch {
        return $null
    }
}

# ============================================================
# HELPER - TREND
# ============================================================

function Get-Trend {

    param(
        [double]$OlderValue,
        [double]$NewerValue,
        [double]$ThresholdPercent = 15
    )

    if (
        $null -eq $OlderValue -or
        $null -eq $NewerValue
    ) {
        return "Insufficient Data"
    }

    if ($OlderValue -eq 0) {

        if ($NewerValue -eq 0) {
            return "Stable"
        }

        return "Increasing"
    }

    $change =
        (($NewerValue - $OlderValue) /
        [math]::Abs($OlderValue)) * 100

    if ($change -gt $ThresholdPercent) {
        return "Increasing"
    }

    if ($change -lt (-1 * $ThresholdPercent)) {
        return "Decreasing"
    }

    return "Stable"
}

# ============================================================
# HELPER - THRESHOLD ANALYSIS
# ============================================================

function Get-ThresholdAnalysis {

    param(
        [double[]]$Values,
        [double]$Threshold
    )

    if (-not $Values -or $Values.Count -eq 0) {

        return [PSCustomObject]@{
            Threshold      = $Threshold
            SamplesAbove   = 0
            SamplesTotal   = 0
            PercentAbove   = $null
        }
    }

    $above = @(
        $Values |
        Where-Object {
            $_ -gt $Threshold
        }
    ).Count

    $total = $Values.Count

    $percent = ($above / $total) * 100

    return [PSCustomObject]@{
        Threshold      = $Threshold
        SamplesAbove   = $above
        SamplesTotal   = $total
        PercentAbove   = [math]::Round($percent, 2)
    }
}

# ============================================================
# METRIC DEFINITIONS
# ============================================================

function Get-MetricProfile {

    param(
        [string]$ResourceType
    )

    switch -Regex ($ResourceType.ToLower()) {

        "microsoft.compute/virtualmachines$" {

            return @(
                [PSCustomObject]@{
                    Name      = "Percentage CPU"
                    Threshold = 80
                    Unit      = "%"
                }

                [PSCustomObject]@{
                    Name      = "Network In Total"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Network Out Total"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Disk Read Bytes"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Disk Write Bytes"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Disk Read Operations/Sec"
                    Threshold = $null
                    Unit      = "Count"
                }

                [PSCustomObject]@{
                    Name      = "Disk Write Operations/Sec"
                    Threshold = $null
                    Unit      = "Count"
                }
            )

            break
        }

        "microsoft.network/publicipaddresses$" {

            return @(
                [PSCustomObject]@{
                    Name      = "ByteCount"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "PacketCount"
                    Threshold = $null
                    Unit      = "Count"
                }
            )

            break
        }

        "microsoft.storage/storageaccounts$" {

            return @(
                [PSCustomObject]@{
                    Name      = "Transactions"
                    Threshold = $null
                    Unit      = "Count"
                }

                [PSCustomObject]@{
                    Name      = "Ingress"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Egress"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "UsedCapacity"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Availability"
                    Threshold = 99
                    Unit      = "%"
                }
            )

            break
        }

        "microsoft.compute/disks$" {

            return @(
                [PSCustomObject]@{
                    Name      = "Disk Read Bytes"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Disk Write Bytes"
                    Threshold = $null
                    Unit      = "Bytes"
                }

                [PSCustomObject]@{
                    Name      = "Disk Read Operations/Sec"
                    Threshold = $null
                    Unit      = "Count"
                }

                [PSCustomObject]@{
                    Name      = "Disk Write Operations/Sec"
                    Threshold = $null
                    Unit      = "Count"
                }
            )

            break
        }

        default {
            return @()
        }
    }
}

# ============================================================
# AZURE AUTHENTICATION
# ============================================================

Write-Section "CloudLens - Azure Environment Analyzer"

Write-Host "Version : $AnalyzerVersion"
Write-Host "Mode    : READ-ONLY"
Write-Host ""

$context = Get-AzContext

if (-not $context) {

    Write-Host "Azure session not found. Connecting..." -ForegroundColor Yellow

    Connect-AzAccount

    $context = Get-AzContext
}

# ============================================================
# SUBSCRIPTION SELECTION
# ============================================================

$subscriptions = @(
    Get-AzSubscription |
    Where-Object {
        $_.State -eq "Enabled"
    } |
    Sort-Object Name
)

Write-Host "Available subscriptions:" -ForegroundColor Yellow
Write-Host ""

for ($i = 0; $i -lt $subscriptions.Count; $i++) {

    Write-Host "[$($i + 1)] $($subscriptions[$i].Name)"
}

Write-Host ""

$selection = Read-Host "Select subscription"

if (-not ($selection -as [int])) {
    throw "Invalid subscription selection."
}

$index = [int]$selection - 1

if (
    $index -lt 0 -or
    $index -ge $subscriptions.Count
) {
    throw "Invalid subscription selection."
}

$subscription = $subscriptions[$index]

Set-AzContext `
    -SubscriptionId $subscription.Id `
    -ErrorAction Stop |
    Out-Null

$subscriptionId   = $subscription.Id
$subscriptionName = $subscription.Name

Write-Host ""
Write-Host "Selected subscription:" -ForegroundColor Green
Write-Host "Name : $subscriptionName"
Write-Host "ID   : $subscriptionId"
Write-Host ""

# ============================================================
# RESOURCE GRAPH PAGINATION
# ============================================================

Write-Section "Discovering Azure resources..."

$resourceQuery = @"
Resources
| project
    id,
    name,
    type,
    resourceGroup,
    location,
    subscriptionId,
    tags,
    sku,
    kind,
    properties
| order by type asc, name asc
"@

$resources = @()
$skipToken = $null
$page = 0

do {

    $page++

    Write-Host "  Resource Graph page $page..." -ForegroundColor DarkGray

    if ($skipToken) {

        $result = Search-AzGraph `
            -Query $resourceQuery `
            -Subscription $subscriptionId `
            -First 1000 `
            -SkipToken $skipToken
    }
    else {

        $result = Search-AzGraph `
            -Query $resourceQuery `
            -Subscription $subscriptionId `
            -First 1000
    }

    $pageResources = @($result)

    $resources += $pageResources

    Write-Host "  Page $page returned $($pageResources.Count) resources." -ForegroundColor DarkGray

    $skipToken = $result.SkipToken

}
while ($skipToken)

Write-Host ""
Write-Host "Resources found: $($resources.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# RAW METRICS COLLECTION
# ============================================================

Write-Section "Collecting Azure Monitor workload metrics..."

$metricEndTime =
    Get-Date

$metricStartTime =
    $metricEndTime.AddDays(
        -$MetricLookbackDays
    )

Write-Host "Lookback period : $MetricLookbackDays days"
Write-Host "Time grain      : $($MetricTimeGrain.ToString())"
Write-Host "Chunk size      : $MetricChunkDays days"
Write-Host ""

# Internal raw data.
# This object is deliberately NOT exported to Excel.
$rawMetrics = @()

$metricResources = @()

foreach ($resource in $resources) {

    $profile = Get-MetricProfile `
        -ResourceType $resource.type
        
    if ($profile.Count -gt 0) {

        $metricResources += $resource
    }
}

Write-Host "Resources with metric profiles: $($metricResources.Count)"
Write-Host ""

# ============================================================
# COLLECT METRICS
# ============================================================

foreach ($resource in $metricResources) {

    $profile =
        Get-MetricProfile `
            -ResourceType $resource.type

    Write-Host ""
    Write-Host "    Collecting $($resource.type.Split('/')[-1]) metrics: $($resource.name)" `
        -ForegroundColor Yellow

    $windowStart = $metricStartTime

    while ($windowStart -lt $metricEndTime) {

        $windowEnd =
            $windowStart.AddDays($MetricChunkDays)

        if ($windowEnd -gt $metricEndTime) {
            $windowEnd = $metricEndTime
        }

        Write-Host `
            "        Window: $($windowStart.ToString('yyyy-MM-dd')) -> $($windowEnd.ToString('yyyy-MM-dd'))" `
            -ForegroundColor DarkGray

        foreach ($metricDefinition in $profile) {

            try {

                $metricResult = Get-AzMetric `
                    -ResourceId $resource.id `
                    -MetricName $metricDefinition.Name `
                    -TimeGrain $MetricTimeGrain `
                    -StartTime $windowStart `
                    -EndTime $windowEnd `
                    -AggregationType Average `
                    -ErrorAction Stop

                foreach ($metric in @($metricResult)) {

                    foreach ($metricSeries in @($metric.TimeSeries)) {

                        foreach ($dataPoint in @($metricSeries.Data)) {

                            $value = $null

                            if ($null -ne $dataPoint.Average) {
                                $value = Get-SafeDouble $dataPoint.Average
                            }
                            elseif ($null -ne $dataPoint.Total) {
                                $value = Get-SafeDouble $dataPoint.Total
                            }
                            elseif ($null -ne $dataPoint.Maximum) {
                                $value = Get-SafeDouble $dataPoint.Maximum
                            }

                            if ($null -eq $value) {
                                continue
                            }

                            $rawMetrics += [PSCustomObject]@{

                                ResourceId   = $resource.id
                                ResourceName = $resource.name
                                ResourceType = $resource.type

                                MetricName   = $metricDefinition.Name
                                Unit         = $metricDefinition.Unit

                                Timestamp    = $dataPoint.TimeStamp
                                Value        = $value

                                Threshold    = $metricDefinition.Threshold
                            }
                        }
                    }
                }
            }
            catch {

                Write-Host `
                    "        Metric unavailable: $($metricDefinition.Name)" `
                    -ForegroundColor DarkYellow

                Write-Host `
                    "        Resource: $($resource.name)" `
                    -ForegroundColor DarkGray

                Write-Host `
                    "        Reason: $($_.Exception.Message)" `
                    -ForegroundColor DarkGray
            }
        }

        $windowStart = $windowEnd
    }
}

Write-Host ""
Write-Host "Raw metric collection completed." -ForegroundColor Green
Write-Host "Raw metric records: $($rawMetrics.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# METRIC AGGREGATION
# ============================================================

Write-Section "Aggregating workload metrics..."

$metricAggregates = @()

$metricGroups =
    $rawMetrics |
    Group-Object `
        ResourceId,
        ResourceName,
        ResourceType,
        MetricName,
        Unit,
        Threshold

foreach ($group in $metricGroups) {

    $items = @(
        $group.Group |
        Sort-Object Timestamp
    )

    if ($items.Count -eq 0) {
        continue
    }

    $values = @(
        $items |
        ForEach-Object {
            [double]$_.Value
        }
    )

    $latestTimestamp =
        ($items |
            Measure-Object Timestamp -Maximum).Maximum

    $latestValue =
        [double](
            $items |
            Sort-Object Timestamp |
            Select-Object -Last 1
        ).Value

    # --------------------------------------------------------
    # 90 DAYS
    # --------------------------------------------------------

    $period90 =
        $metricEndTime.AddDays(-90)

    $values90 = @(
        $items |
        Where-Object {
            $_.Timestamp -ge $period90
        } |
        ForEach-Object {
            [double]$_.Value
        }
    )

    # --------------------------------------------------------
    # 60 DAYS
    # --------------------------------------------------------

    $period60 =
        $metricEndTime.AddDays(-60)

    $values60 = @(
        $items |
        Where-Object {
            $_.Timestamp -ge $period60
        } |
        ForEach-Object {
            [double]$_.Value
        }
    )

    # --------------------------------------------------------
    # 30 DAYS
    # --------------------------------------------------------

    $period30 =
        $metricEndTime.AddDays(-30)

    $values30 = @(
        $items |
        Where-Object {
            $_.Timestamp -ge $period30
        } |
        ForEach-Object {
            [double]$_.Value
        }
    )

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    $min =
        ($values |
            Measure-Object -Minimum).Minimum

    $max =
        ($values |
            Measure-Object -Maximum).Maximum

    $average =
        ($values |
            Measure-Object -Average).Average

    $p50 =
        Get-Percentile `
            -Values $values `
            -Percentile 0.50

    $p95 =
        Get-Percentile `
            -Values $values `
            -Percentile 0.95

    $p99 =
        Get-Percentile `
            -Values $values `
            -Percentile 0.99

    # --------------------------------------------------------
    # 30 / 60 / 90 P95
    # --------------------------------------------------------

    $p95_30 =
        Get-Percentile `
            -Values $values30 `
            -Percentile 0.95

    $p95_60 =
        Get-Percentile `
            -Values $values60 `
            -Percentile 0.95

    $p95_90 =
        Get-Percentile `
            -Values $values90 `
            -Percentile 0.95

    # --------------------------------------------------------
    # TREND
    # --------------------------------------------------------

    $trend =
        Get-Trend `
            -OlderValue $p95_90 `
            -NewerValue $p95_30

    # --------------------------------------------------------
    # THRESHOLD
    # --------------------------------------------------------

    $threshold = $group.Group[0].Threshold

    $thresholdAnalysis = $null

    if ($null -ne $threshold) {

        $thresholdAnalysis =
            Get-ThresholdAnalysis `
                -Values $values `
                -Threshold $threshold
    }

    $percentAbove = $null

    if ($thresholdAnalysis) {
        $percentAbove =
            $thresholdAnalysis.PercentAbove
    }

    # --------------------------------------------------------
    # AGGREGATED RECORD
    # --------------------------------------------------------

    $metricAggregates += [PSCustomObject]@{

        ResourceId   = $group.Group[0].ResourceId
        ResourceName = $group.Group[0].ResourceName
        ResourceType = $group.Group[0].ResourceType

        MetricName   = $group.Group[0].MetricName
        Unit         = $group.Group[0].Unit

        SampleCount  = $values.Count

        Min          = [math]::Round($min, 4)
        Average      = [math]::Round($average, 4)

        P50          = [math]::Round($p50, 4)
        P95          = [math]::Round($p95, 4)
        P99          = [math]::Round($p99, 4)

        Max          = [math]::Round($max, 4)

        LatestValue  = [math]::Round($latestValue, 4)

        P95_30Days   = if ($null -ne $p95_30) {
            [math]::Round($p95_30, 4)
        }
        else {
            $null
        }

        P95_60Days   = if ($null -ne $p95_60) {
            [math]::Round($p95_60, 4)
        }
        else {
            $null
        }

        P95_90Days   = if ($null -ne $p95_90) {
            [math]::Round($p95_90, 4)
        }
        else {
            $null
        }

        Trend        = $trend

        Threshold    = $threshold

        PercentAboveThreshold =
            $percentAbove

        LatestTimestamp =
            $latestTimestamp
    }
}

Write-Host "Metric aggregation completed." -ForegroundColor Green
Write-Host "Aggregated metric profiles: $($metricAggregates.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# WORKLOAD PROFILES
# ============================================================

Write-Section "Building workload profiles..."

$workloadProfiles = @()

$resourceGroups =
    $metricAggregates |
    Group-Object `
        ResourceId,
        ResourceName,
        ResourceType

foreach ($resourceGroup in $resourceGroups) {

    $metrics =
        @($resourceGroup.Group)

    $metricNames =
        @(
            $metrics |
            Select-Object -ExpandProperty MetricName -Unique
        )

    # --------------------------------------------------------
    # General workload classification
    #
    # This is intentionally descriptive only.
    # V0.6 does NOT make architecture decisions.
    # --------------------------------------------------------

    $cpuMetric =
        $metrics |
        Where-Object {
            $_.MetricName -eq "Percentage CPU"
        } |
        Select-Object -First 1

    $workloadClassification = "Unknown"

    if ($cpuMetric) {

        if (
            $cpuMetric.P95 -lt 20 -and
            $cpuMetric.PercentAboveThreshold -lt 1
        ) {
            $workloadClassification = "Low"
        }
        elseif ($cpuMetric.P95 -lt 60) {
            $workloadClassification = "Moderate"
        }
        else {
            $workloadClassification = "High"
        }
    }
    else {

        $workloadClassification = "Metrics Available"
    }

    # --------------------------------------------------------
    # Overall trend
    # --------------------------------------------------------

    $trends =
        @(
            $metrics |
            Where-Object {
                $_.Trend -ne "Insufficient Data"
            } |
            Select-Object -ExpandProperty Trend
        )

    $overallTrend = "Stable"

    if ($trends -contains "Increasing") {
        $overallTrend = "Increasing"
    }
    elseif ($trends -contains "Decreasing") {
        $overallTrend = "Decreasing"
    }

    $workloadProfiles += [PSCustomObject]@{

        ResourceId =
            $resourceGroup.Group[0].ResourceId

        ResourceName =
            $resourceGroup.Group[0].ResourceName

        ResourceType =
            $resourceGroup.Group[0].ResourceType

        MetricCount =
            $metrics.Count

        WorkloadClassification =
            $workloadClassification

        OverallTrend =
            $overallTrend

        MetricsCollected =
            ($metricNames -join ", ")

        AnalysisPeriodDays =
            90
    }
}

Write-Host "Workload profiles generated: $($workloadProfiles.Count)" `
    -ForegroundColor Green

Write-Host ""

# ============================================================
# AZURE ADVISOR
# ============================================================

Write-Section "Collecting Azure Advisor recommendations..."

$findings = @()

$advisorRecommendations =
    @(Get-AzAdvisorRecommendation)

Write-Host `
    "Advisor recommendations found: $($advisorRecommendations.Count)" `
    -ForegroundColor Green

Write-Host ""

foreach ($recommendation in $advisorRecommendations) {

    $category = switch ($recommendation.Category) {

        "Cost" {
            "Cost"
            break
        }

        "Security" {
            "Security"
            break
        }

        "HighAvailability" {
            "Reliability"
            break
        }

        "Performance" {
            "Performance"
            break
        }

        "OperationalExcellence" {
            "Operational Excellence"
            break
        }

        default {
            $recommendation.Category
        }
    }

    $resourceId =
        $recommendation.ResourceMetadataResourceId

    if ([string]::IsNullOrWhiteSpace($resourceId)) {
        $resourceId =
            $recommendation.ImpactedValue
    }

    $resourceName = $null
    $resourceType = $null

    if ($resourceId) {

        $resource =
            $resources |
            Where-Object {
                $_.id -eq $resourceId
            } |
            Select-Object -First 1

        if ($resource) {

            $resourceName =
                $resource.name

            $resourceType =
                $resource.type
        }
    }

    $estimatedSavings = $null

    if ($recommendation.PotentialBenefit) {
        $estimatedSavings =
            $recommendation.PotentialBenefit
    }

    $findings += [PSCustomObject]@{

        Id =
            "ADVISOR-$($recommendation.Name)"

        RuleId =
            "AZ-ADVISOR"

        Source =
            "Azure Advisor"

        ResourceType =
            $resourceType

        ResourceName =
            $resourceName

        Category =
            $category

        Severity =
            $recommendation.Impact

        Description =
            $recommendation.ShortDescriptionProblem

        Evidence =
            $null

        Recommendation =
            $recommendation.ShortDescriptionSolution

        EstimatedSavings =
            $estimatedSavings

        RemediationAvailable =
            $false

        RemediationAction =
            $null
    }
}

# ============================================================
# CUSTOM SECURITY RULES
# ============================================================

Write-Section "Running custom security rules..."

$nsgQuery = @"
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| project
    nsgId = id,
    nsgName = name,
    resourceGroup,
    location,
    ruleName = tostring(rule.name),
    access = tostring(rule.properties.access),
    direction = tostring(rule.properties.direction),
    protocol = tostring(rule.properties.protocol),
    sourceAddressPrefix = tostring(rule.properties.sourceAddressPrefix),
    destinationPortRange = tostring(rule.properties.destinationPortRange),
    priority = toint(rule.properties.priority)
| where direction =~ 'Inbound'
| where access =~ 'Allow'
| where sourceAddressPrefix in ('*', '0.0.0.0/0', 'Internet')
| where destinationPortRange in ('22', '3389')
"@

$nsgFindings =
    @(Search-AzGraph `
        -Query $nsgQuery `
        -Subscription $subscriptionId)

foreach ($rule in $nsgFindings) {

    if ($rule.destinationPortRange -eq "22") {
        $service = "SSH"
    }
    else {
        $service = "RDP"
    }

    $description =
        "$service management port exposed to unrestricted inbound traffic."

    if ($service -eq "SSH") {

        $recommendation =
            "Restrict SSH access to trusted source IP ranges or use a secure access mechanism."
    }
    else {

        $recommendation =
            "Restrict RDP access to trusted source IP ranges or use Azure Bastion or JIT."
    }

    $evidence = [PSCustomObject]@{

        Direction =
            $rule.direction

        Access =
            $rule.access

        Protocol =
            $rule.protocol

        SourceAddressPrefix =
            $rule.sourceAddressPrefix

        DestinationPort =
            $rule.destinationPortRange

        Priority =
            $rule.priority
    }

    $findings += [PSCustomObject]@{

        Id =
            "CUSTOM-NET-001-$($rule.nsgName)-$($rule.ruleName)"

        RuleId =
            "CUSTOM-NET-001"

        Source =
            "Custom"

        ResourceType =
            "Microsoft.Network/networkSecurityGroups"

        ResourceName =
            $rule.nsgName

        Category =
            "Security"

        Severity =
            "Critical"

        Description =
            $description

        Evidence =
            ($evidence | ConvertTo-Json -Compress)

        Recommendation =
            $recommendation

        EstimatedSavings =
            $null

        RemediationAvailable =
            $false

        RemediationAction =
            $null
    }
}

Write-Host `
    "Custom security findings: $($nsgFindings.Count)" `
    -ForegroundColor Green

# ============================================================
# SUMMARY
# ============================================================

Write-Section "ANALYSIS SUMMARY"

Write-Host "Resources analyzed : $($resources.Count)"
Write-Host "Metric records      : $($rawMetrics.Count)"
Write-Host "Metric profiles     : $($metricAggregates.Count)"
Write-Host "Workload profiles   : $($workloadProfiles.Count)"
Write-Host "Findings generated  : $($findings.Count)"
Write-Host ""

if ($findings.Count -gt 0) {

    Write-Host "Findings by category:" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Group-Object Category |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Write-Host ""

    Write-Host "Findings by severity:" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Group-Object Severity |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize
}

Write-Host ""

# ============================================================
# WORKLOAD SUMMARY
# ============================================================

Write-Host "Workload analysis summary:" -ForegroundColor Yellow
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

    Write-Host "No workload profiles available."
}

# ============================================================
# EXCEL REPORT
# ============================================================

Write-Section "Generating Excel report..."

$excelFile =
    Join-Path `
        $outputDirectory `
        "CloudLens-$subscriptionId-v$AnalyzerVersion.xlsx"

try {

    $excelModule =
        Get-Module -ListAvailable -Name ImportExcel |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $excelModule) {

        throw `
            "The ImportExcel PowerShell module is required. Install it with: Install-Module ImportExcel -Scope CurrentUser"
    }

    Import-Module ImportExcel -ErrorAction Stop

    # --------------------------------------------------------
    # Remove previous file
    # --------------------------------------------------------

    if (Test-Path $excelFile) {

        Remove-Item `
            -Path $excelFile `
            -Force
    }

    # --------------------------------------------------------
    # SUMMARY SHEET
    # --------------------------------------------------------

    $summaryData = @(
        [PSCustomObject]@{
            Property = "CloudLens Version"
            Value    = $AnalyzerVersion
        }

        [PSCustomObject]@{
            Property = "Generated At"
            Value    = (Get-Date).ToUniversalTime().ToString("o")
        }

        [PSCustomObject]@{
            Property = "Subscription Name"
            Value    = $subscriptionName
        }

        [PSCustomObject]@{
            Property = "Subscription ID"
            Value    = $subscriptionId
        }

        [PSCustomObject]@{
            Property = "Resources Analyzed"
            Value    = $resources.Count
        }

        [PSCustomObject]@{
            Property = "Raw Metric Records"
            Value    = $rawMetrics.Count
        }

        [PSCustomObject]@{
            Property = "Aggregated Metric Profiles"
            Value    = $metricAggregates.Count
        }

        [PSCustomObject]@{
            Property = "Workload Profiles"
            Value    = $workloadProfiles.Count
        }

        [PSCustomObject]@{
            Property = "Findings"
            Value    = $findings.Count
        }

        [PSCustomObject]@{
            Property = "Metric Lookback"
            Value    = "90 days"
        }

        [PSCustomObject]@{
            Property = "Metric Chunk Size"
            Value    = "30 days"
        }

        [PSCustomObject]@{
            Property = "Metric Time Grain"
            Value    = "1 hour"
        }
    )

    $summaryData |
        Export-Excel `
            -Path $excelFile `
            -WorksheetName "Summary" `
            -AutoSize `
            -FreezeTopRow

    # --------------------------------------------------------
    # FINDINGS SHEET
    # --------------------------------------------------------

    $findings |
        Select-Object `
            ResourceType,
            ResourceName,
            Category,
            Severity,
            Description,
            Evidence,
            Recommendation,
            EstimatedSavings |
        Export-Excel `
            -Path $excelFile `
            -WorksheetName "Findings" `
            -AutoSize `
            -FreezeTopRow `
            -Append

    # --------------------------------------------------------
    # WORKLOAD ANALYSIS
    # --------------------------------------------------------

    $metricAggregates |
        Select-Object `
            ResourceType,
            ResourceName,
            MetricName,
            Unit,
            SampleCount,
            Min,
            Average,
            P50,
            P95,
            P99,
            Max,
            LatestValue,
            P95_30Days,
            P95_60Days,
            P95_90Days,
            Trend,
            Threshold,
            PercentAboveThreshold,
            LatestTimestamp |
        Export-Excel `
            -Path $excelFile `
            -WorksheetName "Workload Analysis" `
            -AutoSize `
            -FreezeTopRow `
            -Append

    # --------------------------------------------------------
    # WORKLOAD PROFILES
    # --------------------------------------------------------

    $workloadProfiles |
        Export-Excel `
            -Path $excelFile `
            -WorksheetName "Workload Profiles" `
            -AutoSize `
            -FreezeTopRow `
            -Append

    # --------------------------------------------------------
    # RESOURCES
    # --------------------------------------------------------

    $resources |
        Select-Object `
            name,
            type,
            resourceGroup,
            location,
            subscriptionId,
            kind,
            sku,
            tags |
        Export-Excel `
            -Path $excelFile `
            -WorksheetName "Resources" `
            -AutoSize `
            -FreezeTopRow `
            -Append

    Write-Host ""
    Write-Host "Excel report generated successfully." `
        -ForegroundColor Green
}
catch {

    Write-Host ""
    Write-Host "Excel generation failed." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message `
        -ForegroundColor Red

    throw
}

# ============================================================
# COMPLETION
# ============================================================

Write-Section "ANALYSIS COMPLETED"

Write-Host "Report saved:"
Write-Host $excelFile
Write-Host ""

Write-Host "Metric lookback : $MetricLookbackDays days"
Write-Host "Metric chunk     : $MetricChunkDays days"
Write-Host "Metric grain     : 1 hour"
Write-Host "Raw records      : $($rawMetrics.Count)"
Write-Host "Aggregated       : $($metricAggregates.Count)"
Write-Host "Workload profiles: $($workloadProfiles.Count)"
Write-Host ""

Write-Host "CloudLens V$AnalyzerVersion completed successfully." `
    -ForegroundColor Green

Write-Host ""