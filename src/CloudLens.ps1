#Requires -Modules Az.Accounts, Az.ResourceGraph, Az.Advisor, Az.Monitor

$ErrorActionPreference = "Stop"

# ============================================================
# CloudLens - Azure Environment Analyzer
#
# Owner        : Francesco Leuci
# Version      : 0.4
# Last Modified: 2026-08-21
#
# Mode         : READ-ONLY
#
# Description:
# Azure environment assessment tool.
#
# V0.4 additions:
# - Azure Monitor metric collection
# - 90-day workload analysis
# - P95 / P99 / Maximum
# - Resource-specific metric profiles
# - Workload Analysis Excel sheet
#
# No Azure resources are modified by this version.
# ============================================================

$AnalyzerVersion = "0.4"
$MetricLookbackDays = 90
$MetricTimeGrain = [TimeSpan]::FromHours(1)

# ============================================================
# CONFIGURATION
# ============================================================

$outputDirectory = Join-Path $PSScriptRoot "output"

if (-not (Test-Path $outputDirectory)) {

    New-Item `
        -Path $outputDirectory `
        -ItemType Directory |
        Out-Null
}

# ============================================================
# FUNCTIONS
# ============================================================

function Get-CloudLensPercentile {

    param (

        [Parameter(Mandatory = $true)]
        [double[]]$Values,

        [Parameter(Mandatory = $true)]
        [double]$Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) {

        return $null
    }

    $sortedValues = @(
        $Values |
            Where-Object {
                $_ -ne $null -and
                $_ -is [double] -or
                $_ -is [int] -or
                $_ -is [decimal]
            } |
            Sort-Object
    )

    if ($sortedValues.Count -eq 0) {

        return $null
    }

    if ($sortedValues.Count -eq 1) {

        return [double]$sortedValues[0]
    }

    $rank = ($Percentile / 100) * ($sortedValues.Count - 1)

    $lowerIndex = [math]::Floor($rank)
    $upperIndex = [math]::Ceiling($rank)

    if ($lowerIndex -eq $upperIndex) {

        return [double]$sortedValues[$lowerIndex]
    }

    $weight = $rank - $lowerIndex

    return (
        [double]$sortedValues[$lowerIndex] +
        (
            (
                [double]$sortedValues[$upperIndex] -
                [double]$sortedValues[$lowerIndex]
            ) * $weight
        )
    )
}

# ============================================================

function Get-CloudLensMetric {

    param (

        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [string]$MetricName,

        [string]$MetricNamespace,

        [int]$LookbackDays = 90,

        [TimeSpan]$TimeGrain = ([TimeSpan]::FromHours(1))
    )

    $endTime = Get-Date

    $startTime = $endTime.AddDays(
        -$LookbackDays
    )

    try {

        $parameters = @{

            ResourceId = $ResourceId

            MetricName = $MetricName

            StartTime = $startTime

            EndTime = $endTime

            TimeGrain = $TimeGrain

            AggregationType = "Average"

            DetailedOutput = $true
        }

        if ($MetricNamespace) {

            $parameters["MetricNamespace"] =
                $MetricNamespace
        }

        $metricResult = Get-AzMetric @parameters

        if (-not $metricResult) {

            return [PSCustomObject]@{

                Available = $false

                MetricName = $MetricName

                Unit = $null

                P95 = $null

                P99 = $null

                Maximum = $null

                SampleCount = 0

                Error = "No metric data returned."
            }
        }

        # ----------------------------------------------------
        # Extract metric values
        # ----------------------------------------------------

        $values = @()

        foreach ($metric in $metricResult) {

            if (-not $metric.Timeseries) {

                continue
            }

            foreach ($series in $metric.Timeseries) {

                if (-not $series.Data) {

                    continue
                }

                foreach ($dataPoint in $series.Data) {

                    if ($null -ne $dataPoint.Average) {

                        $values += [double]$dataPoint.Average
                    }
                    elseif ($null -ne $dataPoint.Maximum) {

                        $values += [double]$dataPoint.Maximum
                    }
                }
            }
        }

        if ($values.Count -eq 0) {

            return [PSCustomObject]@{

                Available = $false

                MetricName = $MetricName

                Unit = $null

                P95 = $null

                P99 = $null

                Maximum = $null

                SampleCount = 0

                Error = "Metric exists but no datapoints were returned."
            }
        }

        # ----------------------------------------------------
        # Determine unit
        # ----------------------------------------------------

        $unit = $null

        try {

            $unit = (
                $metricResult |
                    Select-Object -First 1
            ).Unit

        }
        catch {

            $unit = $null
        }

        # ----------------------------------------------------
        # Statistical analysis
        # ----------------------------------------------------

        $p95 = Get-CloudLensPercentile `
            -Values $values `
            -Percentile 95

        $p99 = Get-CloudLensPercentile `
            -Values $values `
            -Percentile 99

        $maximum = (
            $values |
                Measure-Object -Maximum
        ).Maximum

        return [PSCustomObject]@{

            Available = $true

            MetricName = $MetricName

            Unit = $unit

            P95 = [math]::Round($p95, 3)

            P99 = [math]::Round($p99, 3)

            Maximum = [math]::Round(
                [double]$maximum,
                3
            )

            SampleCount = $values.Count

            Error = $null
        }
    }
    catch {

        return [PSCustomObject]@{

            Available = $false

            MetricName = $MetricName

            Unit = $null

            P95 = $null

            P99 = $null

            Maximum = $null

            SampleCount = 0

            Error = $_.Exception.Message
        }
    }
}

# ============================================================

function Get-CloudLensMetricProfile {

    param (

        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [string]$ResourceType,

        [Parameter(Mandatory = $true)]
        [string]$ResourceName
    )

    $profile = @()

    # ========================================================
    # VIRTUAL MACHINES
    # ========================================================

    if ($ResourceType -eq "microsoft.compute/virtualmachines") {

        Write-Host `
            "    Collecting VM metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "Percentage CPU"
                DisplayName = "CPU"
            }

            @{
                Name = "Network In Total"
                DisplayName = "Network In"
            }

            @{
                Name = "Network Out Total"
                DisplayName = "Network Out"
            }

            @{
                Name = "Disk Read Operations/Sec"
                DisplayName = "Disk Read IOPS"
            }

            @{
                Name = "Disk Write Operations/Sec"
                DisplayName = "Disk Write IOPS"
            }

            @{
                Name = "Disk Read Bytes"
                DisplayName = "Disk Read Throughput"
            }

            @{
                Name = "Disk Write Bytes"
                DisplayName = "Disk Write Throughput"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    # ========================================================
    # VM SCALE SETS
    # ========================================================

    elseif ($ResourceType -eq "microsoft.compute/virtualmachinescalesets") {

        Write-Host `
            "    Collecting VMSS metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "Percentage CPU"
                DisplayName = "CPU"
            }

            @{
                Name = "Network In Total"
                DisplayName = "Network In"
            }

            @{
                Name = "Network Out Total"
                DisplayName = "Network Out"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    # ========================================================
    # MANAGED DISKS
    # ========================================================

    elseif ($ResourceType -eq "microsoft.compute/disks") {

        Write-Host `
            "    Collecting disk metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "Disk Read Operations/Sec"
                DisplayName = "Read IOPS"
            }

            @{
                Name = "Disk Write Operations/Sec"
                DisplayName = "Write IOPS"
            }

            @{
                Name = "Disk Read Bytes"
                DisplayName = "Read Throughput"
            }

            @{
                Name = "Disk Write Bytes"
                DisplayName = "Write Throughput"
            }

            @{
                Name = "Disk Queue Depth"
                DisplayName = "Queue Depth"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    # ========================================================
    # APP SERVICE
    # ========================================================

    elseif ($ResourceType -eq "microsoft.web/sites") {

        Write-Host `
            "    Collecting App Service metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "CpuPercentage"
                DisplayName = "CPU"
            }

            @{
                Name = "MemoryPercentage"
                DisplayName = "Memory"
            }

            @{
                Name = "Requests"
                DisplayName = "Requests"
            }

            @{
                Name = "Http5xx"
                DisplayName = "HTTP 5xx"
            }

            @{
                Name = "Http4xx"
                DisplayName = "HTTP 4xx"
            }

            @{
                Name = "AverageResponseTime"
                DisplayName = "Response Time"
            }

            @{
                Name = "HttpQueueLength"
                DisplayName = "HTTP Queue"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    # ========================================================
    # STORAGE ACCOUNT
    # ========================================================

    elseif ($ResourceType -eq "microsoft.storage/storageaccounts") {

        Write-Host `
            "    Collecting Storage metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "UsedCapacity"
                DisplayName = "Used Capacity"
            }

            @{
                Name = "Transactions"
                DisplayName = "Transactions"
            }

            @{
                Name = "Ingress"
                DisplayName = "Ingress"
            }

            @{
                Name = "Egress"
                DisplayName = "Egress"
            }

            @{
                Name = "Availability"
                DisplayName = "Availability"
            }

            @{
                Name = "SuccessE2ELatency"
                DisplayName = "E2E Latency"
            }

            @{
                Name = "SuccessServerLatency"
                DisplayName = "Server Latency"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    # ========================================================
    # SQL DATABASE
    # ========================================================

    elseif ($ResourceType -eq "microsoft.sql/servers/databases") {

        Write-Host `
            "    Collecting SQL Database metrics: $ResourceName" `
            -ForegroundColor DarkGray

        $metricDefinitions = @(

            @{
                Name = "cpu_percent"
                DisplayName = "CPU"
            }

            @{
                Name = "dtu_consumption_percent"
                DisplayName = "DTU Consumption"
            }

            @{
                Name = "physical_data_read_percent"
                DisplayName = "Data IO"
            }

            @{
                Name = "log_write_percent"
                DisplayName = "Log IO"
            }

            @{
                Name = "storage_percent"
                DisplayName = "Storage"
            }

            @{
                Name = "sessions_percent"
                DisplayName = "Sessions"
            }

            @{
                Name = "workers_percent"
                DisplayName = "Workers"
            }

            @{
                Name = "deadlock"
                DisplayName = "Deadlocks"
            }
        )

        foreach ($definition in $metricDefinitions) {

            $result = Get-CloudLensMetric `
                -ResourceId $ResourceId `
                -MetricName $definition.Name `
                -LookbackDays $MetricLookbackDays `
                -TimeGrain $MetricTimeGrain

            $profile += [PSCustomObject]@{

                ResourceId = $ResourceId

                ResourceType = $ResourceType

                ResourceName = $ResourceName

                Metric = $definition.DisplayName

                AzureMetricName = $definition.Name

                P95 = $result.P95

                P99 = $result.P99

                Maximum = $result.Maximum

                Unit = $result.Unit

                SampleCount = $result.SampleCount

                Available = $result.Available

                Status = if ($result.Available) {
                    "Available"
                }
                else {
                    "Not Available"
                }
            }
        }
    }

    return $profile
}

# ============================================================

function Get-CloudLensResourceGraph {

    param (

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    $query = @"
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

    $allResources = @()

    $skipToken = $null

    $page = 1

    do {

        Write-Host `
            "  Resource Graph page $page..." `
            -ForegroundColor DarkGray

        if ($skipToken) {

            $result = Search-AzGraph `
                -Query $query `
                -Subscription $SubscriptionId `
                -First 1000 `
                -SkipToken $skipToken
        }
        else {

            $result = Search-AzGraph `
                -Query $query `
                -Subscription $SubscriptionId `
                -First 1000
        }

        if ($result) {

            $allResources += @($result)

            Write-Host `
                "  Page $page returned $($result.Count) resources." `
                -ForegroundColor DarkGray
        }

        $skipToken = $null

        if ($result.PSObject.Properties.Name -contains "SkipToken") {

            $skipToken = $result.SkipToken
        }

        $page++

    } while ($skipToken)

    return $allResources
}

# ============================================================

function Get-CloudLensAdvisorFindings {

    param (

        [Parameter(Mandatory = $true)]
        $Resources
    )

    $findings = @()

    $advisorRecommendations =
        Get-AzAdvisorRecommendation

    Write-Host `
        "Advisor recommendations found: $($advisorRecommendations.Count)" `
        -ForegroundColor Green

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

        $resource = $Resources |
            Where-Object {
                $_.id -eq $resourceId
            } |
            Select-Object -First 1

        if ($resource) {

            $resourceName =
                $resource.name
        }

        $estimatedSavings = $null

        if ($recommendation.PotentialBenefit) {

            $estimatedSavings =
                $recommendation.PotentialBenefit
        }

        $description =
            $recommendation.ShortDescriptionProblem

        $recommendationText =
            $recommendation.ShortDescriptionSolution

        $findings += [PSCustomObject]@{

            Id =
                "ADVISOR-$($recommendation.Name)"

            RuleId =
                "AZ-ADVISOR"

            Source =
                "Azure Advisor"

            ResourceType =
                if ($resource) {
                    $resource.type
                }
                else {
                    $null
                }

            ResourceName =
                $resourceName

            Category =
                $category

            Severity =
                $recommendation.Impact

            Description =
                $description

            Evidence =
                $null

            Recommendation =
                $recommendationText

            EstimatedSavings =
                $estimatedSavings

            RemediationAvailable =
                $false

            RemediationAction =
                $null

            ResourceId =
                $resourceId
        }
    }

    return $findings
}

# ============================================================

function Get-CloudLensSecurityFindings {

    param (

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    $findings = @()

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

    $nsgFindings = @()

    $skipToken = $null

    do {

        if ($skipToken) {

            $result = Search-AzGraph `
                -Query $nsgQuery `
                -Subscription $SubscriptionId `
                -First 1000 `
                -SkipToken $skipToken
        }
        else {

            $result = Search-AzGraph `
                -Query $nsgQuery `
                -Subscription $SubscriptionId `
                -First 1000
        }

        if ($result) {

            $nsgFindings += @($result)
        }

        $skipToken = $null

        if ($result.PSObject.Properties.Name -contains "SkipToken") {

            $skipToken = $result.SkipToken
        }

    } while ($skipToken)

    foreach ($rule in $nsgFindings) {

        if ($rule.destinationPortRange -eq "22") {

            $service = "SSH"

            $recommendation =
                "Restrict SSH access to trusted source IP ranges or use a secure access mechanism."
        }
        else {

            $service = "RDP"

            $recommendation =
                "Restrict RDP access to trusted source IP ranges or use Azure Bastion or JIT."
        }

        $description =
            "$service management port exposed to unrestricted inbound traffic."

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
                "microsoft.network/networksecuritygroups"

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

            ResourceId =
                $rule.nsgId
        }
    }

    return $findings
}

# ============================================================

function Export-CloudLensExcel {

    param (

        [Parameter(Mandatory = $true)]
        $Findings,

        [Parameter(Mandatory = $true)]
        $WorkloadAnalysis,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {

        throw @"
ImportExcel module is not installed.

Install it with:

Install-Module ImportExcel -Scope CurrentUser
"@
    }

    Import-Module ImportExcel -ErrorAction Stop

    Write-Host ""
    Write-Host "Generating Excel report..." -ForegroundColor Yellow

    # --------------------------------------------------------
    # Findings sheet
    # --------------------------------------------------------

    $findingRows = @()

    foreach ($finding in $Findings) {

        $descriptionEvidence = $finding.Description

        if (-not [string]::IsNullOrWhiteSpace(
            [string]$finding.Evidence
        )) {

            $descriptionEvidence +=
                "`r`nEvidence: " +
                $finding.Evidence
        }

        $findingRows += [PSCustomObject]@{

            "Resource Type" =
                $finding.ResourceType

            "Resource Name" =
                $finding.ResourceName

            "Category" =
                $finding.Category

            "Severity" =
                $finding.Severity

            "Description + Evidence" =
                $descriptionEvidence

            "Estimated Savings" =
                $finding.EstimatedSavings

            "Recommendation" =
                $finding.Recommendation

            "Rule ID" =
                $finding.RuleId

            "Source" =
                $finding.Source
        }
    }

    if (Test-Path $OutputFile) {

        Remove-Item `
            -Path $OutputFile `
            -Force
    }

    $findingRows |
        Export-Excel `
            -Path $OutputFile `
            -WorksheetName "Findings" `
            -AutoSize `
            -FreezeTopRow `
            -BoldTopRow `
            -AutoFilter

    # --------------------------------------------------------
    # Workload Analysis sheet
    # --------------------------------------------------------

    if ($WorkloadAnalysis.Count -gt 0) {

        $WorkloadAnalysis |
            Export-Excel `
                -Path $OutputFile `
                -WorksheetName "Workload Analysis" `
                -AutoSize `
                -FreezeTopRow `
                -BoldTopRow `
                -AutoFilter
    }

    # --------------------------------------------------------
    # Metadata sheet
    # --------------------------------------------------------

    $metadata = @(

        [PSCustomObject]@{
            Property = "Analyzer"
            Value = "CloudLens"
        }

        [PSCustomObject]@{
            Property = "Version"
            Value = $AnalyzerVersion
        }

        [PSCustomObject]@{
            Property = "Owner"
            Value = "Francesco Leuci"
        }

        [PSCustomObject]@{
            Property = "Generated At"
            Value = (Get-Date).ToUniversalTime().ToString("o")
        }

        [PSCustomObject]@{
            Property = "Subscription"
            Value = $SubscriptionName
        }

        [PSCustomObject]@{
            Property = "Subscription ID"
            Value = $SubscriptionId
        }

        [PSCustomObject]@{
            Property = "Metric Lookback"
            Value = "$MetricLookbackDays days"
        }

        [PSCustomObject]@{
            Property = "Metric Time Grain"
            Value = $MetricTimeGrain.ToString()
        }
    )

    $metadata |
        Export-Excel `
            -Path $OutputFile `
            -WorksheetName "Assessment Info" `
            -AutoSize `
            -BoldTopRow

    Write-Host `
        "Excel report generated successfully." `
        -ForegroundColor Green
}

# ============================================================
# MAIN
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CloudLens - Azure Environment Analyzer" -ForegroundColor Cyan
Write-Host " Version $AnalyzerVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# AZURE AUTHENTICATION
# ============================================================

$context = Get-AzContext

if (-not $context) {

    Write-Host `
        "Azure session not found. Connecting..." `
        -ForegroundColor Yellow

    Connect-AzAccount

    $context = Get-AzContext
}

# ============================================================
# SUBSCRIPTION SELECTION
# ============================================================

$subscriptions =
    Get-AzSubscription |
        Where-Object {
            $_.State -eq "Enabled"
        } |
        Sort-Object Name

Write-Host `
    "Available subscriptions:" `
    -ForegroundColor Yellow

Write-Host ""

for ($i = 0; $i -lt $subscriptions.Count; $i++) {

    Write-Host `
        "[$($i + 1)] $($subscriptions[$i].Name)"
}

Write-Host ""

$selection =
    Read-Host "Select subscription"

if (-not ($selection -as [int])) {

    throw "Invalid subscription selection."
}

$index =
    [int]$selection - 1

if (
    $index -lt 0 -or
    $index -ge $subscriptions.Count
) {

    throw "Invalid subscription selection."
}

$subscription =
    $subscriptions[$index]

Set-AzContext `
    -SubscriptionId $subscription.Id `
    -ErrorAction Stop |
    Out-Null

$subscriptionId =
    $subscription.Id

$subscriptionName =
    $subscription.Name

Write-Host ""
Write-Host `
    "Selected subscription:" `
    -ForegroundColor Green

Write-Host "Name : $subscriptionName"
Write-Host "ID   : $subscriptionId"
Write-Host ""

# ============================================================
# RESOURCE DISCOVERY
# ============================================================

Write-Host `
    "Discovering Azure resources..." `
    -ForegroundColor Yellow

$resources =
    @(Get-CloudLensResourceGraph `
        -SubscriptionId $subscriptionId)

Write-Host ""

Write-Host `
    "Resources found: $($resources.Count)" `
    -ForegroundColor Green

Write-Host ""

# ============================================================
# WORKLOAD METRICS
# ============================================================

Write-Host ""
Write-Host "Collecting Azure Monitor workload metrics..." `
    -ForegroundColor Yellow

Write-Host ""
Write-Host `
    "Lookback period : $MetricLookbackDays days" `
    -ForegroundColor DarkGray

Write-Host `
    "Time grain      : $MetricTimeGrain" `
    -ForegroundColor DarkGray

Write-Host ""

$workloadAnalysis = @()

$metricResources = $resources |
    Where-Object {

        $_.type -in @(
            "microsoft.compute/virtualmachines",
            "microsoft.compute/virtualmachinescalesets",
            "microsoft.compute/disks",
            "microsoft.web/sites",
            "microsoft.sql/servers/databases",
            "microsoft.storage/storageaccounts"
        )
    }

Write-Host `
    "Resources with metric profiles: $($metricResources.Count)" `
    -ForegroundColor Green

Write-Host ""

foreach ($resource in $metricResources) {

    $profile = Get-CloudLensMetricProfile `
        -ResourceId $resource.id `
        -ResourceType $resource.type `
        -ResourceName $resource.name

    foreach ($metric in $profile) {

        $workloadAnalysis += $metric
    }
}

Write-Host ""

Write-Host `
    "Metric analysis completed." `
    -ForegroundColor Green

Write-Host `
    "Metric records generated: $($workloadAnalysis.Count)" `
    -ForegroundColor Green

Write-Host ""

# ============================================================
# AZURE ADVISOR
# ============================================================

Write-Host `
    "Collecting Azure Advisor recommendations..." `
    -ForegroundColor Yellow

$advisorFindings =
    @(Get-CloudLensAdvisorFindings `
        -Resources $resources)

Write-Host ""

# ============================================================
# CUSTOM SECURITY RULES
# ============================================================

Write-Host `
    "Running custom security rules..." `
    -ForegroundColor Yellow

$securityFindings =
    @(Get-CloudLensSecurityFindings `
        -SubscriptionId $subscriptionId)

Write-Host `
    "Custom security findings: $($securityFindings.Count)" `
    -ForegroundColor Green

Write-Host ""

# ============================================================
# COMBINE FINDINGS
# ============================================================

$findings = @()

$findings += $advisorFindings
$findings += $securityFindings

# ============================================================
# ANALYSIS SUMMARY
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host `
    "Resources analyzed : $($resources.Count)"

Write-Host `
    "Metric records      : $($workloadAnalysis.Count)"

Write-Host `
    "Findings generated  : $($findings.Count)"

Write-Host ""

# ============================================================
# FINDINGS BY CATEGORY
# ============================================================

if ($findings.Count -gt 0) {

    Write-Host `
        "Findings by category:" `
        -ForegroundColor Yellow

    Write-Host ""

    $findings |
        Group-Object Category |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Write-Host ""

    Write-Host `
        "Findings by severity:" `
        -ForegroundColor Yellow

    Write-Host ""

    $findings |
        Group-Object Severity |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Write-Host ""

    Write-Host `
        "Findings:" `
        -ForegroundColor Yellow

    Write-Host ""

    $findings |
        Select-Object `
            RuleId,
            Source,
            Category,
            Severity,
            ResourceName,
            Description,
            Recommendation |
        Format-Table `
            -Wrap `
            -AutoSize
}
else {

    Write-Host `
        "No findings detected." `
        -ForegroundColor Green
}

# ============================================================
# WORKLOAD SUMMARY
# ============================================================

Write-Host ""

Write-Host `
    "Workload analysis summary:" `
    -ForegroundColor Yellow

Write-Host ""

$workloadAnalysis |
    Where-Object {
        $_.Available -eq $true
    } |
    Group-Object ResourceType |
    Select-Object `
        Count,
        Name |
    Format-Table -AutoSize

Write-Host ""

# ============================================================
# EXCEL OUTPUT
# ============================================================

$outputFile = Join-Path `
    $outputDirectory `
    "CloudLens-$subscriptionId-v$AnalyzerVersion.xlsx"

Export-CloudLensExcel `
    -Findings $findings `
    -WorkloadAnalysis $workloadAnalysis `
    -OutputFile $outputFile `
    -SubscriptionName $subscriptionName `
    -SubscriptionId $subscriptionId

# ============================================================
# COMPLETION
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS COMPLETED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host `
    "Report saved:" `
    -ForegroundColor Green

Write-Host $outputFile

Write-Host ""

Write-Host `
    "Metric lookback: $MetricLookbackDays days"

Write-Host `
    "Metric time grain: $MetricTimeGrain"

Write-Host ""

Write-Host `
    "CloudLens V$AnalyzerVersion completed successfully." `
    -ForegroundColor Green

Write-Host ""