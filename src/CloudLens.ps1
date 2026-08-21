#Requires -Modules Az.Accounts, Az.ResourceGraph, Az.Advisor

$ErrorActionPreference = "Stop"

# ============================================================
# CloudLens - Azure Environment Analyzer
#
# Owner        : Francesco Leuci
# Last Modified: 21/08/2026
# Version      : 0.5
# Mode         : READ-ONLY
#
# ============================================================
#
# V0.5 CHANGES
#
# - Reworked Azure Monitor metric collection
# - Removed Get-AzMetric dependency
# - Removed deprecated DetailedOutput parameter
# - Uses Invoke-AzRestMethod / ARM authentication
# - Dynamic metric definition discovery
# - Metric collection in 30-day chunks
# - 90-day workload analysis
# - 1-hour metric granularity
# - Multiple metrics per REST request
# - Workload profile generation
# - Metric availability tracking
# - Azure Advisor integration
# - Custom security rules
# - Excel report
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

$CloudLensVersion = "0.5"

$MetricLookbackDays = 90

$MetricChunkDays = 30

$MetricTimeGrain = "PT1H"

$MetricApiVersion = "2023-10-01"

$outputDirectory = Join-Path `
    $PSScriptRoot `
    "output"


# ============================================================
# HEADER
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CloudLens - Azure Environment Analyzer" -ForegroundColor Cyan
Write-Host " Version $CloudLensVersion" -ForegroundColor Cyan
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

if (-not $context) {

    throw "Azure authentication failed."
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

if ($subscriptions.Count -eq 0) {

    throw "No enabled Azure subscriptions were found."
}

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

if ($index -lt 0 -or $index -ge $subscriptions.Count) {

    throw "Invalid subscription selection."
}

$subscription = $subscriptions[$index]

Set-AzContext `
    -SubscriptionId $subscription.Id `
    -ErrorAction Stop |
    Out-Null

$subscriptionId = $subscription.Id

$subscriptionName = $subscription.Name

Write-Host ""
Write-Host "Selected subscription:" -ForegroundColor Green
Write-Host "Name : $subscriptionName"
Write-Host "ID   : $subscriptionId"
Write-Host ""


# ============================================================
# FINDINGS COLLECTION
# ============================================================

$findings = @()


# ============================================================
# RESOURCE DISCOVERY
# ============================================================

Write-Host `
    "Discovering Azure resources..." `
    -ForegroundColor Yellow

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

$resources = @()

$skipToken = $null

$page = 1

do {

    Write-Host `
        "  Resource Graph page $page..." `
        -ForegroundColor DarkGray

    if ($skipToken) {

        $pageResult = Search-AzGraph `
            -Query $resourceQuery `
            -Subscription $subscriptionId `
            -First 1000 `
            -SkipToken $skipToken
    }
    else {

        $pageResult = Search-AzGraph `
            -Query $resourceQuery `
            -Subscription $subscriptionId `
            -First 1000
    }

    if ($pageResult) {

        $resources += @($pageResult)

        Write-Host `
            "  Page $page returned $($pageResult.Count) resources." `
            -ForegroundColor DarkGray
    }

    $skipToken = $null

    if (
        $pageResult -and
        $pageResult.PSObject.Properties.Name -contains "SkipToken"
    ) {

        $skipToken = $pageResult.SkipToken
    }

    $page++

}
while ($skipToken)

Write-Host ""
Write-Host `
    "Resources found: $($resources.Count)" `
    -ForegroundColor Green
Write-Host ""


# ============================================================
# RESOURCE INDEX
# ============================================================

$resourceIndex = @{}

foreach ($resource in $resources) {

    if ($resource.id) {

        $resourceIndex[
            $resource.id.ToString().ToLowerInvariant()
        ] = $resource
    }
}


# ============================================================
# METRIC PROFILES
# ============================================================
#
# These are desired metrics.
#
# CloudLens first asks Azure Monitor which metrics actually
# exist on the resource. Only metrics that really exist are
# queried.
#
# This prevents false assumptions between resource types,
# regions and SKUs.
#
# ============================================================

$metricProfiles = @{

    "microsoft.compute/virtualmachines" = @(
        "Percentage CPU",
        "Network In Total",
        "Network Out Total",
        "Disk Read Bytes",
        "Disk Write Bytes",
        "Disk Read Operations/Sec",
        "Disk Write Operations/Sec"
    )

    "microsoft.compute/disks" = @(
        "Disk Read Bytes/sec",
        "Disk Write Bytes/sec",
        "Disk Read Operations/Sec",
        "Disk Write Operations/Sec",
        "Burst IO Credits Consumed Percentage"
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

    "microsoft.web/sites" = @(
        "Requests",
        "Http5xx",
        "Http4xx",
        "AverageMemoryWorkingSet",
        "CpuTime"
    )

    "microsoft.sql/servers/databases" = @(
        "cpu_percent",
        "dtu_consumption_percent",
        "storage_percent",
        "connection_successful",
        "connection_failed"
    )
}


# ============================================================
# METRIC DEFINITIONS CACHE
# ============================================================

$metricDefinitionsCache = @{}

$metricAvailability = @()


# ============================================================
# HELPER
# INVOKE ARM REST API
# ============================================================

function Invoke-CloudLensArmGet {

    param (

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {

        $response = Invoke-AzRestMethod `
            -Path $Path `
            -Method GET `
            -ErrorAction Stop

        if (
            $null -eq $response `
            -or [string]::IsNullOrWhiteSpace(
                $response.Content
            )
        ) {

            return $null
        }

        return (
            $response.Content |
                ConvertFrom-Json
        )
    }
    catch {

        throw $_
    }
}


# ============================================================
# HELPER
# GET METRIC DEFINITIONS
# ============================================================

function Get-CloudLensMetricDefinitions {

    param (

        [Parameter(Mandatory = $true)]
        [string]$ResourceId
    )

    $cacheKey =
        $ResourceId.ToLowerInvariant()

    if ($metricDefinitionsCache.ContainsKey($cacheKey)) {

        return $metricDefinitionsCache[$cacheKey]
    }

    $path =
        "$ResourceId/providers/Microsoft.Insights/metricDefinitions" +
        "?api-version=$MetricApiVersion"

    try {

        $response =
            Invoke-CloudLensArmGet `
                -Path $path

        if (
            $null -eq $response `
            -or $null -eq $response.value
        ) {

            $metricDefinitionsCache[$cacheKey] = @()

            return @()
        }

        $definitions = @(
            $response.value
        )

        $metricDefinitionsCache[$cacheKey] =
            $definitions

        return $definitions
    }
    catch {

        Write-Host ""
        Write-Host `
            "      Unable to retrieve metric definitions." `
            -ForegroundColor DarkYellow

        Write-Host `
            "      Resource: $ResourceId" `
            -ForegroundColor DarkYellow

        Write-Host `
            "      Reason: $($_.Exception.Message)" `
            -ForegroundColor DarkYellow

        $metricDefinitionsCache[$cacheKey] = @()

        return @()
    }
}


# ============================================================
# HELPER
# GET AVAILABLE METRIC NAMES
# ============================================================

function Get-CloudLensAvailableMetrics {

    param (

        [Parameter(Mandatory = $true)]
        [array]$Definitions
    )

    $names = @()

    foreach ($definition in $Definitions) {

        $metricName = $null

        if (
            $definition.name `
            -and
            $definition.name.value
        ) {

            $metricName =
                $definition.name.value
        }

        elseif (
            $definition.name `
            -and
            $definition.name.localizedValue
        ) {

            $metricName =
                $definition.name.localizedValue
        }

        if ($metricName) {

            $names += $metricName
        }
    }

    return @(
        $names |
            Sort-Object -Unique
    )
}


# ============================================================
# HELPER
# RESOLVE DESIRED METRICS
# ============================================================

function Resolve-CloudLensMetricNames {

    param (

        [Parameter(Mandatory = $true)]
        [array]$Definitions,

        [Parameter(Mandatory = $true)]
        [array]$DesiredNames
    )

    $resolved = @()

    foreach ($desired in $DesiredNames) {

        foreach ($definition in $Definitions) {

            $actualName = $null

            if (
                $definition.name `
                -and
                $definition.name.value
            ) {

                $actualName =
                    $definition.name.value
            }

            elseif (
                $definition.name `
                -and
                $definition.name.localizedValue
            ) {

                $actualName =
                    $definition.name.localizedValue
            }

            if (
                $actualName `
                -and
                $actualName.Equals(
                    $desired,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {

                $resolved += $actualName

                break
            }
        }
    }

    return @(
        $resolved |
            Sort-Object -Unique
    )
}


# ============================================================
# HELPER
# GET METRICS FROM AZURE MONITOR
# ============================================================

function Get-CloudLensMetrics {

    param (

        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [array]$MetricNames,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    if ($MetricNames.Count -eq 0) {

        return $null
    }

    $metricNamesString =
        ($MetricNames -join ",")

    $startUtc =
        $StartTime.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

    $endUtc =
        $EndTime.ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

    $encodedMetricNames =
        [Uri]::EscapeDataString(
            $metricNamesString
        )

    $path =
        "$ResourceId/providers/Microsoft.Insights/metrics" +
        "?api-version=$MetricApiVersion" +
        "&timespan=$startUtc/$endUtc" +
        "&interval=$MetricTimeGrain" +
        "&metricnames=$encodedMetricNames" +
        "&aggregation=Average,Minimum,Maximum,Total" +
        "&AutoAdjustTimegrain=True" +
        "&ValidateDimensions=False"

    try {

        return (
            Invoke-CloudLensArmGet `
                -Path $path
        )
    }
    catch {

        throw $_
    }
}


# ============================================================
# METRIC RESOURCE SELECTION
# ============================================================

$metricResources = @(
    $resources |
        Where-Object {

            $resourceType =
                $_.type.ToString().ToLowerInvariant()

            $metricProfiles.ContainsKey(
                $resourceType
            )
        }
)

Write-Host ""
Write-Host `
    "Collecting Azure Monitor workload metrics..." `
    -ForegroundColor Yellow
Write-Host ""

Write-Host `
    "Lookback period : $MetricLookbackDays days"
Write-Host `
    "Time grain      : 01:00:00"
Write-Host `
    "Chunk size      : $MetricChunkDays days"
Write-Host ""

Write-Host `
    "Resources with metric profiles: $($metricResources.Count)"
Write-Host ""


# ============================================================
# METRIC COLLECTION
# ============================================================

$metricRecords = @()

$endTime = Get-Date

$startTime =
    $endTime.AddDays(
        -$MetricLookbackDays
    )


foreach ($resource in $metricResources) {

    $resourceType =
        $resource.type.ToString().ToLowerInvariant()

    $desiredMetrics =
        $metricProfiles[$resourceType]

    Write-Host `
        "    Collecting $($resourceType.Split('/')[-1]) metrics: $($resource.name)" `
        -ForegroundColor DarkGray


    # --------------------------------------------------------
    # Retrieve definitions
    # --------------------------------------------------------

    $definitions =
        Get-CloudLensMetricDefinitions `
            -ResourceId $resource.id

    if ($definitions.Count -eq 0) {

        $metricAvailability += [PSCustomObject]@{

            ResourceName =
                $resource.name

            ResourceType =
                $resource.type

            ResourceId =
                $resource.id

            Status =
                "Metric definitions unavailable"

            AvailableMetrics =
                $null

            RequestedMetrics =
                ($desiredMetrics -join ", ")
        }

        continue
    }


    # --------------------------------------------------------
    # Resolve actual metric names
    # --------------------------------------------------------

    $resolvedMetrics =
        Resolve-CloudLensMetricNames `
            -Definitions $definitions `
            -DesiredNames $desiredMetrics


    $missingMetrics =
        @(
            $desiredMetrics |
                Where-Object {
                    $_ -notin $resolvedMetrics
                }
        )


    if ($resolvedMetrics.Count -gt 0) {

        $metricAvailability += [PSCustomObject]@{

            ResourceName =
                $resource.name

            ResourceType =
                $resource.type

            ResourceId =
                $resource.id

            Status =
                "Available"

            AvailableMetrics =
                ($resolvedMetrics -join ", ")

            RequestedMetrics =
                ($desiredMetrics -join ", ")

            MissingMetrics =
                ($missingMetrics -join ", ")
        }
    }
    else {

        $metricAvailability += [PSCustomObject]@{

            ResourceName =
                $resource.name

            ResourceType =
                $resource.type

            ResourceId =
                $resource.id

            Status =
                "No requested metrics available"

            AvailableMetrics =
                $null

            RequestedMetrics =
                ($desiredMetrics -join ", ")

            MissingMetrics =
                ($missingMetrics -join ", ")
        }

        continue
    }


    # --------------------------------------------------------
    # Split 90 days into 30-day chunks
    # --------------------------------------------------------

    $chunkStart =
        $startTime

    while ($chunkStart -lt $endTime) {

        $chunkEnd =
            $chunkStart.AddDays(
                $MetricChunkDays
            )

        if ($chunkEnd -gt $endTime) {

            $chunkEnd = $endTime
        }


        Write-Host `
            "        Window: $($chunkStart.ToString('yyyy-MM-dd')) -> $($chunkEnd.ToString('yyyy-MM-dd'))" `
            -ForegroundColor DarkGray


        try {

            $metricResponse =
                Get-CloudLensMetrics `
                    -ResourceId $resource.id `
                    -MetricNames $resolvedMetrics `
                    -StartTime $chunkStart `
                    -EndTime $chunkEnd


            if (
                $null -eq $metricResponse `
                -or
                $null -eq $metricResponse.value
            ) {

                $chunkStart =
                    $chunkEnd

                continue
            }


            # ------------------------------------------------
            # Process metrics
            # ------------------------------------------------

            foreach ($metric in @(
                $metricResponse.value
            )) {

                $actualMetricName = $null

                if (
                    $metric.name `
                    -and
                    $metric.name.value
                ) {

                    $actualMetricName =
                        $metric.name.value
                }

                if (-not $actualMetricName) {

                    continue
                }


                $unit = $metric.unit


                foreach ($timeSeries in @(
                    $metric.timeseries
                )) {

                    if (
                        $null -eq $timeSeries.data
                    ) {

                        continue
                    }


                    foreach ($dataPoint in @(
                        $timeSeries.data
                    )) {

                        if (
                            $null -eq $dataPoint.average -and
                            $null -eq $dataPoint.minimum -and
                            $null -eq $dataPoint.maximum -and
                            $null -eq $dataPoint.total
                        ) {

                            continue
                        }


                        $metricRecords +=
                            [PSCustomObject]@{

                                ResourceId =
                                    $resource.id

                                ResourceName =
                                    $resource.name

                                ResourceType =
                                    $resource.type

                                ResourceGroup =
                                    $resource.resourceGroup

                                Location =
                                    $resource.location

                                MetricName =
                                    $actualMetricName

                                Unit =
                                    $unit

                                TimeStamp =
                                    $dataPoint.timeStamp

                                Average =
                                    $dataPoint.average

                                Minimum =
                                    $dataPoint.minimum

                                Maximum =
                                    $dataPoint.maximum

                                Total =
                                    $dataPoint.total
                            }
                    }
                }
            }
        }
        catch {

            Write-Host ""
            Write-Host `
                "        Metric collection failed." `
                -ForegroundColor DarkYellow

            Write-Host `
                "        Resource: $($resource.name)" `
                -ForegroundColor DarkYellow

            Write-Host `
                "        Window: $($chunkStart.ToString('yyyy-MM-dd')) -> $($chunkEnd.ToString('yyyy-MM-dd'))" `
                -ForegroundColor DarkYellow

            Write-Host `
                "        Reason: $($_.Exception.Message)" `
                -ForegroundColor DarkYellow
        }


        $chunkStart =
            $chunkEnd
    }
}


Write-Host ""
Write-Host `
    "Metric analysis completed." `
    -ForegroundColor Green

Write-Host `
    "Metric records generated: $($metricRecords.Count)"
Write-Host ""


# ============================================================
# WORKLOAD PROFILE ANALYSIS
# ============================================================
#
# This is deliberately statistical rather than AI-based.
#
# The AI layer will come later.
#
# We calculate:
#
# - sample count
# - average
# - minimum
# - maximum
# - P50
# - P95
# - P99
# - zero/idle percentage
#
# ============================================================

function Get-CloudLensPercentile {

    param (

        [Parameter(Mandatory = $true)]
        [double[]]$Values,

        [Parameter(Mandatory = $true)]
        [double]$Percentile
    )

    if ($Values.Count -eq 0) {

        return $null
    }

    $sorted =
        @(
            $Values |
                Sort-Object
        )

    if ($sorted.Count -eq 1) {

        return $sorted[0]
    }

    $rank =
        ($Percentile / 100) *
        ($sorted.Count - 1)

    $lower =
        [math]::Floor($rank)

    $upper =
        [math]::Ceiling($rank)

    if ($lower -eq $upper) {

        return $sorted[$lower]
    }

    $weight =
        $rank - $lower

    return (
        $sorted[$lower] +
        (
            (
                $sorted[$upper] -
                $sorted[$lower]
            ) * $weight
        )
    )
}


$workloadProfiles = @()


$metricGroups =
    $metricRecords |
        Group-Object `
            ResourceId,
            MetricName


foreach ($group in $metricGroups) {

    $records =
        @($group.Group)

    if ($records.Count -eq 0) {

        continue
    }

    $resourceId =
        $records[0].ResourceId

    $resource =
        $null

    if (
        $resourceIndex.ContainsKey(
            $resourceId.ToLowerInvariant()
        )
    ) {

        $resource =
            $resourceIndex[
                $resourceId.ToLowerInvariant()
            ]
    }

    if (-not $resource) {

        continue
    }


    $values =
        @(
            $records |
                ForEach-Object {

                    if (
                        $null -ne $_.Average
                    ) {

                        [double]$_.Average
                    }
                }
        )


    if ($values.Count -eq 0) {

        continue
    }


    $zeroCount =
        @(
            $values |
                Where-Object {
                    $_ -eq 0
                }
        ).Count


    $idlePercentage =
        (
            $zeroCount /
            $values.Count
        ) * 100


    $workloadProfiles +=
        [PSCustomObject]@{

            ResourceName =
                $resource.name

            ResourceType =
                $resource.type

            ResourceId =
                $resource.id

            MetricName =
                $records[0].MetricName

            Unit =
                $records[0].Unit

            Samples =
                $values.Count

            Average =
                [math]::Round(
                    (
                        ($values |
                            Measure-Object -Average).Average
                    ),
                    4
                )

            Minimum =
                [math]::Round(
                    (
                        ($values |
                            Measure-Object -Minimum).Minimum
                    ),
                    4
                )

            Maximum =
                [math]::Round(
                    (
                        ($values |
                            Measure-Object -Maximum).Maximum
                    ),
                    4
                )

            P50 =
                [math]::Round(
                    (
                        Get-CloudLensPercentile `
                            -Values $values `
                            -Percentile 50
                    ),
                    4
                )

            P95 =
                [math]::Round(
                    (
                        Get-CloudLensPercentile `
                            -Values $values `
                            -Percentile 95
                    ),
                    4
                )

            P99 =
                [math]::Round(
                    (
                        Get-CloudLensPercentile `
                            -Values $values `
                            -Percentile 99
                    ),
                    4
                )

            ZeroOrIdlePercentage =
                [math]::Round(
                    $idlePercentage,
                    2
                )
        }
}


# ============================================================
# ADVISOR
# ============================================================

Write-Host `
    "Collecting Azure Advisor recommendations..." `
    -ForegroundColor Yellow

$advisorRecommendations =
    Get-AzAdvisorRecommendation

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

    if (
        [string]::IsNullOrWhiteSpace(
            $resourceId
        )
    ) {

        $resourceId =
            $recommendation.ImpactedValue
    }


    $resourceName = $null

    $resourceType = $null


    if ($resourceId) {

        $lookupId =
            $resourceId.ToString().ToLowerInvariant()

        if (
            $resourceIndex.ContainsKey(
                $lookupId
            )
        ) {

            $resource =
                $resourceIndex[$lookupId]

            $resourceName =
                $resource.name

            $resourceType =
                $resource.type
        }
    }


    $estimatedSavings = $null

    if (
        $recommendation.PotentialBenefit
    ) {

        $estimatedSavings =
            $recommendation.PotentialBenefit
    }


    $evidence = $null

    if (
        $recommendation.ImpactedValue
    ) {

        $evidence =
            "Impacted resource/value: $($recommendation.ImpactedValue)"
    }


    $findings +=
        [PSCustomObject]@{

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
                $evidence

            Recommendation =
                $recommendation.ShortDescriptionSolution

            EstimatedSavings =
                $estimatedSavings

            ResourceId =
                $resourceId

            RemediationAvailable =
                $false

            RemediationAction =
                $null
        }
}


# ============================================================
# CUSTOM SECURITY RULES
# ============================================================

Write-Host `
    "Running custom security rules..." `
    -ForegroundColor Yellow


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
    Search-AzGraph `
        -Query $nsgQuery `
        -Subscription $subscriptionId


foreach ($rule in $nsgFindings) {

    if (
        $rule.destinationPortRange -eq "22"
    ) {

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


    $evidence =
        [PSCustomObject]@{

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


    $findings +=
        [PSCustomObject]@{

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
                (
                    $evidence |
                        ConvertTo-Json -Compress
                )

            Recommendation =
                $recommendation

            EstimatedSavings =
                $null

            ResourceId =
                $rule.nsgId

            RemediationAvailable =
                $false

            RemediationAction =
                $null
        }
}


Write-Host `
    "Custom security findings: $($nsgFindings.Count)" `
    -ForegroundColor Green

Write-Host ""


# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host `
    "Resources analyzed : $($resources.Count)"

Write-Host `
    "Metric records      : $($metricRecords.Count)"

Write-Host `
    "Workload profiles   : $($workloadProfiles.Count)"

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
        Format-Table -Wrap -AutoSize
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

if ($workloadProfiles.Count -gt 0) {

    $workloadProfiles |
        Group-Object ResourceType |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize
}
else {

    Write-Host `
        "No workload metrics available." `
        -ForegroundColor DarkYellow
}

Write-Host ""


# ============================================================
# OUTPUT DIRECTORY
# ============================================================

if (
    -not (
        Test-Path $outputDirectory
    )
) {

    New-Item `
        -Path $outputDirectory `
        -ItemType Directory |
        Out-Null
}


# ============================================================
# IMPORTEXCEL
# ============================================================

$excelModule =
    Get-Module `
        -ListAvailable `
        -Name ImportExcel

if (-not $excelModule) {

    throw @"
The ImportExcel PowerShell module is required.

Install it with:

Install-Module ImportExcel -Scope CurrentUser
"@
}

Import-Module ImportExcel -ErrorAction Stop


# ============================================================
# OUTPUT FILE
# ============================================================

$outputFile =
    Join-Path `
        $outputDirectory `
        "CloudLens-$subscriptionId-v$CloudLensVersion.xlsx"


# ============================================================
# FINDINGS EXCEL DATA
# ============================================================

$excelFindings =
    foreach ($finding in $findings) {

        $descriptionEvidence =
            $finding.Description

        if (
            -not (
                [string]::IsNullOrWhiteSpace(
                    $finding.Evidence
                )
            )
        ) {

            $descriptionEvidence +=
                "`r`n`r`nEvidence: $($finding.Evidence)"
        }


        [PSCustomObject]@{

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

            "Source" =
                $finding.Source

            "Rule ID" =
                $finding.RuleId

            "Resource ID" =
                $finding.ResourceId
        }
    }


# ============================================================
# FINDINGS WORKSHEET
# ============================================================

if ($excelFindings.Count -gt 0) {

    $excelFindings |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Findings" `
            -AutoSize `
            -AutoFilter `
            -FreezeTopRow `
            -BoldTopRow `
            -ErrorAction Stop
}
else {

    [PSCustomObject]@{
        Message =
            "No findings detected."
    } |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Findings" `
            -AutoSize `
            -BoldTopRow `
            -ErrorAction Stop
}


# ============================================================
# WORKLOAD PROFILES WORKSHEET
# ============================================================

if ($workloadProfiles.Count -gt 0) {

    $workloadProfiles |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Workload Profiles" `
            -AutoSize `
            -AutoFilter `
            -FreezeTopRow `
            -BoldTopRow `
            -ErrorAction Stop
}
else {

    [PSCustomObject]@{
        Message =
            "No workload profiles generated."
    } |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Workload Profiles" `
            -AutoSize `
            -BoldTopRow `
            -ErrorAction Stop
}


# ============================================================
# METRIC AVAILABILITY WORKSHEET
# ============================================================

if ($metricAvailability.Count -gt 0) {

    $metricAvailability |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Metric Availability" `
            -AutoSize `
            -AutoFilter `
            -FreezeTopRow `
            -BoldTopRow `
            -ErrorAction Stop
}


# ============================================================
# RAW METRICS WORKSHEET
# ============================================================

if ($metricRecords.Count -gt 0) {

    $metricRecords |
        Select-Object `
            ResourceName,
            ResourceType,
            MetricName,
            Unit,
            TimeStamp,
            Average,
            Minimum,
            Maximum,
            Total |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Metrics" `
            -AutoSize `
            -AutoFilter `
            -FreezeTopRow `
            -BoldTopRow `
            -ErrorAction Stop
}
else {

    [PSCustomObject]@{
        Message =
            "No metric records collected."
    } |
        Export-Excel `
            -Path $outputFile `
            -WorksheetName "Metrics" `
            -AutoSize `
            -BoldTopRow `
            -ErrorAction Stop
}


# ============================================================
# SUMMARY WORKSHEET
# ============================================================

$summaryData = @(

    [PSCustomObject]@{
        Metric = "CloudLens Version"
        Value = $CloudLensVersion
    }

    [PSCustomObject]@{
        Metric = "Generated At UTC"
        Value =
            (
                Get-Date
            ).ToUniversalTime().ToString("o")
    }

    [PSCustomObject]@{
        Metric = "Subscription Name"
        Value = $subscriptionName
    }

    [PSCustomObject]@{
        Metric = "Subscription ID"
        Value = $subscriptionId
    }

    [PSCustomObject]@{
        Metric = "Resources Analyzed"
        Value = $resources.Count
    }

    [PSCustomObject]@{
        Metric = "Metric Resources"
        Value = $metricResources.Count
    }

    [PSCustomObject]@{
        Metric = "Metric Records"
        Value = $metricRecords.Count
    }

    [PSCustomObject]@{
        Metric = "Workload Profiles"
        Value = $workloadProfiles.Count
    }

    [PSCustomObject]@{
        Metric = "Findings"
        Value = $findings.Count
    }

    [PSCustomObject]@{
        Metric = "Metric Lookback"
        Value = "$MetricLookbackDays days"
    }

    [PSCustomObject]@{
        Metric = "Metric Chunk"
        Value = "$MetricChunkDays days"
    }

    [PSCustomObject]@{
        Metric = "Metric Time Grain"
        Value = "1 hour"
    }

    [PSCustomObject]@{
        Metric = "Mode"
        Value = "READ-ONLY"
    }
)


$summaryData |
    Export-Excel `
        -Path $outputFile `
        -WorksheetName "Summary" `
        -AutoSize `
        -BoldTopRow `
        -ErrorAction Stop


# ============================================================
# COMPLETION
# ============================================================

Write-Host ""

Write-Host `
    "Excel report generated successfully." `
    -ForegroundColor Green

Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS COMPLETED" -ForegroundColor Cyan
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
    "Metric time grain: 01:00:00"

Write-Host `
    "Metric records: $($metricRecords.Count)"

Write-Host `
    "Workload profiles: $($workloadProfiles.Count)"

Write-Host ""

Write-Host `
    "CloudLens V$CloudLensVersion completed successfully." `
    -ForegroundColor Green

Write-Host ""