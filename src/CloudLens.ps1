#Requires -Modules Az.Accounts, Az.ResourceGraph, Az.Advisor, ImportExcel

<#
    ============================================================
    CloudLens - Azure Environment Analyzer
    ============================================================

    Owner         : Francesco Leuci
    Version       : 0.3
    Last Modified : 2026-08-20

    Description:
    Read-only Azure environment assessment tool.

    Changes in v0.3:
    - Added Excel report generation.
    - Replaced JSON output with XLSX output.
    - Added Summary worksheet.
    - Added Findings worksheet.
    - Simplified Excel presentation.
    - Combined Description and Evidence into one column.
    - Added Recommendation column.
    - Improved Estimated Savings handling.
    - Resource Graph pagination retained.

    ============================================================
#>

$ErrorActionPreference = "Stop"

# ============================================================
# CLOUDLENS
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CloudLens - V0.3" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# AZURE AUTHENTICATION
# ============================================================

$context = Get-AzContext

if (-not $context) {

    Write-Host "Azure session not found. Connecting..." -ForegroundColor Yellow

    Connect-AzAccount

    $context = Get-AzContext
}

# ============================================================
# SUBSCRIPTION SELECTION
# ============================================================

$subscriptions = Get-AzSubscription |
    Where-Object {
        $_.State -eq "Enabled"
    } |
    Sort-Object Name

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
# RESOURCE GRAPH PAGINATION
# ============================================================

function Search-AzGraphAll {

    param (
        [Parameter(Mandatory)]
        [string]$Query,

        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $skipToken = $null
    $page = 0

    do {

        $page++

        $params = @{
            Query        = $Query
            Subscription = $SubscriptionId
            First        = 1000
        }

        if ($skipToken) {

            $params.SkipToken = $skipToken
        }

        Write-Host `
            "  Resource Graph page $page..." `
            -ForegroundColor DarkGray

        $response = Search-AzGraph @params

        if ($response.Data) {

            foreach ($item in $response.Data) {

                $results.Add($item)
            }

            Write-Host `
                "  Page $page returned $($response.Data.Count) resources." `
                -ForegroundColor DarkGray
        }

        $skipToken = $response.SkipToken

    }
    while ($skipToken)

    return $results.ToArray()
}

# ============================================================
# FINDING COLLECTION
# ============================================================

$findings = @()

# ============================================================
# RESOURCE DISCOVERY
# ============================================================

Write-Host "Discovering Azure resources..." -ForegroundColor Yellow
Write-Host ""

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

$resources = Search-AzGraphAll `
    -Query $query `
    -SubscriptionId $subscriptionId

Write-Host ""
Write-Host "Resources found: $($resources.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# AZURE ADVISOR
# ============================================================

Write-Host "Collecting Azure Advisor recommendations..." -ForegroundColor Yellow

$advisorRecommendations = Get-AzAdvisorRecommendation

Write-Host "Advisor recommendations found: $($advisorRecommendations.Count)" -ForegroundColor Green
Write-Host ""

foreach ($recommendation in $advisorRecommendations) {

    # --------------------------------------------------------
    # Category normalization
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Resource identification
    # --------------------------------------------------------

    $resourceId = $recommendation.ResourceMetadataResourceId

    if ([string]::IsNullOrWhiteSpace($resourceId)) {

        $resourceId = $recommendation.ImpactedValue
    }

    # --------------------------------------------------------
    # Resource information
    # --------------------------------------------------------

    $resourceName = $null
    $resourceType = $null

    if ($resourceId) {

        $resource = $resources |
            Where-Object {
                $_.id -eq $resourceId
            } |
            Select-Object -First 1

        if ($resource) {

            $resourceName = $resource.name
            $resourceType = $resource.type
        }
    }

    # --------------------------------------------------------
    # Estimated savings
    #
    # PotentialBenefit is not necessarily a monetary value.
    # Only expose it as Estimated Savings if it can be
    # interpreted as a numeric monetary amount.
    # --------------------------------------------------------

    $estimatedSavings = "N/A"

    if ($recommendation.PotentialBenefit) {

        $potentialBenefit = [string]$recommendation.PotentialBenefit

        $numericValue = 0

        if (
            [decimal]::TryParse(
                $potentialBenefit,
                [System.Globalization.NumberStyles]::Any,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$numericValue
            )
        ) {

            $estimatedSavings = $numericValue
        }
    }

    # --------------------------------------------------------
    # Create normalized finding
    # --------------------------------------------------------

    $findings += [PSCustomObject]@{

        Id =
            "ADVISOR-$($recommendation.Name)"

        RuleId =
            "AZ-ADVISOR"

        Source =
            "Azure Advisor"

        Category =
            $category

        Severity =
            $recommendation.Impact

        ResourceId =
            $resourceId

        ResourceName =
            $resourceName

        ResourceType =
            $resourceType

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

Write-Host "Running custom security rules..." -ForegroundColor Yellow

# ------------------------------------------------------------
# CUSTOM-NET-001
#
# SSH / RDP exposed to unrestricted inbound traffic
# ------------------------------------------------------------

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

$nsgFindings = Search-AzGraphAll `
    -Query $nsgQuery `
    -SubscriptionId $subscriptionId

foreach ($rule in $nsgFindings) {

    # --------------------------------------------------------
    # Determine service
    # --------------------------------------------------------

    if ($rule.destinationPortRange -eq "22") {

        $service = "SSH"
    }
    else {

        $service = "RDP"
    }

    # --------------------------------------------------------
    # Description
    # --------------------------------------------------------

    $description =
        "$service management port exposed to unrestricted inbound traffic."

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    if ($rule.destinationPortRange -eq "22") {

        $recommendation =
            "Restrict SSH access to trusted source IP ranges or use a secure access mechanism."
    }
    else {

        $recommendation =
            "Restrict RDP access to trusted source IP ranges or use Azure Bastion or JIT."
    }

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Resource type
    # --------------------------------------------------------

    $resourceType =
        "Microsoft.Network/networkSecurityGroups"

    # --------------------------------------------------------
    # Finding
    # --------------------------------------------------------

    $findings += [PSCustomObject]@{

        Id =
            "CUSTOM-NET-001-$($rule.nsgName)-$($rule.ruleName)"

        RuleId =
            "CUSTOM-NET-001"

        Source =
            "Custom"

        Category =
            "Security"

        Severity =
            "Critical"

        ResourceId =
            $rule.nsgId

        ResourceName =
            $rule.nsgName

        ResourceType =
            $resourceType

        Description =
            $description

        Evidence =
            ($evidence | ConvertTo-Json -Compress)

        Recommendation =
            $recommendation

        EstimatedSavings =
            "N/A"

        RemediationAvailable =
            $false

        RemediationAction =
            $null
    }
}

Write-Host "Custom security findings: $($nsgFindings.Count)" -ForegroundColor Green
Write-Host ""

# ============================================================
# ANALYSIS SUMMARY
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Resources analyzed : $($resources.Count)"
Write-Host "Findings generated  : $($findings.Count)"
Write-Host ""

# ============================================================
# FINDINGS BY CATEGORY
# ============================================================

if ($findings.Count -gt 0) {

    Write-Host "Findings by category:" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Group-Object Category |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Write-Host ""

    # --------------------------------------------------------
    # Findings by severity
    # --------------------------------------------------------

    Write-Host "Findings by severity:" -ForegroundColor Yellow
    Write-Host ""

    $findings |
        Group-Object Severity |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Write-Host ""

    # --------------------------------------------------------
    # Detailed findings
    # --------------------------------------------------------

    Write-Host "Findings:" -ForegroundColor Yellow
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

    Write-Host "No findings detected." -ForegroundColor Green
}

# ============================================================
# EXCEL OUTPUT
# ============================================================

$outputDirectory = Join-Path `
    $PSScriptRoot `
    "output"

if (-not (Test-Path $outputDirectory)) {

    New-Item `
        -Path $outputDirectory `
        -ItemType Directory |
        Out-Null
}

$outputFile = Join-Path `
    $outputDirectory `
    "assessment-$($subscriptionId).xlsx"

# ============================================================
# PREPARE EXCEL FINDINGS
# ============================================================

$excelFindings = foreach ($finding in $findings) {

    # --------------------------------------------------------
    # Description + Evidence
    # --------------------------------------------------------

    $descriptionAndEvidence =
        $finding.Description

    if (-not [string]::IsNullOrWhiteSpace($finding.Evidence)) {

        $descriptionAndEvidence +=
            "`r`n`r`nEvidence:`r`n"

        try {

            $evidenceObject =
                $finding.Evidence | ConvertFrom-Json

            foreach ($property in $evidenceObject.PSObject.Properties) {

                $descriptionAndEvidence +=
                    "$($property.Name): $($property.Value)`r`n"
            }
        }
        catch {

            $descriptionAndEvidence +=
                "$($finding.Evidence)`r`n"
        }
    }

    # --------------------------------------------------------
    # Excel presentation object
    # --------------------------------------------------------

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
            $descriptionAndEvidence

        "Recommendation" =
            $finding.Recommendation

        "Estimated Savings" =
            $finding.EstimatedSavings
    }
}

# ============================================================
# EXCEL SUMMARY
# ============================================================

$criticalCount = @(
    $findings |
        Where-Object {
            $_.Severity -eq "Critical"
        }
).Count

$highCount = @(
    $findings |
        Where-Object {
            $_.Severity -eq "High"
        }
).Count

$mediumCount = @(
    $findings |
        Where-Object {
            $_.Severity -eq "Medium"
        }
).Count

$lowCount = @(
    $findings |
        Where-Object {
            $_.Severity -eq "Low"
        }
).Count

$summary = @(
    [PSCustomObject]@{
        Metric = "Analyzer Version"
        Value  = "0.3"
    }

    [PSCustomObject]@{
        Metric = "Generated At"
        Value  = (Get-Date).ToUniversalTime().ToString("o")
    }

    [PSCustomObject]@{
        Metric = "Subscription"
        Value  = $subscriptionName
    }

    [PSCustomObject]@{
        Metric = "Subscription ID"
        Value  = $subscriptionId
    }

    [PSCustomObject]@{
        Metric = "Resources Analyzed"
        Value  = $resources.Count
    }

    [PSCustomObject]@{
        Metric = "Findings"
        Value  = $findings.Count
    }

    [PSCustomObject]@{
        Metric = "Critical"
        Value  = $criticalCount
    }

    [PSCustomObject]@{
        Metric = "High"
        Value  = $highCount
    }

    [PSCustomObject]@{
        Metric = "Medium"
        Value  = $mediumCount
    }

    [PSCustomObject]@{
        Metric = "Low"
        Value  = $lowCount
    }
)

# ============================================================
# EXCEL EXPORT
# ============================================================

Write-Host "Generating Excel report..." -ForegroundColor Yellow

if (Test-Path $outputFile) {

    Remove-Item `
        -Path $outputFile `
        -Force
}

# ------------------------------------------------------------
# Summary worksheet
# ------------------------------------------------------------

$summary |
    Export-Excel `
        -Path $outputFile `
        -WorksheetName "Summary" `
        -AutoSize `
        -BoldTopRow

# ------------------------------------------------------------
# Findings worksheet
# ------------------------------------------------------------

$excelFindings |
    Export-Excel `
        -Path $outputFile `
        -WorksheetName "Findings" `
        -AutoSize `
        -FreezeTopRow `
        -BoldTopRow `
        -TableName "CloudLensFindings"

# ============================================================
# EXCEL FORMATTING
# ============================================================

$excelPackage =
    Open-ExcelPackage -Path $outputFile

# ------------------------------------------------------------
# Summary worksheet
# ------------------------------------------------------------

$summarySheet =
    $excelPackage.Workbook.Worksheets["Summary"]

$summarySheet.Column(1).Width = 28
$summarySheet.Column(2).Width = 55

# ------------------------------------------------------------
# Findings worksheet
# ------------------------------------------------------------

$findingsSheet =
    $excelPackage.Workbook.Worksheets["Findings"]

# Resource Type
$findingsSheet.Column(1).Width = 38

# Resource Name
$findingsSheet.Column(2).Width = 35

# Category
$findingsSheet.Column(3).Width = 22

# Severity
$findingsSheet.Column(4).Width = 14

# Description + Evidence
$findingsSheet.Column(5).Width = 75

# Recommendation
$findingsSheet.Column(6).Width = 75

# Estimated Savings
$findingsSheet.Column(7).Width = 22

# Enable text wrapping
$findingsSheet.Cells.Style.WrapText = $true

# Vertical alignment
$findingsSheet.Cells.Style.VerticalAlignment =
    [OfficeOpenXml.Style.ExcelVerticalAlignment]::Top

# ------------------------------------------------------------
# Save Excel package
# ------------------------------------------------------------

Close-ExcelPackage $excelPackage

# ============================================================
# COMPLETION
# ============================================================

Write-Host ""
Write-Host "Report saved:" -ForegroundColor Green
Write-Host $outputFile
Write-Host ""
Write-Host "Analysis completed successfully." -ForegroundColor Green
Write-Host ""