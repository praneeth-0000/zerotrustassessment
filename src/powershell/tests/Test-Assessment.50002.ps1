<#
.SYNOPSIS
    Queries Microsoft Cloud Security Benchmark (MCSB) regulatory compliance assessments
    and emits one test result per grouped recommendation.

.DESCRIPTION
    This test queries Azure Resource Graph for all MCSB regulatory compliance assessments
    across accessible subscriptions. Assessments are grouped by recommendationName (GUID),
    and each group becomes one Infrastructure pillar test result with a resource table
    showing all affected resources and the MCSB control(s) each row satisfies.

    Status logic:
    - All notapplicable → Skipped (with notApplicableReason)
    - Any unhealthy → Failed
    - All healthy → Passed

    The KQL query returns per-resource, per-control rows from
    microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments
    filtered to the Microsoft Cloud Security Benchmark standard.

.NOTES
    Test ID: 50002
    Category: Microsoft Defender for Cloud
    Required API: Azure Resource Graph - SecurityResources
        (microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments)
#>

function Test-Assessment-50002 {
    [ZtTest(
        Category = 'Microsoft Defender for Cloud',
        ImplementationCost = 'Low',
        MinimumLicense = ('N/A'),
        Pillar = 'Infrastructure',
        RiskLevel = 'High',
        Service = ('Azure'),
        SfiPillar = 'Protect infrastructure',
        TenantType = ('Workforce'),
        TestId = 50002,
        Title = 'Microsoft Cloud Security Benchmark Compliance Assessments',
        UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    #region Data Collection
    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = 'Checking Microsoft Cloud Security Benchmark Compliance Assessments'

    Write-ZtProgress -Activity $activity -Status 'Checking Azure connection'

    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) {
        Write-PSFMessage 'Not connected to Azure.' -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotConnectedAzure
        return
    }

    Write-ZtProgress -Activity $activity -Status 'Querying Azure Resource Graph for MCSB assessments'

    $argQuery = @'
securityresources
| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments"
| extend scope = properties.scope
| where isempty(scope) or scope in~("Subscription", "MultiCloudAggregation")
| parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" complianceControlId "/regulatoryComplianceAssessments" *
| extend complianceStandardId = replace("-", " ", complianceStandardId)
| where complianceStandardId == "Microsoft cloud security benchmark"
| extend failedResources = toint(properties.failedResources), passedResources = toint(properties.passedResources), skippedResources = toint(properties.skippedResources)
| where failedResources + passedResources + skippedResources > 0 or properties.assessmentType == "MicrosoftManaged"
| join kind = leftouter (
    securityresources
    | where type == "microsoft.security/assessments"
) on subscriptionId, name
| extend complianceState = tostring(properties.state)
| extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))
| extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)
| extend resourceId = trim(' ', tolower(tostring(case(
    resourceSource =~ "azure", properties1.resourceDetails.Id,
    resourceSource =~ "gcp", properties1.resourceDetails.GcpResourceId,
    resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,
    resourceSource =~ "aws", properties1.resourceDetails.AwsResourceId,
    extract("^(.+)/providers/Microsoft.Security/assessments/.+$", 1, recommendationId)
))))
| extend regexResourceId = extract_all(@"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$", resourceId)[0]
| extend resourceType = iff(
    resourceSource =~ "aws" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType),
    iff(regexResourceId[1] != "", regexResourceId[1], iff(regexResourceId[0] != "", regexResourceId[0], "subscriptions"))
)
| extend resourceName = tostring(regexResourceId[2])
| extend recommendationName = name
| extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))
| extend description = tostring(properties1.metadata.description)
| extend remediationSteps = tostring(properties1.metadata.remediationDescription)
| extend severity = tostring(properties1.metadata.severity)
| extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal)
| mvexpand statusPerInitiative = properties1.statusPerInitiative
| extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ "ASC Default"
| summarize arg_max(toint(expectedInitiative), *) by complianceControlId, recommendationId
| extend expectedInitiativeBool = expectedInitiative == 1
| extend state = iff(expectedInitiativeBool, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))
| extend notApplicableReason = iff(expectedInitiativeBool, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))
| join kind = leftouter (
    securityresources
    | where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
    | parse id with * "regulatoryComplianceStandards/" complianceStandardId "/regulatoryComplianceControls/" *
    | extend complianceStandardId = replace("-", " ", complianceStandardId)
    | where complianceStandardId == "Microsoft cloud security benchmark"
    | where properties.state != "Unsupported"
    | extend controlName = tostring(properties.description)
    | project controlId = name, controlName
    | distinct controlId, controlName
) on $left.complianceControlId == $right.controlId
| extend exportedTimestamp = now()
| join kind=leftouter (
    resourcecontainers
    | where type == "microsoft.resources/subscriptions"
    | extend subscriptionId = tostring(split(id, "/")[2])
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    exportedTimestamp,
    complianceStandard = complianceStandardId,
    complianceControl = complianceControlId,
    complianceControlName = controlName,
    recommendationState = complianceState,
    subscriptionId,
    subscriptionName,
    resourceGroup = resourceGroup1,
    resourceType,
    resourceName,
    resourceId,
    recommendationId,
    recommendationName,
    recommendationDisplayName,
    description,
    remediationSteps,
    severity,
    resourceState = state,
    notApplicableReason,
    azurePortalRecommendationLink
| order by complianceControl asc, recommendationId asc
'@

    $assessments = @()
    try {
        $assessments = @(Invoke-ZtAzureResourceGraphRequest -Query $argQuery)
        Write-PSFMessage "ARG Query returned $($assessments.Count) MCSB assessment records" -Tag Test -Level VeryVerbose
    }
    catch {
        Write-PSFMessage "Azure Resource Graph query failed: $($_.Exception.Message)" -Tag Test -Level Warning
        Add-ZtTestResultDetail -SkippedBecause NotSupported
        return
    }
    #endregion Data Collection

    #region Report Generation
    if ($assessments.Count -eq 0) {
        Write-PSFMessage 'No MCSB assessments found. Ensure Microsoft Cloud Security Benchmark is enabled.' -Tag Test -Level Verbose
        Add-ZtTestResultDetail -SkippedBecause NotApplicable -Result 'No Microsoft Cloud Security Benchmark assessments found. Ensure the MCSB compliance standard is enabled in Defender for Cloud.'
        return
    }

    # Group by recommendationName GUID — stable, unique per recommendation across all MCSB controls
    $groups = $assessments | Group-Object -Property recommendationName

    $mcsbDomainMap = @{
        'NS' = 'Network Security'
        'IM' = 'Identity Management'
        'PA' = 'Privileged Access'
        'DP' = 'Data Protection'
        'AM' = 'Asset Management'
        'LT' = 'Logging and Threat Detection'
        'IR' = 'Incident Response'
        'PV' = 'Posture and Vulnerability Management'
        'ES' = 'Endpoint Security'
        'BR' = 'Backup and Recovery'
        'DS' = 'DevOps Security'
        'GS' = 'Governance and Strategy'
    }

    # Pre-register each recommendation as a Pending worker in the progress dashboard
    foreach ($g in $groups) {
        Update-ZtProgressState -WorkerId "50002-$($g.Name)" -WorkerName $g.Group[0].recommendationDisplayName -WorkerStatus 'Pending'
    }

    foreach ($group in $groups) {
        $rows = $group.Group
        $firstRow = $rows[0]

        $testId = "50002-$($group.Name)"

        $title = $firstRow.recommendationDisplayName

        # Category: MCSB domain names derived from control ID prefixes (e.g. IR-3 or IR.3 → Incident Response)
        $domainNames = @($rows | Select-Object -ExpandProperty complianceControl | ForEach-Object {
            $prefix = ($_ -split '\.')[0].ToUpper()
            if ($mcsbDomainMap.ContainsKey($prefix)) { $mcsbDomainMap[$prefix] } else { $_ }
        } | Sort-Object -Unique)
        $category = if ($domainNames.Count -eq 0) { 'Microsoft cloud security benchmark' } else { $domainNames -join ', ' }

        $risk = $firstRow.severity

        Update-ZtProgressState -WorkerId $testId -WorkerName $title -WorkerStatus 'Running' -WorkerDetail 'Building report...'

        # --- Build "What was checked" section ---
        $descriptionText = ConvertTo-ZtMarkdown $firstRow.description
        if ([string]::IsNullOrWhiteSpace($descriptionText)) {
            $descriptionText = $firstRow.recommendationDisplayName
        }

        $remediationSection = ''
        if (-not [string]::IsNullOrWhiteSpace($firstRow.remediationSteps)) {
            $cleanRemediation = ConvertTo-ZtMarkdown $firstRow.remediationSteps
            if (-not [string]::IsNullOrWhiteSpace($cleanRemediation)) {
                $remediationSection = @"

**Remediation action**

$cleanRemediation
"@
            }
        }

        $descriptionMd = @"
$descriptionText
$remediationSection
"@

        # Separate rows by resourceState (lowercase in MCSB)
        $applicableRows    = @($rows | Where-Object { $_.resourceState -ne 'notapplicable' })
        $notApplicableRows = @($rows | Where-Object { $_.resourceState -eq 'notapplicable' })

        # --- Per-column presence flags (any non-empty value across the group → show that column) ---
        # Note: Subscription, MCSB control, MCSB control name, and Azure portal columns are always present
        $showResourceGroup = [bool]($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.resourceGroup) } | Select-Object -First 1)
        $showResourceType  = [bool]($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.resourceType) } | Select-Object -First 1)
        $showResource      = [bool]($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.resourceName) } | Select-Object -First 1)

        # --- Build dynamic table header and separator from active columns ---
        $tableHeader = '|'
        $tableSep    = '|'
        $tableHeader += ' Subscription |'; $tableSep += ' :----------- |'
        if ($showResourceGroup) { $tableHeader += ' Resource group |'; $tableSep += ' :------------- |' }
        if ($showResourceType)  { $tableHeader += ' Resource type |'; $tableSep += ' :------------ |' }
        $tableHeader += ' MCSB control |';       $tableSep += ' :----------- |'
        $tableHeader += ' MCSB control name |';  $tableSep += ' :---------------- |'
        if ($showResource)      { $tableHeader += ' Affected resource |'; $tableSep += ' :---------------- |' }
        $tableHeader += ' Status |'
        $tableSep    += ' :----- |'
        $tableHeader += ' Azure portal |'; $tableSep += ' :----------- |'
        $tableHeaderMd = "$tableHeader`n$tableSep"

        # If all rows are notapplicable → Skip
        if ($applicableRows.Count -eq 0) {
            $naReasons = ($notApplicableRows | ForEach-Object { $_.notApplicableReason } | Where-Object { $_ } | Select-Object -Unique) -join '; '

            $naTableRows = @(foreach ($row in $notApplicableRows | Sort-Object subscriptionName, complianceControl, resourceGroup, resourceName) {
                $subLink = "https://portal.azure.com/#resource/subscriptions/$($row.subscriptionId)"
                $subMd   = "[$(Get-SafeMarkdown $row.subscriptionName)]($subLink)"
                $resLink = "https://portal.azure.com/#resource$($row.resourceId)"
                $resMd   = "[$(Get-SafeMarkdown $row.resourceName)]($resLink)"
                $portalLinkMd = if (-not [string]::IsNullOrWhiteSpace($row.azurePortalRecommendationLink)) {
                    "[View recommendation]($($row.azurePortalRecommendationLink))"
                } else { '' }

                $rowMd = '|'
                $rowMd += " $subMd |"
                if ($showResourceGroup) { $rowMd += " $($row.resourceGroup) |" }
                if ($showResourceType)  { $rowMd += " $($row.resourceType) |" }
                $rowMd += " $($row.complianceControl) |"
                $rowMd += " $($row.complianceControlName) |"
                if ($showResource)      { $rowMd += " $resMd |" }
                $rowMd += ' N/A |'
                $rowMd += " $portalLinkMd |"
                "$rowMd`n"
            }) -join ''

            $naResultMd = @"
$naReasons

$tableHeaderMd
$naTableRows
"@

            $params = @{
                TestId         = $testId
                Title          = $title
                Description    = $descriptionMd
                SkippedBecause = 'NotApplicable'
                Result         = $naResultMd
                Pillar         = 'Infrastructure'
                Category       = $category
                Risk           = $risk
            }
            Add-ZtTestResultDetail @params
            Update-ZtProgressState -WorkerId $testId -WorkerName $title -WorkerStatus 'Done'
            continue
        }

        # Any unhealthy → Failed; all healthy → Passed
        $hasUnhealthy = @($applicableRows | Where-Object { $_.resourceState -eq 'unhealthy' }).Count -gt 0
        $passed = -not $hasUnhealthy

        # --- Build Result table ---
        $tableRows = @(foreach ($row in $rows | Sort-Object subscriptionName, complianceControl, resourceGroup, resourceName) {
            $subLink = "https://portal.azure.com/#resource/subscriptions/$($row.subscriptionId)"
            $subMd   = "[$(Get-SafeMarkdown $row.subscriptionName)]($subLink)"
            $resLink = "https://portal.azure.com/#resource$($row.resourceId)"
            $resMd   = "[$(Get-SafeMarkdown $row.resourceName)]($resLink)"

            $stateIcon = switch ($row.resourceState) {
                'healthy'       { '✅' }
                'unhealthy'     { '❌' }
                default         { 'N/A' }
            }

            $portalLinkMd = if (-not [string]::IsNullOrWhiteSpace($row.azurePortalRecommendationLink)) {
                "[View recommendation]($($row.azurePortalRecommendationLink))"
            } else { '' }

            $rowMd = '|'
            $rowMd += " $subMd |"
            if ($showResourceGroup) { $rowMd += " $($row.resourceGroup) |" }
            if ($showResourceType)  { $rowMd += " $($row.resourceType) |" }
            $rowMd += " $($row.complianceControl) |"
            $rowMd += " $($row.complianceControlName) |"
            if ($showResource)      { $rowMd += " $resMd |" }
            $rowMd += " $stateIcon |"
            $rowMd += " $portalLinkMd |"
            "$rowMd`n"
        }) -join ''

        $resultMd = @"
$title

$tableHeaderMd
$tableRows
"@

        $params = @{
            TestId      = $testId
            Title       = $title
            Status      = $passed
            Result      = $resultMd
            Description = $descriptionMd
            Risk        = $risk
            Pillar      = 'Infrastructure'
            Category    = $category
        }

        Add-ZtTestResultDetail @params
        Update-ZtProgressState -WorkerId $testId -WorkerName $title -WorkerStatus 'Done'
    }
    #endregion Report Generation

    Write-PSFMessage "Emitted $($groups.Count) grouped MCSB assessment test results" -Tag Test -Level VeryVerbose
}
