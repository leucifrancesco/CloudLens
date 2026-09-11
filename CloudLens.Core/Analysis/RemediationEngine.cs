using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class RemediationEngine
{
    public RemediationPlan BuildPlan(
        IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return new RemediationPlan();
        }

        var actions =
            findings
                .Select(BuildAction)
                .Where(action => action is not null)
                .Cast<RemediationAction>()
                .GroupBy(
                    action =>
                        $"{action.RuleId}|{action.ResourceId ?? action.ResourceName}",
                    StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderByDescending(action => action.Severity)
                .ThenBy(
                    action => action.Category)
                .ThenBy(
                    action => action.ResourceName,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        return new RemediationPlan
        {
            Actions = actions
        };
    }

    private static RemediationAction? BuildAction(
        Finding finding)
    {
        var rule =
            finding.RuleId.Trim().ToUpperInvariant();

        return rule switch
        {
            "SEC-NSG-INTERNET-ANY" =>
                BuildNsgInternetAny(finding),

            "SEC-NSG-SSH-INTERNET" =>
                BuildNsgSsh(finding),

            "SEC-NSG-RDP-INTERNET" =>
                BuildNsgRdp(finding),

            "SEC-UNUSED-PUBLIC-IP" =>
                BuildUnusedPublicIp(finding),

            "SEC-STORAGE-BLOB-PUBLIC" =>
                BuildStorageBlobPublic(finding),

            "SEC-STORAGE-HTTPS" =>
                BuildStorageHttps(finding),

            "SEC-STORAGE-TLS" =>
                BuildStorageTls(finding),

            "SEC-STORAGE-PUBLIC-NETWORK" =>
                BuildStoragePublicNetwork(finding),

            "SEC-KEYVAULT-PUBLIC-NETWORK" =>
                BuildKeyVaultPublicNetwork(finding),

            "SEC-KEYVAULT-PURGE-PROTECTION" =>
                BuildKeyVaultPurgeProtection(finding),

            "SEC-APP-HTTPS" =>
                BuildAppHttps(finding),

            "SEC-APP-FTP" =>
                BuildAppFtp(finding),

            "SEC-SQL-PUBLIC-NETWORK" =>
                BuildSqlPublicNetwork(finding),

            "SEC-AKS-PUBLIC-API" =>
                BuildAksPublicApi(finding),

            "SEC-AKS-LOCAL-ACCOUNTS" =>
                BuildAksLocalAccounts(finding),

            "SEC-ACR-ADMIN" =>
                BuildAcrAdmin(finding),

            "SEC-ACR-PUBLIC-NETWORK" =>
                BuildAcrPublicNetwork(finding),

            "SEC-COSMOS-PUBLIC-NETWORK" =>
                BuildCosmosPublicNetwork(finding),

            "SEC-SERVICEBUS-PUBLIC-NETWORK" =>
                BuildServiceBusPublicNetwork(finding),

            "SEC-EVENTHUB-PUBLIC-NETWORK" =>
                BuildEventHubPublicNetwork(finding),

            "SEC-COMPUTE-SECUREBOOT" =>
                BuildVmSecureBoot(finding),

            "OPS-VM-NO-BACKUP" =>
                BuildVmBackup(finding),

            "VM-NO-HA-DOMAIN" =>
                BuildVmAvailability(finding),

            "ARCH-VM-NO-HA-DOMAIN" =>
                BuildVmAvailability(finding),

            "OPS-DISK-UNATTACHED" =>
                BuildUnattachedDisk(finding),

            "ARCH-SUBNET-NO-NSG" =>
                BuildSubnetNsg(finding),

            "ARCH-NIC-PUBLIC-IP" =>
                BuildNicPublicIp(finding),

            "ARCH-APPGW-HTTP" =>
                BuildApplicationGatewayHttp(finding),

            "ARCH-PRIVATE-ENDPOINT-NO-RELATIONSHIP" =>
                BuildPrivateEndpoint(finding),

            "COST-APPSERVICE-F1" =>
                BuildAppServicePlan(finding),

            "COST-VMSS-BASIC-SKU" =>
                BuildVmssSku(finding),

            "COST-STORAGE-LRS" =>
                BuildStorageLrs(finding),

            "OPS-BACKUP-SOFTDELETE" =>
                BuildBackupSoftDelete(finding),

            "OPS-LOGANALYTICS-RETENTION" =>
                BuildLogAnalyticsRetention(finding),

            _ =>
                BuildGenericAction(finding)
        };
    }

    private static RemediationAction BuildNsgInternetAny(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Restrict the NSG inbound rule from Internet/Any to the minimum required source, destination port and protocol.",
            BuildAzureCliFromFinding(
                finding,
                "Review and replace the overly permissive NSG rule with a least-privilege rule."));
    }

    private static RemediationAction BuildNsgSsh(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Restrict or remove inbound SSH access from the Internet. Prefer a controlled administrative path such as Bastion or a private management network.",
            BuildAzureCliFromFinding(
                finding,
                "Restrict the SSH rule to approved management source ranges."));
    }

    private static RemediationAction BuildNsgRdp(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Restrict or remove inbound RDP access from the Internet. Prefer Azure Bastion or a private management path.",
            BuildAzureCliFromFinding(
                finding,
                "Restrict the RDP rule to approved management source ranges."));
    }

    private static RemediationAction BuildUnusedPublicIp(
        Finding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.ResourceId))
        {
            return BuildManualAction(
                finding,
                "Identify the unused public IP resource and remove it after confirming that it is not required.");
        }

        return BuildReadyAction(
            finding,
            "Delete the unused public IP after confirming that no resource depends on it.",
            $"az network public-ip delete --ids \"{finding.ResourceId}\"");
    }

    private static RemediationAction BuildStorageBlobPublic(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Disable anonymous public blob access unless explicitly required by the workload.",
            BuildAzureCliFromFinding(
                finding,
                "Disable blob public access on the storage account."));
    }

    private static RemediationAction BuildStorageHttps(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Require HTTPS-only traffic for the storage account.",
            BuildAzureCliFromFinding(
                finding,
                "Enable HTTPS-only traffic for the storage account."));
    }

    private static RemediationAction BuildStorageTls(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Raise the minimum TLS version to TLS 1.2 or the current Azure-supported secure baseline after validating client compatibility.",
            BuildAzureCliFromFinding(
                finding,
                "Set the minimum TLS version to TLS 1.2 or newer."));
    }

    private static RemediationAction BuildStoragePublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict storage account network access to approved virtual networks, private endpoints or explicitly approved IP ranges.",
            BuildAzureCliFromFinding(
                finding,
                "Review storage firewall/network rules before applying a restriction."));
    }

    private static RemediationAction BuildKeyVaultPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict Key Vault network access to approved networks and private endpoints after validating application dependencies.",
            BuildAzureCliFromFinding(
                finding,
                "Review Key Vault firewall/network configuration before restricting public access."));
    }

    private static RemediationAction BuildKeyVaultPurgeProtection(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Enable Key Vault purge protection after confirming the vault's lifecycle requirements.",
            BuildAzureCliFromFinding(
                finding,
                "Enable purge protection on the Key Vault."));
    }

    private static RemediationAction BuildAppHttps(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Require HTTPS-only access for the App Service.",
            BuildAzureCliFromFinding(
                finding,
                "Enable HTTPS-only access for the App Service."));
    }

    private static RemediationAction BuildAppFtp(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Disable FTP/FTPS publishing when it is not required. Prefer deployment mechanisms such as GitHub Actions, Azure DevOps or managed deployment tooling.",
            BuildAzureCliFromFinding(
                finding,
                "Review App Service FTP publishing configuration before disabling it."));
    }

    private static RemediationAction BuildSqlPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Disable public network access to the SQL server where private connectivity is available and validate all application dependencies first.",
            BuildAzureCliFromFinding(
                finding,
                "Review SQL connectivity dependencies before disabling public network access."));
    }

    private static RemediationAction BuildAksPublicApi(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict AKS API server exposure using private cluster configuration or authorized IP ranges according to the cluster architecture.",
            BuildAzureCliFromFinding(
                finding,
                "Review AKS API server exposure and migration impact before changing the cluster."));
    }

    private static RemediationAction BuildAksLocalAccounts(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Disable local AKS accounts where Microsoft Entra ID authentication is available and compatible with the operational model.",
            BuildAzureCliFromFinding(
                finding,
                "Migrate administrative access to Microsoft Entra ID before disabling local accounts."));
    }

    private static RemediationAction BuildAcrAdmin(
        Finding finding)
    {
        return BuildReadyAction(
            finding,
            "Disable the Azure Container Registry admin user and use Microsoft Entra ID, managed identities or service principals with least privilege.",
            BuildAzureCliFromFinding(
                finding,
                "Disable the ACR admin user."));
    }

    private static RemediationAction BuildAcrPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict ACR network access using private endpoints or approved network rules after validating image-pull dependencies.",
            BuildAzureCliFromFinding(
                finding,
                "Review ACR network dependencies before restricting public access."));
    }

    private static RemediationAction BuildCosmosPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict Cosmos DB network access using private endpoints or approved network rules after validating application connectivity.",
            BuildAzureCliFromFinding(
                finding,
                "Review Cosmos DB network dependencies before restricting public access."));
    }

    private static RemediationAction BuildServiceBusPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict Service Bus network access using private endpoints or approved network rules after validating producer and consumer connectivity.",
            BuildAzureCliFromFinding(
                finding,
                "Review Service Bus network dependencies before restricting public access."));
    }

    private static RemediationAction BuildEventHubPublicNetwork(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Restrict Event Hubs network access using private endpoints or approved network rules after validating producer and consumer connectivity.",
            BuildAzureCliFromFinding(
                finding,
                "Review Event Hubs network dependencies before restricting public access."));
    }

    private static RemediationAction BuildVmSecureBoot(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Enable Secure Boot for supported VM generations after validating the operating system and boot configuration.",
            BuildAzureCliFromFinding(
                finding,
                "Validate VM generation and operating system compatibility before enabling Secure Boot."));
    }

    private static RemediationAction BuildVmBackup(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Configure an appropriate Azure Backup policy for the VM after confirming retention, RPO/RTO and recovery requirements.",
            BuildAzureCliFromFinding(
                finding,
                "Create or assign an appropriate Recovery Services backup policy."));
    }

    private static RemediationAction BuildVmAvailability(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Review VM high-availability requirements. For workloads requiring resilience, consider Availability Zones or an Availability Set where appropriate.",
            BuildAzureCliFromFinding(
                finding,
                "Review the VM architecture before introducing an availability configuration."));
    }

    private static RemediationAction BuildUnattachedDisk(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Confirm that the managed disk is no longer required, then delete it to eliminate unnecessary storage cost.",
            BuildAzureCliFromFinding(
                finding,
                "Verify that the disk is not required before deletion."));
    }

    private static RemediationAction BuildSubnetNsg(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Associate an appropriate Network Security Group with the subnet and validate the resulting effective security rules.",
            BuildAzureCliFromFinding(
                finding,
                "Associate the subnet with the approved NSG configuration."));
    }

    private static RemediationAction BuildNicPublicIp(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Remove unnecessary public IP exposure from the network interface and use private connectivity where possible.",
            BuildAzureCliFromFinding(
                finding,
                "Validate the workload's inbound/outbound connectivity requirements before removing the public IP."));
    }

    private static RemediationAction BuildApplicationGatewayHttp(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Replace HTTP listener exposure with HTTPS and configure a valid TLS certificate.",
            BuildAzureCliFromFinding(
                finding,
                "Configure HTTPS listener and certificate before removing HTTP access."));
    }

    private static RemediationAction BuildPrivateEndpoint(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Validate that the Private Endpoint is correctly associated with the intended private DNS zone and target resource.",
            BuildAzureCliFromFinding(
                finding,
                "Review Private Endpoint and private DNS relationships."));
    }

    private static RemediationAction BuildAppServicePlan(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Evaluate whether the App Service workload requires a higher service tier based on availability, scaling, networking and performance requirements.",
            BuildAzureCliFromFinding(
                finding,
                "Review the App Service Plan SKU against workload requirements."));
    }

    private static RemediationAction BuildVmssSku(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Review the VM Scale Set SKU and migrate from Basic when the workload requires supported production capabilities.",
            BuildAzureCliFromFinding(
                finding,
                "Review VM Scale Set SKU requirements before changing the configuration."));
    }

    private static RemediationAction BuildStorageLrs(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Evaluate whether locally redundant storage provides sufficient resilience. Consider ZRS/GRS/GZRS where the workload's availability and DR requirements justify it.",
            BuildAzureCliFromFinding(
                finding,
                "Review storage redundancy requirements before changing replication."));
    }

    private static RemediationAction BuildBackupSoftDelete(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Enable soft delete for backup data and validate the retention period against the organization's recovery requirements.",
            BuildAzureCliFromFinding(
                finding,
                "Review backup vault protection settings before enabling soft delete."));
    }

    private static RemediationAction BuildLogAnalyticsRetention(
        Finding finding)
    {
        return BuildReviewAction(
            finding,
            "Review Log Analytics retention against operational, compliance and cost requirements.",
            BuildAzureCliFromFinding(
                finding,
                "Set an appropriate Log Analytics retention period after validating compliance and cost requirements."));
    }

    private static RemediationAction BuildGenericAction(
        Finding finding)
    {
        if (!string.IsNullOrWhiteSpace(finding.AzureCli))
        {
            return new RemediationAction(
                Id: $"REM-{finding.Id}",
                FindingId: finding.Id,
                RuleId: finding.RuleId,
                Category: finding.Category,
                Severity: finding.Severity,
                Title: finding.Title,
                Description: finding.Description,
                ResourceName: finding.ResourceName,
                ResourceType: finding.ResourceType,
                ResourceId: finding.ResourceId,
                ActionType: RemediationActionType.AzureCli,
                Status: RemediationStatus.ReviewRequired,
                Action: finding.Recommendation,
                Command: finding.AzureCli,
                RequiresReview: true);
        }

        return BuildManualAction(
            finding,
            finding.Recommendation);
    }

    private static RemediationAction BuildReadyAction(
        Finding finding,
        string action,
        string? command)
    {
        return new RemediationAction(
            Id: $"REM-{finding.Id}",
            FindingId: finding.Id,
            RuleId: finding.RuleId,
            Category: finding.Category,
            Severity: finding.Severity,
            Title: finding.Title,
            Description: finding.Description,
            ResourceName: finding.ResourceName,
            ResourceType: finding.ResourceType,
            ResourceId: finding.ResourceId,
            ActionType:
                string.IsNullOrWhiteSpace(command)
                    ? RemediationActionType.Manual
                    : RemediationActionType.AzureCli,
            Status:
                string.IsNullOrWhiteSpace(command)
                    ? RemediationStatus.ReviewRequired
                    : RemediationStatus.Ready,
            Action: action,
            Command: command,
            RequiresReview:
                string.IsNullOrWhiteSpace(command));
    }

    private static RemediationAction BuildReviewAction(
        Finding finding,
        string action,
        string? command)
    {
        return new RemediationAction(
            Id: $"REM-{finding.Id}",
            FindingId: finding.Id,
            RuleId: finding.RuleId,
            Category: finding.Category,
            Severity: finding.Severity,
            Title: finding.Title,
            Description: finding.Description,
            ResourceName: finding.ResourceName,
            ResourceType: finding.ResourceType,
            ResourceId: finding.ResourceId,
            ActionType:
                string.IsNullOrWhiteSpace(command)
                    ? RemediationActionType.Manual
                    : RemediationActionType.AzureCli,
            Status: RemediationStatus.ReviewRequired,
            Action: action,
            Command: command,
            RequiresReview: true);
    }

    private static RemediationAction BuildManualAction(
        Finding finding,
        string action)
    {
        return new RemediationAction(
            Id: $"REM-{finding.Id}",
            FindingId: finding.Id,
            RuleId: finding.RuleId,
            Category: finding.Category,
            Severity: finding.Severity,
            Title: finding.Title,
            Description: finding.Description,
            ResourceName: finding.ResourceName,
            ResourceType: finding.ResourceType,
            ResourceId: finding.ResourceId,
            ActionType: RemediationActionType.Manual,
            Status: RemediationStatus.NotAutomatable,
            Action: action,
            Command: null,
            RequiresReview: true);
    }

    private static string? BuildAzureCliFromFinding(
        Finding finding,
        string fallback)
    {
        if (!string.IsNullOrWhiteSpace(finding.AzureCli))
        {
            return finding.AzureCli;
        }

        return null;
    }
}