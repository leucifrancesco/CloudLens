using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class RemediationEngine
{
    public RemediationPlan BuildPlan(
        IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return new RemediationPlan();
        }

        var actions = findings
            .Select(BuildAction)
            .Where(action => action is not null)
            .Cast<RemediationAction>()
            .GroupBy(
                action =>
                    $"{action.RuleId}|{action.ResourceId ?? action.ResourceName}",
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderByDescending(action => action.Severity)
            .ThenBy(action => action.Category)
            .ThenBy(
                action => action.ResourceName,
                StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new RemediationPlan
        {
            Actions = actions
        };
    }

    private static RemediationAction? BuildAction(Finding finding)
    {
        var rule = finding.RuleId.Trim().ToUpperInvariant();

        return rule switch
        {
            "SEC-NSG-INBOUND-ANY" =>
                Review(finding,
                    "Restrict the inbound NSG rule to the minimum required source, destination port and protocol."),

            "SEC-NSG-SSH-INTERNET" =>
                Review(finding,
                    "Restrict or remove inbound SSH access from the Internet. Prefer Bastion or a private management network."),

            "SEC-NSG-RDP-INTERNET" =>
                Review(finding,
                    "Restrict or remove inbound RDP access from the Internet. Prefer Bastion or a private management network."),

            "COST-UNUSED-PIP" =>
                Review(finding,
                    "Confirm that the public IP is not required by any workload or operational process, then remove it to avoid unnecessary cost."),

            "SEC-STORAGE-BLOB-PUBLIC" =>
                Review(finding,
                    "Disable anonymous public blob access unless explicitly required by the workload."),

            "SEC-STORAGE-HTTPS" =>
                Review(finding,
                    "Require HTTPS-only traffic for the storage account and validate client compatibility."),

            "SEC-STORAGE-TLS-OLD" =>
                Review(finding,
                    "Raise the minimum TLS version to TLS 1.2 or newer after validating client compatibility."),

            "SEC-STORAGE-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict storage account network access to approved virtual networks, private endpoints or explicitly approved IP ranges. Validate dependencies first."),

            "SEC-KV-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict Key Vault network access to approved networks and private endpoints after validating application dependencies."),

            "SEC-KV-NO-PURGE" =>
                Review(finding,
                    "Enable Key Vault purge protection after confirming vault lifecycle and recovery requirements."),

            "SEC-APP-NO-HTTPS" =>
                Review(finding,
                    "Require HTTPS-only access for the App Service and verify TLS configuration."),

            "SEC-APP-FTP-ALL" =>
                Review(finding,
                    "Disable FTP/FTPS publishing when it is not required. Prefer managed deployment mechanisms."),

            "SEC-SQL-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict or disable public network access where private connectivity is available. Validate all application dependencies first."),

            "SEC-DB-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict public network access to the database service and validate application connectivity before applying changes."),

            "SEC-COSMOS-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict Cosmos DB network access using private endpoints or approved network rules after validating application connectivity."),

            "SEC-AKS-PUBLIC-API" =>
                Review(finding,
                    "Restrict AKS API server exposure using private cluster configuration or authorized IP ranges, according to the cluster architecture."),

            "SEC-AKS-LOCAL-ACCOUNTS" =>
                Review(finding,
                    "Migrate administrative access to Microsoft Entra ID where supported, then disable local AKS accounts if compatible with operations."),

            "SEC-ACR-ADMIN-USER" =>
                Review(finding,
                    "Disable the ACR admin user and use Microsoft Entra ID, managed identities or service principals with least privilege."),

            "SEC-ACR-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict ACR network access using private endpoints or approved network rules after validating image-pull dependencies."),

            "SEC-MESSAGING-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict Service Bus or Event Hubs network access using private endpoints or approved network rules after validating producer and consumer connectivity."),

            "SEC-VM-SECURE-BOOT-DISABLED" =>
                Review(finding,
                    "Enable Secure Boot for supported VM generations after validating operating system and boot configuration compatibility."),

            "OPS-VM-NO-BACKUP" =>
                Review(finding,
                    "Configure an appropriate Azure Backup policy after confirming retention, RPO, RTO and recovery requirements."),

            "CORR-VM-NO-BACKUP-NO-HA" =>
                Review(finding,
                    "Review the combined backup and availability posture. Define appropriate backup protection and resilience based on workload criticality."),

            "ARCH-VM-NO-HA-DOMAIN" =>
                Review(finding,
                    "Review VM high-availability requirements. Consider Availability Zones, Availability Sets or another suitable resilience architecture."),

            "ARCH-VMSS-NO-ZONE" =>
                Review(finding,
                    "Review availability requirements and consider Availability Zones when supported by the VM Scale Set configuration and workload."),

            "ARCH-VMSS-SINGLE-INSTANCE" =>
                Review(finding,
                    "Assess workload availability requirements and configure multiple instances if required. Validate application behaviour during instance failure."),

            "ARCH-STORAGE-LRS" =>
                Review(finding,
                    "Evaluate whether LRS provides sufficient resilience. Consider ZRS, GRS or GZRS where justified by availability and disaster recovery requirements."),

            "ARCH-SINGLE-REGION" =>
                Review(finding,
                    "Review business continuity, disaster recovery, latency and data residency requirements. Consider multi-region architecture only when justified."),

            "CORR-STORAGE-SINGLE-REGION-LRS" =>
                Review(finding,
                    "Review the combined storage replication and regional resilience strategy. Consider ZRS, GRS or GZRS according to workload requirements."),

            "CORR-VM-PUBLIC-IP-MGMT-EXPOSURE" =>
                Review(finding,
                    "Remove unnecessary public exposure and provide administrative access through Bastion, VPN, private connectivity or tightly restricted network rules."),

            "COST-UNATTACHED-DISK" =>
                Review(finding,
                    "Confirm that the managed disk is no longer required, then delete it to eliminate unnecessary storage cost."),

            "OPS-PIP-BASIC-SKU" =>
                Review(finding,
                    "Review the Basic Public IP dependency and plan migration to a supported SKU, validating associated resources and connectivity."),

            "GOV-NO-TAGS" =>
                Review(finding,
                    "Define and apply an organizational tagging standard for ownership, environment, application and cost attribution."),

            "GOV-NO-LOCATION" =>
                Review(finding,
                    "Verify whether the missing location is expected for the resource type or results from incomplete discovery. Do not treat it automatically as non-compliance."),

            "SEC-SUBNET-NO-NSG" =>
                Review(finding,
                    "Associate an appropriate Network Security Group with the subnet and validate the resulting effective security rules."),

            "SEC-NIC-PUBLIC-IP" =>
                Review(finding,
                    "Remove unnecessary public IP exposure from the network interface and use private connectivity where possible."),

            "SEC-APPGW-HTTP-LISTENER" =>
                Review(finding,
                    "Replace HTTP listener exposure with HTTPS and configure a valid TLS certificate before removing HTTP access."),

            "OPS-PRIVATE-ENDPOINT-UNRESOLVED" =>
                Review(finding,
                    "Validate that the Private Endpoint is associated with the intended target resource and the correct private DNS configuration."),

            "COST-APPPLAN-FREE" =>
                Review(finding,
                    "Evaluate whether the App Service workload requires a higher service tier based on availability, scaling, networking and performance requirements."),

            "COST-SQLDB-PAUSED" =>
                Review(finding,
                    "Verify whether the paused SQL database is expected and assess its workload, availability and cost requirements before changing its state."),

            "COST-VMSS-BASIC-SKU" =>
                Review(finding,
                    "Review the VM Scale Set SKU and migrate from Basic when the workload requires capabilities not supported by that tier."),

            "SEC-BACKUP-SOFTDELETE" =>
                Review(finding,
                    "Review backup vault protection settings and enable soft delete with a retention period aligned to recovery requirements."),

            "OPS-LOG-RETENTION-LOW" =>
                Review(finding,
                    "Review Log Analytics retention against operational, compliance and cost requirements."),

            "OPS-APPINSIGHTS-CONFIG" =>
                Review(finding,
                    "Review Application Insights configuration, including availability of telemetry, sampling, retention and integration with the application."),

            "SEC-AI-PUBLIC-NETWORK" =>
                Review(finding,
                    "Restrict Cognitive Services network access using private endpoints or approved network rules after validating application dependencies."),

            "SEC-APIM-PUBLIC-NETWORK" =>
                Review(finding,
                    "Review API Management network exposure and restrict access using the appropriate private networking or access-control architecture."),

            _ => BuildGenericAction(finding)
        };
    }

    private static RemediationAction BuildGenericAction(Finding finding)
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

        return Manual(finding, finding.Recommendation);
    }

    private static RemediationAction Review(
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
            ActionType:
                string.IsNullOrWhiteSpace(finding.AzureCli)
                    ? RemediationActionType.Manual
                    : RemediationActionType.AzureCli,
            Status: RemediationStatus.ReviewRequired,
            Action: action,
            Command: finding.AzureCli,
            RequiresReview: true);
    }

    private static RemediationAction Manual(
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
}