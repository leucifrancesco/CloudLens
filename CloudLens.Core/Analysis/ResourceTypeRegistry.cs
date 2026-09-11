using System.Collections.ObjectModel;

namespace CloudLens.Core.Analysis;

public sealed record ResourceTypeDefinition(
    string ResourceType,
    string ServiceFamily,
    bool SpecializedAnalyzer,
    string Description);

public sealed class ResourceTypeRegistry
{
    private readonly Dictionary<string, ResourceTypeDefinition> _definitions =
        new(StringComparer.OrdinalIgnoreCase);

    public ResourceTypeRegistry()
    {
        RegisterDefaults();
    }

    public IReadOnlyCollection<ResourceTypeDefinition> Definitions =>
        new ReadOnlyCollection<ResourceTypeDefinition>(
            _definitions.Values
                .OrderBy(
                    x => x.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .ToList());

    public ResourceTypeDefinition Resolve(string? resourceType)
    {
        if (string.IsNullOrWhiteSpace(resourceType))
        {
            return new ResourceTypeDefinition(
                "unknown",
                "Unknown",
                false,
                "Resource type non disponibile.");
        }

        if (_definitions.TryGetValue(
                resourceType,
                out var definition))
        {
            return definition;
        }

        return CreateGenericDefinition(resourceType);
    }

    public bool HasSpecializedAnalyzer(string? resourceType)
    {
        return Resolve(resourceType).SpecializedAnalyzer;
    }

    private void RegisterDefaults()
    {
        // =========================================================
        // COMPUTE
        // =========================================================

        Register(
            "Microsoft.Compute/virtualMachines",
            "Compute",
            true,
            "Azure Virtual Machines: security, backup, availability and exposure checks.");

        Register(
            "Microsoft.Compute/virtualMachineScaleSets",
            "Compute",
            true,
            "Virtual Machine Scale Sets: security and availability checks.");

        Register(
            "Microsoft.Compute/disks",
            "Compute",
            true,
            "Managed disks: encryption and lifecycle/cost checks.");

        Register(
            "Microsoft.Compute/snapshots",
            "Compute",
            true,
            "Managed disk snapshots: lifecycle and cost checks.");

        Register(
            "Microsoft.Compute/images",
            "Compute",
            false,
            "Managed VM images.");

        Register(
            "Microsoft.Compute/availabilitySets",
            "Compute",
            false,
            "VM availability sets.");

        // =========================================================
        // NETWORK
        // =========================================================

        Register(
            "Microsoft.Network/virtualNetworks",
            "Network",
            true,
            "Virtual networks: network topology and security configuration.");

        Register(
            "Microsoft.Network/virtualNetworks/subnets",
            "Network",
            true,
            "Virtual network subnets: NSG and network security configuration.");

        Register(
            "Microsoft.Network/networkInterfaces",
            "Network",
            true,
            "Network interfaces: public IP exposure and topology.");

        Register(
            "Microsoft.Network/networkSecurityGroups",
            "Network",
            true,
            "Network security groups: inbound exposure and dangerous rules.");

        Register(
            "Microsoft.Network/publicIPAddresses",
            "Network",
            true,
            "Public IP addresses: exposure and unused-resource checks.");

        Register(
            "Microsoft.Network/loadBalancers",
            "Network",
            true,
            "Azure Load Balancers.");

        Register(
            "Microsoft.Network/applicationGateways",
            "Network",
            true,
            "Application Gateway: HTTPS and exposure checks.");

        Register(
            "Microsoft.Network/azureFirewalls",
            "Network",
            true,
            "Azure Firewall.");

        Register(
            "Microsoft.Network/natGateways",
            "Network",
            true,
            "NAT Gateway.");

        Register(
            "Microsoft.Network/routeTables",
            "Network",
            false,
            "Route tables.");

        Register(
            "Microsoft.Network/virtualNetworkGateways",
            "Network",
            true,
            "VPN and ExpressRoute virtual network gateways.");

        Register(
            "Microsoft.Network/connections",
            "Network",
            false,
            "VPN or ExpressRoute connections.");

        Register(
            "Microsoft.Network/bastionHosts",
            "Network",
            true,
            "Azure Bastion.");

        Register(
            "Microsoft.Network/privateEndpoints",
            "Network",
            true,
            "Private endpoints.");

        Register(
            "Microsoft.Network/privateDnsZones",
            "Network",
            false,
            "Private DNS zones.");

        Register(
            "Microsoft.Network/frontDoors",
            "Network",
            true,
            "Azure Front Door.");

        Register(
            "Microsoft.Network/trafficManagerProfiles",
            "Network",
            true,
            "Traffic Manager profiles.");

        // =========================================================
        // STORAGE
        // =========================================================

        Register(
            "Microsoft.Storage/storageAccounts",
            "Storage",
            true,
            "Storage accounts: public access, TLS, network access, replication and security.");

        Register(
            "Microsoft.Storage/storageAccounts/blobServices",
            "Storage",
            false,
            "Blob services.");

        Register(
            "Microsoft.Storage/storageAccounts/fileServices",
            "Storage",
            false,
            "Azure Files services.");

        Register(
            "Microsoft.Storage/storageAccounts/queueServices",
            "Storage",
            false,
            "Queue services.");

        Register(
            "Microsoft.Storage/storageAccounts/tableServices",
            "Storage",
            false,
            "Table services.");

        Register(
            "Microsoft.StorageSync/storageSyncServices",
            "Storage",
            true,
            "Azure File Sync.");

        // =========================================================
        // WEB
        // =========================================================

        Register(
            "Microsoft.Web/sites",
            "Web",
            true,
            "App Services and Function Apps: HTTPS, public exposure and application security.");

        Register(
            "Microsoft.Web/serverfarms",
            "Web",
            true,
            "App Service Plans: SKU and scaling configuration.");

        Register(
            "Microsoft.Web/hostingEnvironments",
            "Web",
            true,
            "App Service Environments.");

        // =========================================================
        // DATABASE
        // =========================================================

        Register(
            "Microsoft.Sql/servers",
            "Database",
            true,
            "Azure SQL logical servers: public network and firewall security.");

        Register(
            "Microsoft.Sql/servers/databases",
            "Database",
            true,
            "Azure SQL databases: security, backup and configuration.");

        Register(
            "Microsoft.Sql/managedInstances",
            "Database",
            true,
            "Azure SQL Managed Instances.");

        Register(
            "Microsoft.DBforPostgreSQL/flexibleServers",
            "Database",
            true,
            "Azure Database for PostgreSQL Flexible Server.");

        Register(
            "Microsoft.DBforMySQL/flexibleServers",
            "Database",
            true,
            "Azure Database for MySQL Flexible Server.");

        Register(
            "Microsoft.DocumentDB/databaseAccounts",
            "Database",
            true,
            "Azure Cosmos DB: network and security configuration.");

        Register(
            "Microsoft.Cache/Redis",
            "Database",
            true,
            "Azure Cache for Redis.");

        // =========================================================
        // CONTAINERS
        // =========================================================

        Register(
            "Microsoft.ContainerService/managedClusters",
            "Containers",
            true,
            "Azure Kubernetes Service: API exposure, RBAC and network security.");

        Register(
            "Microsoft.ContainerRegistry/registries",
            "Containers",
            true,
            "Azure Container Registry: public access and administrative access.");

        Register(
            "Microsoft.App/containerApps",
            "Containers",
            true,
            "Azure Container Apps.");

        Register(
            "Microsoft.App/managedEnvironments",
            "Containers",
            true,
            "Container Apps managed environments.");

        // =========================================================
        // INTEGRATION
        // =========================================================

        Register(
            "Microsoft.ServiceBus/namespaces",
            "Integration",
            true,
            "Azure Service Bus: network security and public exposure.");

        Register(
            "Microsoft.EventHub/namespaces",
            "Integration",
            true,
            "Azure Event Hubs: network security and public exposure.");

        Register(
            "Microsoft.EventGrid/topics",
            "Integration",
            true,
            "Event Grid topics.");

        Register(
            "Microsoft.EventGrid/domains",
            "Integration",
            true,
            "Event Grid domains.");

        Register(
            "Microsoft.Logic/workflows",
            "Integration",
            true,
            "Logic Apps workflows.");

        Register(
            "Microsoft.ApiManagement/service",
            "Integration",
            true,
            "API Management: public exposure and security configuration.");

        // =========================================================
        // SECURITY
        // =========================================================

        Register(
            "Microsoft.KeyVault/vaults",
            "Security",
            true,
            "Azure Key Vault: network access, purge protection and security configuration.");

        Register(
            "Microsoft.ManagedIdentity/userAssignedIdentities",
            "Security",
            false,
            "User-assigned managed identities.");

        // =========================================================
        // MONITORING
        // =========================================================

        Register(
            "Microsoft.OperationalInsights/workspaces",
            "Monitoring",
            true,
            "Log Analytics workspaces.");

        Register(
            "Microsoft.Insights/components",
            "Monitoring",
            true,
            "Application Insights.");

        Register(
            "Microsoft.Insights/metricalerts",
            "Monitoring",
            true,
            "Azure Monitor metric alerts.");

        Register(
            "Microsoft.Insights/activityLogAlerts",
            "Monitoring",
            true,
            "Azure Activity Log alerts.");

        Register(
            "Microsoft.Insights/actionGroups",
            "Monitoring",
            true,
            "Azure Monitor action groups.");

        Register(
            "Microsoft.Insights/dataCollectionRules",
            "Monitoring",
            true,
            "Azure Monitor data collection rules.");

        // =========================================================
        // BACKUP
        // =========================================================

        Register(
            "Microsoft.RecoveryServices/vaults",
            "Backup",
            true,
            "Recovery Services vaults.");

        Register(
            "Microsoft.DataProtection/backupVaults",
            "Backup",
            true,
            "Azure Backup vaults.");

        // =========================================================
        // DATA / ANALYTICS
        // =========================================================

        Register(
            "Microsoft.DataFactory/factories",
            "DataAnalytics",
            true,
            "Azure Data Factory.");

        Register(
            "Microsoft.Synapse/workspaces",
            "DataAnalytics",
            true,
            "Azure Synapse Analytics.");

        Register(
            "Microsoft.Databricks/workspaces",
            "DataAnalytics",
            true,
            "Azure Databricks.");

        Register(
            "Microsoft.Purview/accounts",
            "DataAnalytics",
            true,
            "Microsoft Purview.");

        // =========================================================
        // MANAGEMENT
        // =========================================================

        Register(
            "Microsoft.Automation/automationAccounts",
            "Management",
            true,
            "Azure Automation.");

        Register(
            "Microsoft.Resources/resourceGroups",
            "Management",
            false,
            "Azure resource groups.");

        // =========================================================
        // AI
        // =========================================================

        Register(
            "Microsoft.CognitiveServices/accounts",
            "AI",
            true,
            "Azure AI services.");

        Register(
            "Microsoft.MachineLearningServices/workspaces",
            "AI",
            true,
            "Azure Machine Learning workspaces.");
    }

    private void Register(
        string resourceType,
        string serviceFamily,
        bool specializedAnalyzer,
        string description)
    {
        _definitions[resourceType] =
            new ResourceTypeDefinition(
                resourceType,
                serviceFamily,
                specializedAnalyzer,
                description);
    }

    private static ResourceTypeDefinition CreateGenericDefinition(
        string resourceType)
    {
        var parts =
            resourceType.Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length == 0)
        {
            return new ResourceTypeDefinition(
                resourceType,
                "Unknown",
                false,
                "Resource type non riconosciuto.");
        }

        var provider = parts[0];

        var serviceFamily =
            provider switch
            {
                "Microsoft.Compute" => "Compute",
                "Microsoft.Network" => "Network",
                "Microsoft.Storage" => "Storage",
                "Microsoft.StorageSync" => "Storage",
                "Microsoft.Web" => "Web",
                "Microsoft.Sql" => "Database",
                "Microsoft.DBforPostgreSQL" => "Database",
                "Microsoft.DBforMySQL" => "Database",
                "Microsoft.DocumentDB" => "Database",
                "Microsoft.Cache" => "Database",
                "Microsoft.ContainerService" => "Containers",
                "Microsoft.ContainerRegistry" => "Containers",
                "Microsoft.App" => "Containers",
                "Microsoft.ServiceBus" => "Integration",
                "Microsoft.EventHub" => "Integration",
                "Microsoft.EventGrid" => "Integration",
                "Microsoft.Logic" => "Integration",
                "Microsoft.ApiManagement" => "Integration",
                "Microsoft.KeyVault" => "Security",
                "Microsoft.ManagedIdentity" => "Security",
                "Microsoft.Insights" => "Monitoring",
                "Microsoft.OperationalInsights" => "Monitoring",
                "Microsoft.RecoveryServices" => "Backup",
                "Microsoft.DataProtection" => "Backup",
                "Microsoft.DataFactory" => "DataAnalytics",
                "Microsoft.Synapse" => "DataAnalytics",
                "Microsoft.Databricks" => "DataAnalytics",
                "Microsoft.Purview" => "DataAnalytics",
                "Microsoft.Automation" => "Management",
                "Microsoft.Resources" => "Management",
                "Microsoft.CognitiveServices" => "AI",
                "Microsoft.MachineLearningServices" => "AI",
                _ => "Other"
            };

        return new ResourceTypeDefinition(
            resourceType,
            serviceFamily,
            false,
            "Resource type rilevato automaticamente; nessun analyzer specializzato registrato.");
    }
}