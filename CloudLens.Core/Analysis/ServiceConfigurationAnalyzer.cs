using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ServiceConfigurationAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        foreach (var resource in resources)
        {
            switch (resource.Type.ToLowerInvariant())
            {
                case "microsoft.compute/virtualmachines":
                    AnalyzeVirtualMachine(resource, findings);
                    break;
                case "microsoft.compute/virtualmachinescalesets":
                    AnalyzeVmScaleSet(resource, findings);
                    break;
                case "microsoft.network/virtualnetworks/subnets":
                    AnalyzeSubnet(resource, resources, findings);
                    break;
                case "microsoft.network/networkinterfaces":
                    AnalyzeNetworkInterface(resource, findings);
                    break;
                case "microsoft.network/applicationgateways":
                    AnalyzeApplicationGateway(resource, findings);
                    break;
                case "microsoft.network/privateendpoints":
                    AnalyzePrivateEndpoint(resource, findings);
                    break;
                case "microsoft.web/sites":
                    AnalyzeWebApp(resource, findings);
                    break;
                case "microsoft.web/serverfarms":
                    AnalyzeAppServicePlan(resource, findings);
                    break;
                case "microsoft.sql/servers/databases":
                    AnalyzeSqlDatabase(resource, findings);
                    break;
                case "microsoft.sql/servers":
                    AnalyzeSqlServer(resource, resources, findings);
                    break;
                case "microsoft.documentdb/databaseaccounts":
                    AnalyzeCosmosDb(resource, resources, findings);
                    break;
                case "microsoft.containerservice/managedclusters":
                    AnalyzeAks(resource, findings);
                    break;
                case "microsoft.containerregistry/registries":
                    AnalyzeAcr(resource, resources, findings);
                    break;
                case "microsoft.messaging/namespaces":
                    AnalyzeMessaging(resource, resources, findings);
                    break;
                case "microsoft.recoveryservices/vaults":
                    AnalyzeRecoveryServicesVault(resource, findings);
                    break;
                case "microsoft.operationalinsights/workspaces":
                    AnalyzeLogAnalyticsWorkspace(resource, findings);
                    break;
                case "microsoft.insights/components":
                    AnalyzeApplicationInsights(resource, findings);
                    break;
                case "microsoft.cognitiveservices/accounts":
                    AnalyzeCognitiveServices(resource, resources, findings);
                    break;
                case "microsoft.apimanagement/service":
                    AnalyzeApiManagement(resource, resources, findings);
                    break;
                case "microsoft.dbforpostgresql/flexibleservers":
                case "microsoft.dbformysql/flexibleservers":
                    AnalyzeFlexibleDatabase(resource, resources, findings);
                    break;
            }
        }

        return findings;
    }

    // =========================================================
    // VIRTUAL MACHINE
    // =========================================================

    private static void AnalyzeVirtualMachine(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (TryGetBool(
                properties.Value,
                "securityProfile",
                "uefiSettings",
                "secureBootEnabled",
                out var secureBootEnabled) &&
            !secureBootEnabled)
        {
            Add(
                findings, resource,
                "SEC-VM-SECURE-BOOT-DISABLED",
                Severity.Medium,
                "Secure Boot disabilitato",
                "La macchina virtuale non utilizza Secure Boot.",
                "La disabilitazione di Secure Boot riduce le protezioni disponibili contro componenti di boot non attendibili.",
                "Valutare l'abilitazione di Secure Boot se compatibile con il sistema operativo e il workload.",
                Category.Security);
        }
    }

    // =========================================================
    // VM SCALE SET
    // =========================================================

    private static void AnalyzeVmScaleSet(
        AzureResource resource,
        List<Finding> findings)
    {
        if (!resource.Sku.HasValue)
            return;

        if (TryGetString(resource.Sku.Value, "name", out var skuName) &&
            string.Equals(skuName, "Basic", StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings, resource,
                "COST-VMSS-BASIC-SKU",
                Severity.Low,
                "VM Scale Set con SKU Basic",
                "Il Virtual Machine Scale Set utilizza uno SKU Basic.",
                "Lo SKU Basic offre funzionalità e capacità inferiori rispetto agli SKU più recenti e può limitare le opzioni architetturali disponibili.",
                "Valutare la migrazione a uno SKU più appropriato per il workload.",
                Category.Cost);
        }
    }

    // =========================================================
    // SUBNET
    // =========================================================

    private static void AnalyzeSubnet(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (GetProperty(properties.Value, "networkSecurityGroup").HasValue)
            return;

        var subnetId = NormalizeId(resource.Id);

        var hasNetworkInterface = resources.Any(otherResource =>
            string.Equals(
                otherResource.Type,
                "Microsoft.Network/networkInterfaces",
                StringComparison.OrdinalIgnoreCase) &&
            otherResource.Relationships.Any(relationship =>
                string.Equals(
                    relationship.RelationshipType,
                    "Subnet",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    NormalizeId(relationship.TargetResourceId),
                    subnetId,
                    StringComparison.OrdinalIgnoreCase)));

        if (!hasNetworkInterface)
            return;

        Add(
            findings, resource,
            "SEC-SUBNET-NO-NSG",
            Severity.Low,
            "Subnet utilizzata senza NSG associato",
            "La subnet è utilizzata da almeno una Network Interface ma non risulta associata a un Network Security Group.",
            "La subnet non dispone di un controllo NSG dedicato, aumentando il rischio di una segmentazione di rete meno restrittiva del necessario.",
            "Valutare l'associazione di un NSG coerente con i requisiti di sicurezza e con il modello di segmentazione della rete.",
            Category.Security);
    }

    // =========================================================
    // NETWORK INTERFACE
    // =========================================================

    private static void AnalyzeNetworkInterface(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (!TryGetArray(properties.Value, "ipConfigurations", out var configurations))
            return;

        foreach (var configuration in configurations.EnumerateArray())
        {
            if (!TryGetProperty(configuration, "properties", out var ipProperties) ||
                !TryGetProperty(ipProperties, "publicIPAddress", out var publicIp) ||
                publicIp.ValueKind != JsonValueKind.Object ||
                !TryGetString(publicIp, "id", out var publicIpId))
            {
                continue;
            }

            Add(
                findings, resource,
                "SEC-NIC-PUBLIC-IP",
                Severity.Medium,
                "Network Interface associata a un Public IP",
                "La Network Interface dispone di almeno una configurazione IP associata a un Public IP.",
                "L'associazione di un Public IP rende la risorsa potenzialmente raggiungibile direttamente da Internet, a seconda delle regole NSG e degli altri controlli di rete.",
                "Verificare se l'esposizione pubblica è necessaria e applicare NSG e altri controlli di rete appropriati.",
                Category.Security);
            break;
        }
    }

    // =========================================================
    // APPLICATION GATEWAY
    // =========================================================

    private static void AnalyzeApplicationGateway(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetArray(properties.Value, "httpListeners", out var listeners))
            return;

        foreach (var listener in listeners.EnumerateArray())
        {
            if (!TryGetProperty(listener, "properties", out var listenerProperties))
                continue;

            if (!string.Equals(
                    GetString(listenerProperties, "protocol"),
                    "Http",
                    StringComparison.OrdinalIgnoreCase))
                continue;

            Add(
                findings, resource,
                "SEC-APPGW-HTTP-LISTENER",
                Severity.Medium,
                "Application Gateway con listener HTTP",
                "L'Application Gateway espone almeno un listener HTTP non cifrato.",
                "Il traffico gestito dal listener HTTP non utilizza TLS sul tratto client-to-gateway.",
                "Valutare la conversione del listener a HTTPS e l'utilizzo di un certificato TLS valido.",
                Category.Security);
            break;
        }
    }

    // =========================================================
    // PRIVATE ENDPOINT
    // =========================================================

    private static void AnalyzePrivateEndpoint(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetArray(properties.Value, "privateLinkServiceConnections", out var connections))
            return;

        foreach (var connection in connections.EnumerateArray())
        {
            if (!TryGetProperty(connection, "properties", out var connectionProperties) ||
                !TryGetProperty(
                    connectionProperties,
                    "privateLinkServiceConnectionState",
                    out var connectionState))
                continue;

            var status = GetString(connectionState, "status");

            if (string.Equals(status, "Approved", StringComparison.OrdinalIgnoreCase))
                continue;

            Add(
                findings, resource,
                "OPS-PRIVATE-ENDPOINT-UNRESOLVED",
                Severity.Medium,
                "Private Endpoint con connessione non approvata",
                "Il Private Endpoint presenta almeno una private link service connection non approvata.",
                "La connessione al servizio target potrebbe non essere operativa.",
                "Verificare lo stato della connessione e completare l'approvazione se prevista dall'architettura.",
                Category.Operations);
            break;
        }
    }

    // =========================================================
    // WEB APP
    // =========================================================

    private static void AnalyzeWebApp(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (TryGetBool(properties.Value, "httpsOnly", out var httpsOnly) && !httpsOnly)
        {
            Add(
                findings, resource,
                "SEC-APP-NO-HTTPS",
                Severity.Medium,
                "Web App senza HTTPS obbligatorio",
                "La Web App non forza il traffico HTTPS.",
                "Le richieste HTTP possono transitare senza cifratura end-to-end verso il servizio.",
                "Abilitare HTTPS Only per forzare il traffico HTTPS.",
                Category.Security);
        }

        if (TryGetString(properties.Value, "ftpState", out var ftpState) &&
            string.Equals(ftpState, "AllAllowed", StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings, resource,
                "SEC-APP-FTP-ALL",
                Severity.Medium,
                "Web App con accesso FTP non cifrato consentito",
                "La Web App consente l'accesso FTP secondo la configurazione corrente.",
                "FTP può trasmettere credenziali e dati senza protezioni TLS.",
                "Disabilitare FTP non necessario oppure utilizzare FTPS secondo i requisiti del workload.",
                Category.Security);
        }
    }

    // =========================================================
    // APP SERVICE PLAN
    // =========================================================

    private static void AnalyzeAppServicePlan(
        AzureResource resource,
        List<Finding> findings)
    {
        if (!resource.Sku.HasValue ||
            !TryGetString(resource.Sku.Value, "name", out var skuName))
            return;

        if (!string.Equals(skuName, "F1", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(skuName, "D1", StringComparison.OrdinalIgnoreCase))
            return;

        Add(
            findings, resource,
            "COST-APPPLAN-FREE",
            Severity.Low,
            "App Service Plan con tier Free/Shared",
            "L'App Service Plan utilizza un tier Free/Shared.",
            "Il tier può essere inadeguato per workload produttivi e presenta limitazioni di capacità e funzionalità.",
            "Verificare i requisiti del workload e valutare un tier appropriato.",
            Category.Cost);
    }

    // =========================================================
    // SQL DATABASE
    // =========================================================

    private static void AnalyzeSqlDatabase(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (TryGetBool(properties.Value, "paused", out var paused) && paused)
        {
            Add(
                findings, resource,
                "COST-SQLDB-PAUSED",
                Severity.Low,
                "SQL Database attualmente in stato paused",
                "Il database SQL risulta in stato paused.",
                "Il database potrebbe avere un utilizzo intermittente e la configurazione può richiedere una revisione in funzione del workload.",
                "Verificare il comportamento atteso del database e il modello di utilizzo.",
                Category.Cost);
        }
    }

    // =========================================================
    // SQL SERVER
    // =========================================================

    private static void AnalyzeSqlServer(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-DB-PUBLIC-NETWORK",
            Severity.Medium,
            "SQL Server accessibile tramite rete pubblica",
            "Il SQL Server risulta abilitato all'accesso tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "Un endpoint pubblico aumenta la superficie di esposizione del database.",
            "Valutare l'utilizzo di Private Endpoint oppure configurare restrizioni di rete coerenti con i requisiti del workload.",
            Category.Security);
    }

    // =========================================================
    // COSMOS DB
    // =========================================================

    private static void AnalyzeCosmosDb(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-COSMOS-PUBLIC-NETWORK",
            Severity.Medium,
            "Cosmos DB accessibile tramite rete pubblica",
            "Cosmos DB risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "Un endpoint pubblico aumenta la superficie di esposizione del servizio.",
            "Valutare Private Endpoint oppure configurare restrizioni di rete appropriate.",
            Category.Security);
    }

    // =========================================================
    // AKS
    // =========================================================

    private static void AnalyzeAks(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        var isPrivateCluster =
            TryGetBool(
                properties.Value,
                "apiServerAccessProfile",
                "enablePrivateCluster",
                out var privateCluster) &&
            privateCluster;

        var hasAuthorizedIpRanges =
            TryGetArray(
                properties.Value,
                "apiServerAccessProfile",
                "authorizedIpRanges",
                out var ranges) &&
            ranges.GetArrayLength() > 0;

        if (!isPrivateCluster && !hasAuthorizedIpRanges)
        {
            Add(
                findings, resource,
                "SEC-AKS-PUBLIC-API",
                Severity.Medium,
                "AKS con API Server pubblicamente accessibile",
                "Il cluster AKS non risulta private e non presenta authorized IP ranges valorizzati nei dati raccolti.",
                "L'API Server può risultare raggiungibile da reti non previste, aumentando la superficie di attacco amministrativa.",
                "Valutare un private cluster oppure limitare l'accesso tramite authorized IP ranges.",
                Category.Security);
        }

        if (TryGetBool(properties.Value, "disableLocalAccounts", out var disableLocalAccounts) &&
            !disableLocalAccounts)
        {
            Add(
                findings, resource,
                "SEC-AKS-LOCAL-ACCOUNTS",
                Severity.Medium,
                "AKS con account locali abilitati",
                "Il cluster AKS consente l'utilizzo degli account locali.",
                "Gli account locali possono aumentare la superficie di autenticazione oltre ai meccanismi di identità centralizzata.",
                "Valutare la disabilitazione degli account locali quando compatibile con il modello operativo.",
                Category.Security);
        }
    }

    // =========================================================
    // ACR
    // =========================================================

    private static void AnalyzeAcr(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (TryGetBool(properties.Value, "adminUserEnabled", out var adminUserEnabled) &&
            adminUserEnabled)
        {
            Add(
                findings, resource,
                "SEC-ACR-ADMIN-USER",
                Severity.Medium,
                "Azure Container Registry con admin user abilitato",
                "L'admin user del Container Registry risulta abilitato.",
                "L'utilizzo di credenziali amministrative statiche aumenta la superficie di gestione delle credenziali.",
                "Preferire Microsoft Entra ID e managed identity quando supportati dal workload.",
                Category.Security);
        }

        if (!TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-ACR-PUBLIC-NETWORK",
            Severity.Medium,
            "Azure Container Registry accessibile tramite rete pubblica",
            "Il Container Registry risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "L'accesso pubblico aumenta la superficie di esposizione del registry e delle immagini container.",
            "Valutare Private Endpoint oppure configurare restrizioni di rete appropriate.",
            Category.Security);
    }

    // =========================================================
    // MESSAGING
    // =========================================================

    private static void AnalyzeMessaging(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-MESSAGING-PUBLIC-NETWORK",
            Severity.Medium,
            "Messaging namespace accessibile tramite rete pubblica",
            "Il namespace Messaging risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "L'accesso pubblico aumenta la superficie di esposizione del servizio di messaging.",
            "Valutare Private Endpoint oppure configurare restrizioni di rete appropriate.",
            Category.Security);
    }

    // =========================================================
    // RECOVERY SERVICES
    // =========================================================

    private static void AnalyzeRecoveryServicesVault(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (TryGetBool(properties.Value, "softDeleteFeatureState", out var softDeleteEnabled) &&
            !softDeleteEnabled)
        {
            Add(
                findings, resource,
                "SEC-BACKUP-SOFTDELETE",
                Severity.High,
                "Soft Delete del Recovery Services Vault non abilitato",
                "Il Recovery Services Vault non risulta configurato con Soft Delete abilitato.",
                "La cancellazione accidentale o malevola dei dati di backup può risultare più difficile da recuperare.",
                "Abilitare Soft Delete secondo i requisiti di protezione del workload.",
                Category.Security);
        }
    }

    // =========================================================
    // LOG ANALYTICS
    // =========================================================

    private static void AnalyzeLogAnalyticsWorkspace(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetInt(properties.Value, "retentionInDays", out var retentionDays) ||
            retentionDays >= 30)
            return;

        Add(
            findings, resource,
            "OPS-LOG-RETENTION-LOW",
            Severity.Low,
            "Log Analytics con retention inferiore a 30 giorni",
            $"Il workspace Log Analytics presenta una retention di {retentionDays} giorni.",
            "Una retention ridotta limita la disponibilità dei dati storici per troubleshooting, auditing e analisi.",
            "Valutare una retention coerente con i requisiti operativi, di sicurezza e compliance.",
            Category.Operations);
    }

    // =========================================================
    // APPLICATION INSIGHTS
    // =========================================================

    private static void AnalyzeApplicationInsights(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue)
            return;

        if (properties.Value.TryGetProperty("Application_Type", out var appType) &&
            appType.ValueKind == JsonValueKind.String &&
            string.IsNullOrWhiteSpace(appType.GetString()))
        {
            Add(
                findings, resource,
                "OPS-APPINSIGHTS-CONFIG",
                Severity.Low,
                "Application Insights con configurazione incompleta",
                "Application Insights non presenta un Application Type valorizzato nei dati raccolti.",
                "Una configurazione incompleta può ridurre la qualità della telemetria e delle informazioni disponibili.",
                "Verificare la configurazione di Application Insights.",
                Category.Operations);
        }
    }

    // =========================================================
    // COGNITIVE SERVICES
    // =========================================================

    private static void AnalyzeCognitiveServices(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-AI-PUBLIC-NETWORK",
            Severity.Medium,
            "Cognitive Services accessibile tramite rete pubblica",
            "Il servizio Cognitive Services risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "L'accesso pubblico aumenta la superficie di esposizione delle API cognitive.",
            "Valutare Private Endpoint oppure configurare restrizioni di rete appropriate.",
            Category.Security);
    }

    // =========================================================
    // API MANAGEMENT
    // =========================================================

    private static void AnalyzeApiManagement(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-APIM-PUBLIC-NETWORK",
            Severity.Medium,
            "API Management accessibile tramite rete pubblica",
            "API Management risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "L'accesso pubblico aumenta la superficie di esposizione degli endpoint API.",
            "Valutare Private Endpoint oppure configurare restrizioni di rete appropriate.",
            Category.Security);
    }

    // =========================================================
    // FLEXIBLE DATABASE
    // =========================================================

    private static void AnalyzeFlexibleDatabase(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();
        if (!properties.HasValue ||
            !TryGetString(properties.Value, "publicNetworkAccess", out var access) ||
            !string.Equals(access, "Enabled", StringComparison.OrdinalIgnoreCase))
            return;

        if (HasPrivateEndpointConnection(resource, resources) ||
            HasNetworkRestriction(properties.Value))
            return;

        Add(
            findings, resource,
            "SEC-DB-PUBLIC-NETWORK",
            Severity.Medium,
            "Flexible Database accessibile tramite rete pubblica",
            "Il database Flexible Server risulta accessibile tramite rete pubblica senza evidenza di restrizioni di rete sufficienti nei dati raccolti.",
            "L'accesso pubblico aumenta la superficie di esposizione del database.",
            "Valutare Private Endpoint o configurare correttamente le regole di rete.",
            Category.Security);
    }

    // =========================================================
    // NETWORK HELPERS
    // =========================================================

    private static bool HasPrivateEndpointConnection(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources)
    {
        var targetId = NormalizeId(resource.Id);

        foreach (var endpoint in resources)
        {
            if (!string.Equals(
                    endpoint.Type,
                    "Microsoft.Network/privateEndpoints",
                    StringComparison.OrdinalIgnoreCase))
                continue;

            var hasTargetRelationship = endpoint.Relationships.Any(relationship =>
                string.Equals(
                    relationship.RelationshipType,
                    "PrivateLinkTarget",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    NormalizeId(relationship.TargetResourceId),
                    targetId,
                    StringComparison.OrdinalIgnoreCase));

            if (!hasTargetRelationship)
                continue;

            var properties = endpoint.GetEffectiveProperties();
            if (!properties.HasValue ||
                !TryGetArray(
                    properties.Value,
                    "privateLinkServiceConnections",
                    out var connections))
                continue;

            foreach (var connection in connections.EnumerateArray())
            {
                if (!TryGetProperty(
                        connection,
                        "properties",
                        out var connectionProperties) ||
                    !TryGetString(
                        connectionProperties,
                        "privateLinkServiceId",
                        out var linkedResourceId) ||
                    string.IsNullOrWhiteSpace(linkedResourceId) ||
                    !string.Equals(
                        NormalizeId(linkedResourceId),
                        targetId,
                        StringComparison.OrdinalIgnoreCase) ||
                    !TryGetProperty(
                        connectionProperties,
                        "privateLinkServiceConnectionState",
                        out var connectionState))
                {
                    continue;
                }

                if (TryGetString(connectionState, "status", out var status) &&
                    string.Equals(
                        status,
                        "Approved",
                        StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static bool HasNetworkRestriction(JsonElement properties)
    {
        if (HasDefaultActionDeny(properties))
            return true;

        if (!TryGetArray(properties, "networkAcls", out var networkAcls))
            return false;

        foreach (var acl in networkAcls.EnumerateArray())
        {
            if (acl.ValueKind != JsonValueKind.Object)
                continue;

            if (TryGetString(acl, "defaultAction", out var defaultAction) &&
                string.Equals(
                    defaultAction,
                    "Deny",
                    StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool HasDefaultActionDeny(JsonElement properties)
    {
        return TryGetString(
                properties,
                "networkRuleSet",
                "defaultAction",
                out var defaultAction) &&
            string.Equals(
                defaultAction,
                "Deny",
                StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================
    // JSON HELPERS
    // =========================================================

    private static JsonElement? GetProperty(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value)
            ? value
            : null;
    }

    private static bool TryGetProperty(
        JsonElement element,
        string propertyName,
        out JsonElement value)
    {
        return element.TryGetProperty(propertyName, out value);
    }

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        return TryGetString(element, propertyName, out var value)
            ? value
            : null;
    }

    private static bool TryGetString(
        JsonElement element,
        string propertyName,
        out string? value)
    {
        value = null;

        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
            return false;

        value = property.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryGetString(
        JsonElement element,
        string parentProperty,
        string childProperty,
        out string? value)
    {
        value = null;

        return element.TryGetProperty(parentProperty, out var parent) &&
            TryGetString(parent, childProperty, out value);
    }

    private static bool TryGetBool(
        JsonElement element,
        string propertyName,
        out bool value)
    {
        value = false;

        if (!element.TryGetProperty(propertyName, out var property) ||
            (property.ValueKind != JsonValueKind.True &&
             property.ValueKind != JsonValueKind.False))
            return false;

        value = property.GetBoolean();
        return true;
    }

    private static bool TryGetBool(
        JsonElement element,
        string parentProperty,
        string childProperty,
        out bool value)
    {
        value = false;

        return element.TryGetProperty(parentProperty, out var parent) &&
            TryGetBool(parent, childProperty, out value);
    }

    private static bool TryGetBool(
        JsonElement element,
        string parentProperty,
        string childProperty,
        string grandChildProperty,
        out bool value)
    {
        value = false;

        if (!element.TryGetProperty(parentProperty, out var parent) ||
            !parent.TryGetProperty(childProperty, out var child))
            return false;

        return TryGetBool(child, grandChildProperty, out value);
    }

    private static bool TryGetArray(
        JsonElement element,
        string propertyName,
        out JsonElement value)
    {
        value = default;

        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.Array)
            return false;

        value = property;
        return true;
    }

    private static bool TryGetArray(
        JsonElement element,
        string parentProperty,
        string childProperty,
        out JsonElement value)
    {
        value = default;

        return element.TryGetProperty(parentProperty, out var parent) &&
            TryGetArray(parent, childProperty, out value);
    }

    private static bool TryGetInt(
        JsonElement element,
        string propertyName,
        out int value)
    {
        value = 0;

        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.Number)
            return false;

        return property.TryGetInt32(out value);
    }

    private static string NormalizeId(string id)
    {
        return id.Trim().TrimEnd('/');
    }

    // =========================================================
    // FINDING CREATION
    // =========================================================

    private static void Add(
        List<Finding> findings,
        AzureResource resource,
        string ruleId,
        Severity severity,
        string title,
        string description,
        string impact,
        string recommendation,
        Category category)
    {
        findings.Add(
            new Finding(
                $"{ruleId}-{resource.Id}",
                category,
                severity,
                ruleId,
                title,
                description,
                impact,
                recommendation,
                resource.Name,
                resource.Type,
                0,
                null,
                resource.Id));
    }
}
