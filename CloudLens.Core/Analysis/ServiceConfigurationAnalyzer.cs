using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ServiceConfigurationAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(nameof(resources));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(nameof(subscription));
        }

        var findings = new List<Finding>();

        foreach (var resource in resources)
        {
            switch (resource.Type.ToLowerInvariant())
            {
                case "microsoft.compute/virtualmachines":
                    AnalyzeVirtualMachine(resource, resources, findings);
                    break;

                case "microsoft.compute/virtualmachinescalesets":
                    AnalyzeVmScaleSet(resource, findings);
                    break;

                case "microsoft.compute/disks":
                    AnalyzeDisk(resource, findings);
                    break;

                case "microsoft.network/virtualnetworks/subnets":
                    AnalyzeSubnet(resource, findings);
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

                case "microsoft.storage/storageaccounts":
                    AnalyzeStorageAccount(resource, findings);
                    break;

                case "microsoft.web/sites":
                    AnalyzeWebSite(resource, findings);
                    break;

                case "microsoft.web/serverfarms":
                    AnalyzeAppServicePlan(resource, findings);
                    break;

                case "microsoft.sql/servers":
                    AnalyzeSqlServer(resource, findings);
                    break;

                case "microsoft.sql/servers/databases":
                    AnalyzeSqlDatabase(resource, findings);
                    break;

                case "microsoft.dbforpostgresql/flexibleservers":
                case "microsoft.dbformysql/flexibleservers":
                    AnalyzeFlexibleDatabase(resource, findings);
                    break;

                case "microsoft.documentdb/databaseaccounts":
                    AnalyzeCosmos(resource, findings);
                    break;

                case "microsoft.containerservice/managedclusters":
                    AnalyzeAks(resource, findings);
                    break;

                case "microsoft.containerregistry/registries":
                    AnalyzeContainerRegistry(resource, findings);
                    break;

                case "microsoft.servicebus/namespaces":
                case "microsoft.eventhub/namespaces":
                    AnalyzeMessagingNamespace(resource, findings);
                    break;

                case "microsoft.keyvault/vaults":
                    AnalyzeKeyVault(resource, findings);
                    break;

                case "microsoft.recoveryservices/vaults":
                case "microsoft.dataprotection/backupvaults":
                    AnalyzeBackupVault(resource, findings);
                    break;

                case "microsoft.operationalinsights/workspaces":
                    AnalyzeLogAnalytics(resource, findings);
                    break;

                case "microsoft.insights/components":
                    AnalyzeApplicationInsights(resource, findings);
                    break;

                case "microsoft.cognitiveservices/accounts":
                    AnalyzeCognitiveServices(resource, findings);
                    break;

                case "microsoft.apimanagement/service":
                    AnalyzeApiManagement(resource, findings);
                    break;
            }
        }

        return findings;
    }

    private static void AnalyzeVirtualMachine(
        AzureResource resource,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var securityProfile =
            GetProperty(
                properties.Value,
                "securityProfile");

        if (securityProfile.HasValue)
        {
            var secureBoot =
                GetBool(
                    securityProfile.Value,
                    "uefiSettings",
                    "secureBootEnabled");

            if (secureBoot.HasValue &&
                !secureBoot.Value)
            {
                Add(
                    findings,
                    resource,
                    "SEC-VM-SECURE-BOOT-DISABLED",
                    Severity.Medium,
                    "Secure Boot disabilitato sulla VM",
                    "La VM non risulta configurata con Secure Boot abilitato.",
                    "Riduce le protezioni contro componenti di boot non attendibili.",
                    "Abilitare Secure Boot quando compatibile con il sistema operativo e il workload.");
            }
        }

        var availabilitySet =
            GetString(
                properties.Value,
                "availabilitySet");

        if (string.IsNullOrWhiteSpace(availabilitySet))
        {
            Add(
                findings,
                resource,
                "ARCH-VM-NO-AVAILABILITY-SET",
                Severity.Low,
                "VM senza Availability Set",
                "La VM non risulta associata a un Availability Set.",
                "La disponibilità della VM può dipendere esclusivamente dalla singola istanza.",
                "Valutare Availability Zones o un'architettura HA coerente con il workload.");
        }

        var hasBackup =
            resources.Any(
                x =>
                    x.Type.Equals(
                        "Microsoft.RecoveryServices/vaults",
                        StringComparison.OrdinalIgnoreCase) &&
                    x.Relationships.Any(
                        r =>
                            r.SourceResourceId.Equals(
                                resource.Id,
                                StringComparison.OrdinalIgnoreCase) ||
                            r.TargetResourceId.Equals(
                                resource.Id,
                                StringComparison.OrdinalIgnoreCase)));

        if (!hasBackup)
        {
            Add(
                findings,
                resource,
                "OPS-VM-NO-BACKUP-COVERAGE",
                Severity.Medium,
                "VM senza relazione di backup rilevata",
                "Non è stata individuata una relazione diretta tra la VM e un Recovery Services Vault nel modello di topology.",
                "La VM potrebbe non essere protetta da backup Azure.",
                "Verificare che la VM sia inclusa in una policy Azure Backup.");
        }
    }

    private static void AnalyzeVmScaleSet(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var sku =
            GetString(
                properties.Value,
                "sku",
                "name");

        if (string.IsNullOrWhiteSpace(sku))
        {
            return;
        }

        if (sku.Contains(
                "_Basic",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "COST-VMSS-BASIC-SKU",
                Severity.Low,
                "VM Scale Set con SKU Basic",
                $"Il VM Scale Set utilizza lo SKU '{sku}'.",
                "Lo SKU potrebbe non essere adeguato per workload che richiedono funzionalità avanzate.",
                "Verificare requisiti e costo dello SKU rispetto al workload.");
        }
    }

    private static void AnalyzeDisk(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var managedBy =
            GetString(
                properties.Value,
                "managedBy");

        if (string.IsNullOrWhiteSpace(managedBy) &&
            resource.Relationships.Count == 0)
        {
            Add(
                findings,
                resource,
                "COST-DISK-UNATTACHED",
                Severity.Medium,
                "Managed Disk non associato",
                "Il managed disk non risulta associato a una VM o ad altra risorsa tramite le relazioni disponibili.",
                "Un disco non utilizzato può generare costi ricorrenti senza fornire valore operativo.",
                "Verificare il disco e rimuoverlo se non più necessario.");
        }
    }

    private static void AnalyzeSubnet(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var nsg =
            GetProperty(
                properties.Value,
                "networkSecurityGroup");

        if (!nsg.HasValue)
        {
            Add(
                findings,
                resource,
                "SEC-SUBNET-NO-NSG",
                Severity.Low,
                "Subnet senza NSG associato",
                "La subnet non risulta associata a un Network Security Group.",
                "La segmentazione di rete può risultare meno restrittiva del necessario.",
                "Valutare l'associazione di un NSG coerente con i requisiti applicativi.");
        }
    }

    private static void AnalyzeNetworkInterface(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var ipConfigurations =
            GetProperty(
                properties.Value,
                "ipConfigurations");

        if (!ipConfigurations.HasValue ||
            ipConfigurations.Value.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var configuration in
                 ipConfigurations.Value.EnumerateArray())
        {
            var publicIp =
                GetProperty(
                    configuration,
                    "publicIPAddress");

            if (publicIp.HasValue)
            {
                Add(
                    findings,
                    resource,
                    "SEC-NIC-PUBLIC-IP",
                    Severity.Medium,
                    "NIC associata a Public IP",
                    "La Network Interface dispone di una configurazione IP pubblica.",
                    "La VM associata può essere direttamente esposta a Internet.",
                    "Verificare se l'accesso pubblico è realmente necessario e preferire accessi tramite servizi controllati.");
            }
        }
    }

    private static void AnalyzeApplicationGateway(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var httpListeners =
            GetProperty(
                properties.Value,
                "httpListeners");

        if (httpListeners.HasValue &&
            httpListeners.Value.ValueKind == JsonValueKind.Array &&
            httpListeners.Value.GetArrayLength() > 0)
        {
            Add(
                findings,
                resource,
                "SEC-APPGW-HTTP-LISTENER",
                Severity.Medium,
                "Application Gateway con HTTP listener",
                "È presente almeno un HTTP listener.",
                "Il traffico HTTP può non essere cifrato durante il transito.",
                "Preferire HTTPS e reindirizzare HTTP verso HTTPS quando compatibile.");
        }
    }

    private static void AnalyzePrivateEndpoint(
        AzureResource resource,
        List<Finding> findings)
    {
        if (resource.Relationships.Count == 0)
        {
            Add(
                findings,
                resource,
                "OPS-PRIVATE-ENDPOINT-UNRESOLVED",
                Severity.Low,
                "Private Endpoint senza relazione rilevata",
                "Il Private Endpoint non presenta relazioni nel modello di topology.",
                "La configurazione potrebbe essere incompleta oppure non completamente rilevata.",
                "Verificare la connessione del Private Endpoint alla risorsa target.");
        }
    }

    private static void AnalyzeStorageAccount(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        if (GetBool(
                properties.Value,
                "allowBlobPublicAccess",
                false))
        {
            Add(
                findings,
                resource,
                "SEC-STORAGE-BLOB-PUBLIC",
                Severity.High,
                "Blob public access consentito",
                "La Storage Account consente il public access ai blob.",
                "Container o blob possono essere esposti pubblicamente se configurati in modo permissivo.",
                "Disabilitare Allow Blob Public Access quando non esplicitamente richiesto.");
        }

        if (!GetBool(
                properties.Value,
                "supportsHttpsTrafficOnly",
                true))
        {
            Add(
                findings,
                resource,
                "SEC-STORAGE-HTTPS",
                Severity.Medium,
                "Storage Account senza HTTPS obbligatorio",
                "La Storage Account non risulta configurata per richiedere esclusivamente HTTPS.",
                "Il traffico non cifrato può essere utilizzato dai client.",
                "Abilitare HTTPS-only.");
        }

        var tls =
            GetString(
                properties.Value,
                "minimumTlsVersion");

        if (tls is "TLS1_0" or "TLS1_1")
        {
            Add(
                findings,
                resource,
                "SEC-STORAGE-OLD-TLS",
                Severity.High,
                "Storage Account con TLS obsoleto",
                $"La Storage Account utilizza {tls}.",
                "Versioni TLS obsolete riducono il livello di sicurezza delle connessioni.",
                "Portare il minimum TLS version ad almeno TLS 1.2 verificando la compatibilità dei client.");
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-STORAGE-PUBLIC-NETWORK",
                Severity.Low,
                "Storage Account accessibile tramite rete pubblica",
                "La Storage Account consente accesso tramite rete pubblica.",
                "La superficie di rete è maggiore rispetto a un'architettura completamente privata.",
                "Valutare firewall, virtual network rules e Private Endpoint.");
        }

        var replication =
            GetString(
                properties.Value,
                "sku",
                "name");

        if (string.Equals(
                replication,
                "Standard_LRS",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "ARCH-STORAGE-LRS",
                Severity.Low,
                "Storage Account con replica LRS",
                "La Storage Account utilizza una replica LRS.",
                "La ridondanza rimane confinata alla singola regione e al singolo datacenter logico.",
                "Valutare ZRS, GRS o GZRS in funzione dei requisiti di resilienza.");
        }
    }

    private static void AnalyzeWebSite(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        if (!GetBool(
                properties.Value,
                "httpsOnly",
                true))
        {
            Add(
                findings,
                resource,
                "SEC-APP-NO-HTTPS",
                Severity.Medium,
                "App Service senza HTTPS Only",
                "L'applicazione non forza HTTPS.",
                "Le richieste HTTP possono transitare senza il livello di protezione previsto.",
                "Abilitare HTTPS Only.");
        }

        var ftpState =
            GetString(
                properties.Value,
                "ftpsState");

        if (string.Equals(
                ftpState,
                "AllAllowed",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-APP-FTP-ALL",
                Severity.Medium,
                "App Service con FTP non sicuro",
                "L'App Service consente sia FTP sia FTPS.",
                "FTP non cifra il traffico.",
                "Impostare FTPS Only o disabilitare il protocollo quando non necessario.");
        }
    }

    private static void AnalyzeAppServicePlan(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var sku =
            GetString(
                properties.Value,
                "sku",
                "name");

        if (string.Equals(
                sku,
                "F1",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "COST-APPPLAN-FREE",
                Severity.Low,
                "App Service Plan con SKU Free",
                "Il piano utilizza lo SKU Free.",
                "Potrebbe essere appropriato per workload di test ma non per carichi produttivi.",
                "Verificare che il piano sia coerente con l'utilizzo effettivo.");
        }
    }

    private static void AnalyzeSqlServer(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-SQL-PUBLIC-NETWORK",
                Severity.Medium,
                "Azure SQL con public network access",
                "Il SQL Server consente accesso tramite rete pubblica.",
                "La superficie di rete del database è maggiore del necessario in scenari privati.",
                "Valutare Private Endpoint e limitazioni tramite firewall.");
        }
    }

    private static void AnalyzeSqlDatabase(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var status =
            GetString(
                properties.Value,
                "status");

        if (string.Equals(
                status,
                "Paused",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "COST-SQLDB-PAUSED",
                Severity.Low,
                "Azure SQL Database in stato Paused",
                "Il database risulta in stato Paused.",
                "Verificare se la configurazione e il livello di servizio sono coerenti con l'utilizzo previsto.",
                "Verificare il lifecycle del database e lo SKU configurato.");
        }
    }

    private static void AnalyzeFlexibleDatabase(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicAccess =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicAccess,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-DB-PUBLIC-NETWORK",
                Severity.Medium,
                "Database con public network access",
                "Il database consente accesso tramite rete pubblica.",
                "La superficie di esposizione del database aumenta.",
                "Valutare Private Endpoint o regole di rete più restrittive.");
        }
    }

    private static void AnalyzeCosmos(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-COSMOS-PUBLIC-NETWORK",
                Severity.Medium,
                "Cosmos DB accessibile tramite rete pubblica",
                "L'account Cosmos DB consente accesso tramite rete pubblica.",
                "La superficie di rete del database è maggiore del necessario.",
                "Valutare Private Endpoint e limitazioni di rete.");
        }
    }

    private static void AnalyzeAks(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var privateCluster =
            GetBool(
                properties.Value,
                "apiServerAccessProfile",
                "enablePrivateCluster");

        if (privateCluster.HasValue &&
            !privateCluster.Value)
        {
            Add(
                findings,
                resource,
                "SEC-AKS-PUBLIC-API",
                Severity.Medium,
                "AKS con API Server pubblico",
                "Il cluster AKS non risulta configurato come private cluster.",
                "L'API Server può essere raggiungibile tramite endpoint pubblico.",
                "Valutare Private Cluster o restrizioni tramite authorized IP ranges.");
        }

        var disableLocalAccounts =
            GetBool(
                properties.Value,
                "disableLocalAccounts");

        if (disableLocalAccounts.HasValue &&
            !disableLocalAccounts.Value)
        {
            Add(
                findings,
                resource,
                "SEC-AKS-LOCAL-ACCOUNTS",
                Severity.Medium,
                "AKS con local accounts abilitati",
                "Gli account locali del cluster non risultano disabilitati.",
                "Gli account locali possono introdurre un ulteriore meccanismo di autenticazione da gestire.",
                "Valutare Microsoft Entra ID e RBAC come meccanismo principale di accesso.");
        }
    }

    private static void AnalyzeContainerRegistry(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        if (GetBool(
                properties.Value,
                "adminUserEnabled",
                false))
        {
            Add(
                findings,
                resource,
                "SEC-ACR-ADMIN-USER",
                Severity.Medium,
                "ACR admin user abilitato",
                "L'admin user del Container Registry risulta abilitato.",
                "Le credenziali statiche aumentano la superficie di gestione delle identità.",
                "Preferire Microsoft Entra ID, managed identity o service principals con privilegi minimi.");
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-ACR-PUBLIC-NETWORK",
                Severity.Low,
                "ACR accessibile tramite rete pubblica",
                "Il Container Registry consente accesso tramite rete pubblica.",
                "Il registry è raggiungibile da una superficie di rete più ampia.",
                "Valutare Private Endpoint e limitazioni di rete.");
        }
    }

    private static void AnalyzeMessagingNamespace(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-MESSAGING-PUBLIC-NETWORK",
                Severity.Low,
                "Messaging namespace accessibile tramite rete pubblica",
                "Il namespace consente accesso tramite rete pubblica.",
                "La superficie di esposizione del servizio aumenta.",
                "Valutare Private Endpoint e network rules.");
        }
    }

    private static void AnalyzeKeyVault(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        var networkAcls =
            GetProperty(
                properties.Value,
                "networkAcls");

        var defaultAction =
            networkAcls.HasValue
                ? GetString(
                    networkAcls.Value,
                    "defaultAction")
                : null;

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(
                defaultAction,
                "Deny",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-KV-PUBLIC-NETWORK",
                Severity.Medium,
                "Key Vault accessibile dalla rete pubblica",
                "Il Key Vault consente accesso tramite rete pubblica senza una policy network ACL predefinita Deny.",
                "Aumenta la superficie di esposizione di segreti, chiavi e certificati.",
                "Valutare Private Endpoint oppure network ACL con default action Deny.");
        }

        if (!GetBool(
                properties.Value,
                "enablePurgeProtection",
                true))
        {
            Add(
                findings,
                resource,
                "SEC-KV-NO-PURGE",
                Severity.Medium,
                "Key Vault senza purge protection",
                "La purge protection non risulta abilitata.",
                "Una cancellazione potrebbe diventare definitiva prima del termine della retention.",
                "Abilitare purge protection quando richiesta dai requisiti di sicurezza.");
        }
    }

    private static void AnalyzeBackupVault(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var softDelete =
            GetBool(
                properties.Value,
                "softDeleteFeatureState");

        if (softDelete.HasValue &&
            !softDelete.Value)
        {
            Add(
                findings,
                resource,
                "SEC-BACKUP-SOFTDELETE",
                Severity.Medium,
                "Backup Vault con soft delete non attivo",
                "Il vault non risulta configurato con soft delete attivo.",
                "La protezione contro cancellazioni accidentali o malevole è ridotta.",
                "Abilitare le funzionalità di protezione dalla cancellazione supportate dal vault.");
        }
    }

    private static void AnalyzeLogAnalytics(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var retention =
            GetInt(
                properties.Value,
                "retentionInDays");

        if (retention.HasValue &&
            retention.Value < 30)
        {
            Add(
                findings,
                resource,
                "OPS-LOG-RETENTION-LOW",
                Severity.Low,
                "Log Analytics con retention ridotta",
                $"Il workspace utilizza una retention di circa {retention.Value} giorni.",
                "La disponibilità dello storico diagnostico può essere insufficiente per troubleshooting e audit.",
                "Verificare i requisiti di retention e aumentare il periodo quando necessario.");
        }
    }

    private static void AnalyzeApplicationInsights(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var kind =
            GetString(
                properties.Value,
                "kind");

        if (string.IsNullOrWhiteSpace(kind))
        {
            Add(
                findings,
                resource,
                "OPS-APPINSIGHTS-CONFIG",
                Severity.Low,
                "Application Insights con configurazione non determinata",
                "La configurazione applicativa non è completamente determinabile dai dati ARM disponibili.",
                "Potrebbero mancare informazioni necessarie per valutare la copertura del monitoring.",
                "Verificare diagnostica, availability tests e integrazione con l'applicazione.");
        }
    }

    private static void AnalyzeCognitiveServices(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-AI-PUBLIC-NETWORK",
                Severity.Low,
                "Azure AI service accessibile tramite rete pubblica",
                "Il servizio Azure AI consente accesso tramite rete pubblica.",
                "L'endpoint è esposto a una superficie di rete più ampia.",
                "Valutare Private Endpoint e restrizioni di rete.");
        }
    }

    private static void AnalyzeApiManagement(
        AzureResource resource,
        List<Finding> findings)
    {
        var properties = resource.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        var publicNetwork =
            GetString(
                properties.Value,
                "publicNetworkAccess");

        if (string.Equals(
                publicNetwork,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            Add(
                findings,
                resource,
                "SEC-APIM-PUBLIC-NETWORK",
                Severity.Low,
                "API Management accessibile pubblicamente",
                "API Management dispone di accesso pubblico.",
                "Le API possono essere esposte direttamente a Internet.",
                "Verificare che l'esposizione sia intenzionale e applicare le necessarie policy di sicurezza.");
        }
    }

    private static JsonElement? GetProperty(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return null;
        }

        return value;
    }

    private static JsonElement? GetProperty(
        JsonElement element,
        string parent,
        string child)
    {
        if (!element.TryGetProperty(
                parent,
                out var parentValue))
        {
            return null;
        }

        if (!parentValue.TryGetProperty(
                child,
                out var value))
        {
            return null;
        }

        return value;
    }

    private static string? GetString(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static string? GetString(
        JsonElement element,
        string parent,
        string child)
    {
        var value =
            GetProperty(
                element,
                parent,
                child);

        return value.HasValue &&
               value.Value.ValueKind == JsonValueKind.String
            ? value.Value.GetString()
            : null;
    }

    private static bool GetBool(
        JsonElement element,
        string name,
        bool defaultValue)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return defaultValue;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => defaultValue
        };
    }

    private static bool? GetBool(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static bool? GetBool(
        JsonElement element,
        string parent,
        string child)
    {
        var value =
            GetProperty(
                element,
                parent,
                child);

        if (!value.HasValue)
        {
            return null;
        }

        return value.Value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static int? GetInt(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Number &&
               value.TryGetInt32(out var result)
            ? result
            : null;
    }

    private static void Add(
        List<Finding> findings,
        AzureResource resource,
        string ruleId,
        Severity severity,
        string title,
        string description,
        string impact,
        string recommendation,
        Category category = Category.Security)
    {
        findings.Add(
            new Finding(
                Id:
                    $"{ruleId}-{resource.Id}",

                Category:
                    category,

                Severity:
                    severity,

                RuleId:
                    ruleId,

                Title:
                    title,

                Description:
                    description,

                Impact:
                    impact,

                Recommendation:
                    recommendation,

                ResourceName:
                    resource.Name,

                ResourceType:
                    resource.Type,

                ResourceId:
                    resource.Id));
    }
}