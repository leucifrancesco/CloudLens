using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class SecurityAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings =
            new List<Finding>();

        AnalyzeNsgs(
            resources,
            findings);

        AnalyzeNetworkInterfaces(
            resources,
            findings);

        AnalyzeVirtualMachines(
            resources,
            findings);

        AnalyzeStorageAccounts(
            resources,
            findings);

        AnalyzePublicIpAddresses(
            resources,
            findings);

        AnalyzeAppServices(
            resources,
            findings);

        AnalyzeKeyVaults(
            resources,
            findings);

        AnalyzeSqlServers(
            resources,
            findings);

        AnalyzeSqlFirewallRules(
            resources,
            findings);

        AnalyzeServiceBusNamespaces(
            resources,
            findings);

        AnalyzeEventHubNamespaces(
            resources,
            findings);

        AnalyzeContainerRegistries(
            resources,
            findings);

        return findings;
    }

    // =========================================================
    // NSG
    // =========================================================

    private static void AnalyzeNsgs(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var nsgs =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Network/networkSecurityGroups"));

        foreach (var resource in nsgs)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            if (!properties.Value.TryGetProperty(
                    "securityRules",
                    out var rules) ||
                rules.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var rule in rules.EnumerateArray())
            {
                if (!rule.TryGetProperty(
                        "properties",
                        out var ruleProperties))
                {
                    continue;
                }

                var access =
                    GetString(
                        ruleProperties,
                        "access");

                var direction =
                    GetString(
                        ruleProperties,
                        "direction");

                if (!string.Equals(
                        access,
                        "Allow",
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(
                        direction,
                        "Inbound",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var sources =
                    GetStringValues(
                        ruleProperties,
                        "sourceAddressPrefix",
                        "sourceAddressPrefixes");

                var destinationPorts =
                    GetStringValues(
                        ruleProperties,
                        "destinationPortRange",
                        "destinationPortRanges");

                if (!sources.Any(IsInternetSource))
                {
                    continue;
                }

                if (destinationPorts.Any(
                        IsManagementPort))
                {
                    var managementPorts =
                        destinationPorts
                            .Where(IsManagementPort)
                            .Select(GetManagementPortName)
                            .Distinct(
                                StringComparer.OrdinalIgnoreCase)
                            .ToList();

                    var portName =
                        string.Join(
                            "/",
                            managementPorts);

                    findings.Add(
                        new Finding(
                            Id:
                                Guid.NewGuid().ToString(),

                            Category:
                                Category.Security,

                            Severity:
                                Severity.Critical,

                            RuleId:
                                "NSG-OPEN-MGMT",

                            Title:
                                $"Porta di gestione {portName} esposta a Internet",

                            Description:
                                $"Il NSG '{ResourceName(resource)}' " +
                                $"consente traffico inbound da Internet " +
                                $"verso {portName}.",

                            Impact:
                                "Superficie di attacco diretta verso " +
                                "un servizio di amministrazione.",

                            Recommendation:
                                "Limitare la sorgente a reti autorizzate " +
                                "oppure utilizzare Azure Bastion o JIT.",

                            ResourceName:
                                ResourceName(resource),

                            ResourceType:
                                ResourceType(resource),

                            ResourceId:
                                ResourceId(resource),

                            AzureCli:
                                $"az network nsg rule list " +
                                $"--resource-group {ResourceGroup(resource)} " +
                                $"--nsg-name {ResourceName(resource)}"));
                }

                if (destinationPorts.Any(
                        IsAnyDestinationPort))
                {
                    findings.Add(
                        new Finding(
                            Id:
                                Guid.NewGuid().ToString(),

                            Category:
                                Category.Security,

                            Severity:
                                Severity.Critical,

                            RuleId:
                                "NSG-ANY-ANY-INBOUND",

                            Title:
                                "Regola NSG Any/Any inbound da Internet",

                            Description:
                                $"Il NSG '{ResourceName(resource)}' " +
                                "consente traffico inbound da Internet " +
                                "senza limitare la porta di destinazione.",

                            Impact:
                                "Espone potenzialmente numerosi servizi " +
                                "alla rete Internet.",

                            Recommendation:
                                "Limitare sorgente, destinazione e porte " +
                                "alle sole comunicazioni necessarie.",

                            ResourceName:
                                ResourceName(resource),

                            ResourceType:
                                ResourceType(resource),

                            ResourceId:
                                ResourceId(resource)));
                }
            }
        }
    }

    // =========================================================
    // NETWORK INTERFACES
    // =========================================================

    private static void AnalyzeNetworkInterfaces(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var networkInterfaces =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Network/networkInterfaces"));

        foreach (var networkInterface in networkInterfaces)
        {
            var properties =
                networkInterface.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var hasNetworkInterfaceNsg =
                HasNetworkSecurityGroup(
                    properties.Value);

            if (hasNetworkInterfaceNsg)
            {
                continue;
            }

            if (!properties.Value.TryGetProperty(
                    "ipConfigurations",
                    out var ipConfigurations) ||
                ipConfigurations.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var hasSubnetNsg =
                false;

            foreach (var ipConfiguration in
                     ipConfigurations.EnumerateArray())
            {
                if (!ipConfiguration.TryGetProperty(
                        "properties",
                        out var ipConfigurationProperties))
                {
                    continue;
                }

                if (!ipConfigurationProperties.TryGetProperty(
                        "subnet",
                        out var subnetReference) ||
                    subnetReference.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var subnetId =
                    GetString(
                        subnetReference,
                        "id");

                if (string.IsNullOrWhiteSpace(subnetId))
                {
                    continue;
                }

                var subnet =
                    resources.FirstOrDefault(
                        resource =>
                            string.Equals(
                                resource.Id,
                                subnetId,
                                StringComparison.OrdinalIgnoreCase));

                if (subnet == null)
                {
                    continue;
                }

                var subnetProperties =
                    subnet.GetEffectiveProperties();

                if (!subnetProperties.HasValue)
                {
                    continue;
                }

                if (HasNetworkSecurityGroup(
                        subnetProperties.Value))
                {
                    hasSubnetNsg = true;
                    break;
                }
            }

            if (hasSubnetNsg)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "NIC-NO-EFFECTIVE-NSG",

                    Title:
                        "Network Interface senza NSG effettivo",

                    Description:
                        $"La Network Interface '{ResourceName(networkInterface)}' " +
                        "non risulta associata a un NSG e la subnet associata " +
                        "non risulta protetta da un NSG.",

                    Impact:
                        "La NIC non dispone di una Network Security Group " +
                        "a livello NIC o subnet per controllare il traffico.",

                    Recommendation:
                        "Associare un NSG alla NIC o alla subnet, " +
                        "definendo regole coerenti con i requisiti applicativi.",

                    ResourceName:
                        ResourceName(networkInterface),

                    ResourceType:
                        ResourceType(networkInterface),

                    ResourceId:
                        ResourceId(networkInterface)));
        }
    }

    // =========================================================
    // VIRTUAL MACHINES
    // =========================================================

    private static void AnalyzeVirtualMachines(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vms =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Compute/virtualMachines"));

        foreach (var vm in vms)
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            if (!properties.Value.TryGetProperty(
                    "networkProfile",
                    out var networkProfile) ||
                networkProfile.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (!networkProfile.TryGetProperty(
                    "networkInterfaces",
                    out var networkInterfaces) ||
                networkInterfaces.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var networkInterface in
                     networkInterfaces.EnumerateArray())
            {
                var nicId =
                    GetString(
                        networkInterface,
                        "id");

                if (string.IsNullOrWhiteSpace(nicId))
                {
                    continue;
                }

                var nic =
                    resources.FirstOrDefault(
                        r => string.Equals(
                            r.Id,
                            nicId,
                            StringComparison.OrdinalIgnoreCase));

                if (nic == null)
                {
                    continue;
                }

                AnalyzeVirtualMachineNetworkInterface(
                    vm,
                    nic,
                    resources,
                    findings);
            }
        }
    }

    private static void AnalyzeVirtualMachineNetworkInterface(
        AzureResource vm,
        AzureResource nic,
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var properties =
            nic.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return;
        }

        if (!properties.Value.TryGetProperty(
                "ipConfigurations",
                out var ipConfigurations) ||
            ipConfigurations.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var ipConfiguration in
                 ipConfigurations.EnumerateArray())
        {
            if (!ipConfiguration.TryGetProperty(
                    "properties",
                    out var ipConfigurationProperties))
            {
                continue;
            }

            if (!ipConfigurationProperties.TryGetProperty(
                    "publicIPAddress",
                    out var publicIp) ||
                publicIp.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var publicIpId =
                GetString(
                    publicIp,
                    "id");

            if (string.IsNullOrWhiteSpace(publicIpId))
            {
                continue;
            }

            var publicIpResource =
                resources.FirstOrDefault(
                    r => string.Equals(
                        r.Id,
                        publicIpId,
                        StringComparison.OrdinalIgnoreCase));

            if (publicIpResource == null)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "VM-PUBLIC-IP",

                    Title:
                        "Virtual Machine con Public IP",

                    Description:
                        $"La VM '{ResourceName(vm)}' " +
                        $"utilizza il Public IP '{ResourceName(publicIpResource)}'.",

                    Impact:
                        "La VM dispone di un endpoint pubblicamente " +
                        "indirizzabile e aumenta la superficie di esposizione.",

                    Recommendation:
                        "Verificare che l'accesso pubblico sia necessario. " +
                        "Quando possibile, utilizzare Azure Bastion, " +
                        "VPN o Private Endpoint.",

                    ResourceName:
                        ResourceName(vm),

                    ResourceType:
                        ResourceType(vm),

                    ResourceId:
                        ResourceId(vm)));
        }
    }

    // =========================================================
    // STORAGE
    // =========================================================

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Storage/storageAccounts"));

        foreach (var resource in storageAccounts)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicAccess =
                GetBool(
                    properties.Value,
                    "allowBlobPublicAccess");

            if (publicAccess == true)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "ST-PUBLIC-BLOB",

                        Title:
                            "Accesso pubblico ai blob consentito",

                        Description:
                            $"Lo storage account '{ResourceName(resource)}' " +
                            "consente l'accesso pubblico ai blob.",

                        Impact:
                            "Configurazione che può consentire " +
                            "l'esposizione involontaria di dati.",

                        Recommendation:
                            "Disabilitare l'accesso pubblico ai blob e " +
                            "utilizzare Entra ID/RBAC o SAS quando necessario.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource),

                        AzureCli:
                            $"az storage account update " +
                            $"--ids \"{ResourceId(resource)}\" " +
                            "--allow-blob-public-access false"));
            }

            var secureTransfer =
                GetBool(
                    properties.Value,
                    "supportsHttpsTrafficOnly");

            if (secureTransfer == false)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "ST-HTTPS-ONLY",

                        Title:
                            "Storage Account senza HTTPS obbligatorio",

                        Description:
                            $"Lo storage account '{ResourceName(resource)}' " +
                            "non richiede esclusivamente traffico HTTPS.",

                        Impact:
                            "Il traffico verso lo storage può utilizzare " +
                            "un protocollo non cifrato.",

                        Recommendation:
                            "Abilitare il requisito di trasferimento sicuro " +
                            "e consentire esclusivamente HTTPS.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource),

                        AzureCli:
                            $"az storage account update " +
                            $"--ids \"{ResourceId(resource)}\" " +
                            "--https-only true"));
            }

            var tlsVersion =
                GetString(
                    properties.Value,
                    "minimumTlsVersion");

            if (IsTlsVersionBelow12(tlsVersion))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "ST-TLS-VERSION",

                        Title:
                            "Storage Account con TLS inferiore a 1.2",

                        Description:
                            $"Lo storage account '{ResourceName(resource)}' " +
                            $"utilizza {tlsVersion ?? "una versione TLS non conforme"} " +
                            "come versione minima.",

                        Impact:
                            "Riduce il livello minimo di sicurezza " +
                            "delle connessioni al servizio.",

                        Recommendation:
                            "Impostare TLS 1.2 come versione minima supportata.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "ST-PUBLIC-NETWORK",

                        Title:
                            "Storage Account accessibile dalla rete pubblica",

                        Description:
                            $"Lo storage account '{ResourceName(resource)}' " +
                            "consente l'accesso tramite rete pubblica.",

                        Impact:
                            "Aumenta la superficie di esposizione " +
                            "del servizio di storage.",

                        Recommendation:
                            "Valutare firewall, virtual network rules " +
                            "o Private Endpoint in base ai requisiti.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }
        }
    }

    // =========================================================
    // PUBLIC IP
    // =========================================================

    private static void AnalyzePublicIpAddresses(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var publicIps =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Network/publicIPAddresses"));

        foreach (var resource in publicIps)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var ipConfiguration =
                GetProperty(
                    properties.Value,
                    "ipConfiguration");

            if (!ipConfiguration.HasValue)
            {
                continue;
            }

            if (ipConfiguration.Value.ValueKind !=
                JsonValueKind.Null)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "PIP-UNASSOCIATED",

                    Title:
                        "Public IP non associato",

                    Description:
                        $"L'IP pubblico '{ResourceName(resource)}' " +
                        "non risulta associato ad alcuna risorsa.",

                    Impact:
                        "Una risorsa pubblicamente indirizzabile " +
                        "può rimanere inutilizzata o dimenticata.",

                    Recommendation:
                        "Verificare l'utilizzo dell'indirizzo e " +
                        "rimuoverlo se non necessario.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    ResourceId:
                        ResourceId(resource)));
        }
    }

    // =========================================================
    // APP SERVICE
    // =========================================================

    private static void AnalyzeAppServices(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var apps =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Web/sites"));

        foreach (var resource in apps)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var httpsOnly =
                GetBool(
                    properties.Value,
                    "httpsOnly");

            if (httpsOnly == false)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "APP-HTTPS-ONLY",

                        Title:
                            "App Service senza HTTPS obbligatorio",

                        Description:
                            $"L'App Service '{ResourceName(resource)}' " +
                            "non richiede esclusivamente connessioni HTTPS.",

                        Impact:
                            "Il servizio può accettare traffico HTTP " +
                            "non cifrato.",

                        Recommendation:
                            "Abilitare HTTPS Only e utilizzare TLS " +
                            "per tutto il traffico applicativo.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource),

                        AzureCli:
                            $"az webapp update " +
                            $"--ids \"{ResourceId(resource)}\" " +
                            "--https-only true"));
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "APP-PUBLIC-NETWORK",

                        Title:
                            "App Service accessibile dalla rete pubblica",

                        Description:
                            $"L'App Service '{ResourceName(resource)}' " +
                            "consente l'accesso tramite rete pubblica.",

                        Impact:
                            "L'applicazione è esposta direttamente " +
                            "all'endpoint pubblico del servizio.",

                        Recommendation:
                            "Valutare Private Endpoint e restrizioni " +
                            "di accesso quando il requisito applicativo lo consente.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }

            var siteConfig =
                GetProperty(
                    properties.Value,
                    "siteConfig");

            if (!siteConfig.HasValue)
            {
                continue;
            }

            var minTls =
                GetString(
                    siteConfig.Value,
                    "minTlsVersion");

            if (IsTlsVersionBelow12(minTls))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "APP-TLS-VERSION",

                        Title:
                            "App Service con TLS inferiore a 1.2",

                        Description:
                            $"L'App Service '{ResourceName(resource)}' " +
                            $"utilizza {minTls ?? "una versione TLS non conforme"} " +
                            "come versione minima.",

                        Impact:
                            "Client e connessioni potrebbero utilizzare " +
                            "protocolli crittografici obsoleti.",

                        Recommendation:
                            "Impostare TLS 1.2 come versione minima.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }
        }
    }

    // =========================================================
    // KEY VAULT
    // =========================================================

    private static void AnalyzeKeyVaults(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vaults =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.KeyVault/vaults"));

        foreach (var resource in vaults)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "KV-PUBLIC-NETWORK",

                        Title:
                            "Key Vault accessibile dalla rete pubblica",

                        Description:
                            $"Il Key Vault '{ResourceName(resource)}' " +
                            "consente l'accesso tramite rete pubblica.",

                        Impact:
                            "Aumenta la superficie di esposizione " +
                            "di segreti, chiavi e certificati.",

                        Recommendation:
                            "Valutare Private Endpoint o restrizioni " +
                            "di rete tramite firewall e virtual network rules.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }

            var softDelete =
                GetBool(
                    properties.Value,
                    "enableSoftDelete");

            if (softDelete == false)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "KV-SOFT-DELETE",

                        Title:
                            "Key Vault senza soft delete",

                        Description:
                            $"Il Key Vault '{ResourceName(resource)}' " +
                            "non espone il soft delete come abilitato.",

                        Impact:
                            "La protezione contro la cancellazione " +
                            "accidentale o malevola delle risorse è ridotta.",

                        Recommendation:
                            "Abilitare e mantenere la protezione " +
                            "di recupero prevista dal servizio.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }

            var purgeProtection =
                GetBool(
                    properties.Value,
                    "enablePurgeProtection");

            if (purgeProtection == false)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "KV-PURGE-PROTECTION",

                        Title:
                            "Key Vault senza purge protection",

                        Description:
                            $"Il Key Vault '{ResourceName(resource)}' " +
                            "non espone la purge protection come abilitata.",

                        Impact:
                            "Una cancellazione potrebbe essere " +
                            "definitiva prima del termine della retention.",

                        Recommendation:
                            "Abilitare la purge protection quando " +
                            "richiesta dai requisiti di sicurezza.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }
        }
    }

    // =========================================================
    // AZURE SQL SERVER
    // =========================================================

    private static void AnalyzeSqlServers(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var servers =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Sql/servers"));

        foreach (var resource in servers)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "SQL-PUBLIC-NETWORK",

                        Title:
                            "Azure SQL Server accessibile dalla rete pubblica",

                        Description:
                            $"Il SQL Server '{ResourceName(resource)}' " +
                            "consente l'accesso dalla rete pubblica.",

                        Impact:
                            "Il database endpoint è raggiungibile " +
                            "attraverso la rete pubblica.",

                        Recommendation:
                            "Preferire Private Endpoint e disabilitare " +
                            "l'accesso pubblico quando non necessario.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }
        }
    }

    // =========================================================
    // AZURE SQL FIREWALL RULES
    // =========================================================

    private static void AnalyzeSqlFirewallRules(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var firewallRules =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Sql/servers/firewallRules"));

        foreach (var resource in firewallRules)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var startIp =
                GetString(
                    properties.Value,
                    "startIpAddress");

            var endIp =
                GetString(
                    properties.Value,
                    "endIpAddress");

            if (!string.Equals(
                    startIp,
                    "0.0.0.0",
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    endIp,
                    "255.255.255.255",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Critical,

                    RuleId:
                        "SQL-FIREWALL-ANYWHERE",

                    Title:
                        "Azure SQL Firewall aperto a qualsiasi indirizzo IP",

                    Description:
                        $"La regola firewall '{ResourceName(resource)}' " +
                        "consente connessioni da qualsiasi indirizzo IPv4.",

                    Impact:
                        "L'endpoint SQL può essere raggiunto " +
                        "da qualsiasi indirizzo Internet.",

                    Recommendation:
                        "Limitare l'intervallo IP alle sole reti autorizzate " +
                        "e preferire Private Endpoint quando applicabile.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    ResourceId:
                        ResourceId(resource)));
        }
    }

    // =========================================================
    // SERVICE BUS
    // =========================================================

    private static void AnalyzeServiceBusNamespaces(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var namespaces =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.ServiceBus/namespaces"));

        foreach (var resource in namespaces)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (!string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "SB-PUBLIC-NETWORK",

                    Title:
                        "Service Bus accessibile dalla rete pubblica",

                    Description:
                        $"Il namespace Service Bus '{ResourceName(resource)}' " +
                        "consente l'accesso dalla rete pubblica.",

                    Impact:
                        "Aumenta la superficie di esposizione " +
                        "del servizio di messaggistica.",

                    Recommendation:
                        "Valutare Private Endpoint o restrizioni " +
                        "di rete in base ai requisiti applicativi.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    ResourceId:
                        ResourceId(resource)));
        }
    }

    // =========================================================
    // EVENT HUB
    // =========================================================

    private static void AnalyzeEventHubNamespaces(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var namespaces =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.EventHub/namespaces"));

        foreach (var resource in namespaces)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (!string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "EH-PUBLIC-NETWORK",

                    Title:
                        "Event Hubs accessibile dalla rete pubblica",

                    Description:
                        $"Il namespace Event Hubs '{ResourceName(resource)}' " +
                        "consente l'accesso dalla rete pubblica.",

                    Impact:
                        "Aumenta la superficie di esposizione " +
                        "del servizio di event streaming.",

                    Recommendation:
                        "Valutare Private Endpoint o restrizioni " +
                        "di rete in base ai requisiti applicativi.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    ResourceId:
                        ResourceId(resource)));
        }
    }

    // =========================================================
    // CONTAINER REGISTRY
    // =========================================================

    private static void AnalyzeContainerRegistries(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var registries =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.ContainerRegistry/registries"));

        foreach (var resource in registries)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var publicNetworkAccess =
                GetString(
                    properties.Value,
                    "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "ACR-PUBLIC-NETWORK",

                        Title:
                            "Container Registry accessibile dalla rete pubblica",

                        Description:
                            $"Il registry '{ResourceName(resource)}' " +
                            "consente l'accesso tramite rete pubblica.",

                        Impact:
                            "Aumenta la superficie di esposizione " +
                            "del registry e degli artifact container.",

                        Recommendation:
                            "Valutare Private Endpoint e restrizioni " +
                            "di rete per il registry.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }

            var adminUserEnabled =
                GetBool(
                    properties.Value,
                    "adminUserEnabled");

            if (adminUserEnabled == true)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.High,

                        RuleId:
                            "ACR-ADMIN-USER",

                        Title:
                            "Container Registry con admin user abilitato",

                        Description:
                            $"Il registry '{ResourceName(resource)}' " +
                            "ha abilitato l'account amministratore locale.",

                        Impact:
                            "L'accesso tramite credenziali amministrative " +
                            "aumenta il rischio di compromissione del registry.",

                        Recommendation:
                            "Disabilitare l'admin user e utilizzare " +
                            "Microsoft Entra ID e RBAC per l'accesso al registry.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        ResourceId:
                            ResourceId(resource)));
            }
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool HasNetworkSecurityGroup(
        JsonElement properties)
    {
        if (!properties.TryGetProperty(
                "networkSecurityGroup",
                out var networkSecurityGroup))
        {
            return false;
        }

        if (networkSecurityGroup.ValueKind !=
            JsonValueKind.Object)
        {
            return false;
        }

        var id =
            GetString(
                networkSecurityGroup,
                "id");

        return !string.IsNullOrWhiteSpace(id);
    }

    private static bool IsManagementPort(
        string? port)
    {
        if (string.IsNullOrWhiteSpace(port))
        {
            return false;
        }

        var normalized =
            port.Trim();

        if (normalized == "*" ||
            normalized.Equals(
                "Any",
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (normalized == "22" ||
            normalized == "3389")
        {
            return true;
        }

        if (TryParsePortRange(
                normalized,
                out var start,
                out var end))
        {
            return IsPortInRange(
                       22,
                       start,
                       end) ||
                   IsPortInRange(
                       3389,
                       start,
                       end);
        }

        return false;
    }

    private static string GetManagementPortName(
        string? port)
    {
        if (string.IsNullOrWhiteSpace(port))
        {
            return "SSH/RDP";
        }

        var normalized =
            port.Trim();

        if (normalized == "22")
        {
            return "SSH";
        }

        if (normalized == "3389")
        {
            return "RDP";
        }

        if (TryParsePortRange(
                normalized,
                out var start,
                out var end))
        {
            var containsSsh =
                IsPortInRange(
                    22,
                    start,
                    end);

            var containsRdp =
                IsPortInRange(
                    3389,
                    start,
                    end);

            if (containsSsh && containsRdp)
            {
                return "SSH/RDP";
            }

            if (containsSsh)
            {
                return "SSH";
            }

            if (containsRdp)
            {
                return "RDP";
            }
        }

        return "SSH/RDP";
    }

    private static bool IsAnyDestinationPort(
        string? port)
    {
        return string.Equals(
                   port,
                   "*",
                   StringComparison.OrdinalIgnoreCase) ||
               string.Equals(
                   port,
                   "Any",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInternetSource(
        string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return false;
        }

        var normalized =
            source.Trim();

        return normalized == "*" ||
               normalized.Equals(
                   "Internet",
                   StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(
                   "0.0.0.0/0",
                   StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(
                   "::/0",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParsePortRange(
        string value,
        out int start,
        out int end)
    {
        start = 0;
        end = 0;

        var separatorIndex =
            value.IndexOf('-');

        if (separatorIndex <= 0 ||
            separatorIndex >= value.Length - 1)
        {
            return false;
        }

        var startText =
            value[..separatorIndex].Trim();

        var endText =
            value[(separatorIndex + 1)..].Trim();

        if (!int.TryParse(
                startText,
                out start) ||
            !int.TryParse(
                endText,
                out end))
        {
            return false;
        }

        return start >= 0 &&
               end >= start &&
               end <= 65535;
    }

    private static bool IsPortInRange(
        int port,
        int start,
        int end)
    {
        return port >= start &&
               port <= end;
    }

    private static List<string> GetStringValues(
        JsonElement element,
        string singleProperty,
        string arrayProperty)
    {
        var values =
            new List<string>();

        if (element.TryGetProperty(
                arrayProperty,
                out var arrayValue) &&
            arrayValue.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arrayValue.EnumerateArray())
            {
                if (item.ValueKind ==
                    JsonValueKind.String)
                {
                    var value =
                        item.GetString();

                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        values.Add(value);
                    }
                }
            }
        }

        if (element.TryGetProperty(
                singleProperty,
                out var singleValue) &&
            singleValue.ValueKind ==
                JsonValueKind.String)
        {
            var value =
                singleValue.GetString();

            if (!string.IsNullOrWhiteSpace(value))
            {
                values.Add(value);
            }
        }

        return values
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsTlsVersionBelow12(
        string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return false;
        }

        return version.Equals(
                   "TLS1_0",
                   StringComparison.OrdinalIgnoreCase) ||
               version.Equals(
                   "TLS1_1",
                   StringComparison.OrdinalIgnoreCase) ||
               version.Equals(
                   "1.0",
                   StringComparison.OrdinalIgnoreCase) ||
               version.Equals(
                   "1.1",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool TypeEquals(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string ResourceName(
        AzureResource resource)
    {
        return resource.Name;
    }

    private static string ResourceType(
        AzureResource resource)
    {
        return resource.Type;
    }

    private static string ResourceId(
        AzureResource resource)
    {
        return resource.Id;
    }

    private static string ResourceGroup(
        AzureResource resource)
    {
        return resource.ResourceGroup;
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            ? value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : value.ToString()
            : null;
    }

    private static bool? GetBool(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
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

    private static JsonElement? GetProperty(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            ? value
            : null;
    }
}