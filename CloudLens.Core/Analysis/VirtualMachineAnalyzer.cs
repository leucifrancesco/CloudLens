using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class VirtualMachineAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzePublicIpExposure(
            resources,
            findings);

        return findings;
    }

    // ============================================================
    // VM PUBLIC IP EXPOSURE
    // ============================================================

    private static void AnalyzePublicIpExposure(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var virtualMachines = resources.Where(
            resource => TypeEquals(
                resource,
                "Microsoft.Compute/virtualMachines"));

        foreach (var vm in virtualMachines)
        {
            var publicIps =
                GetPublicIpsForVirtualMachine(
                    vm,
                    resources);

            if (publicIps.Count == 0)
                continue;

            var publicIpNames =
                publicIps
                    .Select(ResourceName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

            var publicIpDescription =
                publicIpNames.Count == 1
                    ? $"Public IP associato: '{publicIpNames[0]}'."
                    : $"Public IP associati: {string.Join(", ", publicIpNames.Select(name => $"'{name}'"))}.";

            findings.Add(
                new Finding(
                    Id: Guid.NewGuid().ToString(),
                    Category: Category.Security,
                    Severity: Severity.Medium,
                    RuleId: "VM-PUBLIC-IP",
                    Title: "Virtual Machine con Public IP",
                    Description:
                        $"La Virtual Machine '{ResourceName(vm)}' " +
                        "dispone di almeno un'interfaccia di rete " +
                        "direttamente associata a un Public IP. " +
                        publicIpDescription,
                    Impact:
                        "La VM dispone di un endpoint direttamente indirizzabile " +
                        "da Internet. Questo aumenta la superficie di esposizione " +
                        "e richiede che NSG, autenticazione e servizi esposti siano " +
                        "configurati correttamente.",
                    Recommendation:
                        "Verificare che l'esposizione pubblica sia intenzionale. " +
                        "Quando non necessaria, preferire accesso tramite Azure Bastion, " +
                        "VPN, ExpressRoute o altri percorsi di rete privati.",
                    ResourceName: ResourceName(vm),
                    ResourceType: ResourceType(vm),
                    ResourceId: ResourceId(vm)));
        }
    }

    // ============================================================
    // VM → NIC → PUBLIC IP
    // ============================================================

    private static List<AzureResource> GetPublicIpsForVirtualMachine(
        AzureResource vm,
        IReadOnlyList<AzureResource> resources)
    {
        var publicIps = new Dictionary<string, AzureResource>(
            StringComparer.OrdinalIgnoreCase);

        var nicRelationships =
            vm.Relationships.Where(
                relationship =>
                    string.Equals(
                        relationship.RelationshipType,
                        "NetworkInterface",
                        StringComparison.OrdinalIgnoreCase));

        foreach (var nicRelationship in nicRelationships)
        {
            var nicId =
                NormalizeId(
                    nicRelationship.TargetResourceId);

            var nic =
                resources.FirstOrDefault(
                    resource =>
                        string.Equals(
                            NormalizeId(resource.Id),
                            nicId,
                            StringComparison.OrdinalIgnoreCase) &&
                        TypeEquals(
                            resource,
                            "Microsoft.Network/networkInterfaces"));

            if (nic == null)
                continue;

            var publicIpRelationships =
                nic.Relationships.Where(
                    relationship =>
                        string.Equals(
                            relationship.RelationshipType,
                            "PublicIPAddress",
                            StringComparison.OrdinalIgnoreCase));

            foreach (var publicIpRelationship in publicIpRelationships)
            {
                var publicIpId =
                    NormalizeId(
                        publicIpRelationship.TargetResourceId);

                var publicIp =
                    resources.FirstOrDefault(
                        resource =>
                            string.Equals(
                                NormalizeId(resource.Id),
                                publicIpId,
                                StringComparison.OrdinalIgnoreCase) &&
                            TypeEquals(
                                resource,
                                "Microsoft.Network/publicIPAddresses"));

                if (publicIp == null)
                    continue;

                publicIps[NormalizeId(publicIp.Id)] =
                    publicIp;
            }
        }

        return publicIps.Values.ToList();
    }

    // ============================================================
    // HELPERS
    // ============================================================

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
        return string.IsNullOrWhiteSpace(resource.Name)
            ? "(senza nome)"
            : resource.Name;
    }

    private static string ResourceType(
        AzureResource resource)
    {
        return resource.Type ?? "(tipo sconosciuto)";
    }

    private static string ResourceId(
        AzureResource resource)
    {
        return resource.Id ?? string.Empty;
    }

    private static string NormalizeId(
        string? id)
    {
        return (id ?? string.Empty)
            .Trim()
            .TrimEnd('/');
    }
}