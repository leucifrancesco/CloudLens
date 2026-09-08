using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureRelationshipBuilder
{
    public void Build(
        IReadOnlyList<AzureResource> resources)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(
                nameof(resources));
        }

        if (resources.Count == 0)
        {
            return;
        }

        var resourcesById =
            resources
                .Where(
                    resource =>
                        !string.IsNullOrWhiteSpace(
                            resource.Id))
                .GroupBy(
                    resource =>
                        NormalizeId(resource.Id),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.First(),
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resource in resources)
        {
            resource.Relationships.Clear();
        }

        BuildVirtualMachineRelationships(
            resources,
            resourcesById);

        BuildNetworkInterfaceRelationships(
            resources,
            resourcesById);

        BuildSubnetRelationships(
            resources,
            resourcesById);

        BuildPrivateEndpointRelationships(
            resources,
            resourcesById);

        BuildDiskRelationships(
            resources,
            resourcesById);
    }

    // =========================================================
    // VIRTUAL MACHINE
    // =========================================================

    private static void BuildVirtualMachineRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var vm in
                 resources.Where(IsVirtualMachine))
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            // -------------------------------------------------
            // VM -> NIC
            // -------------------------------------------------

            if (TryGetProperty(
                    properties.Value,
                    "networkProfile",
                    out var networkProfile) &&
                TryGetProperty(
                    networkProfile,
                    "networkInterfaces",
                    out var networkInterfaces) &&
                networkInterfaces.ValueKind ==
                    JsonValueKind.Array)
            {
                foreach (var nicReference in
                         networkInterfaces.EnumerateArray())
                {
                    var nicId =
                        GetString(
                            nicReference,
                            "id");

                    AddRelationship(
                        vm,
                        nicId,
                        "NetworkInterface",
                        resourcesById);
                }
            }

            // -------------------------------------------------
            // VM -> OS DISK
            // -------------------------------------------------

            if (TryGetProperty(
                    properties.Value,
                    "storageProfile",
                    out var storageProfile) &&
                TryGetProperty(
                    storageProfile,
                    "osDisk",
                    out var osDisk))
            {
                var diskId =
                    GetString(
                        osDisk,
                        "managedDisk",
                        "id");

                AddRelationship(
                    vm,
                    diskId,
                    "OsDisk",
                    resourcesById);
            }

            // -------------------------------------------------
            // VM -> DATA DISKS
            // -------------------------------------------------

            if (TryGetProperty(
                    properties.Value,
                    "storageProfile",
                    out storageProfile) &&
                TryGetProperty(
                    storageProfile,
                    "dataDisks",
                    out var dataDisks) &&
                dataDisks.ValueKind ==
                    JsonValueKind.Array)
            {
                foreach (var dataDisk in
                         dataDisks.EnumerateArray())
                {
                    var diskId =
                        GetString(
                            dataDisk,
                            "managedDisk",
                            "id");

                    AddRelationship(
                        vm,
                        diskId,
                        "DataDisk",
                        resourcesById);
                }
            }
        }
    }

    // =========================================================
    // NETWORK INTERFACE
    // =========================================================

    private static void BuildNetworkInterfaceRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var nic in
                 resources.Where(IsNetworkInterface))
        {
            var properties =
                nic.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            // -------------------------------------------------
            // NIC -> NSG
            // -------------------------------------------------

            var nsgId =
                GetString(
                    properties.Value,
                    "networkSecurityGroup",
                    "id");

            AddRelationship(
                nic,
                nsgId,
                "NetworkSecurityGroup",
                resourcesById);

            // -------------------------------------------------
            // IP CONFIGURATIONS
            // -------------------------------------------------

            if (!TryGetProperty(
                    properties.Value,
                    "ipConfigurations",
                    out var ipConfigurations) ||
                ipConfigurations.ValueKind !=
                    JsonValueKind.Array)
            {
                continue;
            }

            foreach (var configuration in
                     ipConfigurations.EnumerateArray())
            {
                if (!TryGetProperty(
                        configuration,
                        "properties",
                        out var ipProperties))
                {
                    continue;
                }

                // NIC -> Subnet

                var subnetId =
                    GetString(
                        ipProperties,
                        "subnet",
                        "id");

                AddRelationship(
                    nic,
                    subnetId,
                    "Subnet",
                    resourcesById);

                // NIC -> Public IP

                var publicIpId =
                    GetString(
                        ipProperties,
                        "publicIPAddress",
                        "id");

                AddRelationship(
                    nic,
                    publicIpId,
                    "PublicIPAddress",
                    resourcesById);
            }
        }
    }

    // =========================================================
    // SUBNET
    // =========================================================

    private static void BuildSubnetRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var subnet in
                 resources.Where(IsSubnet))
        {
            var properties =
                subnet.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            // -------------------------------------------------
            // SUBNET -> NSG
            // -------------------------------------------------

            var nsgId =
                GetString(
                    properties.Value,
                    "networkSecurityGroup",
                    "id");

            AddRelationship(
                subnet,
                nsgId,
                "NetworkSecurityGroup",
                resourcesById);

            // -------------------------------------------------
            // SUBNET -> ROUTE TABLE
            // -------------------------------------------------

            var routeTableId =
                GetString(
                    properties.Value,
                    "routeTable",
                    "id");

            AddRelationship(
                subnet,
                routeTableId,
                "RouteTable",
                resourcesById);

            // -------------------------------------------------
            // SUBNET -> NAT GATEWAY
            // -------------------------------------------------

            var natGatewayId =
                GetString(
                    properties.Value,
                    "natGateway",
                    "id");

            AddRelationship(
                subnet,
                natGatewayId,
                "NatGateway",
                resourcesById);
        }
    }

    // =========================================================
    // PRIVATE ENDPOINT
    // =========================================================

    private static void BuildPrivateEndpointRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var endpoint in
                 resources.Where(IsPrivateEndpoint))
        {
            var properties =
                endpoint.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            // -------------------------------------------------
            // PRIVATE ENDPOINT -> SUBNET
            // -------------------------------------------------

            var subnetId =
                GetString(
                    properties.Value,
                    "subnet",
                    "id");

            AddRelationship(
                endpoint,
                subnetId,
                "Subnet",
                resourcesById);

            // -------------------------------------------------
            // PRIVATE ENDPOINT -> TARGET
            // -------------------------------------------------

            if (!TryGetProperty(
                    properties.Value,
                    "privateLinkServiceConnections",
                    out var connections) ||
                connections.ValueKind !=
                    JsonValueKind.Array)
            {
                continue;
            }

            foreach (var connection in
                     connections.EnumerateArray())
            {
                if (!TryGetProperty(
                        connection,
                        "properties",
                        out var connectionProperties))
                {
                    continue;
                }

                var resourceId =
                    GetString(
                        connectionProperties,
                        "privateLinkServiceId");

                AddRelationship(
                    endpoint,
                    resourceId,
                    "PrivateLinkTarget",
                    resourcesById);
            }
        }
    }

    // =========================================================
    // DISKS
    // =========================================================

    private static void BuildDiskRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        /*
         * Le relazioni dei Managed Disk vengono costruite
         * dal lato VM:
         *
         * VM -> OsDisk
         * VM -> DataDisk
         *
         * Questo metodo rimane come punto di estensione
         * per eventuali relazioni inverse o ulteriori
         * informazioni specifiche dei Managed Disk.
         */
    }

    // =========================================================
    // RELATIONSHIP CREATION
    // =========================================================

    private static void AddRelationship(
        AzureResource source,
        string? targetId,
        string relationshipType,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            return;
        }

        var normalizedTargetId =
            NormalizeId(targetId);

        if (!resourcesById.ContainsKey(
                normalizedTargetId))
        {
            return;
        }

        var relationship =
            new AzureResourceRelationship(
                SourceResourceId:
                    NormalizeId(source.Id),

                TargetResourceId:
                    normalizedTargetId,

                RelationshipType:
                    relationshipType);

        if (!source.Relationships.Contains(
                relationship))
        {
            source.Relationships.Add(
                relationship);
        }
    }

    // =========================================================
    // RESOURCE TYPE HELPERS
    // =========================================================

    private static bool IsVirtualMachine(
        AzureResource resource)
    {
        return TypeEquals(
            resource,
            "Microsoft.Compute/virtualMachines");
    }

    private static bool IsNetworkInterface(
        AzureResource resource)
    {
        return TypeEquals(
            resource,
            "Microsoft.Network/networkInterfaces");
    }

    private static bool IsSubnet(
        AzureResource resource)
    {
        return TypeEquals(
            resource,
            "Microsoft.Network/virtualNetworks/subnets");
    }

    private static bool IsPrivateEndpoint(
        AzureResource resource)
    {
        return TypeEquals(
            resource,
            "Microsoft.Network/privateEndpoints");
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

    // =========================================================
    // JSON HELPERS
    // =========================================================

    private static bool TryGetProperty(
        JsonElement element,
        string property,
        out JsonElement value)
    {
        return element.TryGetProperty(
            property,
            out value);
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value) &&
            value.ValueKind ==
                JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static string? GetString(
        JsonElement element,
        string parentProperty,
        string childProperty)
    {
        if (!element.TryGetProperty(
                parentProperty,
                out var parent))
        {
            return null;
        }

        return GetString(
            parent,
            childProperty);
    }

    // =========================================================
    // ID NORMALIZATION
    // =========================================================

    private static string NormalizeId(
        string id)
    {
        return id
            .Trim()
            .TrimEnd('/');
    }
}
