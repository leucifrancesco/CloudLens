using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureRelationshipBuilder
{
    public void Build(
        IReadOnlyList<AzureResource> resources)
    {
        if (resources == null)
            throw new ArgumentNullException(nameof(resources));

        var resourcesById =
            resources
                .GroupBy(
                    resource => NormalizeId(resource.Id),
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
    // VIRTUAL MACHINES
    // =========================================================

    private static void BuildVirtualMachineRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var vm in resources.Where(IsVirtualMachine))
        {
            var properties = GetEffectiveProperties(vm);

            // VM -> NIC
            if (TryGetObject(
                    properties,
                    out var networkProfile,
                    "networkProfile") &&
                TryGetArray(
                    networkProfile,
                    "networkInterfaces",
                    out var networkInterfaces))
            {
                foreach (var nicReference in
                         networkInterfaces.EnumerateArray())
                {
                    if (nicReference.ValueKind != JsonValueKind.Object)
                        continue;

                    if (!TryGetString(
                            nicReference,
                            "id",
                            out var nicId))
                    {
                        continue;
                    }

                    AddRelationship(
                        vm,
                        nicId,
                        "NetworkInterface",
                        resourcesById);
                }
            }

            // VM -> OS Disk
            if (TryGetObject(
                    properties,
                    out var storageProfile,
                    "storageProfile"))
            {
                if (TryGetObject(
                        storageProfile,
                        out var osDisk,
                        "osDisk"))
                {
                    if (TryGetObject(
                            osDisk,
                            out var managedDisk,
                            "managedDisk"))
                    {
                        if (TryGetString(
                                managedDisk,
                                "id",
                                out var diskId))
                        {
                            AddRelationship(
                                vm,
                                diskId,
                                "OsDisk",
                                resourcesById);
                        }
                    }
                }

                // VM -> Data Disks
                if (TryGetArray(
                        storageProfile,
                        "dataDisks",
                        out var dataDisks))
                {
                    foreach (var dataDisk in
                             dataDisks.EnumerateArray())
                    {
                        if (dataDisk.ValueKind != JsonValueKind.Object)
                            continue;

                        if (!TryGetObject(
                                dataDisk,
                                out var managedDisk,
                                "managedDisk"))
                        {
                            continue;
                        }

                        if (!TryGetString(
                                managedDisk,
                                "id",
                                out var diskId))
                        {
                            continue;
                        }

                        AddRelationship(
                            vm,
                            diskId,
                            "DataDisk",
                            resourcesById);
                    }
                }
            }
        }
    }

    // =========================================================
    // NETWORK INTERFACES
    // =========================================================

    private static void BuildNetworkInterfaceRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var nic in resources.Where(IsNetworkInterface))
        {
            var properties = GetEffectiveProperties(nic);

            // NIC -> NSG
            if (TryGetObject(
                    properties,
                    out var networkSecurityGroup,
                    "networkSecurityGroup"))
            {
                if (TryGetString(
                        networkSecurityGroup,
                        "id",
                        out var nsgId))
                {
                    AddRelationship(
                        nic,
                        nsgId,
                        "NetworkSecurityGroup",
                        resourcesById);
                }
            }

            if (!TryGetArray(
                    properties,
                    "ipConfigurations",
                    out var ipConfigurations))
            {
                continue;
            }

            foreach (var ipConfiguration in
                     ipConfigurations.EnumerateArray())
            {
                if (ipConfiguration.ValueKind != JsonValueKind.Object)
                    continue;

                // NIC -> Subnet
                if (TryGetObject(
                        ipConfiguration,
                        out var subnet,
                        "properties",
                        "subnet"))
                {
                    if (TryGetString(
                            subnet,
                            "id",
                            out var subnetId))
                    {
                        AddRelationship(
                            nic,
                            subnetId,
                            "Subnet",
                            resourcesById);
                    }
                }

                // NIC -> Public IP
                if (TryGetObject(
                        ipConfiguration,
                        out var publicIp,
                        "properties",
                        "publicIPAddress"))
                {
                    if (TryGetString(
                            publicIp,
                            "id",
                            out var publicIpId))
                    {
                        AddRelationship(
                            nic,
                            publicIpId,
                            "PublicIPAddress",
                            resourcesById);
                    }
                }
            }
        }
    }

    // =========================================================
    // SUBNETS
    // =========================================================

    private static void BuildSubnetRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var subnet in resources.Where(IsSubnet))
        {
            var properties = GetEffectiveProperties(subnet);

            // -------------------------------------------------
            // Subnet -> VNet
            // -------------------------------------------------

            var virtualNetworkId =
                GetVirtualNetworkIdFromSubnetId(subnet.Id);

            if (!string.IsNullOrWhiteSpace(virtualNetworkId))
            {
                AddRelationship(
                    subnet,
                    virtualNetworkId,
                    "VirtualNetwork",
                    resourcesById);
            }

            // -------------------------------------------------
            // Subnet -> NSG
            // -------------------------------------------------

            if (TryGetObject(
                    properties,
                    out var networkSecurityGroup,
                    "networkSecurityGroup"))
            {
                if (TryGetString(
                        networkSecurityGroup,
                        "id",
                        out var nsgId))
                {
                    AddRelationship(
                        subnet,
                        nsgId,
                        "NetworkSecurityGroup",
                        resourcesById);
                }
            }

            // -------------------------------------------------
            // Subnet -> Route Table
            // -------------------------------------------------

            if (TryGetObject(
                    properties,
                    out var routeTable,
                    "routeTable"))
            {
                if (TryGetString(
                        routeTable,
                        "id",
                        out var routeTableId))
                {
                    AddRelationship(
                        subnet,
                        routeTableId,
                        "RouteTable",
                        resourcesById);
                }
            }

            // -------------------------------------------------
            // Subnet -> NAT Gateway
            // -------------------------------------------------

            if (TryGetObject(
                    properties,
                    out var natGateway,
                    "natGateway"))
            {
                if (TryGetString(
                        natGateway,
                        "id",
                        out var natGatewayId))
                {
                    AddRelationship(
                        subnet,
                        natGatewayId,
                        "NatGateway",
                        resourcesById);
                }
            }
        }
    }

    // =========================================================
    // PRIVATE ENDPOINTS
    // =========================================================

    private static void BuildPrivateEndpointRelationships(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        foreach (var privateEndpoint in
                 resources.Where(IsPrivateEndpoint))
        {
            var properties =
                GetEffectiveProperties(privateEndpoint);

            // Private Endpoint -> Subnet
            if (TryGetObject(
                    properties,
                    out var subnet,
                    "subnet"))
            {
                if (TryGetString(
                        subnet,
                        "id",
                        out var subnetId))
                {
                    AddRelationship(
                        privateEndpoint,
                        subnetId,
                        "Subnet",
                        resourcesById);
                }
            }

            // Private Endpoint -> Private Link Target
            if (TryGetArray(
                    properties,
                    "privateLinkServiceConnections",
                    out var connections))
            {
                foreach (var connection in
                         connections.EnumerateArray())
                {
                    if (connection.ValueKind != JsonValueKind.Object)
                        continue;

                    if (!TryGetObject(
                            connection,
                            out var privateLinkServiceConnection,
                            "properties"))
                    {
                        continue;
                    }

                    if (TryGetString(
                            privateLinkServiceConnection,
                            "privateLinkServiceId",
                            out var targetId))
                    {
                        AddRelationship(
                            privateEndpoint,
                            targetId,
                            "PrivateLinkTarget",
                            resourcesById);
                    }
                }
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
        // VM -> Disk relationships are sufficient for the current
        // graph model. Disk -> VM can be derived through
        // AzureResourceGraph.GetDependents().
    }

    // =========================================================
    // RELATIONSHIP ADDITION
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

        if (!resourcesById.ContainsKey(normalizedTargetId))
        {
            return;
        }

        var relationship =
            new AzureResourceRelationship(
                RelationshipType: relationshipType,
                SourceResourceId: NormalizeId(source.Id),
                TargetResourceId: normalizedTargetId);

        if (!source.Relationships.Contains(relationship))
        {
            source.Relationships.Add(relationship);
        }
    }

    // =========================================================
    // PROPERTY HELPERS
    // =========================================================

    private static JsonElement GetEffectiveProperties(
        AzureResource resource)
    {
        if (resource.Properties.HasValue &&
            resource.Properties.Value.ValueKind ==
                JsonValueKind.Object)
        {
            return resource.Properties.Value;
        }

        return default;
    }

    private static bool TryGetObject(
        JsonElement element,
        out JsonElement value,
        params string[] path)
    {
        value = default;

        var current = element;

        foreach (var propertyName in path)
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(
                    propertyName,
                    out current))
            {
                return false;
            }
        }

        if (current.ValueKind != JsonValueKind.Object)
            return false;

        value = current;
        return true;
    }

    private static bool TryGetArray(
        JsonElement element,
        string propertyName,
        out JsonElement value)
    {
        value = default;

        if (element.ValueKind != JsonValueKind.Object)
            return false;

        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            return false;
        }

        if (property.ValueKind != JsonValueKind.Array)
            return false;

        value = property;

        return true;
    }

    private static bool TryGetString(
        JsonElement element,
        string propertyName,
        out string? value)
    {
        value = null;

        if (element.ValueKind != JsonValueKind.Object)
            return false;

        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            return false;
        }

        if (property.ValueKind != JsonValueKind.String)
            return false;

        value = property.GetString();

        return !string.IsNullOrWhiteSpace(value);
    }

    // =========================================================
    // RESOURCE TYPE HELPERS
    // =========================================================

    private static bool IsVirtualMachine(
        AzureResource resource)
    {
        return IsType(
            resource,
            "Microsoft.Compute/virtualMachines");
    }

    private static bool IsNetworkInterface(
        AzureResource resource)
    {
        return IsType(
            resource,
            "Microsoft.Network/networkInterfaces");
    }

    private static bool IsSubnet(
        AzureResource resource)
    {
        return IsType(
            resource,
            "Microsoft.Network/virtualNetworks/subnets");
    }

    private static bool IsPrivateEndpoint(
        AzureResource resource)
    {
        return IsType(
            resource,
            "Microsoft.Network/privateEndpoints");
    }

    private static bool IsType(
        AzureResource resource,
        string expectedType)
    {
        return string.Equals(
            resource.Type,
            expectedType,
            StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================
    // SUBNET PARENT VNET
    // =========================================================

    private static string? GetVirtualNetworkIdFromSubnetId(
        string subnetId)
    {
        if (string.IsNullOrWhiteSpace(subnetId))
            return null;

        var normalized =
            NormalizeId(subnetId);

        const string marker =
            "/virtualnetworks/";

        var virtualNetworkIndex =
            normalized.IndexOf(
                marker,
                StringComparison.OrdinalIgnoreCase);

        if (virtualNetworkIndex < 0)
            return null;

        const string subnetMarker =
            "/subnets/";

        var subnetIndex =
            normalized.IndexOf(
                subnetMarker,
                virtualNetworkIndex + marker.Length,
                StringComparison.OrdinalIgnoreCase);

        if (subnetIndex < 0)
            return null;

        return normalized[..subnetIndex];
    }

    // =========================================================
    // ID NORMALIZATION
    // =========================================================

    private static string NormalizeId(
        string id)
    {
        return id.Trim().TrimEnd('/');
    }
}