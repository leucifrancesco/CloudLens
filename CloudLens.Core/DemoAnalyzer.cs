namespace CloudLens.Core;

public static class DemoAnalyzer
{
    public static ScanResult CreateDemo()
    {
        var f = new List<Finding>
        {
            new("F001",Category.Security,Severity.Critical,"NSG-OPEN-MGMT","Porta di gestione esposta a Internet (RDP)","Una regola NSG consente traffico inbound da Internet verso RDP.","Superficie di attacco diretta: brute force, ransomware e movimento laterale.","Rimuovere la regola e usare Azure Bastion o Just-In-Time VM Access.","nsg-prod-web","Microsoft.Network/networkSecurityGroups",0,"az network nsg rule delete --resource-group rg-demo --nsg-name nsg-prod-web --name allow-rdp"),
            new("F002",Category.Security,Severity.Critical,"ST-PUBLIC-BLOB","Accesso pubblico ai blob consentito","Lo storage account consente accesso anonimo ai container blob.","Rischio di esposizione pubblica dei dati aziendali.","Disabilitare l'accesso pubblico ai blob e usare Entra ID con RBAC.","stdemoprod01","Microsoft.Storage/storageAccounts"),
            new("F003",Category.Cost,Severity.High,"DISK-UNATTACHED","Disco gestito non collegato","Un disco Premium da 512 GB non è collegato ad alcuna VM.","Spesa ricorrente senza utilizzo.","Creare uno snapshot e quindi eliminare il disco.","disk-old-app01","Microsoft.Compute/disks",69.12,"az disk delete --resource-group rg-demo --name disk-old-app01 --yes"),
            new("F004",Category.Cost,Severity.High,"VM-UNDERUTILIZED","VM sottoutilizzata: CPU media 3.2% su 30 giorni","La VM vm-erp-01 ha CPU media molto bassa.","Sovradimensionamento e capacità inutilizzata.","Ridurre la SKU e valutare Reservations sul residuo.","vm-erp-01","Microsoft.Compute/virtualMachines",128),
            new("F005",Category.Cost,Severity.Medium,"PIP-ORPHAN","Indirizzo IP pubblico non associato","L'IP pubblico non è associato ad alcuna risorsa.","Costo ricorrente inutile.","Eliminare l'indirizzo IP pubblico.","pip-legacy-lb","Microsoft.Network/publicIPAddresses",3.2),
            new("F006",Category.Reliability,Severity.High,"VM-NO-HA","VM singola senza alta disponibilità","La VM non è protetta da zone o availability set.","Un guasto può causare downtime.","Distribuire istanze su zone diverse dietro Load Balancer o VMSS Flexible.","vm-erp-01","Microsoft.Compute/virtualMachines"),
            new("F007",Category.Reliability,Severity.High,"PIP-BASIC-SKU","IP pubblico con SKU Basic","Lo SKU Basic è in dismissione.","Rischio operativo e assenza di funzionalità moderne.","Migrare allo SKU Standard.","pip-web-01","Microsoft.Network/publicIPAddresses"),
            new("F008",Category.Performance,Severity.Medium,"ARCH-VMSS-CANDIDATE","3 VM identiche candidate a VMSS","Tre VM usano la stessa SKU e formano un pool omogeneo.","Gestione manuale e assenza di autoscale.","Valutare VMSS Flexible con autoscale.","3 VM in rg-demo","Microsoft.Compute/virtualMachines"),
            new("F009",Category.Performance,Severity.High,"VM-CPU-SATURATION","VM in saturazione CPU: media 82.4%","La VM opera stabilmente vicino al limite CPU.","Degrado prestazionale e rischio timeout.","Aumentare SKU o distribuire il carico.","vm-sql-01","Microsoft.Compute/virtualMachines"),
            new("F010",Category.Operations,Severity.Medium,"GOV-NO-TAGS","34 risorse su 78 prive di tag","Una quota rilevante non ha tag di governance.","Difficoltà di attribuzione costi e ownership.","Definire standard di tagging e Azure Policy.","Subscription","Microsoft.Resources/subscriptions"),
            new("F011",Category.Operations,Severity.Low,"NSG-ORPHAN","NSG non associato","Il NSG non è associato a subnet o NIC.","Configurazione morta e confusione operativa.","Associare o eliminare il NSG.","nsg-unused","Microsoft.Network/networkSecurityGroups")
        };
        var penalties = new Dictionary<Severity,int> { [Severity.Critical]=18,[Severity.High]=10,[Severity.Medium]=5,[Severity.Low]=2 };
        var scores = Enum.GetValues<Category>().ToDictionary(c => c, c => Math.Max(0,100-f.Where(x=>x.Category==c).Sum(x=>penalties[x.Severity])));
        return new ScanResult { Findings=f, ScoresByCategory=scores, Score=(int)scores.Values.Average() };
    }
}
