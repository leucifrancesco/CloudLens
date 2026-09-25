using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class MetricAnalyzer
{
    private const int MinimumSamples =
        24;

    private const double VmHighCpuThreshold =
        90;

    private const double VmLowCpuThreshold =
        5;

    private const double SqlHighUtilizationThreshold =
        90;

    private const double SqlHighStorageThreshold =
        85;

    private const double StorageLowAvailabilityThreshold =
        99.9;

    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyList<MetricProfile> metrics,
        AzureSubscription subscription)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(
                nameof(resources));
        }

        if (metrics == null)
        {
            throw new ArgumentNullException(
                nameof(metrics));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

        var findings =
            new List<Finding>();

        AnalyzeVirtualMachines(
            metrics,
            findings);

        AnalyzeAppServices(
            metrics,
            findings);

        AnalyzeSqlDatabases(
            metrics,
            findings);

        AnalyzeStorageAccounts(
            metrics,
            findings);

        AnalyzeMessaging(
            metrics,
            findings);

        return findings;
    }

    // =========================================================
    // VIRTUAL MACHINES
    // =========================================================

    private static void AnalyzeVirtualMachines(
        IReadOnlyList<MetricProfile> metrics,
        List<Finding> findings)
    {
        var vmMetrics =
            metrics
                .Where(
                    metric =>
                        IsType(
                            metric.ResourceType,
                            "Microsoft.Compute/virtualMachines"))
                .GroupBy(
                    metric =>
                        metric.ResourceId,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceMetrics in vmMetrics)
        {
            var cpu =
                FindMetric(
                    resourceMetrics,
                    "Percentage CPU");

            if (cpu == null ||
                cpu.SampleCount < MinimumSamples)
            {
                continue;
            }

            if (cpu.Average >= VmHighCpuThreshold)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-VM-CPU-HIGH-{cpu.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "VM-CPU-HIGH",

                        title:
                            "VM con utilizzo CPU elevato",

                        description:
                            $"La VM presenta una CPU media del " +
                            $"{cpu.Average:F1}% nel periodo analizzato " +
                            $"su {cpu.SampleCount} campioni.",

                        impact:
                            "L'utilizzo elevato può indicare un carico " +
                            "importante o un possibile sottodimensionamento " +
                            "della VM.",

                        recommendation:
                            "Verificare il carico applicativo, i picchi " +
                            "e il dimensionamento della VM. Valutare " +
                            "scaling o ridimensionamento se necessario.",

                        metric:
                            cpu));
            }
            else if (cpu.Average <= VmLowCpuThreshold)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-VM-CPU-LOW-{cpu.ResourceId}",

                        category:
                            Category.Cost,

                        severity:
                            Severity.Low,

                        ruleId:
                            "VM-CPU-LOW",

                        title:
                            "VM con utilizzo CPU molto basso",

                        description:
                            $"La VM presenta una CPU media del " +
                            $"{cpu.Average:F1}% nel periodo analizzato " +
                            $"su {cpu.SampleCount} campioni.",

                        impact:
                            "Il dimensionamento attuale potrebbe essere " +
                            "superiore alle esigenze del carico rilevato.",

                        recommendation:
                            "Verificare i pattern di utilizzo, i picchi " +
                            "e i requisiti applicativi prima di valutare " +
                            "un eventuale ridimensionamento. La sola CPU " +
                            "non è sufficiente per determinare il sizing.",

                        metric:
                            cpu));
            }
        }
    }

    // =========================================================
    // APP SERVICES
    // =========================================================

    private static void AnalyzeAppServices(
        IReadOnlyList<MetricProfile> metrics,
        List<Finding> findings)
    {
        var appMetrics =
            metrics
                .Where(
                    metric =>
                        IsType(
                            metric.ResourceType,
                            "Microsoft.Web/sites"))
                .GroupBy(
                    metric =>
                        metric.ResourceId,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceMetrics in appMetrics)
        {
            var errors =
                FindMetric(
                    resourceMetrics,
                    "Http5xx");

            if (errors != null &&
                errors.SampleCount >= MinimumSamples &&
                errors.Average > 0)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-APP-HTTP5XX-{errors.ResourceId}",

                        category:
                            Category.Operations,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "APP-HTTP5XX",

                        title:
                            "App Service con errori HTTP 5xx",

                        description:
                            $"Sono stati rilevati errori HTTP 5xx " +
                            $"nel periodo analizzato su " +
                            $"{errors.SampleCount} campioni.",

                        impact:
                            "La presenza persistente di errori HTTP 5xx " +
                            "può indicare problemi applicativi, infrastrutturali " +
                            "o nelle dipendenze dell'applicazione.",

                        recommendation:
                            "Correlare il dato con Application Insights, " +
                            "log applicativi, dipendenze e pattern di traffico " +
                            "per identificare la causa degli errori.",

                        metric:
                            errors));
            }
        }
    }

    // =========================================================
    // SQL
    // =========================================================

    private static void AnalyzeSqlDatabases(
        IReadOnlyList<MetricProfile> metrics,
        List<Finding> findings)
    {
        var sqlMetrics =
            metrics
                .Where(
                    metric =>
                        IsType(
                            metric.ResourceType,
                            "Microsoft.Sql/servers/databases"))
                .GroupBy(
                    metric =>
                        metric.ResourceId,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceMetrics in sqlMetrics)
        {
            var dtu =
                FindMetric(
                    resourceMetrics,
                    "dtu_consumption_percent");

            var cpu =
                FindMetric(
                    resourceMetrics,
                    "cpu_percent");

            var utilization =
                dtu != null
                    ? dtu
                    : cpu;

            if (utilization != null &&
                utilization.SampleCount >= MinimumSamples &&
                utilization.Average >= SqlHighUtilizationThreshold)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-SQL-UTILIZATION-HIGH-{utilization.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "SQL-UTILIZATION-HIGH",

                        title:
                            "SQL Database con utilizzo elevato",

                        description:
                            $"Il database presenta un utilizzo medio del " +
                            $"{utilization.Average:F1}% per la metrica " +
                            $"{utilization.MetricName} su " +
                            $"{utilization.SampleCount} campioni.",

                        impact:
                            "L'elevato utilizzo può indicare un carico " +
                            "importante e contribuire al degrado delle " +
                            "prestazioni.",

                        recommendation:
                            "Verificare query, workload, pattern di utilizzo " +
                            "e dimensionamento del database.",

                        metric:
                            utilization));
            }

            var storage =
                FindMetric(
                    resourceMetrics,
                    "storage_percent");

            if (storage != null &&
                storage.SampleCount >= MinimumSamples &&
                storage.Average >= SqlHighStorageThreshold)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-SQL-STORAGE-HIGH-{storage.ResourceId}",

                        category:
                            Category.Reliability,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "SQL-STORAGE-HIGH",

                        title:
                            "SQL Database con storage elevato",

                        description:
                            $"Lo storage medio utilizzato è del " +
                            $"{storage.Average:F1}% su " +
                            $"{storage.SampleCount} campioni.",

                        impact:
                            "La crescita dello storage può portare " +
                            "alla saturazione della capacità disponibile.",

                        recommendation:
                            "Verificare la crescita dei dati e pianificare " +
                            "un intervento sul dimensionamento o sulla gestione " +
                            "dello storage.",

                        metric:
                            storage));
            }
        }
    }

    // =========================================================
    // STORAGE ACCOUNTS
    // =========================================================

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<MetricProfile> metrics,
        List<Finding> findings)
    {
        var storageMetrics =
            metrics
                .Where(
                    metric =>
                        IsType(
                            metric.ResourceType,
                            "Microsoft.Storage/storageAccounts"))
                .GroupBy(
                    metric =>
                        metric.ResourceId,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceMetrics in storageMetrics)
        {
            var availability =
                FindMetric(
                    resourceMetrics,
                    "Availability");

            if (availability != null &&
                availability.SampleCount >= MinimumSamples &&
                availability.Average < StorageLowAvailabilityThreshold)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-STORAGE-AVAILABILITY-{availability.ResourceId}",

                        category:
                            Category.Reliability,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "STORAGE-AVAILABILITY-LOW",

                        title:
                            "Storage Account con availability ridotta",

                        description:
                            $"L'availability media rilevata è " +
                            $"{availability.Average:F2}% su " +
                            $"{availability.SampleCount} campioni.",

                        impact:
                            "Una disponibilità ridotta può indicare " +
                            "problemi di servizio o di accesso alle risorse " +
                            "di storage.",

                        recommendation:
                            "Verificare Azure Service Health, diagnostica, " +
                            "pattern di accesso e eventuali errori correlati.",

                        metric:
                            availability));
            }
        }
    }

    // =========================================================
    // MESSAGING
    // =========================================================

    private static void AnalyzeMessaging(
        IReadOnlyList<MetricProfile> metrics,
        List<Finding> findings)
    {
        var messagingMetrics =
            metrics
                .Where(
                    metric =>
                        IsType(
                            metric.ResourceType,
                            "Microsoft.ServiceBus/namespaces") ||
                        IsType(
                            metric.ResourceType,
                            "Microsoft.EventHub/namespaces"))
                .GroupBy(
                    metric =>
                        metric.ResourceId,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceMetrics in messagingMetrics)
        {
            var throttled =
                FindMetric(
                    resourceMetrics,
                    "ThrottledRequests");

            if (throttled != null &&
                throttled.SampleCount >= MinimumSamples &&
                throttled.Average > 0)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-MESSAGING-THROTTLING-{throttled.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "MESSAGING-THROTTLING",

                        title:
                            "Servizio messaging con richieste throttled",

                        description:
                            $"È stata rilevata una media di " +
                            $"{throttled.Average:F2} richieste throttled " +
                            $"per campione nel periodo analizzato, " +
                            $"su {throttled.SampleCount} campioni.",

                        impact:
                            "Il throttling persistente può causare ritardi " +
                            "o errori nelle operazioni applicative.",

                        recommendation:
                            "Verificare il workload, i pattern di utilizzo " +
                            "e il dimensionamento del namespace.",

                        metric:
                            throttled));
            }
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static MetricProfile? FindMetric(
        IEnumerable<MetricProfile> metrics,
        string metricName)
    {
        return metrics.FirstOrDefault(
            metric =>
                string.Equals(
                    metric.MetricName,
                    metricName,
                    StringComparison.OrdinalIgnoreCase));
    }

    private static Finding CreateFinding(
        string id,
        Category category,
        Severity severity,
        string ruleId,
        string title,
        string description,
        string impact,
        string recommendation,
        MetricProfile metric)
    {
        return new Finding(
            Id:
                id,

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
                metric.ResourceName,

            ResourceType:
                metric.ResourceType,

            ResourceId:
                metric.ResourceId);
    }

    private static bool IsType(
        string resourceType,
        string expectedType)
    {
        return string.Equals(
            resourceType,
            expectedType,
            StringComparison.OrdinalIgnoreCase);
    }
}