using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class MetricAnalyzer
{
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

            if (cpu == null)
            {
                continue;
            }

            if (cpu.Average >= 90)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-VM-CPU-HIGH-{cpu.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.High,

                        ruleId:
                            "VM-CPU-HIGH",

                        title:
                            "VM con utilizzo CPU elevato",

                        description:
                            $"La VM presenta una CPU media del {cpu.Average:F1}% " +
                            $"nel periodo analizzato.",

                        impact:
                            "La VM potrebbe essere sottodimensionata " +
                            "o soggetta a carico elevato.",

                        recommendation:
                            "Verificare il carico applicativo e valutare " +
                            "il dimensionamento della VM.",

                        metric:
                            cpu));
            }
            else if (cpu.Average <= 5 &&
                     cpu.SampleCount >= 24)
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
                            $"La VM presenta una CPU media del {cpu.Average:F1}% " +
                            $"nel periodo analizzato.",

                        impact:
                            "Il dimensionamento attuale potrebbe essere " +
                            "superiore alle esigenze del carico rilevato.",

                        recommendation:
                            "Verificare i pattern di utilizzo e valutare " +
                            "un eventuale ridimensionamento.",

                        metric:
                            cpu));
            }
        }
    }

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
            var cpu =
                FindMetric(
                    resourceMetrics,
                    "CpuTime");

            if (cpu != null &&
                cpu.Average > 90)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-APP-CPU-HIGH-{cpu.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.High,

                        ruleId:
                            "APP-CPU-HIGH",

                        title:
                            "App Service con utilizzo CPU elevato",

                        description:
                            "L'App Service presenta un utilizzo CPU elevato " +
                            "nel periodo analizzato.",

                        impact:
                            "Il carico potrebbe causare degrado delle " +
                            "prestazioni o saturazione.",

                        recommendation:
                            "Analizzare il carico e valutare scaling " +
                            "orizzontale o verticale.",

                        metric:
                            cpu));
            }

            var errors =
                FindMetric(
                    resourceMetrics,
                    "Http5xx");

            if (errors != null &&
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
                            "Sono stati rilevati errori HTTP 5xx " +
                            "nel periodo analizzato.",

                        impact:
                            "Gli errori 5xx indicano possibili problemi " +
                            "applicativi o infrastrutturali.",

                        recommendation:
                            "Analizzare Application Insights, log applicativi " +
                            "e dipendenze dell'applicazione.",

                        metric:
                            errors));
            }
        }
    }

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
                utilization.Average >= 90)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-SQL-UTILIZATION-HIGH-{utilization.ResourceId}",

                        category:
                            Category.Performance,

                        severity:
                            Severity.High,

                        ruleId:
                            "SQL-UTILIZATION-HIGH",

                        title:
                            "SQL Database con utilizzo elevato",

                        description:
                            $"Il database presenta un utilizzo medio del " +
                            $"{utilization.Average:F1}% " +
                            $"per la metrica {utilization.MetricName}.",

                        impact:
                            "L'elevato utilizzo può causare degrado delle " +
                            "prestazioni.",

                        recommendation:
                            "Verificare query, workload e dimensionamento " +
                            "del database.",

                        metric:
                            utilization));
            }

            var storage =
                FindMetric(
                    resourceMetrics,
                    "storage_percent");

            if (storage != null &&
                storage.Average >= 85)
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
                            $"{storage.Average:F1}%.",

                        impact:
                            "La crescita dello storage può portare " +
                            "a saturazione della capacità disponibile.",

                        recommendation:
                            "Verificare la crescita dei dati e pianificare " +
                            "un intervento sul dimensionamento.",

                        metric:
                            storage));
            }
        }
    }

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
                availability.Average < 99)
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
                            $"{availability.Average:F2}%.",

                        impact:
                            "Una disponibilità ridotta può indicare " +
                            "problemi di servizio o accesso.",

                        recommendation:
                            "Verificare Azure Service Health, diagnostica " +
                            "e pattern di accesso.",

                        metric:
                            availability));
            }
        }
    }

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
                throttled.Maximum > 0)
            {
                findings.Add(
                    CreateFinding(
                        id:
                            $"METRIC-MESSAGING-THROTTLING-{throttled.ResourceId}",

                        category:
                            Category.Operations,

                        severity:
                            Severity.Medium,

                        ruleId:
                            "MESSAGING-THROTTLING",

                        title:
                            "Servizio messaging con richieste throttled",

                        description:
                            $"Sono stati rilevati eventi di throttling " +
                            $"per {throttled.MetricName}.",

                        impact:
                            "Il throttling può causare ritardi o errori " +
                            "nelle operazioni applicative.",

                        recommendation:
                            "Verificare il workload e il dimensionamento " +
                            "del namespace.",

                        metric:
                            throttled));
            }
        }
    }

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