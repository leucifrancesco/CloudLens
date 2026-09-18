using System.Text.Json;
using CloudLens.Core;
using CloudLens.Core.Azure;
using Xunit;

namespace CloudLens.Core.Tests;

public sealed class AssessmentQualityTests
{
    [Fact]
    public void Quality_ShouldReturnComplete_WhenAllSubscriptionsAreComplete()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Complete,
                    resources: 4,
                    enrichedResources: 4)
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Complete,
            quality.Status);

        Assert.Equal(1, quality.TotalSubscriptions);
        Assert.Equal(1, quality.CompleteSubscriptions);
        Assert.Equal(0, quality.PartialSubscriptions);
        Assert.Equal(0, quality.FailedSubscriptions);
        Assert.Equal(0, quality.UnsupportedSubscriptions);

        Assert.Equal(
            100,
            quality.EnrichmentCoveragePercent);

        Assert.Equal(
            0,
            quality.MetricCoveragePercent);
    }

    [Fact]
    public void Quality_ShouldReturnPartial_WhenSubscriptionIsPartial()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Partial,
                    resources: 4,
                    enrichedResources: 2,
                    errorMessage: "Enrichment failed.")
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Partial,
            quality.Status);

        Assert.Equal(
            1,
            quality.PartialSubscriptions);

        Assert.Contains(
            quality.Limitations,
            limitation =>
                limitation.Contains(
                    "Enrichment failed.",
                    StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Quality_ShouldReturnFailed_WhenAnySubscriptionFails()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Complete,
                    resources: 2,
                    enrichedResources: 2),

                CreateSubscriptionAssessment(
                    "Subscription B",
                    AssessmentQualityStatus.Failed,
                    resources: 0,
                    enrichedResources: 0,
                    errorMessage: "Assessment failed.")
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Failed,
            quality.Status);

        Assert.Equal(
            2,
            quality.TotalSubscriptions);

        Assert.Equal(
            1,
            quality.CompleteSubscriptions);

        Assert.Equal(
            0,
            quality.PartialSubscriptions);

        Assert.Equal(
            1,
            quality.FailedSubscriptions);

        Assert.Contains(
            quality.Limitations,
            limitation =>
                limitation.Contains(
                    "Assessment failed.",
                    StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Quality_ShouldReturnUnsupported_WhenOnlyUnsupportedSubscriptionsExist()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Unsupported,
                    resources: 2,
                    enrichedResources: 0)
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Unsupported,
            quality.Status);

        Assert.Equal(
            1,
            quality.UnsupportedSubscriptions);

        Assert.NotEmpty(
            quality.Limitations);
    }

    [Fact]
    public void Quality_ShouldReturnPartial_WhenCompleteAndUnsupportedSubscriptionsAreMixed()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Complete,
                    resources: 4,
                    enrichedResources: 3),

                CreateSubscriptionAssessment(
                    "Subscription B",
                    AssessmentQualityStatus.Unsupported,
                    resources: 0,
                    enrichedResources: 0)
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Partial,
            quality.Status);

        Assert.Equal(
            2,
            quality.TotalSubscriptions);

        Assert.Equal(
            1,
            quality.CompleteSubscriptions);

        Assert.Equal(
            0,
            quality.PartialSubscriptions);

        Assert.Equal(
            0,
            quality.FailedSubscriptions);

        Assert.Equal(
            1,
            quality.UnsupportedSubscriptions);

        Assert.Equal(
            75,
            quality.EnrichmentCoveragePercent);

        Assert.Equal(
            0,
            quality.MetricCoveragePercent);
    }

    [Fact]
    public void Quality_ShouldAggregateCoverageAcrossSubscriptions()
    {
        var assessments =
            new[]
            {
                CreateSubscriptionAssessment(
                    "Subscription A",
                    AssessmentQualityStatus.Complete,
                    resources: 4,
                    enrichedResources: 2),

                CreateSubscriptionAssessment(
                    "Subscription B",
                    AssessmentQualityStatus.Complete,
                    resources: 6,
                    enrichedResources: 6)
            };

        var tenant =
            CreateTenantResult(assessments);

        var quality =
            tenant.Quality;

        Assert.Equal(
            2,
            quality.TotalSubscriptions);

        Assert.Equal(
            10,
            quality.Subscriptions
                .SelectMany(
                    subscription =>
                        subscription.Resources)
                .Count());

        Assert.Equal(
            80,
            quality.EnrichmentCoveragePercent);

        Assert.Equal(
            0,
            quality.MetricCoveragePercent);
    }

    [Fact]
    public void Quality_ShouldReturnZeroMetricCoverage_WhenNoMetricProfilesExist()
    {
        var assessment =
            CreateSubscriptionAssessment(
                "Subscription A",
                AssessmentQualityStatus.Complete,
                resources: 4,
                enrichedResources: 4);

        Assert.Empty(
            assessment.Result.MetricProfiles);

        var tenant =
            CreateTenantResult(
                new[]
                {
                    assessment
                });

        var quality =
            tenant.Quality;

        Assert.Equal(
            0,
            quality.MetricCoveragePercent);
    }

    [Fact]
    public void Quality_ShouldUseDefaultMessage_WhenErrorMessageIsMissing()
    {
        var assessment =
            CreateSubscriptionAssessment(
                "Subscription A",
                AssessmentQualityStatus.Partial,
                resources: 2,
                enrichedResources: 1,
                errorMessage: null);

        var tenant =
            CreateTenantResult(
                new[]
                {
                    assessment
                });

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Partial,
            quality.Status);

        Assert.NotEmpty(
            quality.Limitations);

        Assert.Contains(
            quality.Limitations,
            limitation =>
                limitation.Contains(
                    "Subscription A",
                    StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Quality_ShouldReturnEmptyReport_WhenThereAreNoSubscriptions()
    {
        var tenant =
            CreateTenantResult(
                Array.Empty<SubscriptionAssessment>());

        var quality =
            tenant.Quality;

        Assert.Equal(
            AssessmentQualityStatus.Complete,
            quality.Status);

        Assert.Equal(
            0,
            quality.TotalSubscriptions);

        Assert.Equal(
            0,
            quality.CompleteSubscriptions);

        Assert.Equal(
            0,
            quality.PartialSubscriptions);

        Assert.Equal(
            0,
            quality.FailedSubscriptions);

        Assert.Equal(
            0,
            quality.UnsupportedSubscriptions);

        Assert.Equal(
            0,
            quality.EnrichmentCoveragePercent);

        Assert.Equal(
            0,
            quality.MetricCoveragePercent);

        Assert.Empty(
            quality.Limitations);

        Assert.Empty(
            quality.Subscriptions);
    }

    private static TenantScanResult
        CreateTenantResult(
            IReadOnlyList<SubscriptionAssessment> assessments)
    {
        return new TenantScanResult
        {
            TenantId =
                "test-tenant",

            StartedAt =
                DateTimeOffset.UtcNow,

            CompletedAt =
                DateTimeOffset.UtcNow,

            Subscriptions =
                assessments.ToList()
        };
    }

    private static SubscriptionAssessment
        CreateSubscriptionAssessment(
            string name,
            AssessmentQualityStatus status,
            int resources,
            int enrichedResources,
            string? errorMessage = null)
    {
        using var jsonDocument =
            JsonDocument.Parse("{}");

        var raw =
            jsonDocument.RootElement.Clone();

        var resourceList =
            new List<AzureResource>();

        for (var index = 1;
             index <= resources;
             index++)
        {
            var resource =
                new AzureResource(
                    $"/subscriptions/test/resource-{index}",
                    $"resource-{index}",
                    "Microsoft.Test/resources",
                    "test-rg",
                    "westeurope",
                    "subscription-test",
                    null,
                    null,
                    null,
                    raw);

            if (index <= enrichedResources)
            {
                resource.Enrichment =
                    new AzureResourceEnrichment
                    {
                        Success =
                            true,

                        CollectedAt =
                            DateTimeOffset.UtcNow
                    };
            }

            resourceList.Add(
                resource);
        }

        var result =
            new ScanResult
            {
                SubscriptionName =
                    name,

                SubscriptionId =
                    "subscription-test",

                MetricProfiles =
                    []
            };

        return new SubscriptionAssessment(
            new AzureSubscription(
                "subscription-test",
                name),
            result,
            resourceList)
        {
            Status =
                status,

            ErrorMessage =
                errorMessage
        };
    }
}