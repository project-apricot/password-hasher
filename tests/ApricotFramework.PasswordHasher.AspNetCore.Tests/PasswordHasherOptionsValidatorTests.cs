using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.AspNetCore.Extensions;
using ApricotFramework.PasswordHasher.AspNetCore.Validation;
using ApricotFramework.PasswordHasher.Impl;
using ApricotFramework.PasswordHasher.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ApricotFramework.PasswordHasher.AspNetCore.Tests;

public class PasswordHasherOptionsValidatorTests
{
    /// <summary>
    /// Builds a validator over the built-in algorithms.
    /// </summary>
    /// <returns>The validator.</returns>
    private static PasswordHasherOptionsValidator CreateValidator()
    {
        return new PasswordHasherOptionsValidator(null);
    }

    [Fact]
    public void Validate_NothingConfigured_Succeeds()
    {
        var result = CreateValidator().Validate(null, new PasswordHasherOptions());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_IterationsExactlyAtMinimum_Succeeds()
    {
        var options = new PasswordHasherOptions { Iterations = PasswordHasherOptionsValidator.MinimumIterations };

        Assert.True(CreateValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_IterationsOneBelowMinimum_Fails()
    {
        var options = new PasswordHasherOptions { Iterations = PasswordHasherOptionsValidator.MinimumIterations - 1 };

        Assert.True(CreateValidator().Validate(null, options).Failed);
    }

    [Theory]
    [InlineData(100)]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WeakOrNonPositiveIterations_Fails(int iterations)
    {
        var options = new PasswordHasherOptions { Iterations = iterations };

        Assert.True(CreateValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Validate_NonPositiveIterations_ExplainsThatItMustBePositive()
    {
        var result = CreateValidator().Validate(null, new PasswordHasherOptions { Iterations = 0 });

        Assert.Contains("must be positive", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WeakIterations_SaysExistingHashesAreUnaffected()
    {
        var result = CreateValidator().Validate(null, new PasswordHasherOptions { Iterations = 100 });

        Assert.Contains("Existing hashes are unaffected", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_IterationsExactlyAtMaximum_Succeeds()
    {
        var options = new PasswordHasherOptions { Iterations = PasswordHash.MaximumIterations };

        Assert.True(CreateValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_IterationsAboveMaximum_Fails()
    {
        // The validator's ceiling must match the format's, or a configuration could pass
        // startup and then write hashes that cannot be read back.
        var options = new PasswordHasherOptions { Iterations = PasswordHash.MaximumIterations + 1 };

        var result = CreateValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("could not be read back", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AnyAcceptedIterationCount_ProducesAReadableHash()
    {
        // Ties the two bounds together: whatever the validator accepts, the format must parse.
        foreach (var iterations in new[] { PasswordHasherOptionsValidator.MinimumIterations, 210_000, PasswordHash.MaximumIterations })
        {
            var options = new PasswordHasherOptions { Iterations = iterations };

            Assert.True(CreateValidator().Validate(null, options).Succeeded, $"rejected {iterations}");
            Assert.True(
                PasswordHash.TryParse($"PBKDF2-SHA512.{iterations}.AAECAwQFBgcICQoLDA0ODw==.0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=", out _),
                $"unreadable at {iterations}");
        }
    }

    [Fact]
    public void Validate_UnregisteredAlgorithm_Fails()
    {
        var result = CreateValidator().Validate(null, new PasswordHasherOptions { Algorithm = "nope" });

        Assert.True(result.Failed);
        Assert.Contains("nope", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(Pbkdf2Sha512Algorithm.AlgorithmName)]
    [InlineData(Pbkdf2Sha256Algorithm.AlgorithmName)]
    [InlineData(Pbkdf2Sha512Algorithm.LegacyAlgorithmName)]
    [InlineData("rfc")]
    public void Validate_RegisteredAlgorithm_Succeeds(string algorithm)
    {
        var options = new PasswordHasherOptions { Algorithm = algorithm };

        Assert.True(CreateValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_AdditionalAlgorithm_IsAcceptedByName()
    {
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha512Algorithm("CUSTOM")];
        var validator = new PasswordHasherOptionsValidator(additional);

        var options = new PasswordHasherOptions { Algorithm = "CUSTOM" };

        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_AdditionalAlgorithmSupplied_StillAcceptsTheBuiltIns()
    {
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha512Algorithm("CUSTOM")];
        var validator = new PasswordHasherOptionsValidator(additional);

        var options = new PasswordHasherOptions { Algorithm = Pbkdf2Sha512Algorithm.LegacyAlgorithmName };

        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Options_ResolvedWithWeakIterations_ThrowsOnAccess()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(options => options.Iterations = 100);

        using var provider = services.BuildServiceProvider();
        var monitor = provider.GetRequiredService<IOptions<PasswordHasherOptions>>();

        Assert.Throws<OptionsValidationException>(() => monitor.Value);
    }

    [Fact]
    public void Options_ResolvedWithValidIterations_DoesNotThrow()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(options => options.Iterations = 15_000);

        using var provider = services.BuildServiceProvider();

        Assert.Equal(15_000, provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.Iterations);
    }

}
