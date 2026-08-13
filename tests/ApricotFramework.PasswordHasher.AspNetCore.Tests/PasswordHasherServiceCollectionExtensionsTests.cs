using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.AspNetCore.Extensions;
using ApricotFramework.PasswordHasher.AspNetCore.Impl;
using ApricotFramework.PasswordHasher.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ApricotFramework.PasswordHasher.AspNetCore.Tests;

public class PasswordHasherServiceCollectionExtensionsTests
{
    /// <summary>
    /// Builds a configuration from in-memory values.
    /// </summary>
    /// <param name="values">The configuration entries.</param>
    /// <returns>The configuration.</returns>
    private static IConfiguration CreateConfiguration(params (string Key, string Value)[] values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value)))
            .Build();
    }

    [Fact]
    public void AddPasswordHasher_WithConfiguration_ResolvesHasher()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();

        Assert.IsType<OptionsAwarePasswordHasher>(provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void AddPasswordHasher_Always_RegistersHasherAsSingleton()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();

        Assert.Same(provider.GetRequiredService<IPasswordHasher>(), provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void AddPasswordHasher_WithConfiguration_BindsAlgorithmAndIterations()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration(
            ("PasswordHasher:Algorithm", Pbkdf2Sha256Algorithm.AlgorithmName),
            ("PasswordHasher:Iterations", "12345")));

        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<IPasswordHasher>();

        Assert.Equal(Pbkdf2Sha256Algorithm.AlgorithmName, hasher.GetAlgorithm());
        Assert.Equal(12345, hasher.GetIterations());
    }

    [Fact]
    public void AddPasswordHasher_WithCustomSectionName_BindsThatSection()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(
            CreateConfiguration(("Custom:Algorithm", Pbkdf2Sha512Algorithm.LegacyAlgorithmName)),
            "Custom");

        using var provider = services.BuildServiceProvider();

        Assert.Equal(Pbkdf2Sha512Algorithm.LegacyAlgorithmName, provider.GetRequiredService<IPasswordHasher>().GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasher_WithNoConfiguredSection_UsesDefaults()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<IPasswordHasher>();

        Assert.Equal(Pbkdf2Sha512Algorithm.AlgorithmName, hasher.GetAlgorithm());
        Assert.Equal(Pbkdf2Sha512Algorithm.DefaultIterationCount, hasher.GetIterations());
    }

    [Fact]
    public void AddPasswordHasher_WithAction_AppliesSettings()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(options =>
        {
            options.Algorithm = Pbkdf2Sha256Algorithm.AlgorithmName;
            options.Iterations = 20_000;
        });

        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<IPasswordHasher>();

        Assert.Equal(Pbkdf2Sha256Algorithm.AlgorithmName, hasher.GetAlgorithm());
        Assert.Equal(20_000, hasher.GetIterations());
    }

    [Fact]
    public void AddPasswordHasher_Always_RegistersNoAlgorithmsOfItsOwn()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();

        // The built-ins live in the hasher, not the container, so nothing has to be registered
        // and there is no ordering or duplication to get wrong.
        Assert.Empty(provider.GetServices<IPasswordHashAlgorithm>());
    }

    [Fact]
    public void AddPasswordHasher_CalledTwice_StillResolves()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());
        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void AddPasswordHasher_ConsumerRegisteredAlgorithm_IsAddedToTheBuiltIns()
    {
        var services = new ServiceCollection();

        services.AddSingleton<IPasswordHashAlgorithm>(new Pbkdf2Sha512Algorithm("EXTRA"));
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = "EXTRA";
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<IPasswordHasher>();

        Assert.Equal("EXTRA", hasher.GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasher_ConsumerRegisteredAlgorithm_DoesNotDisplaceTheBuiltIns()
    {
        const string LegacyHash = "RFC.100.AAECAwQFBgcICQoLDA0ODw==.0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=";

        var services = new ServiceCollection();

        services.AddSingleton<IPasswordHashAlgorithm>(new Pbkdf2Sha512Algorithm("EXTRA"));
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = "EXTRA";
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider();

        // Registering an algorithm used to silently drop the legacy alias. It no longer can.
        Assert.True(provider.GetRequiredService<IPasswordHasher>().Verify(LegacyHash, "correct horse battery staple").Verified);
    }

    [Fact]
    public void AddPasswordHasher_ConsumerRegisteredHasherFirst_Wins()
    {
        var services = new ServiceCollection();
        var stub = new StubPasswordHasher();

        services.AddSingleton<IPasswordHasher>(stub);
        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();

        Assert.Same(stub, provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void AddPasswordHasher_NullServices_Throws()
    {
        IServiceCollection services = null!;

        Assert.Throws<ArgumentNullException>(() => services.AddPasswordHasher(CreateConfiguration()));
    }

    [Fact]
    public void AddPasswordHasher_NullConfiguration_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => services.AddPasswordHasher((IConfiguration)null!));
    }

    [Fact]
    public void AddPasswordHasher_NullAction_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => services.AddPasswordHasher((Action<PasswordHasherOptions>)null!));
    }

    [Fact]
    public void AddPasswordHasher_BlankSectionName_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddPasswordHasher(CreateConfiguration(), "  "));
    }

    [Fact]
    public void Hasher_ConfigurationReloaded_PicksUpNewIterations()
    {
        var source = new Microsoft.Extensions.Configuration.Memory.MemoryConfigurationSource
        {
            InitialData = [new KeyValuePair<string, string?>("PasswordHasher:Iterations", "11000")],
        };

        var configuration = new ConfigurationBuilder().Add(source).Build();
        var services = new ServiceCollection();

        services.AddPasswordHasher(configuration);

        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<IPasswordHasher>();

        Assert.Equal(11_000, hasher.GetIterations());

        configuration["PasswordHasher:Iterations"] = "12000";
        configuration.Reload();

        // The hasher reads the monitor per operation, so no restart is needed.
        Assert.Equal(12_000, hasher.GetIterations());
    }

    [Fact]
    public void Hasher_ResolvedFromContainer_VerifiesLegacyHashes()
    {
        // The same vector the core tests pin in GoldenVectors, repeated here so the wiring is
        // proven end to end: a container-built hasher must read pre-migration hashes.
        const string LegacyHash = "RFC.100.AAECAwQFBgcICQoLDA0ODw==.0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=";
        const string LegacyPassword = "correct horse battery staple";

        var services = new ServiceCollection();

        services.AddPasswordHasher(CreateConfiguration());

        using var provider = services.BuildServiceProvider();
        var result = provider.GetRequiredService<IPasswordHasher>().Verify(LegacyHash, LegacyPassword);

        Assert.True(result.Verified);
        Assert.True(result.NeedsUpgrade);
    }

    /// <summary>
    /// A hasher that does nothing, used to prove a consumer registration is preferred.
    /// </summary>
    private sealed class StubPasswordHasher : IPasswordHasher
    {
        public string GetAlgorithm()
        {
            return "STUB";
        }

        public int GetIterations()
        {
            return 1;
        }

        public PasswordHash Hash(string password)
        {
            return new PasswordHash { Algorithm = "STUB", Iterations = 1, Salt = "AA==", Key = "AA==" };
        }

        public PasswordCheckResult Verify(string hash, string password)
        {
            return default;
        }
    }
}
