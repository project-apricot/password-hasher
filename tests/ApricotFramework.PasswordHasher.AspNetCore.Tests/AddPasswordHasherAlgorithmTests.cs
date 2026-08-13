using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.AspNetCore.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.PasswordHasher.AspNetCore.Tests;

public class AddPasswordHasherAlgorithmTests
{
    /// <summary>
    /// A hash written by an earlier version of the library, used to prove the built-in
    /// algorithms survive whatever else is registered.
    /// </summary>
    private const string LegacyHash = "RFC.100.AAECAwQFBgcICQoLDA0ODw==.0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=";

    /// <summary>
    /// The password behind <see cref="LegacyHash"/>.
    /// </summary>
    private const string LegacyPassword = "correct horse battery staple";

    [Fact]
    public void AddPasswordHasherAlgorithmOfT_Always_MakesItAvailableToTheHasher()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm<NamedAlgorithm>();
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = NamedAlgorithm.AlgorithmName;
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(NamedAlgorithm.AlgorithmName, provider.GetRequiredService<IPasswordHasher>().GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasherAlgorithmOfT_Always_RegistersAsSingleton()
    {
        // The hasher and the validator are singletons, so anything shorter-lived would fail to
        // resolve. validateScopes: true is what would surface that.
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm<NamedAlgorithm>();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IPasswordHashAlgorithm));

        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
    }

    [Fact]
    public void AddPasswordHasherAlgorithmOfT_CalledTwice_RegistersOnce()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm<NamedAlgorithm>();
        services.AddPasswordHasherAlgorithm<NamedAlgorithm>();

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Single(provider.GetServices<IPasswordHashAlgorithm>());
    }

    [Fact]
    public void AddPasswordHasherAlgorithmOfT_Always_InjectsTheAlgorithmsDependencies()
    {
        var services = new ServiceCollection();

        services.AddSingleton(new AlgorithmNameHolder("INJECTED"));
        services.AddPasswordHasherAlgorithm<DependentAlgorithm>();
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = "INJECTED";
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal("INJECTED", provider.GetRequiredService<IPasswordHasher>().GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasherAlgorithm_WithInstance_MakesItAvailableToTheHasher()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm(new Pbkdf2Sha512Algorithm("INSTANCE"));
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = "INSTANCE";
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal("INSTANCE", provider.GetRequiredService<IPasswordHasher>().GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasherAlgorithm_SameTypeUnderTwoNames_KeepsBoth()
    {
        // Deliberately not deduplicated: this is how one implementation serves several names.
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm(new Pbkdf2Sha512Algorithm("ONE"));
        services.AddPasswordHasherAlgorithm(new Pbkdf2Sha512Algorithm("TWO"));

        using var provider = services.BuildServiceProvider(validateScopes: true);
        var names = provider.GetServices<IPasswordHashAlgorithm>().Select(a => a.Name).ToList();

        Assert.Equal(["ONE", "TWO"], names);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddPasswordHasherAlgorithm_EitherRegistrationOrder_Works(bool algorithmFirst)
    {
        // Injected as IEnumerable<T>, which the container resolves once it is built, so the
        // order these two calls are made in cannot matter.
        var services = new ServiceCollection();

        void AddAlgorithm() => services.AddPasswordHasherAlgorithm(new Pbkdf2Sha512Algorithm("EITHER"));
        void AddHasher() => services.AddPasswordHasher(options =>
        {
            options.Algorithm = "EITHER";
            options.Iterations = 10_000;
        });

        if (algorithmFirst)
        {
            AddAlgorithm();
            AddHasher();
        }
        else
        {
            AddHasher();
            AddAlgorithm();
        }

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal("EITHER", provider.GetRequiredService<IPasswordHasher>().GetAlgorithm());
    }

    [Fact]
    public void AddPasswordHasherAlgorithm_Always_LeavesTheBuiltInsIntact()
    {
        var services = new ServiceCollection();

        services.AddPasswordHasherAlgorithm(new Pbkdf2Sha512Algorithm("EXTRA"));
        services.AddPasswordHasher(options =>
        {
            options.Algorithm = "EXTRA";
            options.Iterations = 10_000;
        });

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.True(provider.GetRequiredService<IPasswordHasher>().Verify(LegacyHash, LegacyPassword).Verified);
    }

    [Fact]
    public void AddPasswordHasherAlgorithmOfT_NullServices_Throws()
    {
        IServiceCollection services = null!;

        Assert.Throws<ArgumentNullException>(() => services.AddPasswordHasherAlgorithm<NamedAlgorithm>());
    }

    [Fact]
    public void AddPasswordHasherAlgorithm_NullAlgorithm_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => services.AddPasswordHasherAlgorithm(null!));
    }

    /// <summary>
    /// An algorithm the container can construct with no arguments.
    /// </summary>
    private sealed class NamedAlgorithm : Pbkdf2Algorithm
    {
        public const string AlgorithmName = "NAMED";

        public NamedAlgorithm()
            : base(AlgorithmName, System.Security.Cryptography.HashAlgorithmName.SHA512, 10_000)
        {
        }
    }

    /// <summary>
    /// Carries a name, to prove the container injects an algorithm's dependencies.
    /// </summary>
    /// <param name="Name">The algorithm name to use.</param>
    private sealed record AlgorithmNameHolder(string Name);

    /// <summary>
    /// An algorithm whose name comes from an injected dependency.
    /// </summary>
    private sealed class DependentAlgorithm : Pbkdf2Algorithm
    {
        public DependentAlgorithm(AlgorithmNameHolder holder)
            : base(holder.Name, System.Security.Cryptography.HashAlgorithmName.SHA512, 10_000)
        {
        }
    }
}
