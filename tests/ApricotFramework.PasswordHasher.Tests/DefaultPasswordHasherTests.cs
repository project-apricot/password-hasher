using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Impl;
using ApricotFramework.PasswordHasher.Options;

namespace ApricotFramework.PasswordHasher.Tests;

public class DefaultPasswordHasherTests
{
    /// <summary>
    /// Builds a hasher whose cost is low enough to run in a test.
    /// </summary>
    /// <param name="algorithm">The algorithm to write with, or null for the default.</param>
    /// <param name="iterations">The iteration count to write with.</param>
    /// <returns>The hasher.</returns>
    private static DefaultPasswordHasher CreateHasher(string? algorithm = null, int iterations = 1000)
    {
        return new DefaultPasswordHasher(new PasswordHasherOptions { Algorithm = algorithm, Iterations = iterations });
    }

    // --- backward compatibility with hashes written before the migration ---

    [Fact]
    public void Verify_LegacyRfcHash_ReturnsVerified()
    {
        var result = CreateHasher().Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password);

        Assert.True(result.Verified);
    }

    [Fact]
    public void Verify_LegacyRfcHash_ReportsNeedsUpgrade()
    {
        var result = CreateHasher().Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password);

        Assert.True(result.NeedsUpgrade);
    }

    [Fact]
    public void Verify_LegacyRfcHashWithUnicodePassword_ReturnsVerified()
    {
        var hash = $"RFC.100.{GoldenVectors.SaltRepeated}.{GoldenVectors.Sha512At100Unicode}";

        var result = CreateHasher().Verify(hash, GoldenVectors.PasswordUnicode);

        Assert.True(result.Verified);
    }

    [Fact]
    public void Verify_LegacyRfcHashWithEmptyPassword_ReturnsVerified()
    {
        var hash = $"RFC.100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100Empty}";

        var result = CreateHasher().Verify(hash, string.Empty);

        Assert.True(result.Verified);
    }

    [Fact]
    public void Verify_LegacyRfcHash_IsCaseInsensitiveOnAlgorithmName()
    {
        var hash = $"rfc.100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}";

        var result = CreateHasher().Verify(hash, GoldenVectors.Password);

        Assert.True(result.Verified);
    }

    // --- verification ---

    [Fact]
    public void Verify_WrongPassword_ReturnsNotVerified()
    {
        var result = CreateHasher().Verify(GoldenVectors.LegacyEncoded, "not the password");

        Assert.False(result.Verified);
    }

    [Fact]
    public void Verify_WrongPassword_DoesNotReportNeedsUpgrade()
    {
        // An upgrade signal is only meaningful alongside a successful check; reporting it on
        // failure would tell a caller something about a hash they did not authenticate against.
        var result = CreateHasher().Verify(GoldenVectors.LegacyEncoded, "not the password");

        Assert.False(result.NeedsUpgrade);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("RFC.100")]
    [InlineData($"RFC.abc.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.0.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.-5.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.100.not-base64!.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.100.{GoldenVectors.SaltSequential}.not-base64!")]
    public void Verify_MalformedStoredHash_ReturnsNotVerifiedWithoutThrowing(string hash)
    {
        // A corrupted or truncated database value must fail the login, not crash it.
        var result = CreateHasher().Verify(hash, GoldenVectors.Password);

        Assert.False(result.Verified);
    }

    [Fact]
    public void Verify_UnregisteredAlgorithm_ReturnsNotVerified()
    {
        var hash = $"NOPE.100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}";

        var result = CreateHasher().Verify(hash, GoldenVectors.Password);

        Assert.False(result.Verified);
    }

    [Fact]
    public void Verify_Sha256HashWhileSha512Configured_VerifiesAndNeedsUpgrade()
    {
        var hash = $"{Pbkdf2Sha256Algorithm.AlgorithmName}.1000.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha256At1000}";

        var result = CreateHasher(Pbkdf2Sha512Algorithm.AlgorithmName).Verify(hash, GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.True(result.NeedsUpgrade);
    }

    [Fact]
    public void Verify_MatchingAlgorithmAndIterations_DoesNotNeedUpgrade()
    {
        var hash = $"{Pbkdf2Sha512Algorithm.AlgorithmName}.1000.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At1000}";

        var result = CreateHasher(Pbkdf2Sha512Algorithm.AlgorithmName).Verify(hash, GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.False(result.NeedsUpgrade);
    }

    [Fact]
    public void Verify_SameAlgorithmDifferentIterations_NeedsUpgrade()
    {
        var hash = $"{Pbkdf2Sha512Algorithm.AlgorithmName}.1000.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At1000}";

        var result = CreateHasher(Pbkdf2Sha512Algorithm.AlgorithmName, iterations: 2000).Verify(hash, GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.True(result.NeedsUpgrade);
    }

    [Fact]
    public void Verify_ConfiguredAlgorithmUnregistered_StillVerifiesAndNeedsUpgrade()
    {
        // Verification depends only on the parameters inside the stored hash, so a host whose
        // configuration is broken still authenticates instead of failing every login.
        var hasher = CreateHasher("does-not-exist");

        var result = hasher.Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.True(result.NeedsUpgrade);
    }

    [Fact]
    public void Verify_NullHash_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateHasher().Verify(null!, GoldenVectors.Password));
    }

    [Fact]
    public void Verify_NullPassword_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateHasher().Verify(GoldenVectors.LegacyEncoded, null!));
    }

    // --- hashing ---

    [Fact]
    public void Hash_ThenVerify_RoundTrips()
    {
        var hasher = CreateHasher();

        var hash = hasher.Hash(GoldenVectors.Password);
        var result = hasher.Verify(hash.AsHash(), GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.False(result.NeedsUpgrade);
    }

    [Fact]
    public void Hash_SamePasswordTwice_ProducesDifferentSalts()
    {
        var hasher = CreateHasher();

        var first = hasher.Hash(GoldenVectors.Password);
        var second = hasher.Hash(GoldenVectors.Password);

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.NotEqual(first.Key, second.Key);
    }

    [Fact]
    public void Hash_Always_WritesConfiguredAlgorithmAndIterations()
    {
        var hash = CreateHasher(Pbkdf2Sha256Algorithm.AlgorithmName, iterations: 1500).Hash(GoldenVectors.Password);

        Assert.Equal(Pbkdf2Sha256Algorithm.AlgorithmName, hash.Algorithm);
        Assert.Equal(1500, hash.Iterations);
    }

    [Fact]
    public void Hash_LegacyAlgorithmConfigured_WritesLegacyToken()
    {
        // The documented escape hatch for a rolling upgrade, where older readers are still live.
        var hash = CreateHasher(Pbkdf2Sha512Algorithm.LegacyAlgorithmName).Hash(GoldenVectors.Password);

        Assert.StartsWith("RFC.", hash.AsHash(), StringComparison.Ordinal);
    }

    [Fact]
    public void Hash_LegacyAlgorithmConfigured_IsVerifiableAsSha512()
    {
        var hasher = CreateHasher(Pbkdf2Sha512Algorithm.LegacyAlgorithmName);

        var written = hasher.Hash(GoldenVectors.Password);
        var reinterpreted = $"{Pbkdf2Sha512Algorithm.AlgorithmName}.{written.Iterations}.{written.Salt}.{written.Key}";

        // Same bytes under either name, which is what makes the legacy alias safe.
        Assert.True(CreateHasher().Verify(reinterpreted, GoldenVectors.Password).Verified);
    }

    [Fact]
    public void Hash_NullPassword_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateHasher().Hash(null!));
    }

    [Fact]
    public void Hash_UnregisteredAlgorithmConfigured_Throws()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => CreateHasher("does-not-exist").Hash(GoldenVectors.Password));

        Assert.Contains("does-not-exist", exception.Message, StringComparison.Ordinal);
    }

    // --- parameter resolution ---

    [Fact]
    public void Algorithm_NothingConfigured_IsSha512()
    {
        var hasher = new DefaultPasswordHasher();

        Assert.Equal(Pbkdf2Sha512Algorithm.AlgorithmName, hasher.GetAlgorithm());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Algorithm_BlankConfigured_FallsBackToDefault(string? configured)
    {
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Algorithm = configured });

        Assert.Equal(Pbkdf2Sha512Algorithm.AlgorithmName, hasher.GetAlgorithm());
    }

    [Fact]
    public void Iterations_NothingConfigured_UsesSha512AlgorithmDefault()
    {
        var hasher = new DefaultPasswordHasher();

        Assert.Equal(Pbkdf2Sha512Algorithm.DefaultIterationCount, hasher.GetIterations());
    }

    [Fact]
    public void Iterations_Sha256WithoutExplicitCount_UsesItsOwnHigherDefault()
    {
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Algorithm = Pbkdf2Sha256Algorithm.AlgorithmName });

        Assert.Equal(Pbkdf2Sha256Algorithm.DefaultIterationCount, hasher.GetIterations());
    }

    [Fact]
    public void Algorithm_UnregisteredConfigured_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => CreateHasher("does-not-exist").GetAlgorithm());
    }

    // --- registration ---

    [Fact]
    public void BuiltIn_Always_ContainsBothPbkdf2NamesAndTheLegacyAlias()
    {
        var names = PasswordHashAlgorithms.BuiltIn().Select(a => a.Name).ToList();

        Assert.Contains(Pbkdf2Sha512Algorithm.AlgorithmName, names);
        Assert.Contains(Pbkdf2Sha256Algorithm.AlgorithmName, names);
        Assert.Contains(Pbkdf2Sha512Algorithm.LegacyAlgorithmName, names);
    }

    [Fact]
    public void Verify_NoAlgorithmsSupplied_StillVerifiesWithTheBuiltIns()
    {
        // The built-ins need no registration, so an empty list cannot switch off backward
        // compatibility.
        var hasher = new DefaultPasswordHasher(null, []);

        Assert.True(hasher.Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password).Verified);
    }

    [Fact]
    public void Verify_AdditionalAlgorithmSharingABuiltInName_ReplacesIt()
    {
        // The one way to swap out a built-in implementation: register the same name.
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha256Algorithm(Pbkdf2Sha512Algorithm.LegacyAlgorithmName)];

        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Iterations = 1000 }, additional);

        // The legacy hash was written with SHA-512, so the replacement no longer verifies it.
        Assert.False(hasher.Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password).Verified);
    }

    [Fact]
    public void Verify_DuplicateAdditionalNames_LastOneWins()
    {
        IPasswordHashAlgorithm[] additional =
        [
            new Pbkdf2Sha256Algorithm("DUP"),
            new Pbkdf2Sha512Algorithm("DUP"),
        ];

        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Algorithm = "DUP", Iterations = 1000 }, additional);

        var written = hasher.Hash(GoldenVectors.Password);
        var asSha512 = $"{Pbkdf2Sha512Algorithm.AlgorithmName}.{written.Iterations}.{written.Salt}.{written.Key}";

        Assert.True(new DefaultPasswordHasher().Verify(asSha512, GoldenVectors.Password).Verified);
    }

    [Fact]
    public void Verify_CustomAlgorithmRegistered_IsUsedForItsOwnHashes()
    {
        // Proves a new algorithm is additive: it does not have to restate the built-ins, and
        // registering it cannot invalidate anything already stored.
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha256Algorithm("CUSTOM")];

        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Algorithm = "CUSTOM", Iterations = 1000 }, additional);

        var written = hasher.Hash(GoldenVectors.Password);

        Assert.Equal("CUSTOM", written.Algorithm);
        Assert.True(hasher.Verify(written.AsHash(), GoldenVectors.Password).Verified);
        Assert.True(hasher.Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password).Verified);
    }
}
