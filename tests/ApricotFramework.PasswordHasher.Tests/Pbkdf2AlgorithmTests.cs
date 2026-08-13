using ApricotFramework.PasswordHasher.Algorithms;

namespace ApricotFramework.PasswordHasher.Tests;

public class Pbkdf2AlgorithmTests
{
    [Theory]
    [InlineData(GoldenVectors.Password, GoldenVectors.SaltSequential, 100, GoldenVectors.Sha512At100)]
    [InlineData(GoldenVectors.PasswordUnicode, GoldenVectors.SaltRepeated, 100, GoldenVectors.Sha512At100Unicode)]
    [InlineData("", GoldenVectors.SaltSequential, 100, GoldenVectors.Sha512At100Empty)]
    [InlineData(GoldenVectors.Password, GoldenVectors.SaltSequential, 1000, GoldenVectors.Sha512At1000)]
    public void DeriveKey_Sha512KnownVector_MatchesGoldenValue(string password, string salt, int iterations, string expected)
    {
        var algorithm = new Pbkdf2Sha512Algorithm();

        var key = algorithm.DeriveKey(password, Convert.FromBase64String(salt), iterations);

        Assert.Equal(expected, Convert.ToBase64String(key));
    }

    [Theory]
    [InlineData(GoldenVectors.Password, GoldenVectors.SaltSequential, 1000, GoldenVectors.Sha256At1000)]
    public void DeriveKey_Sha256KnownVector_MatchesGoldenValue(string password, string salt, int iterations, string expected)
    {
        var algorithm = new Pbkdf2Sha256Algorithm();

        var key = algorithm.DeriveKey(password, Convert.FromBase64String(salt), iterations);

        Assert.Equal(expected, Convert.ToBase64String(key));
    }

    [Fact]
    public void DeriveKey_LegacyName_ProducesSameKeyAsCanonicalName()
    {
        var salt = Convert.FromBase64String(GoldenVectors.SaltSequential);

        var canonical = new Pbkdf2Sha512Algorithm().DeriveKey(GoldenVectors.Password, salt, 100);
        var legacy = new Pbkdf2Sha512Algorithm(Pbkdf2Sha512Algorithm.LegacyAlgorithmName).DeriveKey(GoldenVectors.Password, salt, 100);

        Assert.Equal(canonical, legacy);
    }

    [Fact]
    public void DeriveKey_Sha256AndSha512_ProduceDifferentKeys()
    {
        var salt = Convert.FromBase64String(GoldenVectors.SaltSequential);

        var sha512 = new Pbkdf2Sha512Algorithm().DeriveKey(GoldenVectors.Password, salt, 1000);
        var sha256 = new Pbkdf2Sha256Algorithm().DeriveKey(GoldenVectors.Password, salt, 1000);

        Assert.NotEqual(sha512, sha256);
    }

    [Theory]
    [InlineData(typeof(Pbkdf2Sha512Algorithm))]
    [InlineData(typeof(Pbkdf2Sha256Algorithm))]
    public void DeriveKey_Always_Returns32Bytes(Type algorithmType)
    {
        // 32 bytes is pinned, not merely current. A stored key is compared against a freshly
        // derived one, and a length mismatch fails that comparison, so changing this would
        // invalidate every hash already written under these names.
        var algorithm = (IPasswordHashAlgorithm)Activator.CreateInstance(algorithmType)!;

        var key = algorithm.DeriveKey(GoldenVectors.Password, Convert.FromBase64String(GoldenVectors.SaltSequential), 100);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void DeriveKey_NullPassword_Throws()
    {
        var algorithm = new Pbkdf2Sha512Algorithm();

        Assert.Throws<ArgumentNullException>(() => algorithm.DeriveKey(null!, [1, 2, 3], 100));
    }

    [Fact]
    public void DeriveKey_NullSalt_Throws()
    {
        var algorithm = new Pbkdf2Sha512Algorithm();

        Assert.Throws<ArgumentNullException>(() => algorithm.DeriveKey(GoldenVectors.Password, null!, 100));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DeriveKey_NonPositiveIterations_Throws(int iterations)
    {
        var algorithm = new Pbkdf2Sha512Algorithm();

        Assert.Throws<ArgumentOutOfRangeException>(() => algorithm.DeriveKey(GoldenVectors.Password, [1, 2, 3], iterations));
    }

    [Fact]
    public void Constructor_WhitespaceName_Throws()
    {
        Assert.Throws<ArgumentException>(() => new Pbkdf2Sha512Algorithm("  "));
    }

    [Fact]
    public void Sha512_Defaults_MatchOwaspGuidance()
    {
        var algorithm = new Pbkdf2Sha512Algorithm();

        Assert.Equal(Pbkdf2Sha512Algorithm.AlgorithmName, algorithm.Name);
        Assert.Equal(210_000, algorithm.DefaultIterations);
    }

    [Fact]
    public void Sha256_Defaults_MatchOwaspGuidance()
    {
        var algorithm = new Pbkdf2Sha256Algorithm();

        Assert.Equal(Pbkdf2Sha256Algorithm.AlgorithmName, algorithm.Name);
        Assert.Equal(600_000, algorithm.DefaultIterations);
    }
}
