using ApricotFramework.PasswordHasher.Algorithms;

namespace ApricotFramework.PasswordHasher.Tests;

public class PasswordHashTests
{
    [Fact]
    public void AsHash_Always_JoinsFieldsWithDots()
    {
        var hash = new PasswordHash
        {
            Algorithm = Pbkdf2Sha512Algorithm.AlgorithmName,
            Iterations = 210_000,
            Salt = GoldenVectors.SaltSequential,
            Key = GoldenVectors.Sha512At100,
        };

        Assert.Equal(
            $"PBKDF2-SHA512.210000.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}",
            hash.AsHash());
    }

    [Fact]
    public void AsHash_LargeIterationCount_IsNotGroupedByCulture()
    {
        var original = Thread.CurrentThread.CurrentCulture;

        try
        {
            // A culture that groups digits would otherwise emit "210,000" and corrupt the field.
            Thread.CurrentThread.CurrentCulture = new System.Globalization.CultureInfo("de-DE");

            var hash = new PasswordHash
            {
                Algorithm = Pbkdf2Sha512Algorithm.AlgorithmName,
                Iterations = 210_000,
                Salt = GoldenVectors.SaltSequential,
                Key = GoldenVectors.Sha512At100,
            };

            Assert.Contains(".210000.", hash.AsHash(), StringComparison.Ordinal);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = original;
        }
    }

    [Fact]
    public void ToString_Always_MatchesAsHash()
    {
        Assert.True(PasswordHash.TryParse(GoldenVectors.LegacyEncoded, out var hash));

        Assert.Equal(hash!.AsHash(), hash.ToString());
    }

    [Fact]
    public void TryParse_LegacyHash_ReturnsFields()
    {
        var parsed = PasswordHash.TryParse(GoldenVectors.LegacyEncoded, out var hash);

        Assert.True(parsed);
        Assert.Equal(Pbkdf2Sha512Algorithm.LegacyAlgorithmName, hash!.Algorithm);
        Assert.Equal(100, hash.Iterations);
        Assert.Equal(GoldenVectors.SaltSequential, hash.Salt);
        Assert.Equal(GoldenVectors.Sha512At100, hash.Key);
    }

    [Fact]
    public void TryParse_EncodedHash_RoundTrips()
    {
        Assert.True(PasswordHash.TryParse(GoldenVectors.LegacyEncoded, out var hash));

        Assert.Equal(GoldenVectors.LegacyEncoded, hash!.AsHash());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("RFC")]
    [InlineData("RFC.100")]
    [InlineData($"RFC.100.{GoldenVectors.SaltSequential}")]
    [InlineData($".100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.abc.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC..{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.0.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.-100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC. 100.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.100.not-base64!.{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.100.{GoldenVectors.SaltSequential}.not-base64!")]
    [InlineData($"RFC.100..{GoldenVectors.Sha512At100}")]
    [InlineData($"RFC.100.{GoldenVectors.SaltSequential}.")]
    public void TryParse_MalformedInput_ReturnsFalse(string? value)
    {
        var parsed = PasswordHash.TryParse(value, out var hash);

        Assert.False(parsed);
        Assert.Null(hash);
    }

    [Fact]
    public void TryParse_KeyContainingDots_TreatsTrailingFieldAsKey()
    {
        // Base64 never contains a dot, so a fourth field with dots in it is malformed rather
        // than a fifth field. Split with a count of 4 keeps the remainder in the key, where the
        // Base64 check then rejects it.
        var parsed = PasswordHash.TryParse($"RFC.100.{GoldenVectors.SaltSequential}.a.b", out var hash);

        Assert.False(parsed);
        Assert.Null(hash);
    }
}
