using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Impl;
using ApricotFramework.PasswordHasher.Options;

namespace ApricotFramework.PasswordHasher.Tests;

/// <summary>
/// An algorithm name has to survive a round trip through the encoded hash format. A name
/// carrying the field separator would shift every field, so the hash would write successfully
/// and then never parse back — silent, permanent data loss.
/// </summary>
public class AlgorithmNameValidationTests
{
    [Theory]
    [InlineData("MY.ALG")]
    [InlineData(".LEADING")]
    [InlineData("TRAILING.")]
    [InlineData(".")]
    public void Compose_AdditionalNameContainsSeparator_Throws(string name)
    {
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha512Algorithm(name)];

        var exception = Assert.Throws<ArgumentException>(() => PasswordHashAlgorithms.Compose(additional));

        Assert.Contains(name, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Constructor_AdditionalNameContainsSeparator_Throws()
    {
        // The hasher composes on construction, so the failure lands at wire-up rather than at
        // the first login.
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha512Algorithm("MY.ALG")];

        Assert.Throws<ArgumentException>(() => new DefaultPasswordHasher(null, additional));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Compose_AdditionalNameIsBlank_Throws(string name)
    {
        IPasswordHashAlgorithm[] additional = [new BlankNamedAlgorithm(name)];

        Assert.Throws<ArgumentException>(() => PasswordHashAlgorithms.Compose(additional));
    }

    [Fact]
    public void Compose_AdditionalIsNull_Throws()
    {
        IPasswordHashAlgorithm[] additional = [null!];

        Assert.Throws<ArgumentNullException>(() => PasswordHashAlgorithms.Compose(additional));
    }

    [Theory]
    [InlineData("MY-ALG")]
    [InlineData("MY_ALG")]
    [InlineData("PBKDF2-SHA512-64")]
    [InlineData("argon2id")]
    public void Compose_AcceptableName_RoundTripsThroughTheEncodedForm(string name)
    {
        IPasswordHashAlgorithm[] additional = [new Pbkdf2Sha512Algorithm(name)];

        var hasher = new DefaultPasswordHasher(
            new PasswordHasherOptions { Algorithm = name, Iterations = 1000 },
            additional);

        var written = hasher.Hash(GoldenVectors.Password).AsHash();

        Assert.True(hasher.Verify(written, GoldenVectors.Password).Verified);
    }

    [Fact]
    public void Compose_BuiltInNames_ContainNoSeparator()
    {
        foreach (var algorithm in PasswordHashAlgorithms.BuiltIn())
        {
            Assert.DoesNotContain('.', algorithm.Name);
        }
    }

    /// <summary>
    /// An algorithm that reports whatever name it is given, including a blank one.
    /// </summary>
    /// <param name="name">The name to report.</param>
    private sealed class BlankNamedAlgorithm(string name) : IPasswordHashAlgorithm
    {
        public string Name => name;

        public int DefaultIterations => 1000;

        public byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            return new byte[32];
        }
    }
}
