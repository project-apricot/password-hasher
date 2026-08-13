using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Impl;
using ApricotFramework.PasswordHasher.Options;

namespace ApricotFramework.PasswordHasher.Tests;

/// <summary>
/// Verification re-derives at whatever iteration count the stored hash carries. Without a
/// ceiling, a corrupted or tampered row would pin a CPU for minutes on a single login attempt,
/// so the format refuses an absurd count and the write path refuses to produce one.
/// </summary>
public class IterationCeilingTests
{
    /// <summary>
    /// Builds an encoded hash carrying an arbitrary iteration count.
    /// </summary>
    /// <param name="iterations">The count to embed.</param>
    /// <returns>The encoded hash.</returns>
    private static string EncodedWith(long iterations)
    {
        return $"{Pbkdf2Sha512Algorithm.AlgorithmName}.{iterations}.{GoldenVectors.SaltSequential}.{GoldenVectors.Sha512At100}";
    }

    [Fact]
    public void TryParse_IterationsAtTheCeiling_Succeeds()
    {
        Assert.True(PasswordHash.TryParse(EncodedWith(PasswordHash.MaximumIterations), out _));
    }

    [Theory]
    [InlineData(1L)]
    [InlineData(1000L)]
    public void TryParse_IterationsAboveTheCeiling_Fails(long over)
    {
        var parsed = PasswordHash.TryParse(EncodedWith(PasswordHash.MaximumIterations + over), out var hash);

        Assert.False(parsed);
        Assert.Null(hash);
    }

    [Fact]
    public void TryParse_IntMaxValueIterations_Fails()
    {
        Assert.False(PasswordHash.TryParse(EncodedWith(int.MaxValue), out _));
    }

    [Fact]
    public void Verify_StoredIterationsAboveTheCeiling_ReturnsNotVerifiedPromptly()
    {
        // The point of the ceiling: this must return, not grind through two billion rounds.
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Iterations = 1000 });

        var started = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.Verify(EncodedWith(int.MaxValue), GoldenVectors.Password);
        started.Stop();

        Assert.False(result.Verified);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"took {started.Elapsed}");
    }

    [Fact]
    public void Hash_ConfiguredAboveTheCeiling_Throws()
    {
        // Writing a hash nothing could read back is worse than refusing to write it.
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Iterations = PasswordHash.MaximumIterations + 1 });

        var exception = Assert.Throws<InvalidOperationException>(() => hasher.Hash(GoldenVectors.Password));

        Assert.Contains("could not be read back", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetIterations_ConfiguredAboveTheCeiling_Throws()
    {
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Iterations = PasswordHash.MaximumIterations + 1 });

        Assert.Throws<InvalidOperationException>(() => hasher.GetIterations());
    }

    [Fact]
    public void Verify_ConfiguredAboveTheCeiling_StillVerifiesExistingHashes()
    {
        // Verification stays tolerant of a broken configuration, so a misconfigured host keeps
        // authenticating existing users rather than failing every login.
        var hasher = new DefaultPasswordHasher(new PasswordHasherOptions { Iterations = PasswordHash.MaximumIterations + 1 });

        var result = hasher.Verify(GoldenVectors.LegacyEncoded, GoldenVectors.Password);

        Assert.True(result.Verified);
        Assert.True(result.NeedsUpgrade);
    }

    [Fact]
    public void MaximumIterations_LeavesHeadroomOverPublishedGuidance()
    {
        // The highest current OWASP figure is 600,000, for PBKDF2-HMAC-SHA256. The ceiling must
        // stay well clear of it so no realistic configuration ever brushes against it.
        Assert.True(PasswordHash.MaximumIterations >= 600_000 * 10);
    }
}
