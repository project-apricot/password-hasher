namespace ApricotFramework.PasswordHasher.Options;

/// <summary>
/// The settings controlling how new hashes are produced.
/// </summary>
/// <remarks>
/// These affect newly written hashes only. An existing hash is always verified with the
/// algorithm and iteration count recorded inside it, so changing these never invalidates
/// anything already stored — it only makes those hashes report
/// <see cref="PasswordCheckResult.NeedsUpgrade"/>.
/// </remarks>
public sealed class PasswordHasherOptions
{
    /// <summary>
    /// The name of the algorithm to write with. Defaults to
    /// <see cref="Algorithms.PasswordHashAlgorithms.DefaultName"/> when null or whitespace.
    /// </summary>
    /// <remarks>
    /// Set this to <see cref="Algorithms.Pbkdf2Sha512Algorithm.LegacyAlgorithmName"/> while
    /// migrating from an older version of this library whose readers do not recognise the
    /// current name yet.
    /// </remarks>
    public string? Algorithm { get; set; }

    /// <summary>
    /// The iteration count to write with. Defaults to the chosen algorithm's own default when
    /// null.
    /// </summary>
    public int? Iterations { get; set; }
}
