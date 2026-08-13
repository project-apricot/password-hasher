namespace ApricotFramework.PasswordHasher;

/// <summary>
/// The outcome of checking a candidate password against a stored hash.
/// </summary>
/// <remarks>
/// The default value is "not verified", so an early return communicates failure without any
/// explicit construction.
/// </remarks>
public readonly record struct PasswordCheckResult
{
    /// <summary>
    /// Creates a new result.
    /// </summary>
    /// <param name="verified">Whether the candidate's password matched.</param>
    /// <param name="needsUpgrade">Whether the stored hash should be replaced.</param>
    public PasswordCheckResult(bool verified, bool needsUpgrade)
    {
        this.Verified = verified;
        this.NeedsUpgrade = needsUpgrade;
    }

    /// <summary>
    /// Whether the candidate password matched the stored hash.
    /// </summary>
    public bool Verified { get; }

    /// <summary>
    /// Whether the stored hash was produced with parameters that differ from the ones currently
    /// configured and should be rewritten while the plain password is still in hand. Only ever
    /// <see langword="true"/> when <see cref="Verified"/> is <see langword="true"/>.
    /// </summary>
    public bool NeedsUpgrade { get; }
}
