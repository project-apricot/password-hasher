namespace ApricotFramework.PasswordHasher.Algorithms;

/// <summary>
/// A key derivation algorithm the password hasher can write and verify hashes with.
/// </summary>
/// <remarks>
/// A hasher resolves the algorithm for a stored hash by <see cref="Name"/>, so registering an
/// additional implementation adds support for another algorithm without invalidating anything
/// already stored.
/// </remarks>
public interface IPasswordHashAlgorithm
{
    /// <summary>
    /// The name written into the encoded hash, and matched against it on verification.
    /// Matching is case-insensitive and ordinal.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// The iteration count used when none is configured. It is per algorithm because a cheaper
    /// primitive needs more iterations to reach the same cost.
    /// </summary>
    int DefaultIterations { get; }

    /// <summary>
    /// Derives a key from a password and salt.
    /// </summary>
    /// <param name="password">The plain password.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="iterations">The iteration count, which must be positive.</param>
    /// <returns>The derived key. Its length is whatever the algorithm produces.</returns>
    byte[] DeriveKey(string password, byte[] salt, int iterations);
}
