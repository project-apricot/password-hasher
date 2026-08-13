using System.Security.Cryptography;

namespace ApricotFramework.PasswordHasher.Algorithms;

/// <summary>
/// The shared PBKDF2 (RFC 2898) implementation, parameterised by its HMAC.
/// </summary>
public abstract class Pbkdf2Algorithm : IPasswordHashAlgorithm
{
    /// <summary>
    /// The size in bytes of the derived key (256 bit).
    /// </summary>
    private const int KeySize = 32;

    /// <summary>
    /// The HMAC used for key derivation.
    /// </summary>
    private readonly HashAlgorithmName hashAlgorithm;

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public int DefaultIterations { get; }

    /// <summary>
    /// Creates a new PBKDF2 algorithm.
    /// </summary>
    /// <param name="name">The name written into the encoded hash.</param>
    /// <param name="hashAlgorithm">The HMAC to derive with.</param>
    /// <param name="defaultIterations">The iteration count used when none is configured.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is null or whitespace.</exception>
    protected Pbkdf2Algorithm(string name, HashAlgorithmName hashAlgorithm, int defaultIterations)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentOutOfRangeException.ThrowIfLessThan(defaultIterations, 1);

        this.Name = name;
        this.hashAlgorithm = hashAlgorithm;
        this.DefaultIterations = defaultIterations;
    }


    /// <inheritdoc />
    public byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);

        // The static Pbkdf2 method encodes the password as UTF-8, matching the obsolete
        // Rfc2898DeriveBytes constructors it replaces. That is what keeps previously stored
        // hashes verifiable, and it is pinned by the golden-value tests.
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, this.hashAlgorithm, KeySize);
    }
}
