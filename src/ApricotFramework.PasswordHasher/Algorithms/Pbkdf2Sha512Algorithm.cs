using System.Security.Cryptography;

namespace ApricotFramework.PasswordHasher.Algorithms;

/// <summary>
/// PBKDF2 with HMAC-SHA512.
/// </summary>
/// <remarks>
/// The name is settable so the same algorithm can also be registered under
/// <see cref="LegacyAlgorithmName"/>, which is what earlier versions of this library wrote.
/// Both names denote identical parameters and produce identical keys.
/// </remarks>
public sealed class Pbkdf2Sha512Algorithm : Pbkdf2Algorithm
{
    /// <summary>
    /// The canonical name of this algorithm.
    /// </summary>
    public const string AlgorithmName = "PBKDF2-SHA512";

    /// <summary>
    /// The name earlier versions of this library wrote for this same algorithm. Hashes carrying
    /// it are still verified, which is what keeps a pre-existing store working.
    /// </summary>
    public const string LegacyAlgorithmName = "RFC";

    /// <summary>
    /// The iteration count used when none is configured, per OWASP guidance.
    /// </summary>
    public const int DefaultIterationCount = 210_000;

    /// <summary>
    /// Creates the algorithm under its canonical name.
    /// </summary>
    public Pbkdf2Sha512Algorithm()
        : this(AlgorithmName)
    {
    }

    /// <summary>
    /// Creates the algorithm under a given name.
    /// </summary>
    /// <param name="name">The name written into the encoded hash.</param>
    public Pbkdf2Sha512Algorithm(string name)
        : base(name, HashAlgorithmName.SHA512, DefaultIterationCount)
    {
    }
}
