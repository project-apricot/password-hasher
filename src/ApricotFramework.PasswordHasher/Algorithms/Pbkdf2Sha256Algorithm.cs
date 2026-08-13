using System.Security.Cryptography;

namespace ApricotFramework.PasswordHasher.Algorithms;

/// <summary>
/// PBKDF2 with HMAC-SHA256.
/// </summary>
/// <remarks>
/// Offered for interoperability with stores that already use HMAC-SHA256. It needs a higher
/// iteration count than HMAC-SHA512 to reach comparable cost, which is why its default differs.
/// </remarks>
public sealed class Pbkdf2Sha256Algorithm : Pbkdf2Algorithm
{
    /// <summary>
    /// The canonical name of this algorithm.
    /// </summary>
    public const string AlgorithmName = "PBKDF2-SHA256";

    /// <summary>
    /// The iteration count used when none is configured, per OWASP guidance. It is higher than
    /// the HMAC-SHA512 default because each iteration is cheaper.
    /// </summary>
    public const int DefaultIterationCount = 600_000;

    /// <summary>
    /// Creates the algorithm under its canonical name.
    /// </summary>
    public Pbkdf2Sha256Algorithm()
        : this(AlgorithmName)
    {
    }

    /// <summary>
    /// Creates the algorithm under a given name.
    /// </summary>
    /// <param name="name">The name written into the encoded hash.</param>
    public Pbkdf2Sha256Algorithm(string name)
        : base(name, HashAlgorithmName.SHA256, DefaultIterationCount)
    {
    }
}
