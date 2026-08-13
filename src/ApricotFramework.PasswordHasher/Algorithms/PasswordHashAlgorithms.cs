namespace ApricotFramework.PasswordHasher.Algorithms;

/// <summary>
/// The algorithms hasher understands.
/// </summary>
public static class PasswordHashAlgorithms
{
    /// <summary>
    /// The algorithm used when none is configured.
    /// </summary>
    public const string DefaultName = Pbkdf2Sha512Algorithm.AlgorithmName;

    /// <summary>
    /// The algorithms every hasher supports, without any registration.
    /// </summary>
    /// <returns>
    /// PBKDF2-SHA512, the same algorithm under its legacy name, and PBKDF2-SHA256.
    /// </returns>
    /// <remarks>
    /// These are always present. That is deliberate: it means no registration mistake can stop
    /// a previously written hash from verifying.
    /// </remarks>
    public static IReadOnlyList<IPasswordHashAlgorithm> BuiltIn()
    {
        return
        [
            new Pbkdf2Sha512Algorithm(),
            new Pbkdf2Sha512Algorithm(Pbkdf2Sha512Algorithm.LegacyAlgorithmName),
            new Pbkdf2Sha256Algorithm(),
        ];
    }

    /// <summary>
    /// Builds the lookup a hasher verifies against: the built-in algorithms, plus any extras.
    /// </summary>
    /// <param name="additional">Extra algorithms to support, or null for none.</param>
    /// <returns>The algorithms keyed by name, matched case-insensitively.</returns>
    /// <remarks>
    /// An extra sharing a name with a built-in replaces it, which is the only way to swap out a
    /// built-in implementation. Among the extras themselves, the last one registered wins.
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// An extra has a name that is blank, or that contains the character separating the fields
    /// of an encoded hash.
    /// </exception>
    public static IReadOnlyDictionary<string, IPasswordHashAlgorithm> Compose(IEnumerable<IPasswordHashAlgorithm>? additional)
    {
        var map = new Dictionary<string, IPasswordHashAlgorithm>(StringComparer.OrdinalIgnoreCase);

        foreach (var algorithm in BuiltIn())
        {
            map[algorithm.Name] = algorithm;
        }

        foreach (var algorithm in additional ?? [])
        {
            ArgumentNullException.ThrowIfNull(algorithm, nameof(additional));

            map[ValidateName(algorithm.Name, nameof(additional))] = algorithm;
        }

        return map;
    }

    /// <summary>
    /// Checks that a name can survive a round trip through the encoded hash format.
    /// </summary>
    /// <param name="name">The algorithm name to check.</param>
    /// <param name="paramName">The parameter the algorithm arrived through.</param>
    /// <returns>The name.</returns>
    /// <exception cref="ArgumentException">The name is blank or contains the field separator.</exception>
    /// <remarks>
    /// A name containing the separator would shift every field of the encoded hash, so the hash
    /// would write successfully and then never parse back. Rejecting it here turns silent,
    /// permanent data loss into an error at construction.
    /// </remarks>
    private static string ValidateName(string name, string paramName)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("A password hashing algorithm must have a name.", paramName);
        }

        if (name.Contains(PasswordHash.FieldSeparator, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Password hashing algorithm name '{name}' contains '{PasswordHash.FieldSeparator}', which separates the fields of an encoded hash. A hash written under this name could never be read back.",
                paramName);
        }

        return name;
    }
}
