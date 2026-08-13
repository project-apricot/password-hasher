namespace ApricotFramework.PasswordHasher;

/// <summary>
/// A password hash together with the parameters needed to reproduce it.
/// </summary>
/// <remarks>
/// The encoded form is <c>{algorithm}.{iterations}.{salt}.{key}</c>, where the salt and key are
/// standard Base64. Base64 never contains a <c>.</c>, so the fields are unambiguous. This shape
/// is a compatibility contract: it is what consumers persist, so it does not change outside a
/// major version.
/// </remarks>
public sealed record PasswordHash
{
    /// <summary>
    /// Separates the fields of an encoded hash. Base64 never contains it, so the fields stay
    /// unambiguous.
    /// </summary>
    internal const char FieldSeparator = '.';

    /// <summary>
    /// The highest iteration count an encoded hash may carry. A stored value above this is
    /// treated as malformed.
    /// </summary>
    /// <remarks>
    /// Verification re-derives at whatever count the stored hash carries, so without a ceiling a
    /// corrupted or tampered row could pin a CPU for minutes. This bound is roughly sixteen
    /// times the highest published recommendation, so no realistic configuration approaches it,
    /// while capping the work one verification can cost.
    /// </remarks>
    public const int MaximumIterations = 10_000_000;

    /// <summary>
    /// The name of the algorithm that produced <see cref="Key"/>.
    /// </summary>
    public required string Algorithm { get; init; }

    /// <summary>
    /// The iteration count that produced <see cref="Key"/>.
    /// </summary>
    public required int Iterations { get; init; }

    /// <summary>
    /// The Base64-encoded salt.
    /// </summary>
    public required string Salt { get; init; }

    /// <summary>
    /// The Base64-encoded derived key.
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// Builds the encoded form that is meant to be persisted.
    /// </summary>
    /// <returns>The encoded hash.</returns>
    public string AsHash()
    {
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{this.Algorithm}{FieldSeparator}{this.Iterations}{FieldSeparator}{this.Salt}{FieldSeparator}{this.Key}");
    }

    /// <summary>
    /// Gets the encoded form, identical to <see cref="AsHash"/>.
    /// </summary>
    /// <returns>The encoded hash.</returns>
    public override string ToString()
    {
        return this.AsHash();
    }

    /// <summary>
    /// Attempts to parse an encoded hash.
    /// </summary>
    /// <param name="value">The encoded hash to parse.</param>
    /// <param name="result">The parsed hash, or <see langword="null"/> when parsing failed.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a well-formed encoded hash.</returns>
    /// <remarks>
    /// This never throws. A stored hash can be truncated or corrupted, and that must surface as
    /// a failed verification rather than as an exception on the caller's login path.
    /// </remarks>
    public static bool TryParse(string? value, out PasswordHash? result)
    {
        result = null;

        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var parts = value.Split(FieldSeparator, 4);

        if (parts.Length != 4 || parts[0].Length == 0)
        {
            return false;
        }

        // An iteration count that is absent, non-numeric or non-positive cannot be fed to a key
        // derivation function, so the hash is unusable rather than merely unmatched. An absurdly
        // large one is rejected too: re-deriving at that cost would hang the caller, and no hash
        // this library writes can carry it.
        if (!int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var iterations)
            || iterations < 1
            || iterations > MaximumIterations)
        {
            return false;
        }

        if (!IsBase64(parts[2]) || !IsBase64(parts[3]))
        {
            return false;
        }

        result = new PasswordHash
        {
            Algorithm = parts[0],
            Iterations = iterations,
            Salt = parts[2],
            Key = parts[3],
        };

        return true;
    }

    /// <summary>
    /// Checks that a string decodes as non-empty Base64.
    /// </summary>
    /// <param name="value">The candidate Base64 text.</param>
    /// <returns><see langword="true"/> when the value is valid, non-empty Base64.</returns>
    private static bool IsBase64(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        // Four Base64 characters decode to at most three bytes.
        var buffer = new byte[(value.Length / 4 + 1) * 3];

        return Convert.TryFromBase64String(value, buffer, out var written) && written > 0;
    }
}
