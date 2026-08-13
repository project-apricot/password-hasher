namespace ApricotFramework.PasswordHasher.Tests;

/// <summary>
/// Known-answer vectors for PBKDF2, pinning the exact bytes this library produces.
/// </summary>
/// <remarks>
/// Every expected key here was computed independently of this library, with Python's
/// <c>hashlib.pbkdf2_hmac(alg, password.encode('utf-8'), salt, iterations, 32)</c>. They serve
/// two purposes that a round-trip test cannot:
/// <list type="bullet">
/// <item>They prove the move off the obsolete <c>Rfc2898DeriveBytes</c> constructors did not
/// change a single output byte, so hashes written by earlier versions still verify.</item>
/// <item>They freeze the encoded hash format, which consumers persist. A failure here means the
/// stored-hash contract broke; it is not a value to update without a major version.</item>
/// </list>
/// </remarks>
internal static class GoldenVectors
{
    /// <summary>
    /// A 16-byte salt of 0x00..0x0F.
    /// </summary>
    public const string SaltSequential = "AAECAwQFBgcICQoLDA0ODw==";

    /// <summary>
    /// A 16-byte salt of repeated 0xA5.
    /// </summary>
    public const string SaltRepeated = "paWlpaWlpaWlpaWlpaWlpQ==";

    /// <summary>
    /// The password used by most vectors.
    /// </summary>
    public const string Password = "correct horse battery staple";

    /// <summary>
    /// A password exercising multi-byte UTF-8, including a surrogate pair.
    /// </summary>
    public const string PasswordUnicode = "пароль-Ω-😀";

    /// <summary>
    /// HMAC-SHA512, <see cref="Password"/>, <see cref="SaltSequential"/>, 100 iterations.
    /// </summary>
    public const string Sha512At100 = "0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=";

    /// <summary>
    /// HMAC-SHA512, <see cref="PasswordUnicode"/>, <see cref="SaltRepeated"/>, 100 iterations.
    /// </summary>
    public const string Sha512At100Unicode = "gOuLnmIZ6RxsnAeEUyRXBO4FciCcDOPlp82jry/OXfw=";

    /// <summary>
    /// HMAC-SHA512, empty password, <see cref="SaltSequential"/>, 100 iterations.
    /// </summary>
    public const string Sha512At100Empty = "07D/r0T0+6Bf+MpJ1gt4PmMdJgheJdCqgNK8Jt0WukY=";

    /// <summary>
    /// HMAC-SHA512, <see cref="Password"/>, <see cref="SaltSequential"/>, 1000 iterations.
    /// </summary>
    public const string Sha512At1000 = "A6AmFIti7CKlYdoPiV9jf1d9llp37o27Wms8Zx8fwMI=";

    /// <summary>
    /// HMAC-SHA256, <see cref="Password"/>, <see cref="SaltSequential"/>, 1000 iterations.
    /// </summary>
    public const string Sha256At1000 = "ppsXnjrdPB4KryJ6DrOqKqhkWrhv7PbKAMF1Eml8cZ4=";

    /// <summary>
    /// A complete hash exactly as the pre-migration library wrote it.
    /// </summary>
    public const string LegacyEncoded = $"RFC.100.{SaltSequential}.{Sha512At100}";
}
