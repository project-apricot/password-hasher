namespace ApricotFramework.PasswordHasher;

/// <summary>
/// Hashes passwords and checks candidates against stored hashes.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Gets the name of the algorithm used for newly created hashes.
    /// </summary>
    /// <returns>The algorithm name.</returns>
    /// <exception cref="InvalidOperationException">
    /// The configured algorithm is not one the hasher knows about.
    /// </exception>
    /// <remarks>
    /// A method rather than a property: it resolves the current settings, so it can throw and
    /// can return a different answer on successive calls when configuration is reloaded.
    /// </remarks>
    string GetAlgorithm();

    /// <summary>
    /// Gets the iteration count used for newly created hashes.
    /// </summary>
    /// <returns>The iteration count.</returns>
    /// <exception cref="InvalidOperationException">
    /// The configured algorithm is not one the hasher knows about.
    /// </exception>
    int GetIterations();

    /// <summary>
    /// Hashes a password with a freshly generated salt.
    /// </summary>
    /// <param name="password">The plain password to hash.</param>
    /// <returns>The hash and the parameters that produced it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    PasswordHash Hash(string password);

    /// <summary>
    /// Checks a candidate password against a stored hash.
    /// </summary>
    /// <param name="hash">The stored, encoded hash.</param>
    /// <param name="password">The candidate password.</param>
    /// <returns>
    /// Whether the password matched, and whether the stored hash should be rewritten.
    /// A malformed or unrecognised <paramref name="hash"/> is reported as not verified rather
    /// than raised as an exception.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="hash"/> or <paramref name="password"/> is <see langword="null"/>.
    /// </exception>
    PasswordCheckResult Verify(string hash, string password);
}
