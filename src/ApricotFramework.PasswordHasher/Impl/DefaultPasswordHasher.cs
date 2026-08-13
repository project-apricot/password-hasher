using System.Security.Cryptography;
using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Options;

namespace ApricotFramework.PasswordHasher.Impl;

/// <summary>
/// The default password hasher, writing with one algorithm and verifying against all of them.
/// </summary>
/// <remarks>
/// Derive from this and override <see cref="GetCurrentOptions"/> to source the settings from
/// somewhere that can change at run time.
/// </remarks>
public class DefaultPasswordHasher : IPasswordHasher
{
    /// <summary>
    /// The size in bytes of the salt generated for a new hash (128 bit).
    /// </summary>
    private const int SaltSize = 16;

    /// <summary>
    /// The algorithms available for writing and verification, keyed by name.
    /// </summary>
    private readonly IReadOnlyDictionary<string, IPasswordHashAlgorithm> algorithms;

    /// <summary>
    /// The settings supplied at construction.
    /// </summary>
    private readonly PasswordHasherOptions options;

    /// <summary>
    /// Creates a new hasher.
    /// </summary>
    /// <param name="options">The settings, or null for the defaults.</param>
    /// <param name="additionalAlgorithms">
    /// Algorithms to support in addition to the built-in ones, or null for none. The built-ins
    /// are always available, so no registration can stop an existing hash from verifying.
    /// </param>
    public DefaultPasswordHasher(PasswordHasherOptions? options = null, IEnumerable<IPasswordHashAlgorithm>? additionalAlgorithms = null)
    {
        this.options = options ?? new PasswordHasherOptions();
        this.algorithms = PasswordHashAlgorithms.Compose(additionalAlgorithms);
    }

    /// <summary>
    /// Gets the settings in effect for the next operation.
    /// </summary>
    /// <returns>The current settings.</returns>
    /// <remarks>
    /// Override to track a source that can change at run time. A method rather than a property
    /// because an override is expected to do real work, and may throw while resolving.
    /// </remarks>
    protected virtual PasswordHasherOptions GetCurrentOptions()
    {
        return this.options;
    }

    /// <inheritdoc />
    public virtual string GetAlgorithm()
    {
        return this.ResolveAlgorithm(this.GetCurrentOptions()).Name;
    }

    /// <inheritdoc />
    public virtual int GetIterations()
    {
        var current = this.GetCurrentOptions();

        return ResolveIterationsForWriting(current, this.ResolveAlgorithm(current));
    }

    /// <inheritdoc />
    public virtual PasswordHash Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var current = this.GetCurrentOptions();
        var algorithm = this.ResolveAlgorithm(current);
        var iterations = ResolveIterationsForWriting(current, algorithm);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = algorithm.DeriveKey(password, salt, iterations);

        return new PasswordHash
        {
            Algorithm = algorithm.Name,
            Iterations = iterations,
            Salt = Convert.ToBase64String(salt),
            Key = Convert.ToBase64String(key),
        };
    }

    /// <inheritdoc />
    public virtual PasswordCheckResult Verify(string hash, string password)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(password);

        if (!PasswordHash.TryParse(hash, out var stored) || stored is null)
        {
            return default;
        }

        if (!this.algorithms.TryGetValue(stored.Algorithm, out var algorithm))
        {
            return default;
        }

        var salt = Convert.FromBase64String(stored.Salt);
        var expected = Convert.FromBase64String(stored.Key);
        var actual = algorithm.DeriveKey(password, salt, stored.Iterations);

        // Constant-time: a length-dependent or short-circuiting comparison here leaks how much
        // of a guessed key was correct. This also covers a key of the wrong length.
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return default;
        }

        return new PasswordCheckResult(true, this.NeedsUpgrade(stored));
    }

    /// <summary>
    /// Whether a verified hash was written with parameters other than the current ones.
    /// </summary>
    /// <param name="stored">The parsed stored hash.</param>
    /// <returns><see langword="true"/> when the hash should be rewritten.</returns>
    /// <remarks>
    /// Deliberately tolerant of a broken configuration: if the configured algorithm cannot be
    /// resolved, the hash does not match current policy, which is exactly what an upgrade
    /// signal means. Verification itself relies only on the stored parameters, so a
    /// misconfigured host still authenticates rather than throwing on every login.
    /// </remarks>
    private bool NeedsUpgrade(PasswordHash stored)
    {
        var current = this.GetCurrentOptions();

        if (!this.TryResolveAlgorithm(current, out var algorithm) || algorithm is null)
        {
            return true;
        }

        return stored.Iterations != ResolveIterations(current, algorithm)
            || !string.Equals(stored.Algorithm, algorithm.Name, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolves the algorithm to write with.
    /// </summary>
    /// <param name="current">The settings in effect.</param>
    /// <returns>The resolved algorithm.</returns>
    /// <exception cref="InvalidOperationException">The configured algorithm is not registered.</exception>
    private IPasswordHashAlgorithm ResolveAlgorithm(PasswordHasherOptions current)
    {
        if (this.TryResolveAlgorithm(current, out var algorithm) && algorithm is not null)
        {
            return algorithm;
        }

        throw new InvalidOperationException(
            $"The configured password hashing algorithm '{current.Algorithm}' is not registered. Registered algorithms: {string.Join(", ", this.algorithms.Keys)}.");
    }

    /// <summary>
    /// Attempts to resolve the algorithm to write with.
    /// </summary>
    /// <param name="current">The settings in effect.</param>
    /// <param name="algorithm">The resolved algorithm, or null when unresolvable.</param>
    /// <returns><see langword="true"/> when an algorithm was resolved.</returns>
    private bool TryResolveAlgorithm(PasswordHasherOptions current, out IPasswordHashAlgorithm? algorithm)
    {
        var name = string.IsNullOrWhiteSpace(current.Algorithm)
            ? PasswordHashAlgorithms.DefaultName
            : current.Algorithm;

        return this.algorithms.TryGetValue(name, out algorithm);
    }

    /// <summary>
    /// Resolves the iteration count in effect.
    /// </summary>
    /// <param name="current">The settings in effect.</param>
    /// <param name="algorithm">The algorithm being written with.</param>
    /// <returns>The configured count, or the algorithm's default.</returns>
    private static int ResolveIterations(PasswordHasherOptions current, IPasswordHashAlgorithm algorithm)
    {
        return current.Iterations is > 0 ? current.Iterations.Value : algorithm.DefaultIterations;
    }

    /// <summary>
    /// Resolves the iteration count for a hash that is about to be written, refusing one that
    /// could not be read back.
    /// </summary>
    /// <param name="current">The settings in effect.</param>
    /// <param name="algorithm">The algorithm being written with.</param>
    /// <returns>The count to write with.</returns>
    /// <exception cref="InvalidOperationException">
    /// The count exceeds <see cref="PasswordHash.MaximumIterations"/>.
    /// </exception>
    /// <remarks>
    /// Only the write path enforces this. Verification stays tolerant of a broken configuration,
    /// so a host that is misconfigured still authenticates existing users instead of failing
    /// every login.
    /// </remarks>
    private static int ResolveIterationsForWriting(PasswordHasherOptions current, IPasswordHashAlgorithm algorithm)
    {
        var iterations = ResolveIterations(current, algorithm);

        if (iterations > PasswordHash.MaximumIterations)
        {
            throw new InvalidOperationException(
                $"The configured iteration count {iterations} exceeds the maximum of {PasswordHash.MaximumIterations}. A hash written with it could not be read back.");
        }

        return iterations;
    }
}
