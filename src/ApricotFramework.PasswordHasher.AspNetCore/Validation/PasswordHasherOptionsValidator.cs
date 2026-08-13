using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Options;
using Microsoft.Extensions.Options;

namespace ApricotFramework.PasswordHasher.AspNetCore.Validation;

/// <summary>
/// Rejects hashing settings that cannot work, or that would produce a hash weaker than the
/// permitted floor.
/// </summary>
/// <remarks>
/// This bounds only newly written hashes. An existing hash is always verified at the iteration
/// count recorded inside it, so raising the floor never locks anyone out of their account.
/// </remarks>
public sealed class PasswordHasherOptionsValidator : IValidateOptions<PasswordHasherOptions>
{
    /// <summary>
    /// The lowest iteration count that may be configured, per NIST SP 800-63B. It bounds only
    /// newly written hashes.
    /// </summary>
    public const int MinimumIterations = 10_000;

    /// <summary>
    /// The algorithms the hasher will understand, keyed by name.
    /// </summary>
    private readonly IReadOnlyDictionary<string, IPasswordHashAlgorithm> algorithms;

    /// <summary>
    /// Creates a new validator.
    /// </summary>
    /// <param name="additionalAlgorithms">
    /// Any algorithms registered in the container, composed with the built-in ones exactly as
    /// the hasher composes them.
    /// </param>
    public PasswordHasherOptionsValidator(IEnumerable<IPasswordHashAlgorithm>? additionalAlgorithms)
    {
        this.algorithms = PasswordHashAlgorithms.Compose(additionalAlgorithms);
    }

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, PasswordHasherOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var requested = string.IsNullOrWhiteSpace(options.Algorithm)
            ? PasswordHashAlgorithms.DefaultName
            : options.Algorithm;

        if (!this.algorithms.ContainsKey(requested))
        {
            return ValidateOptionsResult.Fail(
                $"Password hashing algorithm '{requested}' is not registered. Registered algorithms: {string.Join(", ", this.algorithms.Keys)}.");
        }

        if (options.Iterations is null)
        {
            return ValidateOptionsResult.Success;
        }

        var iterations = options.Iterations.Value;

        if (iterations < 1)
        {
            return ValidateOptionsResult.Fail(
                $"Password hashing iteration count must be positive, but was {iterations}.");
        }

        if (iterations < MinimumIterations)
        {
            return ValidateOptionsResult.Fail(
                $"Password hashing iteration count {iterations} is below the minimum of {MinimumIterations}. Existing hashes are unaffected and still verify at their own recorded count.");
        }

        // Matches the ceiling the encoded format enforces, so a configuration that passes here
        // can never produce a hash that fails to parse back.
        if (iterations > PasswordHash.MaximumIterations)
        {
            return ValidateOptionsResult.Fail(
                $"Password hashing iteration count {iterations} exceeds the maximum of {PasswordHash.MaximumIterations}. A hash written with it could not be read back.");
        }

        return ValidateOptionsResult.Success;
    }
}
