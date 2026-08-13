using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.Impl;
using ApricotFramework.PasswordHasher.Options;
using Microsoft.Extensions.Options;

namespace ApricotFramework.PasswordHasher.AspNetCore.Impl;

/// <summary>
/// A password hasher that reads its settings from the options system on every operation, so a
/// configuration reload takes effect without restarting the host.
/// </summary>
public sealed class OptionsAwarePasswordHasher : DefaultPasswordHasher
{
    /// <summary>
    /// The monitor supplying the current settings.
    /// </summary>
    private readonly IOptionsMonitor<PasswordHasherOptions> optionsMonitor;

    /// <summary>
    /// Creates a new hasher.
    /// </summary>
    /// <param name="optionsMonitor">The monitor supplying the current settings.</param>
    /// <param name="additionalAlgorithms">
    /// Any algorithms registered in the container, supported in addition to the built-in ones.
    /// Empty unless the caller registered some.
    /// </param>
    public OptionsAwarePasswordHasher(
        IOptionsMonitor<PasswordHasherOptions> optionsMonitor,
        IEnumerable<IPasswordHashAlgorithm> additionalAlgorithms)
        : base(null, additionalAlgorithms)
    {
        ArgumentNullException.ThrowIfNull(optionsMonitor);

        this.optionsMonitor = optionsMonitor;
    }

    /// <inheritdoc />
    protected override PasswordHasherOptions GetCurrentOptions()
    {
        return this.optionsMonitor.CurrentValue;
    }
}
