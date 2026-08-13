using ApricotFramework.PasswordHasher.Algorithms;
using ApricotFramework.PasswordHasher.AspNetCore.Impl;
using ApricotFramework.PasswordHasher.AspNetCore.Validation;
using ApricotFramework.PasswordHasher.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace ApricotFramework.PasswordHasher.AspNetCore.Extensions;

/// <summary>
/// Registers the password hasher in a service collection.
/// </summary>
public static class PasswordHasherServiceCollectionExtensions
{
    /// <summary>
    /// The configuration section bound when no other is named.
    /// </summary>
    public const string ConfigurationSectionName = "PasswordHasher";

    /// <summary>
    /// Adds the password hasher, binding its settings from the
    /// <see cref="ConfigurationSectionName"/> configuration section.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration to bind from.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddPasswordHasher(this IServiceCollection services, IConfiguration configuration)
    {
        return services.AddPasswordHasher(configuration, ConfigurationSectionName);
    }

    /// <summary>
    /// Adds the password hasher, binding its settings from a named configuration section.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration to bind from.</param>
    /// <param name="sectionName">The section to bind.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddPasswordHasher(this IServiceCollection services, IConfiguration configuration, string sectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.AddOptions<PasswordHasherOptions>().Bind(configuration.GetSection(sectionName));

        return AddPasswordHasherCore(services);
    }

    /// <summary>
    /// Adds the password hasher, configuring its settings in code.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures the settings.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddPasswordHasher(this IServiceCollection services, Action<PasswordHasherOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<PasswordHasherOptions>().Configure(configure);

        return AddPasswordHasherCore(services);
    }

    /// <summary>
    /// Adds an algorithm the hasher can write and verify with, alongside the built-in ones.
    /// </summary>
    /// <typeparam name="TAlgorithm">The algorithm to add. Its dependencies are injected.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// Registers the algorithm as a singleton, which is required: the hasher and the options
    /// validator are both singletons, and a shorter-lived algorithm cannot be consumed by them.
    /// Order relative to <c>AddPasswordHasher</c> does not matter. Adding the same type twice is
    /// a no-op.
    /// </remarks>
    public static IServiceCollection AddPasswordHasherAlgorithm<TAlgorithm>(this IServiceCollection services)
        where TAlgorithm : class, IPasswordHashAlgorithm
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPasswordHashAlgorithm, TAlgorithm>());

        return services;
    }

    /// <summary>
    /// Adds an already-constructed algorithm the hasher can write and verify with, alongside the
    /// built-in ones.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="algorithm">The algorithm to add.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// Unlike the generic overload this does not deduplicate, so one type can be added several
    /// times under different names — which is how a single implementation serves more than one
    /// algorithm name.
    /// </remarks>
    public static IServiceCollection AddPasswordHasherAlgorithm(this IServiceCollection services, IPasswordHashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(algorithm);

        services.AddSingleton(algorithm);

        return services;
    }

    /// <summary>
    /// Registers the validator and the hasher itself.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// Nothing registers the built-in algorithms because they need no registration. Any
    /// <see cref="IPasswordHashAlgorithm"/> the caller registers is injected as an addition to
    /// them.
    /// </remarks>
    private static IServiceCollection AddPasswordHasherCore(IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<PasswordHasherOptions>, PasswordHasherOptionsValidator>());

        // Surface a bad iteration count or algorithm name when the host starts rather than on
        // the first login. In a bare ServiceProvider there is nothing to run the startup hook,
        // so the validator still runs on first access to the options.
        services.AddOptions<PasswordHasherOptions>().ValidateOnStart();

        services.TryAddSingleton<IPasswordHasher, OptionsAwarePasswordHasher>();

        return services;
    }
}
