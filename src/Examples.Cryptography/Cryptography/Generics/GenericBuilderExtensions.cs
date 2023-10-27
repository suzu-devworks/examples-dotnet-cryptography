namespace Examples.Cryptography.Generics;

/// <summary>
/// Extension methods for method chaining with builders.
/// </summary>
public static class GenericBuilderExtensions
{
    /// <summary>
    /// Call delegate to confine the settings to <c>T</c> to the function scope..
    /// </summary>
    /// <param name="builder">The builder instance.</param>
    /// <param name="configureAction">The delegate method for configuration.</param>
    /// <typeparam name="T">The builder class.</typeparam>
    /// <returns>An extended builder instance.</returns>
    /// <exception cref="ArgumentNullException">If the argument is null.</exception>
    public static T Configure<T>(this T builder, Action<T> configureAction)
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }
        if (configureAction is null) { throw new ArgumentNullException(nameof(configureAction)); }

        configureAction.Invoke(builder);

        return builder;
    }

}
