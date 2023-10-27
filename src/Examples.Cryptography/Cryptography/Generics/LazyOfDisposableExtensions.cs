namespace Examples.Cryptography.Generics;

/// <summary>
/// Extension methods for <see cref="Lazy{T}"/ > of T is <see cref="IDisposable" />.
/// </summary>
public static class LazyOfDisposableExtensions
{
    /// <summary>
    /// Disposes only when <c>IsValueCreated</c> is true.
    /// </summary>
    /// <param name="lazyInstance">The <see cref="Lazy{T}"/ > instance.</param>
    /// <typeparam name="T">The Class that implements <see cref="IDisposable" />.</typeparam>
    public static void DisposeIfValueCreated<T>(this Lazy<T> lazyInstance)
        where T : IDisposable
    {
        if (lazyInstance.IsValueCreated)
        {
            lazyInstance.Value.Dispose();
        }

        return;
    }

    /// <summary>
    /// Disposes only when <c>IsValueCreated</c> is true.
    /// </summary>
    /// <param name="lazyInstance">The <see cref="Lazy{T}"/ > of <see cref="IEnumerable" /> instances.</param>
    /// <typeparam name="T">The Class that implements <see cref="IDisposable" />.</typeparam>
    public static void DisposeIfValueCreated<T>(this Lazy<IEnumerable<T>> lazyInstance)
        where T : IDisposable
    {
        if (lazyInstance.IsValueCreated)
        {
            foreach (var disposable in lazyInstance.Value)
            {
                disposable.Dispose();
            }
        }

        return;
    }
}
