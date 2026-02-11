namespace Examples.Cryptography.Tests.Helpers;

/// <summary>
/// Helper for writing test output to files.
/// </summary>
public sealed class TestFileOutputHelper
{
    private TestFileOutputHelper() { }

    /// <summary>
    /// Writes text content to a file asynchronously.
    /// </summary>
    /// <param name="filePath">The path to the file to write.</param>
    /// <param name="content">The text content to write.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async ValueTask WriteFileAsync(string filePath, string content, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(content);

#if TEST_FILE_OUTPUT_ENABLED
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
        await File.WriteAllTextAsync(filePath, content, cancellationToken).ConfigureAwait(false);
#else
        await ValueTask.CompletedTask.ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Writes binary content to a file asynchronously.
    /// </summary>
    /// <param name="filePath">The path to the file to write.</param>
    /// <param name="content">The binary content to write.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async ValueTask WriteFileAsync(string filePath, byte[] content, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(content);

#if TEST_FILE_OUTPUT_ENABLED
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
        await File.WriteAllBytesAsync(filePath, content, cancellationToken).ConfigureAwait(false);
#else
        await ValueTask.CompletedTask.ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Gets the singleton instance of the helper.
    /// </summary>
    public static TestFileOutputHelper Instance { get; } = new();
}
