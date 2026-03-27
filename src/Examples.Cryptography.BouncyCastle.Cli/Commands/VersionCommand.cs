#pragma warning disable CA1822

using System.Reflection;
using ConsoleAppFramework;

namespace Examples.Cryptography.BouncyCastle.Cli.Commands;

/// <summary>
/// Prints version information.
/// </summary>
[RegisterCommands("version")]
public class VersionCommand
{
    /// <summary>
    /// Executes the version command.
    /// </summary>
    [Command("")]
    public void Run()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var version = assembly.GetName().Version?.ToString() ?? "unknown";
        Console.WriteLine($"{assembly.GetName().Name} {version}");
    }
}
