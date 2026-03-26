#pragma warning disable CA1822

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
        Console.WriteLine("Examples.Cryptography.BouncyCastle.Cli 1.0.0");
    }
}
