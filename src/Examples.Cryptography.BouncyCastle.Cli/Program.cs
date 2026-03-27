using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Cli.Clients;
using Microsoft.Extensions.DependencyInjection;
var app = ConsoleApp.Create()
    .ConfigureServices(services =>
    {
        services.AddHttpClient<OcspHttpClient>();
        services.AddHttpClient<TimeStampHttpClient>();
    });

// ConsoleAppFramework accepts help for subcommands, but not when mixed with other options.
// Normalize args so -h/--help always shows usage for the resolved command path.
var normalizedArgs = NormalizeHelpArgs(args);
await app.RunAsync(normalizedArgs);

static string[] NormalizeHelpArgs(string[] args)
{
    if (args.Length == 0 || !args.Any(IsHelpArgument))
    {
        return args;
    }

    var commandPath = args
        .TakeWhile(static x => !x.StartsWith('-'))
        .ToArray();

    if (commandPath.Length == 0)
    {
        return ["--help"];
    }

    return [.. commandPath, "--help"];
}

static bool IsHelpArgument(string arg)
{
    return string.Equals(arg, "--help", StringComparison.Ordinal)
        || string.Equals(arg, "-h", StringComparison.Ordinal);
}
