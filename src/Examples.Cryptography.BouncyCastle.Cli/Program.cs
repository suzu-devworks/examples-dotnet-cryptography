using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Cli.Clients;
using Microsoft.Extensions.DependencyInjection;

var app = ConsoleApp.Create()
    .ConfigureServices(services =>
    {
        services.AddHttpClient();
        services.AddTransient<OcspHttpClient>();
        services.AddTransient<TimeStampHttpClient>();
    });

await app.RunAsync(args);
