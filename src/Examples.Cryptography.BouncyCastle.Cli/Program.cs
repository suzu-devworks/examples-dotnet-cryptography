using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Cli.Clients;
using Microsoft.Extensions.DependencyInjection;

var app = ConsoleApp.Create()
    .ConfigureServices(services =>
    {
        services.AddHttpClient<OcspHttpClient>();
        services.AddHttpClient<TimeStampHttpClient>();
    });

await app.RunAsync(args);
