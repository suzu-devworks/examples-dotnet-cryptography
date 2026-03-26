using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Cli;
var app = ConsoleApp.Create();
app.Add<Commands>();
await app.RunAsync(args);
