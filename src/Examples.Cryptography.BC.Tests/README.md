# Examples.Cryptography.BC.Tests

## BouncyCastle.Cryptography

- [Bouncy Castle C# API! ...](https://www.bouncycastle.org/csharp/index.html)


## Project Initialize

```shell
## Solution
dotnet new sln -o .

# dotnet nuget update source github --username suzu-devworks --password "{parsonal access token}" --store-password-in-clear-text

## Examples.Cryptography
dotnet new classlib -o src/Examples.Cryptography
dotnet sln add src/Examples.Cryptography/
cd src/Examples.Cryptography
dotnet add package SWX.Examples.Shared --prerelease
cd ../../

## Examples.Cryptography.BC.Tests
dotnet new xunit -o src/Examples.Cryptography.BC.Tests
dotnet sln add src/Examples.Cryptography.BC.Tests/
cd src/Examples.Cryptography.BC.Tests
dotnet add reference ../../src/Examples.Cryptography/
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package coverlet.collector
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package Microsoft.Extensions.Http
dotnet add package BouncyCastle.Cryptography
cd ../../

# Update outdated package
dotnet list package --outdated
```
