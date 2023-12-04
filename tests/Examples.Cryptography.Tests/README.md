# Examples.Cryptography.Tests

## System.Security.Cryptography

- [System.Security.Cryptography Namespace ...](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography)

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

## Examples.Cryptography.Tests
dotnet new xunit -o tests/Examples.Cryptography.Tests
dotnet sln add tests/Examples.Cryptography.Tests/
cd tests/Examples.Cryptography.Tests
dotnet add reference ../../src/Examples.Cryptography/
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package coverlet.collector
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package System.Security.Cryptography.Xml 
cd ../../

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install dotnet-xscgen

dotnet tool restore
```
