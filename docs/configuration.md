# Configuration

## The way to the present

```shell
git clone https://github.com/suzu-devworks/examples-dotnet-cryptography.git
cd examples-dotnet-cryptography

dotnet new sln -o .

#dotnet nuget update source github --username suzu-devworks --password "{parsonal access token}" --store-password-in-clear-text

## Examples.Cryptography
dotnet new classlib -o src/Examples.Cryptography
dotnet sln add src/Examples.Cryptography/
cd src/Examples.Cryptography
cd ../../

## Examples.Cryptography.Tests
dotnet new xunit -o src/Examples.Cryptography.Tests
dotnet sln add src/Examples.Cryptography.Tests/
cd src/Examples.Cryptography.Tests
dotnet add reference ../Examples.Cryptography/
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package System.Security.Cryptography.Xml 
cd ../../

## Examples.Cryptography.BC.Tests
dotnet new xunit -o src/Examples.Cryptography.BC.Tests
dotnet sln add src/Examples.Cryptography.BC.Tests/
cd src/Examples.Cryptography.BC.Tests
dotnet add reference ../Examples.Cryptography/
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package BouncyCastle.Cryptography
cd ../../


dotnet build

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install coverlet.console

dotnet tool restore

```
