# docs

## Table of Contents

- [C# Features ...](./Features/README.md)
- [Dependency Injection ...](./DependencyInjection/README.md)
- [Design Patterns ...](./DesignPatterns/README.md)
- [Domain-driven design ...](./DDD/README.md)
- [Others ...](./Others/README.md)
- [Tools ...](./Tools/README.md)


## The way to the present

```shell
git clone https://github.com/suzu-devworks/examples-dotnet-cryptography.git
cd examples-dotnet-cryptography

dotnet new sln -o .

## Examples.Cryptography.Tests
dotnet new xunit -o src/Examples.Cryptography.Tests
cd src/Examples.Cryptography.Tests
dotnet add package Moq
dotnet add package ChainingAssertion.Core.Xunit
dotnet add package System.Security.Cryptography.Xml 
cd ../../
dotnet sln add src/Examples.Cryptography.Tests

dotnet build

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install coverlet.console

dotnet tool restore

# Nuget config
dotnet new nugetconfig

```
