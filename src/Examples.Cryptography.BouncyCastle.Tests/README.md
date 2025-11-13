# Examples.Cryptography.BouncyCastle.Tests

## Table of Contents <!-- omit in toc -->

## Development

### How the project was initialized

This project was initialized with the following command:

```shell
## Solution
dotnet new sln -o .

## Examples.Cryptography.Tests
dotnet new xunit3 -o src/Examples.Cryptography.Tests
dotnet sln add src/Examples.Cryptography.Tests/
cd src/Examples.Cryptography.Tests
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit3
dotnet add package xunit.runner.visualstudio
dotnet add package coverlet.collector
dotnet add package Microsoft.Extensions.Http
dotnet add package BouncyCastle.Cryptography

dotnet add reference ../../src/Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated
```
