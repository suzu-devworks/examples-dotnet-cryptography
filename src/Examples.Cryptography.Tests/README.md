# Examples.Cryptography.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography's Tests](#examplescryptographys-tests)
- [Development](#development)
  - [How the project was initialized](#how-the-project-was-initialized)

## Examples.Cryptography's Tests

- [`XmlNamespacesExtensionsTests`](./Cryptography.Tests/Xml/XmlNamespacesExtensionsTests)

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
dotnet add package System.Security.Cryptography.Xml

dotnet add reference ../../src/Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install dotnet-xscgen

dotnet tool restore
```
