# Examples.Cryptography.Xml.Tests

## Table of Contents <!-- omit in toc -->

- [Examples.Cryptography.Xml](#examplescryptographyxml)
- [Development](#development)
  - [How the project was initialized](#how-the-project-was-initialized)

## Examples.Cryptography.Xml

- [`XmlNamespacesExtensionsTests`](./Cryptography.Xml.Tests/XmlNamespacesExtensionsTests.cs)

## Development

### How the project was initialized

This project was initialized with the following command:

```shell
## Solution
dotnet new sln -o .

## Examples.Cryptography.Xml.Tests
dotnet new xunit3 -o src/Examples.Cryptography.Xml.Tests
dotnet sln add src/Examples.Cryptography.Xml.Tests/
cd src/Examples.Cryptography.Xml.Tests
dotnet add package xunit.v3.mtp-v2
dotnet add package Microsoft.Testing.Extensions.CodeCoverage
dotnet add package System.Security.Cryptography.Xml

dotnet add reference ../Examples.Cryptography/
cd ../../

# Update outdated package
dotnet list package --outdated
```
