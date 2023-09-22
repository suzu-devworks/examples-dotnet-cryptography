# Configuration

## The way to the present

```shell
git clone https://github.com/suzu-devworks/examples-dotnet-cryptography.git
cd examples-dotnet-cryptography

dotnet new sln -o .

#dotnet nuget update source github --username suzu-devworks --password "{parsonal access token}" --store-password-in-clear-text

dotnet build

# Update outdated package
dotnet list package --outdated

# Tools config
dotnet new tool-manifest
dotnet tool install coverlet.console

dotnet tool restore

```
