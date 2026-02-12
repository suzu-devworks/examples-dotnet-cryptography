using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Extensions;

/// <summary>
/// Extension methods for <see cref="X500DistinguishedNameBuilder"/> to simplify the creation of distinguished names.
/// </summary>
public static class X500DistinguishedNameBuilderExtensions
{
    /// <summary>
    /// Adds a country or region to the distinguished name builder.
    /// </summary>
    /// <param name="builder">The builder instance.</param>
    /// <param name="countryOrRegion">The country or region value.</param>
    /// <returns>The builder instance.</returns>
    public static X500DistinguishedNameBuilder WithCountryOrRegion(this X500DistinguishedNameBuilder builder,
        string countryOrRegion)
    {
        builder.AddCountryOrRegion(countryOrRegion);
        return builder;
    }

    /// <summary>
    /// Adds an organization to the distinguished name builder.
    /// </summary>
    /// <param name="builder">The builder instance.</param>
    /// <param name="organization">The organization name.</param>
    /// <returns>The builder instance.</returns>
    public static X500DistinguishedNameBuilder WithOrganization(this X500DistinguishedNameBuilder builder,
        string organization)
    {
        builder.AddOrganizationName(organization);
        return builder;
    }

    /// <summary>
    /// Adds a common name to the distinguished name builder.
    /// </summary>
    /// <param name="builder">The builder instance.</param>
    /// <param name="commonName">The common name value.</param>
    /// <returns>The builder instance.</returns>
    public static X500DistinguishedNameBuilder WithCommonName(this X500DistinguishedNameBuilder builder,
        string commonName)
    {
        builder.AddCommonName(commonName);
        return builder;
    }

}
