using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Extension methods for <see cref="X500DistinguishedNameBuilder"/> to simplify the creation of distinguished names.
/// </summary>
public static class X500DistinguishedNameBuilderExtensions
{
    /// <summary>
    /// Adds a country or region to the distinguished name builder.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="countryOrRegion"></param>
    /// <returns></returns>
    public static X500DistinguishedNameBuilder WithCountryOrRegion(this X500DistinguishedNameBuilder builder,
        string countryOrRegion)
    {
        builder.AddCountryOrRegion(countryOrRegion);
        return builder;
    }

    /// <summary>
    /// Adds a organization to the distinguished name builder.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="organization"></param>
    /// <returns></returns>
    public static X500DistinguishedNameBuilder WithOrganization(this X500DistinguishedNameBuilder builder,
        string organization)
    {
        builder.AddOrganizationName(organization);
        return builder;
    }

    /// <summary>
    /// Adds an organizational unit to the distinguished name builder.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="commonName"></param>
    /// <returns></returns>
    [Obsolete("Deprecating the TLS/ SSL Organizational Unit (OU) Field.")]
    public static X500DistinguishedNameBuilder WithOrganizationalUnitName(this X500DistinguishedNameBuilder builder,
        string organizationalUnitName)
    {
        // builder.AddOrganizationalUnitName(organizationalUnitName);
        return builder;
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="commonName"></param>
    /// <returns></returns>
    public static X500DistinguishedNameBuilder WithCommonName(this X500DistinguishedNameBuilder builder,
        string commonName)
    {
        builder.AddCommonName(commonName);
        return builder;
    }

}
