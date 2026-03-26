using Org.BouncyCastle.OpenSsl;

namespace Examples.Cryptography.BouncyCastle.Tests.Fixtures;

/// <summary>
/// Generates random passwords that include a mix of character types (lowercase, uppercase, digits, special characters).
/// </summary>
public class PasswordFinder(string password) : IPasswordFinder
{
    private readonly char[] _password = password.ToCharArray();

    public char[] GetPassword()
    {
        return (char[])_password.Clone();
    }
}
