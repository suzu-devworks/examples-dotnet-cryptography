using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Helpers;

/// <summary>
/// Generates random passwords that include a mix of character types (lowercase, uppercase, digits, special characters).
/// </summary>
public class PasswordGenerator
{
    private static readonly SecureRandom Random = new SecureRandom();

    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Specials = "!@#$%^&*()-_=+";

    public static string Generate(int length)
    {
        if (length < 4) throw new ArgumentException("長さは4文字以上である必要があります。");

        var passwordChars = new List<char>
        {
            // 1. 各カテゴリから最低1文字を強制的に追加
            Lower[Random.Next(Lower.Length)],
            Upper[Random.Next(Upper.Length)],
            Digits[Random.Next(Digits.Length)],
            Specials[Random.Next(Specials.Length)]
        };

        // 2. 残りの文字数を全文字セットからランダムに埋める
        string allChars = Lower + Upper + Digits + Specials;
        for (int i = passwordChars.Count; i < length; i++)
        {
            passwordChars.Add(allChars[Random.Next(allChars.Length)]);
        }

        // 3. フィッシャー–イェーツのシャッフルで順番をバラバラにする
        // (これをしないと最初の4文字が必ず「小・大・数・記」の順になってしまうため)
        return new string(Shuffle(passwordChars).ToArray());
    }

    private static List<char> Shuffle(List<char> list)
    {
        int n = list.Count;
        while (n > 1)
        {
            n--;
            int k = Random.Next(n + 1);
            char value = list[k];
            list[k] = list[n];
            list[n] = value;
        }
        return list;
    }
}
