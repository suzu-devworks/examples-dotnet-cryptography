using System.Security.Cryptography;

namespace Examples.Cryptography.Algorithms.Hash;

public class SHA512Tests
{
    private readonly string _base64data = """
    MIIJKQIBAAKCAgEAoy8AkwiMxa5dAEiPR4XXbu4tIHtBYXAeLgJutfBO8FOGmqvF
    pKi02L77A1GgsRBHJ0QohRQ/58wuqvF5gL6R7Qa+oB7s+SY1OeKKILM6HLIhATpD
    pMP5eYg0uaqqZWE+gKpFxifuuWFaWVbZYHO7zxK/0yi3GmmmvZe7guBfzKUhZ8vH
    t6tADHzZRLnWF673PO2z1etWceeRNpiASQ3oMmIqUd3SBVPjoi4fGoCzQz/dPRNF
    lP4zDuWmIMn3AbErVno39jd4qphiP/p2o3Iq2PbS72oOqUUP9fF/9B72V8D9SCw3
    tM7ZySuCTw6v089Z4rjGeMQ4BXPU757Usd2P4ws1Yowc6mk1uZkv/MEuY1CVVxew
    QB4YnpVFn4EFZFAyghnsHh2vqgDernwxf/75qNwCjcvF1l5rfep96yX9n4VPY6ad
    YnDqtL3gGj+7IxOJfqgLAKnYaFI5PzOBpPhEZffedze0z23J+79LbubVD5AIQ+cu
    PDBtUG+UveMMIUasYmFfJffkJtrWs2K5fe9ct6Wi/LQEMc1iUvmhi+LQ0nm7+YHd
    dbsz+XQLol0DODd10jAfJG3F9qYmMDqP4e2R4Wy7BpgXmsUycnadJpXO5ue4SPiO
    6dSeXJNUNsPoEJbSWdbhEXV75ckccxsXZspm80e8oUF0P8DVl+Nh3bcG++kCAwEA
    AQKCAgEAmTnvTiD/HjgFt9hqQXyZt94JnbBeygGfNRCvqENHvD6R6/ZTFbQcbFGY
    HZuuSdTBG0vSyHMlNqDxSS6JKqzHFUv5/xxK5ABOhlYD4YSpknxopWByV+p0/Ps6
    lwR8D8nqCKLZ9aFVddjGH5F/eCP0PBKc8MgQdsqx+ODa/590FRMRdQdSN1KkR5WL
    5g6hy4dNPHbvIHVkrHwGTL+R5gca+wRWPJ0PMlV9L7IjHp2utfzn3wuTkL3Ib7qP
    7cX3HC2iRgdpONcJhRalWvHyKLNxLF1H3+s0bRkeTZBA15ejNO9QZU6v2CVLNqyW
    JWnjC/5tpoheRNPqzqPfVElN6t3i1oyaQFHIb7At9fBoTx50kIrTXbB0YPh1UTp1
    CmowIa1RSTC1AYLaQsIu+ZAkjbys44wTj+7dmuD7X6HH9dRmLO2U0t9ski1j/PT1
    xxqyvLFk1LkARcso/i6flctEeKzAJYmTaCyMkKq873y1k1PavAMbH4QH1yC/9Kw5
    d3DI3xFMbQOYWskcOus2oybF5Yr6ewxWoJR32qiWJTZzVgWhMncf3ynrBRk1BeCf
    YV9SYtyf5smkSJi1DDSFtYzkzhLCCqX1qI9ycNIH6/DMSaX3TFKs3uAtTUX1op6T
    4V8hF8WZyGLNWsuQRlk8IZkaCyL5WS7JD4blgyAHRsP3hwQVigECggEBANICvqak
    LEKjBXnc+DwYhc+J3aqDPD1MBJ4RYpB4X9J4303P05Ykj74TGclSFTb5Sr5f8BZM
    HpuHO13qdd9iV6HW+dsTDSF0cU5OBQ0ROYcvVCgkCS4iDhPmNqnIUUSedqtJJC1N
    M5TaR1MbqRhYPacE50rjQIWK73CPJB5nI27NBs5wRYIjws7UnuFAR/nvTeGEiYLi
    rM7/JXvGCUAJpE6kmDVc3Nvs8WWkCIEnfc4uRq8WM5iwwQ1r6ik4hn8wb8WJhaTp
    Xys1ODamvuECt4QyB6rz7D3+9q+5QGpiDYiy12h0a2OwG/c5Mu8Ice/QFT3K5aST
    V1bgr4bYGmdlLUkCggEBAMbrHfwdn6ezrw/uXzBQSNogy+dsF4jyTQoOYu6o8LMx
    tX4ViutEwhEAMq8JZG+ubkTxYc17EzaF12HFXy0dJsaVijejDcZQOP+fAwzEOQ3h
    hCyH8sSkiJ7/Ad68uugz3ZH8Pp11cKLKgT0y5H5Mblg9RE2Fb10lO6WMHu4AkjS1
    uQqcjFaJ61M6zgVIq5Nme4BFKu+ZrnWE3/I4NeEXGjtsFd66BrzXGN9h/kmRUjLB
    QvacDhtFumlagm1idd2nFdl6gpWZxt58Mzuo/C08IV6cUl8eURVRGHHvPqe4yRhA
    HaolmvmdDhAlDPLcB0MN07JKmSBW62cXyDUkNEQOeaECggEAZnP4VouZHBkzvrPS
    Vl8QSKNVhK3pYW4IgqSwlRJkjOVy6x8Mdh74ER54YgKtXthXYnCjS/1uoSlkCPks
    8AGmBso9smak7UFFVZIyXKGekxi/0aVi5SKwA304BbQ4EWXNNtrDz2XuWBv019KS
    t9G0ohp+S8Z536xcC2mJkVt3qcJUI7oZ7tdLXmPT7sfRVVktgWuLOlMjQwiuXKfM
    M3WAtu0NZFsdVB1P1uojS/7cHQ3uZdRK756rT8Tpw5pT4xDaNmBU1pMTXpzkA6Vt
    UZBlvxQ5MWk2QzhzWF7j0gJr39h/xfGlwkhUHFPHSV2xV/EHq9GkHpnS7gtHFl2u
    4+o0IQKCAQEAhhhx+keuHUuQNFkpalR1CDcbvkKsCvHs5V6VavYQbXyRMRIsuDV9
    7iAICt92CaO5Sli+6dqSNSs86vg3FR6VyUF+D8unuYzTH99+Gtkc7TKd+7cZ/V49
    i5G1HQZ1qZttPsChJVzKNbP2M99fEZVMvcdviCLv1AcJkqxHHYLdDROETpcCNER9
    k3oM8Jrwr0li8DGwpB0h8q9EmPEzwS3lzTEr/R3C9QK8DbrtxYJluzl1fvHswI3d
    ALC3RC4f7vB4Vke0SE2GNu3bS9i7R3NFu5X+IYk6d/hXVldGEaMMTYDLfqwjMSqj
    FFclx4J0kst7brHDUH3H65Oor8pcQZTQgQKCAQBaOcyk8EcpL9+iCmAr7431W5E9
    Cf6Juwe6kMupGo9r69TnnNFL6EHUdg+POcWBK2WDjG6mTsjv73jbqd7S9rkjOjka
    NYyhP4kgTzh2/a4exfcwr3987v2RIJOSDTQdrG38Eyeg7nLCtl6yEmp08e3RmqkG
    SZhYNkhKCDNUN3GhKEREqbB/f0oJOMZu7nv/l3ntHg9bNYWVXrNpnvbynS7AUxcs
    tvn5lZIIHcawCt6iFw/YQzhkzf8tNd+PzgKqYoh93K8ejEP+0Kt8tOd+LfPcK9it
    GTwVM5kYA9N3UcbtGaOY60IV8hzyaMHNJJWBs+pR6AA0a99mBL+pIIF7G/tw
    """;


    [Fact]
    public void WhenComputeHashs()
    {
        var bytes = Convert.FromBase64String(_base64data);

        // Initialize a SHA512 hash object.
        //CA1850 using var sha = SHA512.Create();
        //CA1850 var actual = sha.ComputeHash(bytes);

        var actual = SHA512.HashData(bytes);
        var again = SHA512.HashData(bytes);

        bytes[3] = 0x00;
        var fake = SHA512.HashData(bytes);

        // Assert
        actual.Is(again);
        actual.IsNot(fake);
    }

    [Fact]
    public void WhenComputeHash_WithStream()
    {
        // Arrange.
        var bytes = Convert.FromBase64String(_base64data);

        byte[] actual;
        byte[] again;
        byte[] fake;

        // Initialize a SHA512 hash object.
        using (var sha = SHA512.Create())
        {

            using (var stream = new MemoryStream(bytes))
            {
                actual = sha.ComputeHash(stream);
            }

            using (var stream = new MemoryStream(bytes))
            {
                again = sha.ComputeHash(stream);
            }

            bytes[3] = 0x00;

            using (var stream = new MemoryStream(bytes))
            {
                fake = sha.ComputeHash(stream);
            }
        }

        // Assert
        actual.Is(again);
        actual.IsNot(fake);
    }

}
