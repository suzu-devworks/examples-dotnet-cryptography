using Examples.Extensions;

namespace Examples.Tests.Extensions;

public class DateTimeExtensionsTests
{
    [Theory]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T12:34:56.7891230Z", TimeSpan.TicksPerMicrosecond)]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T12:34:56.7890000Z", TimeSpan.TicksPerMillisecond)]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T12:34:56.0000000Z", TimeSpan.TicksPerSecond)]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T12:34:00.0000000Z", TimeSpan.TicksPerMinute)]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T12:00:00.0000000Z", TimeSpan.TicksPerHour)]
    [InlineData("2023-01-02T12:34:56.7891234Z", "2023-01-02T00:00:00.0000000Z", TimeSpan.TicksPerDay)]
    public void WhenTruncate(string input, string expected, long tickSpan)
    {
        DateTime.Parse(input).Truncate(tickSpan).Is(DateTime.Parse(expected));
        DateTimeOffset.Parse(input).Truncate(tickSpan).Is(DateTimeOffset.Parse(expected));

        return;
    }

}
