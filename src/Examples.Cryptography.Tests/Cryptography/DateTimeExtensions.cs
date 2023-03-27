namespace Examples.Cryptography;

public static class DateTimeExtensions
{
    public static DateTime Truncate(this DateTime value, long ticksPerAny = TimeSpan.TicksPerSecond)
    => value.AddTicks((value.Ticks % ticksPerAny) * -1);

    public static DateTimeOffset Truncate(this DateTimeOffset value, long ticksPerAny = TimeSpan.TicksPerSecond)
        => value.AddTicks((value.Ticks % ticksPerAny) * -1);

}
