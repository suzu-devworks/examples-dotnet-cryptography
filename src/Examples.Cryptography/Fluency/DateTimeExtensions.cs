using System;

namespace Examples.Fluency;

/// <summary>
/// Extension methods for <see cref="DateTime" /> and <see cref="DateTimeOffset" />.
/// </summary>
public static class DateTimeExtensions
{
    /// <summary>
    /// Truncate time by <paramref name="ticksPerAny" /> value.
    /// </summary>
    /// <param name="value">A <see cref="DateTime" /> instance containing the time.</param>
    /// <param name="ticksPerAny">A baseline value, such as the constant <see cref="TimeSpan.TicksPerSecond" />.</param>
    /// <returns>Truncated <see cref="DateTime" /> instance.</returns>
    public static DateTime Truncate(this DateTime value, long ticksPerAny = TimeSpan.TicksPerSecond)
        => value.AddTicks((value.Ticks % ticksPerAny) * -1);

    /// <summary>
    /// Truncate time by <paramref name="ticksPerAny" /> value.
    /// </summary>
    /// <param name="value"><see cref="DateTimeOffset" /> instance containing the time</param>
    /// <param name="ticksPerAny">A baseline value, such as the constant <see cref="TimeSpan.TicksPerSecond" />.</param>
    /// <returns>Truncated <see cref="DateTimeOffset" /> instance.</returns>
    public static DateTimeOffset Truncate(this DateTimeOffset value, long ticksPerAny = TimeSpan.TicksPerSecond)
        => value.AddTicks((value.Ticks % ticksPerAny) * -1);

}
