#![cfg(feature = "postgres")]

//! Postgres `INTERVAL` → ISO 8601 duration string conversion.
//!
//! # Why three components?
//!
//! Postgres preserves the calendar/clock distinction in its `INTERVAL`
//! type. A `PgInterval` exposes three independent signed fields:
//!
//! * `months` — calendar months. Not 30-day buckets: 1 month is
//!   *whatever the calendar says it is* on a given date.
//! * `days` — calendar days. Not 24×60×60×1_000_000 µs:
//!   the duration of a "day" varies on DST boundaries.
//! * `microseconds` — clock duration with microsecond precision.
//!
//! Collapsing the three into a single total-seconds count would lose
//! information (e.g. `1 month` and `30 days` are not equivalent), so
//! we map each component into the matching ISO 8601 designator and
//! preserve them separately.
//!
//! # Output shape
//!
//! `P[Y]Y[M]M[D]DT[H]H[M]M[S]S` — components with a zero value are
//! skipped. The empty interval renders as the canonical `"PT0S"`,
//! which ISO 8601 requires (a duration must contain at least one
//! designator).
//!
//! Subsecond precision is microseconds (Postgres's native resolution).
//! When the seconds component has any non-zero fractional part we
//! emit `{secs}.{frac}S` with 1–6 fractional digits, trailing zeros
//! stripped (`1.5S`, not `1.500000S`). The integer seconds field is
//! emitted *only* when needed — but if the fractional part is
//! non-zero we always emit `0.{frac}S` rather than dropping the
//! seconds field entirely (otherwise the fractional info would be
//! lost). Other zero components (years, months, days, hours, minutes)
//! follow the strict skip-zero rule.
//!
//! # Sign handling
//!
//! Postgres allows mixed-sign intervals like `INTERVAL '1 month -3
//! days'`. ISO 8601 has no native syntax for mixed signs — a leading
//! `-` applies to the entire duration.
//!
//! * **Uniform negative** (every non-zero component ≤ 0): emit a
//!   leading `-` and unsigned components.
//! * **Uniform positive or zero**: no sign prefix.
//! * **Mixed signs**: emit absolute values without a leading minus
//!   and log a `tracing::warn!` at target `mcpg::sql::interval` —
//!   this is a known lossy fallback.
//!
//! # Overflow safety
//!
//! `i32::MIN` and `i64::MIN` cannot be negated in two's complement
//! (`-i32::MIN` overflows). We use `unsigned_abs()` so extreme values
//! convert cleanly to `u32` / `u64` without panicking.

use std::fmt::Write as _;

use sqlx::postgres::types::PgInterval;

/// Microseconds in one second.
const US_PER_SEC: u64 = 1_000_000;
/// Seconds in one minute.
const SEC_PER_MIN: u64 = 60;
/// Seconds in one hour.
const SEC_PER_HOUR: u64 = 3_600;

/// Render a `PgInterval` as an ISO 8601 duration string.
///
/// See the module docs for the conversion rules. The function never
/// panics, including on `i32::MIN` / `i64::MIN` extremes, and never
/// allocates more than the final string.
///
/// # Mixed-sign limitation
///
/// ISO 8601 cannot express durations whose components disagree in
/// sign (e.g. `+1 month -3 days`). When given such an input the
/// output is the absolute value of every component without a leading
/// minus, and a `tracing::warn!` is emitted at target
/// `mcpg::sql::interval` carrying the original components and the
/// lossy ISO output.
pub(crate) fn pg_interval_to_iso8601(iv: &PgInterval) -> String {
    // Canonical zero — ISO 8601 requires at least one designator.
    if iv.months == 0 && iv.days == 0 && iv.microseconds == 0 {
        return "PT0S".to_string();
    }

    let sign = classify_sign(iv.months, iv.days, iv.microseconds);

    let abs_months: u32 = iv.months.unsigned_abs();
    let abs_days: u32 = iv.days.unsigned_abs();
    let abs_micros: u64 = iv.microseconds.unsigned_abs();

    let years: u32 = abs_months / 12;
    let rem_months: u32 = abs_months % 12;

    let total_secs: u64 = abs_micros / US_PER_SEC;
    let frac_micros: u32 = (abs_micros % US_PER_SEC) as u32;

    let hours: u64 = total_secs / SEC_PER_HOUR;
    let rem_after_hours: u64 = total_secs % SEC_PER_HOUR;
    let minutes: u64 = rem_after_hours / SEC_PER_MIN;
    let seconds: u64 = rem_after_hours % SEC_PER_MIN;

    // Pre-size the buffer. 64 bytes covers every reasonable interval
    // and extreme values still fit without re-allocating much.
    let mut out = String::with_capacity(32);

    if matches!(sign, Sign::Negative) {
        out.push('-');
    }
    out.push('P');

    if years != 0 {
        // Writes to a String are infallible.
        let _ = write!(out, "{years}Y");
    }
    if rem_months != 0 {
        let _ = write!(out, "{rem_months}M");
    }
    if abs_days != 0 {
        let _ = write!(out, "{abs_days}D");
    }

    let has_time = abs_micros != 0;
    if has_time {
        out.push('T');
        if hours != 0 {
            let _ = write!(out, "{hours}H");
        }
        if minutes != 0 {
            let _ = write!(out, "{minutes}M");
        }
        // Seconds field: emit when integer seconds non-zero OR when
        // there's a non-zero fractional remainder. Otherwise (all
        // sub-second carry was absorbed into hours/minutes) skip it.
        if seconds != 0 || frac_micros != 0 {
            if frac_micros == 0 {
                let _ = write!(out, "{seconds}S");
            } else {
                let frac = format_frac_micros(frac_micros);
                let _ = write!(out, "{seconds}.{frac}S");
            }
        }
    }

    if matches!(sign, Sign::Mixed) {
        tracing::warn!(
            target: "mcpg::sql::interval",
            months = iv.months,
            days = iv.days,
            microseconds = iv.microseconds,
            iso = %out,
            "postgres INTERVAL has mixed-sign components; ISO 8601 cannot express \
             this faithfully — emitting absolute components"
        );
    }

    out
}

/// Sign classification of the three `PgInterval` components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sign {
    /// All non-zero components are positive (or every component is zero).
    Positive,
    /// All non-zero components are negative.
    Negative,
    /// Components disagree in sign — ISO 8601 cannot express this faithfully.
    Mixed,
}

/// Classify the overall sign of an interval given its three components.
fn classify_sign(months: i32, days: i32, micros: i64) -> Sign {
    let any_pos = months > 0 || days > 0 || micros > 0;
    let any_neg = months < 0 || days < 0 || micros < 0;
    match (any_pos, any_neg) {
        (true, true) => Sign::Mixed,
        (false, true) => Sign::Negative,
        // (true, false) and (false, false) — uniform positive, or all zero.
        _ => Sign::Positive,
    }
}

/// Format the fractional-microseconds remainder as 1–6 digits with
/// trailing zeros stripped.
///
/// Caller guarantees `frac < 1_000_000` (i.e. a valid `µs % 1_000_000`).
/// Examples: `500_000` → `"5"`, `1` → `"000001"`, `100_000` → `"1"`.
fn format_frac_micros(frac: u32) -> String {
    debug_assert!(frac < 1_000_000);
    // Always produce 6 digits, then trim trailing zeros.
    let mut s = format!("{frac:06}");
    while s.ends_with('0') {
        s.pop();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(months: i32, days: i32, micros: i64) -> PgInterval {
        PgInterval {
            months,
            days,
            microseconds: micros,
        }
    }

    // ----- canonical zero -----

    #[test]
    fn zero_interval_is_pt0s() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 0)), "PT0S");
    }

    // ----- single positive component -----

    #[test]
    fn single_positive_day() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 1, 0)), "P1D");
    }

    #[test]
    fn five_days_only() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 5, 0)), "P5D");
    }

    #[test]
    fn single_positive_hour() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 3_600_000_000)), "PT1H");
    }

    #[test]
    fn single_positive_minute() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 60_000_000)), "PT1M");
    }

    #[test]
    fn single_positive_second() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1_000_000)), "PT1S");
    }

    // ----- combined positive -----

    #[test]
    fn full_positive_combo() {
        // 1 year 2 months 3 days 4h 5m 6s
        let micros = 4 * 3_600_000_000_i64 + 5 * 60_000_000 + 6_000_000;
        assert_eq!(pg_interval_to_iso8601(&iv(14, 3, micros)), "P1Y2M3DT4H5M6S");
    }

    #[test]
    fn time_only_combo() {
        // 2h 30m
        let micros = 2 * 3_600_000_000_i64 + 30 * 60_000_000;
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, micros)), "PT2H30M");
    }

    // ----- fractional precision -----

    #[test]
    fn one_microsecond() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1)), "PT0.000001S");
    }

    #[test]
    fn one_millisecond() {
        // 1 ms = 1000 µs → 0.001 s
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1_000)), "PT0.001S");
    }

    #[test]
    fn half_second() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 500_000)), "PT0.5S");
    }

    #[test]
    fn one_point_one_seconds_strips_trailing_zeros() {
        // 1.1s — must NOT render as 1.100000S
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1_100_000)), "PT1.1S");
    }

    #[test]
    fn six_digit_fractional_full_precision() {
        // 1.234567s
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1_234_567)), "PT1.234567S");
    }

    #[test]
    fn one_and_a_half_seconds() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 1_500_000)), "PT1.5S");
    }

    // ----- roll-up: don't emit "60S" / "60M" -----

    #[test]
    fn sixty_seconds_rolls_to_one_minute() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 60_000_000)), "PT1M");
    }

    #[test]
    fn thirty_six_hundred_seconds_rolls_to_one_hour() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, 3_600_000_000)), "PT1H");
    }

    #[test]
    fn twelve_months_rolls_to_one_year_no_remainder() {
        assert_eq!(pg_interval_to_iso8601(&iv(12, 0, 0)), "P1Y");
    }

    #[test]
    fn twenty_five_months_rolls_to_two_years_one_month() {
        assert_eq!(pg_interval_to_iso8601(&iv(25, 0, 0)), "P2Y1M");
    }

    #[test]
    fn thirteen_months_is_one_year_one_month() {
        assert_eq!(pg_interval_to_iso8601(&iv(13, 0, 0)), "P1Y1M");
    }

    // ----- skip-zero rules -----

    #[test]
    fn skip_zero_month_in_combo() {
        // 24 months → P2Y, not P2Y0M
        assert_eq!(pg_interval_to_iso8601(&iv(24, 0, 0)), "P2Y");
    }

    #[test]
    fn skip_zero_minutes_between_hours_and_seconds() {
        // 1 hour + 1 µs: minutes=0 should be dropped per rule 8;
        // seconds field stays because fractional is non-zero.
        let micros = 3_600_000_000_i64 + 1;
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, micros)), "PT1H0.000001S");
    }

    #[test]
    fn day_plus_hour_no_minutes_or_seconds() {
        // 1 day + 2 hours → P1DT2H, NOT P1DT2H0M0S
        let micros = 2 * 3_600_000_000_i64;
        assert_eq!(pg_interval_to_iso8601(&iv(0, 1, micros)), "P1DT2H");
    }

    // ----- negative single component -----

    #[test]
    fn negative_one_day() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, -1, 0)), "-P1D");
    }

    #[test]
    fn negative_one_hour() {
        assert_eq!(pg_interval_to_iso8601(&iv(0, 0, -3_600_000_000)), "-PT1H");
    }

    #[test]
    fn negative_one_month() {
        assert_eq!(pg_interval_to_iso8601(&iv(-1, 0, 0)), "-P1M");
    }

    #[test]
    fn negative_day_and_hour() {
        // -1 day -1 hour
        assert_eq!(
            pg_interval_to_iso8601(&iv(0, -1, -3_600_000_000)),
            "-P1DT1H"
        );
    }

    // ----- negative all components -----

    #[test]
    fn negative_full_combo_with_fractional() {
        // -(1y 2mo 3d 4h 5m 6.789012s)
        let micros = -(4 * 3_600_000_000_i64 + 5 * 60_000_000 + 6_000_000 + 789_012);
        assert_eq!(
            pg_interval_to_iso8601(&iv(-14, -3, micros)),
            "-P1Y2M3DT4H5M6.789012S"
        );
    }

    // ----- mixed sign -----

    #[test]
    fn mixed_sign_emits_absolute_values_no_leading_minus() {
        // 1 month -3 days. Lossy ISO fallback: P1M3D, no sign.
        // We don't assert on the warn here (would require tracing-test);
        // the absence of a panic and the expected string are sufficient.
        assert_eq!(pg_interval_to_iso8601(&iv(1, -3, 0)), "P1M3D");
    }

    #[test]
    fn mixed_sign_three_way() {
        // +1 month, -1 day, +1 second → still mixed (months and days disagree).
        // Output: P1M1DT1S, no leading minus.
        assert_eq!(pg_interval_to_iso8601(&iv(1, -1, 1_000_000)), "P1M1DT1S");
    }

    // ----- extreme overflow guards -----

    #[test]
    fn i64_min_microseconds_does_not_panic() {
        // -i64::MIN overflows in two's complement. unsigned_abs() must
        // handle this. The exact output isn't asserted in detail — we
        // just need it to render and start with "-P".
        let s = pg_interval_to_iso8601(&iv(0, 0, i64::MIN));
        assert!(s.starts_with("-P"), "got: {s}");
        // i64::MIN µs is a huge but valid duration; verify it ends in S.
        assert!(s.ends_with('S'), "got: {s}");
    }

    #[test]
    fn i32_min_days_does_not_panic() {
        let s = pg_interval_to_iso8601(&iv(0, i32::MIN, 0));
        assert!(s.starts_with("-P"), "got: {s}");
        assert!(s.contains('D'), "got: {s}");
    }

    #[test]
    fn i32_min_months_does_not_panic() {
        let s = pg_interval_to_iso8601(&iv(i32::MIN, 0, 0));
        assert!(s.starts_with("-P"), "got: {s}");
    }

    #[test]
    fn all_extremes_no_panic() {
        // months: i32::MIN → unsigned_abs = 2_147_483_648
        // years = 178_956_970, remainder months = 8
        let s = pg_interval_to_iso8601(&iv(i32::MIN, i32::MIN, i64::MIN));
        assert!(s.starts_with("-P"));
        assert!(s.contains('Y'));
        assert!(s.contains('D'));
        assert!(s.contains('T'));
    }

    // ----- helper unit checks -----

    #[test]
    fn classify_sign_all_zero_is_positive() {
        assert_eq!(classify_sign(0, 0, 0), Sign::Positive);
    }

    #[test]
    fn classify_sign_all_positive() {
        assert_eq!(classify_sign(1, 2, 3), Sign::Positive);
    }

    #[test]
    fn classify_sign_all_negative() {
        assert_eq!(classify_sign(-1, -2, -3), Sign::Negative);
    }

    #[test]
    fn classify_sign_one_negative_two_zero_is_negative() {
        // Zero components don't break the "uniform negative" rule.
        assert_eq!(classify_sign(0, -1, 0), Sign::Negative);
    }

    #[test]
    fn classify_sign_one_pos_one_neg_is_mixed() {
        assert_eq!(classify_sign(1, -1, 0), Sign::Mixed);
    }

    #[test]
    fn format_frac_micros_strips_trailing_zeros() {
        assert_eq!(format_frac_micros(500_000), "5");
        assert_eq!(format_frac_micros(100_000), "1");
        assert_eq!(format_frac_micros(123_456), "123456");
        assert_eq!(format_frac_micros(1), "000001");
        assert_eq!(format_frac_micros(123), "000123");
    }
}
