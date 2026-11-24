//! Small time helpers. Rousseau stores every timestamp as milliseconds since
//! the Unix epoch (UTC) so that Rust, SQLite, JavaScript and Python agree.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        // The clock is before 1970: treat as epoch rather than panicking.
        Err(_) => 0,
    }
}

/// Converts a Windows FILETIME (100 ns intervals since 1601-01-01) to Unix ms.
pub fn filetime_to_ms(ft: i64) -> i64 {
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    (ft - EPOCH_DIFF_100NS) / 10_000
}

/// Parses a duration such as `500ms`, `60s`, `5m` or `1h` into milliseconds.
pub fn parse_duration_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else {
        let n = s.strip_suffix('h')?;
        (n, 3_600_000)
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse::<i64>().ok()?.checked_mul(mult)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parses an RFC 3339 timestamp (`2026-01-31T12:34:56.789Z`, offsets allowed)
/// into Unix milliseconds. Returns `None` on anything malformed; transcript
/// adapters treat that as "no timestamp" rather than failing.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't' || b[10] == b' ') {
        return None;
    }
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if b[13] != b':' || b[16] != b':' || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut i = 19;
    let mut frac_ms = 0i64;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = s.get(start..i)?;
        if digits.is_empty() {
            return None;
        }
        let padded: String = digits.chars().chain("000".chars()).take(3).collect();
        frac_ms = padded.parse().ok()?;
    }
    let offset_min = match b.get(i) {
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let v = oh * 60 + om;
            if *sign == b'-' { -v } else { v }
        }
        None => 0,
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + h * 3_600 + mi * 60 + se - offset_min * 60;
    Some(secs * 1_000 + frac_ms)
}

/// Formats Unix milliseconds as an RFC 3339 UTC timestamp with milliseconds.
pub fn format_rfc3339_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1_000);
    let millis = ms.rem_euclid(1_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("500ms"), Some(500));
        assert_eq!(parse_duration_ms("60s"), Some(60_000));
        assert_eq!(parse_duration_ms("5m"), Some(300_000));
        assert_eq!(parse_duration_ms("1h"), Some(3_600_000));
        assert_eq!(parse_duration_ms("1.5s"), None);
        assert_eq!(parse_duration_ms("s"), None);
        assert_eq!(parse_duration_ms("10"), None);
    }

    #[test]
    fn rfc3339_round_trip() {
        let ms = parse_rfc3339_ms("2026-02-03T04:05:06.789Z").unwrap();
        assert_eq!(format_rfc3339_ms(ms), "2026-02-03T04:05:06.789Z");
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("2026-02-03T05:05:06.789+01:00"), Some(ms));
        assert_eq!(parse_rfc3339_ms("2026-02-03T04:05:06.7891234Z"), Some(ms));
        assert_eq!(parse_rfc3339_ms("garbage"), None);
        assert_eq!(parse_rfc3339_ms("2026-13-03T04:05:06Z"), None);
    }

    #[test]
    fn filetime() {
        assert_eq!(filetime_to_ms(116_444_736_000_000_000), 0);
        assert_eq!(filetime_to_ms(116_444_736_000_000_000 + 10_000), 1);
    }
}
