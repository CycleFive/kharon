//! Duration strings: `<integer><unit>` with unit `ms`, `s`, `m`, `h`, `d`
//! (SPEC uses "10s", "30m", "12h", "30 d"). One unit per value; no
//! fractions, signs, or compound forms, so every value has one reading.

use std::time::Duration;

/// Parse `"30m"`-style durations. Surrounding whitespace and one optional
/// space between number and unit are accepted. Returns `None` on any
/// other shape or on overflow.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit);
    let secs_per = match unit {
        "ms" => return Some(Duration::from_millis(n)),
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    n.checked_mul(secs_per).map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_dep_003_duration_units() {
        assert_eq!(parse_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43200)));
        assert_eq!(parse_duration("30 d"), Some(Duration::from_secs(2_592_000)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("0s"), Some(Duration::ZERO));
    }

    #[test]
    fn req_dep_003_duration_rejects_other_shapes() {
        for bad in [
            "",
            "s",
            "10",
            "-1s",
            "1.5s",
            "10x",
            "1h30m",
            "10  s",
            "ten s",
            "18446744073709551615d",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }
}
