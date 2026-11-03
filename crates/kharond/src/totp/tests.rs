//! REQ-API-007 TOTP vectors and parsing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kharon_bwcrypto::Secret;
use zeroize::Zeroizing;

use super::skew::{ClockSample, ClockSkewGate, SkewPolicy, SkewVerdict};
use super::{Algorithm, Encoding, TotpError, TotpKey};
use crate::audit::Event;

const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// RFC 6238 Appendix B: (time, SHA1, SHA256, SHA512), 8 digits, 30 s.
const RFC6238: &[(u64, &str, &str, &str)] = &[
    (59, "94287082", "46119246", "90693936"),
    (1_111_111_109, "07081804", "68084774", "25091201"),
    (1_111_111_111, "14050471", "67062674", "99943326"),
    (1_234_567_890, "89005924", "91819424", "93441116"),
    (2_000_000_000, "69279037", "90698825", "38618901"),
    (20_000_000_000, "65353130", "77737706", "47863826"),
];

fn key(seed: &[u8], alg: Algorithm, enc: Encoding) -> TotpKey {
    TotpKey::from_parts(Zeroizing::new(seed.to_vec()), alg, enc, 30).unwrap()
}

fn parse(s: &str) -> Result<TotpKey, TotpError> {
    TotpKey::parse(&Secret::new(s.to_string()))
}

#[test]
fn req_api_007_rfc6238_vectors_sha1_sha256_sha512() {
    let eight = Encoding::Decimal { digits: 8 };
    let k1 = key(SEED_SHA1, Algorithm::Sha1, eight);
    let k256 = key(SEED_SHA256, Algorithm::Sha256, eight);
    let k512 = key(SEED_SHA512, Algorithm::Sha512, eight);
    for &(t, c1, c256, c512) in RFC6238 {
        assert_eq!(k1.code_at(t).as_str(), c1, "sha1 t={t}");
        assert_eq!(k256.code_at(t).as_str(), c256, "sha256 t={t}");
        assert_eq!(k512.code_at(t).as_str(), c512, "sha512 t={t}");
    }
}

#[test]
fn req_api_007_adjacent_steps_t_minus_1_t_t_plus_1() {
    // RFC 4226 Appendix D HOTP values are the TOTP codes for counters
    // 0..9 (SHA1, 6 digits); t = 29/59/89 are steps 0/1/2.
    let k = key(SEED_SHA1, Algorithm::Sha1, Encoding::Decimal { digits: 6 });
    assert_eq!(k.code_at(29).as_str(), "755224"); // T-1
    assert_eq!(k.code_at(59).as_str(), "287082"); // T
    assert_eq!(k.code_at(89).as_str(), "359152"); // T+1
    assert_eq!(k.counter_at(59), 1);

    // RFC 6238 vectors 1111111109 and 1111111111 straddle a step
    // boundary: steps T and T+1 for every algorithm; and code_at(t ± 30)
    // is exactly code_for_counter(T ± 1).
    let eight = Encoding::Decimal { digits: 8 };
    for (seed, alg, idx) in [
        (SEED_SHA1, Algorithm::Sha1, 0),
        (SEED_SHA256, Algorithm::Sha256, 1),
        (SEED_SHA512, Algorithm::Sha512, 2),
    ] {
        let k = key(seed, alg, eight);
        let t = 1_111_111_109;
        let step = k.counter_at(t);
        assert_eq!(k.counter_at(1_111_111_111), step + 1);
        let pick = |row: &(u64, &'static str, &'static str, &'static str)| match idx {
            0 => row.1,
            1 => row.2,
            _ => row.3,
        };
        assert_eq!(k.code_for_counter(step).as_str(), pick(&RFC6238[1]));
        assert_eq!(k.code_for_counter(step + 1).as_str(), pick(&RFC6238[2]));
        assert_eq!(k.code_at(t - 30), k.code_for_counter(step - 1));
        assert_eq!(k.code_at(t + 30), k.code_for_counter(step + 1));
        assert_ne!(k.code_at(t - 30), k.code_at(t));
    }
}

#[test]
fn req_api_007_steam_vector() {
    // another-steam-totp's vector: shared secret 0xd34d… (20 bytes).
    let k = parse("steam://2NGTJU2NGTJU2NGTJU2NGTJU2NGTJU2N").unwrap();
    assert_eq!(k.encoding(), Encoding::Steam);
    assert_eq!(k.algorithm(), Algorithm::Sha1);
    assert_eq!(k.period(), 30);
    assert_eq!(k.code_at(1_634_603_498).as_str(), "2C5H2");
    let code = k.code_at(0);
    assert_eq!(code.len(), 5);
    assert!(
        code.chars()
            .all(|c| "23456789BCDFGHJKMNPQRTVWXY".contains(c))
    );
}

#[test]
fn req_api_007_otpauth_uri_parameters() {
    // base32("12345678901234567890") with SHA256/8 digits/60 s.
    let k = parse(
        "otpauth://totp/ACME%20Co:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
         &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
    )
    .unwrap();
    assert_eq!(k.algorithm(), Algorithm::Sha256);
    assert_eq!(k.encoding(), Encoding::Decimal { digits: 8 });
    assert_eq!(k.period(), 60);

    // Defaults: SHA1, 6 digits, 30 s; lower-case secret and algorithm.
    let k =
        parse("otpauth://totp/x?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&algorithm=sha1").unwrap();
    assert_eq!(k.algorithm(), Algorithm::Sha1);
    assert_eq!(k.encoding(), Encoding::Decimal { digits: 6 });
    assert_eq!(k.period(), 30);
    assert_eq!(k.code_at(59).as_str(), "287082");

    // SHA512 seed via otpauth matches the RFC vector.
    let k = parse(
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&algorithm=SHA512&digits=8",
    )
    .unwrap();
    assert_eq!(k.code_at(59).as_str(), "90693936");
}

#[test]
fn req_api_007_bare_base32_secret() {
    let k = parse("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ").unwrap();
    assert_eq!(k.algorithm(), Algorithm::Sha1);
    assert_eq!(k.encoding(), Encoding::Decimal { digits: 6 });
    assert_eq!(k.code_at(59).as_str(), "287082");
    let padded = parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====").unwrap();
    assert_eq!(padded.code_at(59).as_str(), "287082");
}

#[test]
fn req_api_007_rejects_unsupported_fields() {
    assert_eq!(parse("").err(), Some(TotpError::Empty));
    assert_eq!(parse("   ").err(), Some(TotpError::Empty));
    assert_eq!(
        parse("otpauth://hotp/x?secret=GEZDGNBV&counter=1").err(),
        Some(TotpError::UnsupportedType)
    );
    assert_eq!(
        parse("https://example.com/").err(),
        Some(TotpError::UnsupportedType)
    );
    assert_eq!(
        parse("otpauth://totp/x?issuer=a").err(),
        Some(TotpError::MissingSecret)
    );
    assert_eq!(parse("not base32!").err(), Some(TotpError::InvalidSecret));
    assert_eq!(
        parse("otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5").err(),
        Some(TotpError::InvalidAlgorithm)
    );
    assert_eq!(
        parse("otpauth://totp/x?secret=GEZDGNBV&digits=4").err(),
        Some(TotpError::InvalidDigits)
    );
    assert_eq!(
        parse("otpauth://totp/x?secret=GEZDGNBV&period=0").err(),
        Some(TotpError::InvalidPeriod)
    );
    assert_eq!(
        parse("otpauth://totp/x?secret=GEZDGNBV&secret=GEZDGNBV").err(),
        Some(TotpError::Malformed)
    );
    assert_eq!(
        parse(&"A".repeat(super::MAX_FIELD_LEN + 1)).err(),
        Some(TotpError::TooLong)
    );
}

#[test]
fn req_api_007_key_debug_redacts() {
    let k = parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let dbg = format!("{k:?}");
    assert!(!dbg.contains("GEZD"), "{dbg}");
    assert!(!dbg.contains("12345678"), "{dbg}");
    assert!(!dbg.contains("49, 50"), "{dbg}");
}

#[test]
fn req_api_007_code_now_before_epoch() {
    let k = parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    let before = UNIX_EPOCH - Duration::from_secs(1);
    assert_eq!(k.code_now(before).err(), Some(TotpError::ClockBeforeEpoch));
    assert_eq!(
        k.code_now(UNIX_EPOCH + Duration::from_secs(59))
            .unwrap()
            .as_str(),
        "287082"
    );
}

fn sample(skew_secs: i64) -> ClockSample {
    let server = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let local = if skew_secs >= 0 {
        server + Duration::from_secs(skew_secs as u64)
    } else {
        server - Duration::from_secs(skew_secs.unsigned_abs())
    };
    ClockSample { server, local }
}

#[test]
fn req_api_007_skew_thresholds() {
    let p = SkewPolicy::default();
    assert_eq!(p.classify(Duration::from_secs(30)), SkewVerdict::Ok);
    assert_eq!(p.classify(Duration::from_secs(31)), SkewVerdict::Warn);
    assert_eq!(p.classify(Duration::from_secs(90)), SkewVerdict::Warn);
    assert_eq!(p.classify(Duration::from_secs(91)), SkewVerdict::Refuse);
    assert_eq!(sample(-45).skew_secs(), -45);
    assert_eq!(sample(-45).abs_skew(), Duration::from_secs(45));
}

#[test]
fn req_api_007_skew_45s_warns_only() {
    let gate = ClockSkewGate::default();
    assert!(gate.check_totp().is_ok(), "unmeasured gate is open");
    for skew in [45, -45] {
        let obs = gate.observe(sample(skew));
        assert_eq!(obs.verdict, SkewVerdict::Warn);
        assert!(obs.warning.is_some());
        let e = obs.audit.expect("clock_skew audit entry");
        assert_eq!(e.event, Event::ClockSkew);
        assert_eq!(e.result.as_deref(), Some("warn"));
        assert!(gate.check_totp().is_ok(), "45 s is warn-only");
    }
}

#[test]
fn req_api_007_skew_120s_refuses_until_resolved() {
    let gate = ClockSkewGate::default();
    let obs = gate.observe(sample(120));
    assert_eq!(obs.verdict, SkewVerdict::Refuse);
    assert_eq!(obs.skew_secs, 120);
    let e = obs.audit.expect("clock_skew audit entry");
    assert_eq!(e.event, Event::ClockSkew);
    assert_eq!(e.result.as_deref(), Some("refuse"));
    assert_eq!(e.detail_code.as_deref(), Some("skew_+120s"));
    assert!(gate.check_totp().is_err());

    // Resolved by a later in-threshold sample.
    let obs = gate.observe(sample(2));
    assert_eq!(obs.verdict, SkewVerdict::Ok);
    assert_eq!(
        obs.audit.expect("resolution audited").result.as_deref(),
        Some("resolved")
    );
    assert!(gate.check_totp().is_ok());
    // A steady Ok is not audited.
    assert!(gate.observe(sample(1)).audit.is_none());
}

#[test]
fn req_api_007_date_header_parse() {
    let local = UNIX_EPOCH + Duration::from_secs(784_111_777 + 120);
    let s = ClockSample::from_date_header("Sun, 06 Nov 1994 08:49:37 GMT", local).unwrap();
    assert_eq!(s.server, UNIX_EPOCH + Duration::from_secs(784_111_777));
    assert_eq!(s.skew_secs(), 120);
    assert!(ClockSample::from_date_header("yesterday", SystemTime::now()).is_none());
}
