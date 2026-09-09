//! RFC 5424 input validation and RFC 6012 octet-count framing.
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = message.len().to_string().into_bytes();
    out.push(b' ');
    out.extend_from_slice(message);
    out
}

/// Validate the RFC 5424 header and structured data, preserving arbitrary MSG bytes.
pub fn valid_message(m: &[u8]) -> bool {
    if m.first() != Some(&b'<') {
        return false;
    }
    let Some(end) = m.iter().position(|b| *b == b'>') else {
        return false;
    };
    let pri = &m[1..end];
    if pri.is_empty()
        || pri.len() > 3
        || !pri.iter().all(u8::is_ascii_digit)
        || (pri.len() > 1 && pri[0] == b'0')
    {
        return false;
    }
    if std::str::from_utf8(pri)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .is_none_or(|p| p > 191)
    {
        return false;
    }
    let mut rest = &m[end + 1..];
    let mut fields = Vec::with_capacity(6);
    for _ in 0..6 {
        let Some(n) = rest.iter().position(|b| *b == b' ') else {
            return false;
        };
        fields.push(&rest[..n]);
        rest = &rest[n + 1..];
    }
    if fields[0] != b"1" {
        return false;
    }
    if fields[1] != b"-" {
        let Ok(ts) = std::str::from_utf8(fields[1]) else {
            return false;
        };
        if !ts.contains('T')
            || !(ts.ends_with('Z')
                || ts
                    .get(19..)
                    .is_some_and(|s| s.contains('+') || s.contains('-')))
            || OffsetDateTime::parse(ts, &Rfc3339).is_err()
        {
            return false;
        }
        if let Some((_, frac)) = ts.split_once('.') {
            if frac.bytes().take_while(u8::is_ascii_digit).count() > 6 {
                return false;
            }
        }
        if ts.get(17..19) == Some("60") {
            return false;
        }
    }
    for (field, max) in fields[2..].iter().zip([255, 48, 128, 32]) {
        if field.is_empty() || field.len() > max || !field.iter().all(|c| (33..=126).contains(c)) {
            return false;
        }
    }
    if rest.first() == Some(&b'-') {
        return valid_tail(&rest[1..]);
    }
    let mut ids: Vec<&[u8]> = Vec::new();
    while rest.first() == Some(&b'[') {
        rest = &rest[1..];
        let n = rest
            .iter()
            .position(|b| *b == b' ' || *b == b']')
            .unwrap_or(rest.len());
        let id = &rest[..n];
        if !sd_name(id) || ids.contains(&id) {
            return false;
        }
        ids.push(id);
        rest = &rest[n..];
        while rest.first() == Some(&b' ') {
            rest = &rest[1..];
            let Some(n) = rest.iter().position(|b| *b == b'=') else {
                return false;
            };
            if !sd_name(&rest[..n]) || rest.get(n + 1) != Some(&b'"') {
                return false;
            }
            rest = &rest[n + 2..];
            let mut i = 0;
            loop {
                match rest.get(i) {
                    Some(b'"') => break,
                    Some(b']') | None => return false,
                    Some(b'\\')
                        if rest
                            .get(i + 1)
                            .is_some_and(|b| matches!(b, b'"' | b'\\' | b']')) =>
                    {
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            if std::str::from_utf8(&rest[..i]).is_err() {
                return false;
            }
            rest = &rest[i + 1..];
        }
        if rest.first() != Some(&b']') {
            return false;
        }
        rest = &rest[1..];
    }
    !ids.is_empty() && valid_tail(rest)
}
fn sd_name(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.iter()
            .all(|b| (33..=126).contains(b) && !matches!(b, b'=' | b']' | b'"'))
}
fn valid_tail(s: &[u8]) -> bool {
    if s.is_empty() {
        return true;
    }
    if s[0] != b' ' {
        return false;
    }
    let msg = &s[1..];
    !msg.starts_with(&[0xef, 0xbb, 0xbf]) || std::str::from_utf8(msg).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn octets_not_characters() {
        assert_eq!(frame("å\n".as_bytes()), b"3 \xc3\xa5\n");
    }
    #[test]
    fn messages() {
        for m in [
            b"<34>1 - host app - ID - hello".as_slice(),
            b"<0>1 2026-09-09T12:00:00.123Z h a p m [x a=\"escaped\\]value\"] \xff",
        ] {
            assert!(valid_message(m));
        }
        for m in [
            b"".as_slice(),
            b"<34>Sep  9 host legacy",
            b"<192>1 - h a p m - x",
            b"<34>1 - h a p m [x a=\"bad]value\"]",
            b"<34>1 - h a p m [x][x]",
        ] {
            assert!(!valid_message(m));
        }
    }
}
