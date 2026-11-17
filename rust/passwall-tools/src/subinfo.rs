use chrono::Datelike;

use crate::value::json_string;

pub struct SubInfo {
    pub rem_traffic: String,
    pub expired_date: String,
}

impl SubInfo {
    pub fn json(&self) -> String {
        format!(
            "{{\"rem_traffic\":{},\"expired_date\":{}}}",
            json_string(&self.rem_traffic),
            json_string(&self.expired_date)
        )
    }
}

pub fn parse_subscription_userinfo(headers: &str) -> Option<SubInfo> {
    parse_subscription_userinfo_with(headers, local_ymd)
}

fn parse_subscription_userinfo_with(
    headers: &str,
    ymd: impl Fn(i64) -> Option<(i32, u32, u32)>,
) -> Option<SubInfo> {
    let userinfo = userinfo_value(headers)?;
    let upload = take_int(userinfo, "upload").unwrap_or(0);
    let download = take_int(userinfo, "download").unwrap_or(0);
    let total = take_int(userinfo, "total").unwrap_or(0);
    let remain = (total - (upload + download)).max(0);
    let expired_date = match take_int(userinfo, "expire") {
        Some(expire) if expire > 0 => match ymd(expire) {
            Some((year, month, day)) => format!("{year}-{month}-{day}"),
            None => "长期有效".to_string(),
        },
        _ => "长期有效".to_string(),
    };
    Some(SubInfo {
        rem_traffic: format_size(remain as f64),
        expired_date,
    })
}

fn local_ymd(ts: i64) -> Option<(i32, u32, u32)> {
    let dt = chrono::DateTime::from_timestamp(ts, 0)?;
    let local = dt.with_timezone(&chrono::Local);
    Some((local.year(), local.month(), local.day()))
}

fn userinfo_value(headers: &str) -> Option<&str> {
    let bytes = headers.as_bytes();
    let needle = b"ubscription-userinfo:";
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'S' | b's')
            && bytes
                .get(i + 1..)
                .is_some_and(|rest| rest.starts_with(needle))
        {
            let mut j = i + 1 + needle.len();
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            let end = headers[j..]
                .find(['\r', '\n'])
                .map(|n| j + n)
                .unwrap_or(headers.len());
            return Some(&headers[j..end]);
        }
        i += 1;
    }
    None
}

fn take_int(s: &str, key: &str) -> Option<i64> {
    let pat = format!("{key}=");
    let idx = s.find(&pat)?;
    let rest = &s[idx + pat.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

pub fn format_size(mut bytes: f64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut i = 0;
    while bytes >= 1024.0 && i < UNITS.len() - 1 {
        bytes /= 1024.0;
        i += 1;
    }
    let number = if bytes >= 100.0 {
        format!("{bytes:.0}")
    } else if bytes >= 10.0 {
        format!("{bytes:.1}")
    } else {
        format!("{bytes:.2}")
    };
    format!("{number}{}", UNITS[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_size(0.0), "0.00B");
        assert_eq!(format_size(512.0), "512B");
        assert_eq!(format_size(1024.0), "1.00KB");
        assert_eq!(format_size(10.0 * 1024.0), "10.0KB");
        assert_eq!(format_size(100.0 * 1024.0), "100KB");
        assert_eq!(format_size(1024.0 * 1024.0), "1.00MB");
    }

    #[test]
    fn header() {
        let headers = "HTTP/1.1 200\r\nsubscription-userinfo: upload=0; download=0; total=1073741824; expire=1893456000\r\n";
        let info = parse_subscription_userinfo_with(headers, |_| Some((2030, 1, 2))).unwrap();
        assert_eq!(info.expired_date, "2030-1-2");
        assert_eq!(info.rem_traffic, "1.00GB");
    }

    #[test]
    fn missing_expire_is_open() {
        let info =
            parse_subscription_userinfo_with("subscription-userinfo: upload=5", |_| None).unwrap();
        assert_eq!(info.expired_date, "长期有效");
        assert_eq!(info.rem_traffic, "0.00B");
    }

    #[test]
    fn no_header() {
        assert!(parse_subscription_userinfo("HTTP/1.1 200\r\n").is_none());
    }
}
