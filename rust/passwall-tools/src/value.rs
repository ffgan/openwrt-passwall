use indexmap::IndexMap;

pub type Map = IndexMap<String, Value>;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Map(Map),
}

static NULL: Value = Value::Null;

pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    match v {
        Value::Map(map) => map.get(key).unwrap_or(&NULL),
        _ => &NULL,
    }
}

pub fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

pub fn is_false(v: &Value) -> bool {
    matches!(v, Value::Bool(false))
}

pub fn is_true(v: &Value) -> bool {
    matches!(v, Value::Bool(true))
}

/// ucode truthiness: only null and false are falsy.
pub fn truthy(v: &Value) -> bool {
    !is_null(v) && !is_false(v)
}

pub fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s),
        _ => None,
    }
}

pub fn lua_or<'a>(v: &'a Value, fallback: &'a Value) -> &'a Value {
    if is_null(v) || is_false(v) {
        fallback
    } else {
        v
    }
}

pub fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(n) => format_f64(*n),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Map(_) => to_json(v),
    }
}

pub fn format_f64(n: f64) -> String {
    if !n.is_finite() {
        return "null".to_string();
    }
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    let text = format!("{n}");
    text
}

pub fn to_json(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(n) => format_f64(*n),
        Value::String(s) => json_string(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(to_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Map(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, value)| format!("{}:{}", json_string(key), to_json(value)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

pub fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'~' | b'-') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub fn b64_value(v: &Value) -> String {
    if is_null(v) || is_false(v) {
        return String::new();
    }
    base64(as_text(v).as_bytes())
}

pub fn to_number(v: &Value) -> Option<Value> {
    match v {
        Value::Int(n) => Some(Value::Int(*n)),
        Value::Float(n) if n.is_finite() => Some(Value::Float(*n)),
        Value::Float(_) => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => parse_numeric(s),
        _ => None,
    }
}

fn parse_numeric(s: &str) -> Option<Value> {
    if is_int_literal(s) {
        return s.parse::<i64>().ok().map(Value::Int);
    }
    if is_float_literal(s) {
        let n: f64 = s.parse().ok()?;
        if n.is_finite() {
            return Some(Value::Float(n));
        }
    }
    None
}

pub fn is_int_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let rest = match bytes[0] {
        b'+' | b'-' => &bytes[1..],
        _ => bytes,
    };
    !rest.is_empty() && rest.iter().all(|c| c.is_ascii_digit())
}

pub fn is_float_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let rest = match bytes.first() {
        Some(b'+' | b'-') => &bytes[1..],
        Some(_) => bytes,
        None => return false,
    };
    if rest.is_empty() {
        return false;
    }
    let exp = rest.iter().position(|c| *c == b'e' || *c == b'E');
    let (mant, exp) = match exp {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    if mant.is_empty() {
        return false;
    }
    let dot = mant.iter().position(|c| *c == b'.');
    let mant_ok = match dot {
        Some(i) => {
            let whole = &mant[..i];
            let frac = &mant[i + 1..];
            !whole.is_empty()
                && whole.iter().all(|c| c.is_ascii_digit())
                && frac.iter().all(|c| c.is_ascii_digit())
                || whole.is_empty() && !frac.is_empty() && frac.iter().all(|c| c.is_ascii_digit())
        }
        None => false,
    };
    let exp_ok = match exp {
        None => mant_ok,
        Some(exp) => {
            let digits_ok = mant.iter().all(|c| c.is_ascii_digit());
            let exp = match exp.first() {
                Some(b'+' | b'-') => &exp[1..],
                _ => exp,
            };
            (mant_ok || digits_ok && !mant.is_empty())
                && !exp.is_empty()
                && exp.iter().all(|c| c.is_ascii_digit())
        }
    };
    exp_ok && (dot.is_some() || exp.is_some())
}
