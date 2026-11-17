use std::collections::HashMap;

use crate::value::{is_int_literal, Value};

type YResult<T> = Result<T, ()>;

struct Doc {
    lines: Vec<String>,
    i: usize,
    anchors: HashMap<String, Value>,
}

struct Peek {
    index: usize,
    indent: usize,
    text: String,
}

pub fn parse_yaml(src: &str) -> YResult<Value> {
    let mut src = src.to_string();
    if src.starts_with('\u{feff}') {
        src.remove(0);
    }
    src = src.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<String> = src.split('\n').map(|line| line.to_string()).collect();
    let mut doc = Doc {
        lines,
        i: 0,
        anchors: HashMap::new(),
    };
    doc.parse_block(0)
}

impl Doc {
    fn parse_block(&mut self, min_indent: usize) -> YResult<Value> {
        let Some(p) = self.peek() else {
            return Ok(Value::Null);
        };
        if p.indent < min_indent {
            return Ok(Value::Null);
        }
        let text = p.text.as_bytes();
        if text.first() == Some(&b'-') && (text.len() == 1 || text.get(1) == Some(&b' ')) {
            return self.parse_seq(p.indent);
        }
        if text.first() != Some(&b'{')
            && text.first() != Some(&b'[')
            && split_key(&p.text).is_some()
        {
            return self.parse_map(p.indent);
        }
        self.i = p.index + 1;
        self.parse_rest(&p.text, p.indent)
    }

    fn parse_map(&mut self, indent: usize) -> YResult<Value> {
        let mut obj = crate::value::Map::new();
        loop {
            let Some(p) = self.peek() else { break };
            if p.indent != indent {
                break;
            }
            let text = p.text.as_bytes();
            if text.first() == Some(&b'-') && (text.len() == 1 || text.get(1) == Some(&b' ')) {
                break;
            }
            let Some((key, rest)) = split_key(&p.text) else {
                break;
            };
            self.i = p.index + 1;
            obj.insert(key, self.parse_rest(&rest, indent)?);
        }
        Ok(Value::Map(obj))
    }

    fn parse_seq(&mut self, indent: usize) -> YResult<Value> {
        let mut arr = Vec::new();
        loop {
            let Some(p) = self.peek() else { break };
            if p.indent != indent {
                break;
            }
            let text = p.text.as_bytes();
            if !(text.first() == Some(&b'-') && (text.len() == 1 || text.get(1) == Some(&b' '))) {
                break;
            }
            self.i = p.index + 1;
            let mut rest = if p.text.len() == 1 {
                String::new()
            } else {
                slice(&p.text, 1, p.text.len()).trim().to_string()
            };
            if p.text.as_bytes().get(1) == Some(&b' ') {
                rest = slice(&p.text, 2, p.text.len()).trim().to_string();
            }
            rest = strip_tag(&rest);
            let (mut anchor, rest) = take_anchor(&rest);
            let head = rest.as_bytes().first().copied().unwrap_or(0);
            let mut pushed = false;
            if !matches!(head, b'{' | b'[' | b'"' | b'\'' | b'|' | b'>' | b'*') && !rest.is_empty()
            {
                if let Some((key, value)) = split_key(&rest) {
                    pushed = true;
                    let mut obj = crate::value::Map::new();
                    obj.insert(key, self.parse_rest(&value, indent)?);
                    if let Value::Map(more) = self.parse_map(indent + 2)? {
                        for (k, v) in more {
                            obj.insert(k, v);
                        }
                    }
                    arr.push(self.remember(anchor.take(), Value::Map(obj)));
                }
            }
            if !pushed {
                let parsed = self.parse_rest(&rest, indent)?;
                arr.push(self.remember(anchor.take(), parsed));
            }
        }
        Ok(Value::Array(arr))
    }

    fn parse_rest(&mut self, rest: &str, parent_indent: usize) -> YResult<Value> {
        let rest = strip_tag(rest);
        let rest = strip_inline_comment(&rest);
        let (anchor, rest) = take_anchor(&rest);
        if rest.is_empty() {
            let next = self.peek().map(|nx| {
                let head = nx.text.into_bytes();
                let is_seq = nx.indent >= parent_indent
                    && head.first() == Some(&b'-')
                    && (head.len() == 1 || head.get(1) == Some(&b' '));
                (nx.indent, is_seq)
            });
            if let Some((ind, is_seq)) = next {
                if is_seq {
                    let seq = self.parse_seq(ind)?;
                    return Ok(self.remember(anchor, seq));
                }
                if ind > parent_indent {
                    let block = self.parse_block(ind)?;
                    return Ok(self.remember(anchor, block));
                }
            }
            return Ok(self.remember(anchor, Value::Null));
        }
        let head = rest.as_bytes()[0];
        if head == b'|' || head == b'>' {
            let scalar = self.parse_block_scalar(&rest, parent_indent)?;
            return Ok(self.remember(anchor, Value::String(scalar)));
        }
        if head == b'[' || head == b'{' {
            let chunk = self.collect_flow(&rest)?;
            return Ok(self.remember(anchor, parse_flow(&chunk)?));
        }
        if head == b'*' {
            let mut name = rest[1..].trim().to_string();
            if let Some(sp) = name.find(' ') {
                name.truncate(sp);
            }
            let val = self.anchors.get(&name).cloned().unwrap_or(Value::Null);
            return Ok(self.remember(anchor, val));
        }
        if head == b'"' || head == b'\'' {
            return Ok(self.remember(anchor, Value::String(parse_quoted(&rest, false)?)));
        }
        Ok(self.remember(anchor, parse_plain(&strip_inline_comment(&rest))))
    }

    fn parse_block_scalar(&mut self, header: &str, parent_indent: usize) -> YResult<String> {
        let spec = header.trim();
        let style = spec.as_bytes().first().copied().unwrap_or(0);
        let spec = strip_inline_comment(&slice(spec, 1, spec.len()));
        let mut chomp = "clip";
        if spec.contains('-') {
            chomp = "strip";
        }
        if spec.contains('+') {
            chomp = "keep";
        }
        let forced = first_number(&spec);
        let start = self.i;
        let mut end = self.i;
        let mut min_ind: Option<usize> = None;
        while end < self.lines.len() {
            let line = &self.lines[end];
            if blank_or_comment(line) && line.trim().is_empty() {
                end += 1;
                continue;
            }
            if !line.trim().is_empty()
                && line.trim().as_bytes().first() == Some(&b'#')
                && min_ind.is_none()
            {
                break;
            }
            let ind = indent_of(line);
            if !line.trim().is_empty() && ind <= parent_indent {
                break;
            }
            if !line.trim().is_empty() {
                min_ind = Some(min_ind.map(|cur| cur.min(ind)).unwrap_or(ind));
            }
            end += 1;
        }
        self.i = end;
        let Some(min_ind) = min_ind else {
            return Ok(if chomp == "keep" {
                "\n".to_string()
            } else {
                String::new()
            });
        };
        let use_ind = match forced {
            Some(n) => parent_indent + n,
            None => min_ind,
        };
        let mut parts = Vec::new();
        for line in &self.lines[start..end] {
            if line.trim().is_empty() {
                parts.push(String::new());
            } else if line.len() >= use_ind {
                parts.push(slice(line, use_ind, line.len()));
            } else {
                parts.push(line.trim().to_string());
            }
        }
        if style == b'>' {
            Ok(fold_parts(&parts, chomp))
        } else {
            Ok(literal_parts(&parts, chomp))
        }
    }

    fn collect_flow(&mut self, first: &str) -> YResult<String> {
        let mut chunk = first.to_string();
        while flow_depth(&chunk) > 0 {
            if self.i >= self.lines.len() {
                return Err(());
            }
            chunk.push('\n');
            chunk.push_str(&self.lines[self.i]);
            self.i += 1;
        }
        Ok(chunk)
    }

    fn peek(&self) -> Option<Peek> {
        let mut j = self.i;
        while j < self.lines.len() {
            let line = &self.lines[j];
            if blank_or_comment(line) {
                j += 1;
                continue;
            }
            let ind = indent_of(line);
            let text = slice(line, ind, line.len()).trim().to_string();
            if text == "---" || text == "..." || text.as_bytes().first() == Some(&b'%') {
                j += 1;
                continue;
            }
            return Some(Peek {
                index: j,
                indent: ind,
                text,
            });
        }
        None
    }

    fn remember(&mut self, anchor: Option<String>, val: Value) -> Value {
        if let Some(anchor) = anchor {
            self.anchors.insert(anchor, val.clone());
        }
        val
    }
}

fn indent_of(line: &str) -> usize {
    line.bytes().take_while(|c| *c == b' ').count()
}

fn blank_or_comment(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.as_bytes().first() == Some(&b'#')
}

fn first_number(spec: &str) -> Option<usize> {
    let bytes = spec.as_bytes();
    let mut i = 0;
    while i < bytes.len() && !bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    spec[start..i].parse().ok()
}

fn literal_parts(parts: &[String], chomp: &str) -> String {
    let s = parts.join("\n");
    if chomp == "strip" {
        return s.trim_end_matches('\n').to_string();
    }
    if chomp == "keep" {
        if s.ends_with('\n') {
            s
        } else {
            format!("{s}\n")
        }
    } else {
        let s = s.trim_end_matches('\n');
        if s.is_empty() {
            String::new()
        } else {
            format!("{s}\n")
        }
    }
}

fn fold_parts(parts: &[String], chomp: &str) -> String {
    let mut out = String::new();
    let mut buf: Vec<&str> = Vec::new();
    let flush = |out: &mut String, buf: &mut Vec<&str>| {
        if buf.is_empty() {
            return;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&buf.join(" "));
        buf.clear();
    };
    for line in parts {
        if line.is_empty() {
            flush(&mut out, &mut buf);
            out.push('\n');
        } else {
            buf.push(line);
        }
    }
    flush(&mut out, &mut buf);
    if chomp == "strip" {
        return out.trim_end_matches('\n').to_string();
    }
    if chomp == "keep" {
        if out.is_empty() || !out.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }
    let out = out.trim_end_matches('\n');
    if out.is_empty() {
        String::new()
    } else {
        format!("{out}\n")
    }
}

fn strip_inline_comment(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut q: Option<u8> = None;
    let mut esc = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if esc {
            out.push(c);
            esc = false;
            i += 1;
            continue;
        }
        if let Some(quote) = q {
            out.push(c);
            if c == b'\\' && quote == b'"' {
                esc = true;
            } else if c == quote {
                if quote == b'\'' && b.get(i + 1) == Some(&b'\'') {
                    out.push(b'\'');
                    i += 2;
                    continue;
                }
                q = None;
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            q = Some(c);
            out.push(c);
            i += 1;
            continue;
        }
        if c == b'#' && (i == 0 || b.get(i - 1) == Some(&b' ') || b.get(i - 1) == Some(&b'\t')) {
            break;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

fn parse_plain(s: &str) -> Value {
    let s = s.trim();
    if s.is_empty() || s == "~" || s.eq_ignore_ascii_case("null") {
        return Value::Null;
    }
    if matches!(
        s,
        "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON"
    ) {
        return Value::Bool(true);
    }
    if matches!(
        s,
        "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF"
    ) {
        return Value::Bool(false);
    }
    if is_int_literal(s) {
        if let Ok(n) = s.parse::<i64>() {
            return Value::Int(n);
        }
        return Value::String(s.to_string());
    }
    if crate::value::is_float_literal(s) {
        if let Ok(n) = s.parse::<f64>() {
            if n.is_finite() {
                return Value::Float(n);
            }
        }
        return Value::String(s.to_string());
    }
    if let Some(hex) = s.strip_prefix("0x") {
        if !hex.is_empty() && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(n) = i64::from_str_radix(hex, 16) {
                return Value::Int(n);
            }
        }
    }
    Value::String(s.to_string())
}

fn parse_quoted(s: &str, allow_tail: bool) -> YResult<String> {
    let b = s.as_bytes();
    if b.is_empty() {
        return Err(());
    }
    let q = b[0];
    if q != b'"' && q != b'\'' {
        return Err(());
    }
    let mut out = Vec::new();
    let mut i = 1;
    if q == b'\'' {
        while i < b.len() {
            if b[i] == b'\'' {
                if b.get(i + 1) == Some(&b'\'') {
                    out.push(b'\'');
                    i += 2;
                    continue;
                }
                i += 1;
                break;
            }
            out.push(b[i]);
            i += 1;
        }
    } else {
        while i < b.len() {
            if b[i] == b'\\' {
                if i + 1 >= b.len() {
                    i += 2;
                    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                        i += 1;
                    }
                    continue;
                }
                let n = b[i + 1];
                match n {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'\\' => out.push(b'\\'),
                    b'"' => out.push(b'"'),
                    b'/' => out.push(b'/'),
                    b'0' => out.push(0),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'x' => {
                        if i + 4 > b.len() {
                            return Err(());
                        }
                        let h = std::str::from_utf8(&b[i + 2..i + 4]).map_err(|_| ())?;
                        let cp = u32::from_str_radix(h, 16).map_err(|_| ())?;
                        if cp > 255 {
                            return Err(());
                        }
                        out.push(cp as u8);
                        i += 4;
                        continue;
                    }
                    b'u' => {
                        if i + 6 > b.len() {
                            return Err(());
                        }
                        let h = std::str::from_utf8(&b[i + 2..i + 6]).map_err(|_| ())?;
                        let cp = u32::from_str_radix(h, 16).map_err(|_| ())?;
                        let ch = char::from_u32(cp).ok_or(())?;
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        i += 6;
                        continue;
                    }
                    b'\n' => {
                        i += 2;
                        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                            i += 1;
                        }
                        continue;
                    }
                    _ => out.push(n),
                }
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                i += 1;
                break;
            }
            out.push(b[i]);
            i += 1;
        }
    }
    if !allow_tail {
        let rest = std::str::from_utf8(&b[i.min(b.len())..])
            .unwrap_or("")
            .trim();
        if !rest.is_empty() && rest.as_bytes().first() != Some(&b'#') {
            return Err(());
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn flow_depth(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut q: Option<u8> = None;
    let mut esc = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if esc {
            esc = false;
            i += 1;
            continue;
        }
        if let Some(quote) = q {
            if c == b'\\' && quote == b'"' {
                esc = true;
            } else if c == quote {
                if quote == b'\'' && b.get(i + 1) == Some(&b'\'') {
                    i += 1;
                } else {
                    q = None;
                }
            }
            i += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            q = Some(c);
            i += 1;
            continue;
        }
        if c == b'{' || c == b'[' {
            depth += 1;
        } else if c == b'}' || c == b']' {
            depth -= 1;
        }
        i += 1;
    }
    depth
}

struct Flow<'a> {
    s: &'a str,
    p: usize,
}

impl Flow<'_> {
    fn ch(&self) -> Option<u8> {
        self.s.as_bytes().get(self.p).copied()
    }

    fn skip_ws(&mut self) {
        let b = self.s.as_bytes();
        while self.p < b.len() && matches!(b[self.p], b' ' | b'\t' | b'\n' | b'\r') {
            self.p += 1;
        }
    }

    fn parse_val(&mut self) -> YResult<Value> {
        self.skip_ws();
        match self.ch() {
            Some(b'[') => self.parse_seq(),
            Some(b'{') => self.parse_map(),
            Some(b'"' | b'\'') => {
                let rest = slice(self.s, self.p, self.s.len());
                let val = parse_quoted(&rest, true)?;
                self.p = skip_quoted_naive(self.s, self.p);
                Ok(Value::String(val))
            }
            _ => {
                let start = self.p;
                let b = self.s.as_bytes();
                while self.p < b.len() {
                    let ch = b[self.p];
                    if matches!(ch, b',' | b']' | b'}' | b'\n' | b'\r') {
                        break;
                    }
                    if ch == b'#'
                        && (self.p == start
                            || b.get(self.p - 1) == Some(&b' ')
                            || b.get(self.p - 1) == Some(&b'\t'))
                    {
                        break;
                    }
                    self.p += 1;
                }
                Ok(parse_plain(&slice(self.s, start, self.p)))
            }
        }
    }

    fn parse_seq(&mut self) -> YResult<Value> {
        self.p += 1;
        let mut arr = Vec::new();
        self.skip_ws();
        if self.ch() == Some(b']') {
            self.p += 1;
            return Ok(Value::Array(arr));
        }
        while self.p < self.s.len() {
            arr.push(self.parse_val()?);
            self.skip_ws();
            if self.ch() == Some(b',') {
                self.p += 1;
                self.skip_ws();
                if self.ch() == Some(b']') {
                    self.p += 1;
                    break;
                }
                continue;
            }
            if self.ch() == Some(b']') {
                self.p += 1;
                break;
            }
            return Err(());
        }
        Ok(Value::Array(arr))
    }

    fn parse_map(&mut self) -> YResult<Value> {
        self.p += 1;
        let mut obj = crate::value::Map::new();
        self.skip_ws();
        if self.ch() == Some(b'}') {
            self.p += 1;
            return Ok(Value::Map(obj));
        }
        while self.p < self.s.len() {
            self.skip_ws();
            let key = match self.ch() {
                Some(b'"' | b'\'') => {
                    let rest = slice(self.s, self.p, self.s.len());
                    let key = parse_quoted(&rest, true)?;
                    self.p = skip_quoted_naive(self.s, self.p);
                    key
                }
                _ => {
                    let start = self.p;
                    let b = self.s.as_bytes();
                    while self.p < b.len() && !matches!(b[self.p], b':' | b'}' | b',' | b'\n') {
                        self.p += 1;
                    }
                    slice(self.s, start, self.p).trim().to_string()
                }
            };
            self.skip_ws();
            if self.ch() == Some(b':') {
                self.p += 1;
            } else {
                return Err(());
            }
            let val = self.parse_val()?;
            obj.insert(key, val);
            self.skip_ws();
            if self.ch() == Some(b',') {
                self.p += 1;
                self.skip_ws();
                if self.ch() == Some(b'}') {
                    self.p += 1;
                    break;
                }
                continue;
            }
            if self.ch() == Some(b'}') {
                self.p += 1;
                break;
            }
            return Err(());
        }
        Ok(Value::Map(obj))
    }
}

fn parse_flow(s: &str) -> YResult<Value> {
    let mut flow = Flow { s, p: 0 };
    flow.parse_val()
}

fn skip_quoted_naive(s: &str, mut p: usize) -> usize {
    let b = s.as_bytes();
    if p >= b.len() {
        return p;
    }
    let q = b[p];
    p += 1;
    if q == b'\'' {
        while p < b.len() {
            if b[p] == b'\'' {
                if b.get(p + 1) == Some(&b'\'') {
                    p += 2;
                    continue;
                }
                p += 1;
                break;
            }
            p += 1;
        }
    } else {
        while p < b.len() {
            if b[p] == b'\\' {
                p = p.saturating_add(2);
                continue;
            }
            if b[p] == b'"' {
                p += 1;
                break;
            }
            p += 1;
        }
    }
    p
}

fn unquote_key(key: &str) -> YResult<String> {
    let key = key.trim();
    if key.len() >= 2 && (key.as_bytes()[0] == b'"' || key.as_bytes()[0] == b'\'') {
        return parse_quoted(key, false);
    }
    Ok(key.to_string())
}

fn split_key(text: &str) -> Option<(String, String)> {
    let b = text.as_bytes();
    let mut q: Option<u8> = None;
    let mut esc = false;
    let mut k = 0;
    while k < b.len() {
        let c = b[k];
        if esc {
            esc = false;
            k += 1;
            continue;
        }
        if let Some(quote) = q {
            if c == b'\\' && quote == b'"' {
                esc = true;
            } else if c == quote {
                if quote == b'\'' && b.get(k + 1) == Some(&b'\'') {
                    k += 1;
                } else {
                    q = None;
                }
            }
            k += 1;
            continue;
        }
        if c == b'\'' || c == b'"' {
            q = Some(c);
            k += 1;
            continue;
        }
        if c == b'#' {
            break;
        }
        if c == b':' {
            let next = b.get(k + 1).copied();
            if next.is_none() || next == Some(b' ') || next == Some(b'\t') {
                let key = unquote_key(&slice(text, 0, k)).ok()?;
                let rest = slice(text, k + 1, text.len()).trim().to_string();
                if key.is_empty() {
                    return None;
                }
                return Some((key, rest));
            }
        }
        k += 1;
    }
    None
}

fn take_anchor(rest: &str) -> (Option<String>, String) {
    let b = rest.as_bytes();
    if b.first() != Some(&b'&') {
        return (None, rest.to_string());
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-') {
        i += 1;
    }
    if i == 1 {
        return (None, rest.to_string());
    }
    let name = slice(rest, 1, i);
    if i == b.len() {
        return (Some(name), String::new());
    }
    if b[i] == b' ' || b[i] == b'\t' {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        return (Some(name), slice(rest, i, rest.len()));
    }
    (None, rest.to_string())
}

fn strip_tag(rest: &str) -> String {
    let b = rest.as_bytes();
    if b.first() != Some(&b'!') {
        return rest.to_string();
    }
    let mut i = 1;
    while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
        i += 1;
    }
    if i == 1 {
        return rest.to_string();
    }
    if i >= b.len() {
        return String::new();
    }
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    slice(rest, i, rest.len())
}

fn slice(s: &str, start: usize, end: usize) -> String {
    let b = s.as_bytes();
    let start = start.min(b.len());
    let end = end.min(b.len()).max(start);
    String::from_utf8_lossy(&b[start..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::get;

    #[test]
    fn block_proxy_list() {
        let doc =
            parse_yaml("proxies:\n  - name: a\n    type: ss\n    port: 8388\n    tls: true\n")
                .unwrap();
        let proxies = get(&doc, "proxies");
        let Value::Array(items) = proxies else {
            panic!("proxies")
        };
        assert_eq!(get(&items[0], "name"), &Value::String("a".into()));
        assert_eq!(get(&items[0], "port"), &Value::Int(8388));
        assert_eq!(get(&items[0], "tls"), &Value::Bool(true));
    }

    #[test]
    fn flow_and_comment() {
        let doc = parse_yaml("proxies: [{name: \"a\", port: 1}] # tail\n").unwrap();
        let Value::Array(items) = get(&doc, "proxies") else {
            panic!()
        };
        assert_eq!(get(&items[0], "name"), &Value::String("a".into()));
        assert_eq!(get(&items[0], "port"), &Value::Int(1));
    }

    #[test]
    fn anchor_alias() {
        let doc = parse_yaml("h: &h example.com\nproxies:\n  - server: *h\n").unwrap();
        let Value::Array(items) = get(&doc, "proxies") else {
            panic!()
        };
        assert_eq!(
            get(&items[0], "server"),
            &Value::String("example.com".into())
        );
    }

    #[test]
    fn broken_flow_errors() {
        assert!(parse_yaml("proxies: [\n").is_err());
    }
}
