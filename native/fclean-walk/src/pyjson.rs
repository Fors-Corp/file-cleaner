//! `json.dumps(value, indent=2, ensure_ascii=False)`, byte for byte: what
//! `filecleaner.output.dumps` prints, and so what the port must print.
//!
//! Hand-written rather than serde_json's pretty printer because two things
//! have to be Python's: the order of keys (insertion order) and the spelling
//! of floats (`repr(float)`: `1e+16` and `1e-05`, where ryu says `1e16` and
//! `1e-5`).

pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    List(Vec<J>),
    Dict(Vec<(String, J)>),
}

impl J {
    pub fn str(text: impl Into<String>) -> J {
        J::Str(text.into())
    }

    pub fn strings<'a>(items: impl IntoIterator<Item = &'a String>) -> J {
        J::List(items.into_iter().map(|item| J::Str(item.clone())).collect())
    }

    pub fn dict<const N: usize>(pairs: [(&str, J); N]) -> J {
        J::Dict(pairs.into_iter().map(|(key, value)| (key.to_owned(), value)).collect())
    }

    /// What `json.loads` made of it, as far as the two parsers agree: keys in
    /// the order written (serde_json's `preserve_order`), a repeated key
    /// keeping its first place and its last value, and floats read exactly
    /// (`float_roundtrip`). Python also reads `NaN`, `Infinity` and integers
    /// of any size; serde_json refuses the first two and reads the last as a
    /// float — nothing File Cleaner writes contains any of them.
    pub fn from_json(value: &serde_json::Value) -> J {
        use serde_json::Value;
        match value {
            Value::Null => J::Null,
            Value::Bool(flag) => J::Bool(*flag),
            Value::Number(number) => match (number.as_u64(), number.as_i64()) {
                (Some(unsigned), _) => J::UInt(unsigned),
                (None, Some(signed)) => J::Int(signed),
                (None, None) => J::Float(number.as_f64().unwrap_or(f64::NAN)),
            },
            Value::String(text) => J::Str(text.clone()),
            Value::Array(items) => J::List(items.iter().map(J::from_json).collect()),
            Value::Object(pairs) => J::Dict(pairs.iter().map(|(key, item)| (key.clone(), J::from_json(item))).collect()),
        }
    }
}

/// The significant digits of `x` in scientific form, and its exponent.
fn scientific(x: f64, precision: Option<usize>) -> (String, i32) {
    let text = match precision {
        Some(places) => format!("{x:.places$e}"),
        None => format!("{x:e}"),
    };
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    (mantissa.chars().filter(char::is_ascii_digit).collect(), exponent.parse().unwrap_or(0))
}

/// The shortest digits that read back as `x` (`x` > 0), chosen the way
/// Python chooses. Rust and Python agree on how many digits that takes, and
/// on which ones unless `x` lies exactly halfway between two candidates —
/// `827746655.84765625` between `...62` and `...63`. Rust then rounds half
/// up; Python (David Gay's dtoa) rounds half to even. A double's decimal
/// expansion is finite, at most 767 digits, so the tie can be seen exactly.
fn shortest_digits(x: f64) -> (String, i32) {
    let (digits, exponent) = scientific(x, None);
    let (exact, exact_exponent) = scientific(x, Some(800));
    let kept = digits.len();
    let is_tie = exact_exponent == exponent
        && exact.as_bytes().get(kept) == Some(&b'5')
        && exact.bytes().skip(kept + 1).all(|digit| digit == b'0');
    if !is_tie {
        return (digits, exponent);
    }
    let truncated = &exact[..kept];
    let ends_even = truncated.bytes().last().is_some_and(|digit| (digit - b'0') % 2 == 0);
    if !ends_even || truncated == digits {
        return (digits, exponent); // half up and half to even agree
    }
    let reads_back = format!("{}e{}", truncated, exponent - (kept as i32 - 1)).parse::<f64>() == Ok(x);
    if reads_back {
        (truncated.trim_end_matches('0').to_owned(), exponent)
    } else {
        (digits, exponent)
    }
}

/// `repr(float)`: the shortest digits that round-trip, laid out the way
/// Python lays them out.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_owned(); // json.dumps(allow_nan=True)
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let (digits, exponent) = shortest_digits(x.abs());
    let body = if (-4..16).contains(&exponent) {
        if exponent < 0 {
            format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize))
        } else {
            let whole = exponent as usize + 1;
            if digits.len() <= whole {
                format!("{digits}{}.0", "0".repeat(whole - digits.len()))
            } else {
                format!("{}.{}", &digits[..whole], &digits[whole..])
            }
        }
    } else {
        let mantissa = if digits.len() == 1 { digits } else { format!("{}.{}", &digits[..1], &digits[1..]) };
        format!("{mantissa}e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.abs())
    };
    if x < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

fn write_str(out: &mut String, text: &str, ascii: bool) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            // ensure_ascii=True: whatever is not printable ASCII (DEL is not),
            // in UTF-16 — so a character beyond U+FFFF is a surrogate pair.
            c if ascii && (c as u32) > 0x7e => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c), // ensure_ascii=False: everything else as it is
        }
    }
    out.push('"');
}

fn write(out: &mut String, value: &J, depth: usize, ascii: bool) {
    let pad = |out: &mut String, depth: usize| out.push_str(&"  ".repeat(depth));
    match value {
        J::Null => out.push_str("null"),
        J::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        J::Int(number) => out.push_str(&number.to_string()),
        J::UInt(number) => out.push_str(&number.to_string()),
        J::Float(number) => out.push_str(&float_repr(*number)),
        J::Str(text) => write_str(out, text, ascii),
        J::List(items) if items.is_empty() => out.push_str("[]"),
        J::Dict(pairs) if pairs.is_empty() => out.push_str("{}"),
        J::List(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                pad(out, depth + 1);
                write(out, item, depth + 1, ascii);
                out.push_str(if index + 1 < items.len() { ",\n" } else { "\n" });
            }
            pad(out, depth);
            out.push(']');
        }
        J::Dict(pairs) => {
            out.push_str("{\n");
            for (index, (key, item)) in pairs.iter().enumerate() {
                pad(out, depth + 1);
                write_str(out, key, ascii);
                out.push_str(": ");
                write(out, item, depth + 1, ascii);
                out.push_str(if index + 1 < pairs.len() { ",\n" } else { "\n" });
            }
            pad(out, depth);
            out.push('}');
        }
    }
}

pub fn dumps(value: &J) -> String {
    let mut out = String::new();
    write(&mut out, value, 0, false);
    out
}

/// `json.dumps(value, indent=2)`, with `ensure_ascii` left at its default:
/// what Python writes to a file, where `dumps` is what it prints.
pub fn dumps_ascii(value: &J) -> String {
    let mut out = String::new();
    write(&mut out, value, 0, true);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_are_spelled_the_way_python_spells_them() {
        for (number, expected) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.001, "0.001"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.2345e22, "1.2345e+22"),
            (1e100, "1e+100"),
            (-2.5, "-2.5"),
            (1789775128.5018933, "1789775128.5018933"),
            (0.1 + 0.2, "0.30000000000000004"),
            (827746655.84765625, "827746655.8476562"), // an exact tie: half to even, not half up
            (17926652266205.3125, "17926652266205.312"),
            (-1314859137236290.25, "-1314859137236290.2"),
            (0.5, "0.5"),
            (2.5, "2.5"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(float_repr(number), expected);
        }
    }

    #[test]
    fn layout_and_escapes_match_json_dumps() {
        let value = J::dict([
            ("empty", J::List(vec![])),
            ("none", J::Dict(vec![])),
            ("text", J::str("a\"b\\c\n\t\u{1}é\u{2028}\u{7f}")),
            ("nested", J::List(vec![J::Int(-1), J::Bool(true), J::dict([("k", J::Float(2.0))])])),
        ]);
        let expected = "{\n  \"empty\": [],\n  \"none\": {},\n  \"text\": \"a\\\"b\\\\c\\n\\t\\u0001é\u{2028}\u{7f}\",\n  \"nested\": [\n    -1,\n    true,\n    {\n      \"k\": 2.0\n    }\n  ]\n}";
        assert_eq!(dumps(&value), expected);
    }

    #[test]
    fn ensure_ascii_escapes_what_json_dumps_escapes() {
        // json.dumps({"k": None, "t": "é \x7f~ 𝄞"}, indent=2)
        let value = J::dict([("k", J::Null), ("t", J::str("é\u{2028}\u{7f}~ 𝄞"))]);
        assert_eq!(dumps_ascii(&value), "{\n  \"k\": null,\n  \"t\": \"\\u00e9\\u2028\\u007f~ \\ud834\\udd1e\"\n}");
    }

    #[test]
    fn parsed_json_keeps_its_order_and_its_numbers() {
        let parsed: serde_json::Value = serde_json::from_str(r#"{"z": 1, "a": -2, "f": 0.1, "z": [null, 1e3]}"#).unwrap();
        let expected = "{\n  \"z\": [\n    null,\n    1000.0\n  ],\n  \"a\": -2,\n  \"f\": 0.1\n}";
        assert_eq!(dumps(&J::from_json(&parsed)), expected); // as json.dumps(json.loads(...), indent=2)
    }
}
