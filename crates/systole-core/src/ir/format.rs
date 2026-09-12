//! The canonical JSON form (ADR-0010): keys sorted, two-space indent, `\n`
//! line endings, trailing newline, integers never floats, no timestamps.
//! `format_value` is the single serializer; a file is canonical iff its bytes
//! equal `format_value(parse(bytes))`.

/// Serialize a JSON value to its canonical bytes.
///
/// ```
/// use systole_core::ir::format::format_value;
///
/// let value = serde_json::json!({ "b": 1, "a": 2 });
/// let text = String::from_utf8(format_value(&value)).unwrap();
/// assert_eq!(text, "{\n  \"a\": 2,\n  \"b\": 1\n}\n");
/// ```
pub fn format_value(value: &serde_json::Value) -> Vec<u8> {
    // serde_json's map is ordered (BTreeMap) unless `preserve_order` is on,
    // so `to_vec_pretty` emits sorted keys with a two-space indent.
    let mut bytes =
        serde_json::to_vec_pretty(value).expect("serializing a Value cannot fail");
    bytes.push(b'\n');
    bytes
}

/// Parse bytes as JSON and canonicalize them.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    Ok(format_value(&value))
}

/// True iff the bytes are already in canonical form.
pub fn is_canonical(bytes: &[u8]) -> bool {
    canonicalize(bytes).is_ok_and(|c| c == bytes)
}
