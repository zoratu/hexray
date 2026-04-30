//! Minimal MessagePack reader for the AMDGPU metadata note.
//!
//! AMDGPU code objects carry a MessagePack-encoded metadata blob in
//! the `NT_AMDGPU_METADATA` (type 32) ELF note, name `"AMDGPU"`. The
//! schema is the "Code Object V3 Metadata" section of LLVM
//! `AMDGPUUsage.html` — top-level map with `"amdhsa.version"` and
//! `"amdhsa.kernels"` keys.
//!
//! We only need read-only decoding of maps / arrays / strings /
//! integers / booleans. Pulling in a full MessagePack crate would be
//! about 5x the code; this hand-rolled parser is ~150 lines and
//! covers exactly the subset AMDGPU uses.
//!
//! Reference: <https://github.com/msgpack/msgpack/blob/master/spec.md>.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

/// A decoded MessagePack value. Only the subset AMDGPU metadata
/// uses is modelled — extension types, raw binary blobs, and
/// floating-point are deliberately omitted.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Str(String),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
    /// A type we know exists in MessagePack but didn't model.
    /// Unmodelled types parse to `Other(byte_offset)` so the caller
    /// can locate the offending record without aborting the whole
    /// decode.
    Other(u8),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::UInt(n) => Some(*n),
            Self::Int(n) if *n >= 0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub offset: usize,
    pub message: String,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "msgpack decode error @ 0x{:x}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for DecodeError {}

/// Decode the top-level value from a MessagePack-encoded blob.
pub fn decode(data: &[u8]) -> Result<Value, DecodeError> {
    let mut cursor = Cursor { data, pos: 0 };
    cursor.read_value()
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn err(&self, message: impl Into<String>) -> DecodeError {
        DecodeError {
            offset: self.pos,
            message: message.into(),
        }
    }

    fn need(&self, n: usize) -> Result<(), DecodeError> {
        if self.pos + n > self.data.len() {
            Err(self.err(format!(
                "need {n} bytes, only {} remain",
                self.data.len() - self.pos
            )))
        } else {
            Ok(())
        }
    }

    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        self.need(1)?;
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        self.need(4)?;
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        self.need(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(buf))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_str(&mut self, n: usize) -> Result<String, DecodeError> {
        let bytes = self.read_bytes(n)?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| self.err(format!("non-UTF-8 string of {n} bytes")))
    }

    fn read_value(&mut self) -> Result<Value, DecodeError> {
        let head = self.read_byte()?;
        match head {
            // positive fixint (0x00..=0x7f)
            0x00..=0x7f => Ok(Value::UInt(head as u64)),
            // negative fixint (0xe0..=0xff)
            0xe0..=0xff => Ok(Value::Int((head as i8) as i64)),
            // fixmap (0x80..=0x8f)
            0x80..=0x8f => self.read_map((head & 0x0f) as usize),
            // fixarray (0x90..=0x9f)
            0x90..=0x9f => self.read_array((head & 0x0f) as usize),
            // fixstr (0xa0..=0xbf)
            0xa0..=0xbf => {
                let len = (head & 0x1f) as usize;
                self.read_str(len).map(Value::Str)
            }
            0xc0 => Ok(Value::Nil),
            0xc2 => Ok(Value::Bool(false)),
            0xc3 => Ok(Value::Bool(true)),
            0xca => {
                // float32 — skip, we don't need it.
                self.read_u32()?;
                Ok(Value::Other(head))
            }
            0xcb => {
                self.read_u64()?;
                Ok(Value::Other(head))
            }
            0xcc => Ok(Value::UInt(self.read_byte()? as u64)),
            0xcd => Ok(Value::UInt(self.read_u16()? as u64)),
            0xce => Ok(Value::UInt(self.read_u32()? as u64)),
            0xcf => Ok(Value::UInt(self.read_u64()?)),
            0xd0 => Ok(Value::Int((self.read_byte()? as i8) as i64)),
            0xd1 => Ok(Value::Int((self.read_u16()? as i16) as i64)),
            0xd2 => Ok(Value::Int((self.read_u32()? as i32) as i64)),
            0xd3 => Ok(Value::Int(self.read_u64()? as i64)),
            0xd9 => {
                let len = self.read_byte()? as usize;
                self.read_str(len).map(Value::Str)
            }
            0xda => {
                let len = self.read_u16()? as usize;
                self.read_str(len).map(Value::Str)
            }
            0xdb => {
                let len = self.read_u32()? as usize;
                self.read_str(len).map(Value::Str)
            }
            0xdc => {
                let len = self.read_u16()? as usize;
                self.read_array(len)
            }
            0xdd => {
                let len = self.read_u32()? as usize;
                self.read_array(len)
            }
            0xde => {
                let len = self.read_u16()? as usize;
                self.read_map(len)
            }
            0xdf => {
                let len = self.read_u32()? as usize;
                self.read_map(len)
            }
            // Bin / ext: skip the length and payload, surface a
            // synthetic `Other` so the decode keeps progressing.
            0xc4 => {
                let len = self.read_byte()? as usize;
                let _ = self.read_bytes(len)?;
                Ok(Value::Other(head))
            }
            0xc5 => {
                let len = self.read_u16()? as usize;
                let _ = self.read_bytes(len)?;
                Ok(Value::Other(head))
            }
            0xc6 => {
                let len = self.read_u32()? as usize;
                let _ = self.read_bytes(len)?;
                Ok(Value::Other(head))
            }
            _ => Err(self.err(format!("unsupported MessagePack tag 0x{head:02x}"))),
        }
    }

    fn read_array(&mut self, len: usize) -> Result<Value, DecodeError> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.read_value()?);
        }
        Ok(Value::Array(out))
    }

    fn read_map(&mut self, len: usize) -> Result<Value, DecodeError> {
        let mut map = BTreeMap::new();
        for _ in 0..len {
            let key = match self.read_value()? {
                Value::Str(s) => s,
                other => {
                    return Err(self.err(format!(
                        "map key must be a string; got {:?}",
                        std::mem::discriminant(&other)
                    )))
                }
            };
            let value = self.read_value()?;
            map.insert(key, value);
        }
        Ok(Value::Map(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixint_decodes() {
        assert_eq!(decode(&[0x05]).unwrap(), Value::UInt(5));
        assert_eq!(decode(&[0xff]).unwrap(), Value::Int(-1));
        assert_eq!(decode(&[0xe0]).unwrap(), Value::Int(-32));
    }

    #[test]
    fn fixstr_decodes() {
        let mut buf = vec![0xa3]; // fixstr len=3
        buf.extend_from_slice(b"abc");
        assert_eq!(decode(&buf).unwrap(), Value::Str("abc".to_string()));
    }

    #[test]
    fn fixmap_with_string_keys() {
        // {"a": 1, "b": 2}
        let mut buf = vec![0x82]; // fixmap len=2
        buf.push(0xa1);
        buf.push(b'a');
        buf.push(0x01);
        buf.push(0xa1);
        buf.push(b'b');
        buf.push(0x02);
        let v = decode(&buf).unwrap();
        let m = v.as_map().expect("map");
        assert_eq!(m.get("a"), Some(&Value::UInt(1)));
        assert_eq!(m.get("b"), Some(&Value::UInt(2)));
    }

    #[test]
    fn fixarray_decodes() {
        // [1, 2, 3]
        let buf = vec![0x93, 0x01, 0x02, 0x03];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].as_uint(), Some(1));
    }

    #[test]
    fn nested_map_with_array_value() {
        // {"args": [1, 2]}
        let mut buf = vec![0x81, 0xa4]; // fixmap len=1, fixstr len=4
        buf.extend_from_slice(b"args");
        buf.extend_from_slice(&[0x92, 0x01, 0x02]); // fixarray len=2
        let v = decode(&buf).unwrap();
        let m = v.as_map().unwrap();
        let args = m.get("args").unwrap().as_array().unwrap();
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn uint16_decodes() {
        // 0xcd + big-endian u16 = 0x1234
        let buf = [0xcd, 0x12, 0x34];
        assert_eq!(decode(&buf).unwrap(), Value::UInt(0x1234));
    }

    #[test]
    fn truncated_input_errors() {
        // fixstr len=5 but only 2 bytes follow
        let buf = vec![0xa5, b'a', b'b'];
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn unsupported_tag_errors_out() {
        // 0xc1 is reserved.
        assert!(decode(&[0xc1]).is_err());
    }

    #[test]
    fn nil_tag_decodes_to_nil() {
        // 0xc0 = nil.
        assert_eq!(decode(&[0xc0]).unwrap(), Value::Nil);
    }

    #[test]
    fn bool_tags_decode_to_bool() {
        // 0xc2 = false, 0xc3 = true.
        assert_eq!(decode(&[0xc2]).unwrap(), Value::Bool(false));
        assert_eq!(decode(&[0xc3]).unwrap(), Value::Bool(true));
    }

    #[test]
    fn float32_tag_consumes_four_bytes_as_other() {
        // 0xca = float32 (4 byte payload). We don't model floats — the
        // parser should consume them and surface as Value::Other(0xca).
        let mut buf = vec![0xca];
        buf.extend_from_slice(&[0x40, 0x49, 0x0f, 0xdb]); // approx PI
        assert_eq!(decode(&buf).unwrap(), Value::Other(0xca));
    }

    #[test]
    fn float64_tag_consumes_eight_bytes_as_other() {
        // 0xcb = float64 (8 byte payload).
        let mut buf = vec![0xcb];
        buf.extend_from_slice(&[0; 8]);
        assert_eq!(decode(&buf).unwrap(), Value::Other(0xcb));
    }

    #[test]
    fn uint8_tag_decodes_full_range() {
        // 0xcc = u8.
        assert_eq!(decode(&[0xcc, 0x00]).unwrap(), Value::UInt(0));
        assert_eq!(decode(&[0xcc, 0xff]).unwrap(), Value::UInt(0xff));
    }

    #[test]
    fn uint32_tag_decodes_full_word() {
        // 0xce = u32 in big-endian.
        let buf = [0xce, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(decode(&buf).unwrap(), Value::UInt(0x12345678));
    }

    #[test]
    fn uint64_tag_decodes_full_word() {
        // 0xcf = u64 in big-endian.
        let buf = [0xcf, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(decode(&buf).unwrap(), Value::UInt(0x0123456789abcdef));
    }

    #[test]
    fn int8_tag_decodes_negative() {
        // 0xd0 = i8. -1 = 0xff.
        assert_eq!(decode(&[0xd0, 0xff]).unwrap(), Value::Int(-1));
        assert_eq!(decode(&[0xd0, 0x80]).unwrap(), Value::Int(-128));
    }

    #[test]
    fn int16_tag_decodes_negative() {
        // 0xd1 = i16 in big-endian. 0x8000 = -32768.
        assert_eq!(decode(&[0xd1, 0x80, 0x00]).unwrap(), Value::Int(-32768));
    }

    #[test]
    fn int32_tag_decodes_negative() {
        // 0xd2 = i32. 0x80000000 = i32::MIN.
        let buf = [0xd2, 0x80, 0x00, 0x00, 0x00];
        assert_eq!(decode(&buf).unwrap(), Value::Int(i32::MIN as i64));
    }

    #[test]
    fn int64_tag_decodes_negative() {
        // 0xd3 = i64. -1 in big-endian = all 0xff.
        let buf = [0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode(&buf).unwrap(), Value::Int(-1));
    }

    #[test]
    fn str8_tag_decodes_strings_up_to_255_bytes() {
        // 0xd9 = str8. The fixstr range only covers up to 31 bytes.
        let mut buf = vec![0xd9, 0x05];
        buf.extend_from_slice(b"hello");
        assert_eq!(decode(&buf).unwrap(), Value::Str("hello".to_string()));
    }

    #[test]
    fn str16_tag_decodes_strings_up_to_65535_bytes() {
        // 0xda = str16, length encoded as big-endian u16.
        let mut buf = vec![0xda, 0x00, 0x03];
        buf.extend_from_slice(b"abc");
        assert_eq!(decode(&buf).unwrap(), Value::Str("abc".to_string()));
    }

    #[test]
    fn str32_tag_decodes_strings() {
        // 0xdb = str32, length encoded as big-endian u32.
        let mut buf = vec![0xdb, 0x00, 0x00, 0x00, 0x02];
        buf.extend_from_slice(b"hi");
        assert_eq!(decode(&buf).unwrap(), Value::Str("hi".to_string()));
    }

    #[test]
    fn array16_tag_decodes_array() {
        // 0xdc = array16, length encoded as big-endian u16.
        let buf = [0xdc, 0x00, 0x02, 0x01, 0x02];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().expect("array16 should decode as array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::UInt(1));
        assert_eq!(arr[1], Value::UInt(2));
    }

    #[test]
    fn array32_tag_decodes_array() {
        // 0xdd = array32.
        let buf = [0xdd, 0x00, 0x00, 0x00, 0x01, 0x42];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], Value::UInt(0x42));
    }

    #[test]
    fn map16_tag_decodes_map() {
        // 0xde = map16. {"a": 1}.
        let buf = [0xde, 0x00, 0x01, 0xa1, b'a', 0x01];
        let v = decode(&buf).unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(m.get("a"), Some(&Value::UInt(1)));
    }

    #[test]
    fn map32_tag_decodes_map() {
        // 0xdf = map32. {"x": 5}.
        let buf = [0xdf, 0x00, 0x00, 0x00, 0x01, 0xa1, b'x', 0x05];
        let v = decode(&buf).unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(m.get("x"), Some(&Value::UInt(5)));
    }

    #[test]
    fn bin8_tag_consumes_payload_as_other() {
        // 0xc4 = bin8. We don't model binary; surface as Value::Other.
        let buf = [0xc4, 0x03, 0xaa, 0xbb, 0xcc];
        assert_eq!(decode(&buf).unwrap(), Value::Other(0xc4));
    }

    #[test]
    fn bin16_tag_consumes_payload_as_other() {
        // 0xc5 = bin16.
        let buf = [0xc5, 0x00, 0x02, 0xaa, 0xbb];
        assert_eq!(decode(&buf).unwrap(), Value::Other(0xc5));
    }

    #[test]
    fn bin32_tag_consumes_payload_as_other() {
        // 0xc6 = bin32.
        let buf = [0xc6, 0x00, 0x00, 0x00, 0x01, 0x42];
        assert_eq!(decode(&buf).unwrap(), Value::Other(0xc6));
    }

    #[test]
    fn read_u32_advances_cursor_by_four_bytes() {
        // After a 4-byte u32, the next value must come from byte 5.
        // Use [0xce, AABBCCDD, 0x05] (u32 then fixint(5)) inside an
        // array so we can observe both reads.
        let buf = [0x92, 0xce, 0xaa, 0xbb, 0xcc, 0xdd, 0x05];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::UInt(0xaabbccdd));
        assert_eq!(arr[1], Value::UInt(5));
    }

    #[test]
    fn read_u64_advances_cursor_by_eight_bytes() {
        // [0xcf, 8 bytes, 0x42] inside an array of 2.
        let buf = [
            0x92, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42,
        ];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::UInt(1));
        assert_eq!(arr[1], Value::UInt(0x42));
    }

    #[test]
    fn read_u16_advances_cursor_by_two_bytes() {
        // [0xcd, 0x12, 0x34, 0x05] inside an array of 2.
        let buf = [0x92, 0xcd, 0x12, 0x34, 0x05];
        let v = decode(&buf).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], Value::UInt(0x1234));
        assert_eq!(arr[1], Value::UInt(5));
    }

    #[test]
    fn as_uint_accepts_positive_int_only() {
        // Value::Int with non-negative value must coerce to u64;
        // negative must return None.
        assert_eq!(Value::Int(5).as_uint(), Some(5));
        assert_eq!(Value::Int(0).as_uint(), Some(0));
        assert_eq!(Value::Int(-1).as_uint(), None);
        assert_eq!(Value::Int(-100).as_uint(), None);
        // UInt always coerces.
        assert_eq!(Value::UInt(123).as_uint(), Some(123));
    }

    #[test]
    fn decode_error_display_is_non_empty() {
        // Empty input: read_value on no bytes errors. The Display impl
        // must produce a non-empty string with the offset.
        let err = decode(&[]).unwrap_err();
        let s = format!("{err}");
        assert!(!s.is_empty(), "DecodeError display must not be empty");
        assert!(
            s.contains("0x0"),
            "Display should mention offset; got {s:?}"
        );
    }
}
