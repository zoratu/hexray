//! Typed AMDGPU metadata records — what the `NT_AMDGPU_METADATA`
//! note carries.
//!
//! Schema is the "Code Object V3 Metadata" section of LLVM
//! `AMDGPUUsage.html`. The top-level MessagePack map has:
//!
//! - `amdhsa.version`: `[major, minor]`
//! - `amdhsa.target`: e.g. `"amdgcn-amd-amdhsa--gfx906"`
//! - `amdhsa.printf`: array of printf format strings (optional)
//! - `amdhsa.kernels`: array of per-kernel records
//!
//! Per-kernel keys (the ones we surface):
//!
//! - `.name` / `.symbol`
//! - `.kernarg_segment_size` / `.kernarg_segment_align`
//! - `.group_segment_fixed_size` / `.private_segment_fixed_size`
//! - `.sgpr_count` / `.vgpr_count` / `.agpr_count`
//! - `.max_flat_workgroup_size` / `.wavefront_size`
//! - `.args[]`: per-arg `(name, type_name, size, offset, value_kind,
//!   address_space, access)` records
//!
//! Anything we don't recognise is preserved verbatim in the
//! [`AmdMetadata::raw`] map for forward compatibility.

use super::msgpack::{decode as decode_msgpack, DecodeError, Value};

/// Top-level decoded AMDGPU metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct AmdMetadata {
    /// `amdhsa.version` — `[major, minor]` (typically `[1, 0]` for
    /// V3 / V5 metadata).
    pub version: Option<(u32, u32)>,
    /// `amdhsa.target` — e.g. `"amdgcn-amd-amdhsa--gfx906"`.
    pub target: Option<String>,
    /// `amdhsa.kernels` — one record per kernel.
    pub kernels: Vec<AmdMetadataKernel>,
    /// The full raw decoded value, retained for callers that want to
    /// inspect fields we didn't model.
    pub raw: Value,
}

/// One kernel record from `amdhsa.kernels[]`.
#[derive(Debug, Clone, PartialEq)]
pub struct AmdMetadataKernel {
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub kernarg_segment_size: Option<u64>,
    pub kernarg_segment_align: Option<u64>,
    pub group_segment_fixed_size: Option<u64>,
    pub private_segment_fixed_size: Option<u64>,
    pub sgpr_count: Option<u32>,
    pub vgpr_count: Option<u32>,
    pub agpr_count: Option<u32>,
    pub max_flat_workgroup_size: Option<u32>,
    pub wavefront_size: Option<u32>,
    pub args: Vec<AmdMetadataArg>,
}

/// One kernel-argument record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdMetadataArg {
    pub name: Option<String>,
    pub type_name: Option<String>,
    pub size: Option<u32>,
    pub offset: Option<u32>,
    /// `.value_kind` — `"by_value"`, `"global_buffer"`, `"hidden_*"`,
    /// etc. Preserved as-is so the cmp comparator can match on it.
    pub value_kind: Option<String>,
    pub address_space: Option<String>,
    pub access: Option<String>,
}

impl AmdMetadata {
    /// Decode a `NT_AMDGPU_METADATA` payload (the bytes after the
    /// note name + alignment padding).
    pub fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_msgpack(bytes)?;
        Ok(Self::from_value(raw))
    }

    /// Build from an already-decoded MessagePack value.
    pub fn from_value(raw: Value) -> Self {
        let mut out = Self {
            version: None,
            target: None,
            kernels: Vec::new(),
            raw: raw.clone(),
        };
        let Some(map) = raw.as_map() else {
            return out;
        };

        if let Some(arr) = map.get("amdhsa.version").and_then(Value::as_array) {
            if arr.len() >= 2 {
                let major = arr.first().and_then(|v| v.as_uint()).unwrap_or(0) as u32;
                let minor = arr.get(1).and_then(|v| v.as_uint()).unwrap_or(0) as u32;
                out.version = Some((major, minor));
            }
        }
        if let Some(s) = map.get("amdhsa.target").and_then(Value::as_str) {
            out.target = Some(s.to_string());
        }
        if let Some(arr) = map.get("amdhsa.kernels").and_then(Value::as_array) {
            for entry in arr {
                if let Some(map) = entry.as_map() {
                    out.kernels.push(parse_kernel(map));
                }
            }
        }
        out
    }
}

fn parse_kernel(map: &std::collections::BTreeMap<String, Value>) -> AmdMetadataKernel {
    AmdMetadataKernel {
        name: map.get(".name").and_then(Value::as_str).map(str::to_string),
        symbol: map
            .get(".symbol")
            .and_then(Value::as_str)
            .map(str::to_string),
        kernarg_segment_size: map.get(".kernarg_segment_size").and_then(Value::as_uint),
        kernarg_segment_align: map.get(".kernarg_segment_align").and_then(Value::as_uint),
        group_segment_fixed_size: map
            .get(".group_segment_fixed_size")
            .and_then(Value::as_uint),
        private_segment_fixed_size: map
            .get(".private_segment_fixed_size")
            .and_then(Value::as_uint),
        sgpr_count: map
            .get(".sgpr_count")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        vgpr_count: map
            .get(".vgpr_count")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        agpr_count: map
            .get(".agpr_count")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        max_flat_workgroup_size: map
            .get(".max_flat_workgroup_size")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        wavefront_size: map
            .get(".wavefront_size")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        args: map
            .get(".args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_map().map(parse_arg))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn parse_arg(map: &std::collections::BTreeMap<String, Value>) -> AmdMetadataArg {
    AmdMetadataArg {
        name: map.get(".name").and_then(Value::as_str).map(str::to_string),
        type_name: map
            .get(".type_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        size: map.get(".size").and_then(Value::as_uint).map(|n| n as u32),
        offset: map
            .get(".offset")
            .and_then(Value::as_uint)
            .map(|n| n as u32),
        value_kind: map
            .get(".value_kind")
            .and_then(Value::as_str)
            .map(str::to_string),
        address_space: map
            .get(".address_space")
            .and_then(Value::as_str)
            .map(str::to_string),
        access: map
            .get(".access")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a small AMDGPU-shaped MessagePack blob in tests.
    fn synth_metadata() -> Vec<u8> {
        // Build with the rmp-style helpers — we need to roll our own
        // since we don't depend on rmp. Just emits the exact bytes
        // we'd see in a real V3 metadata note.
        //
        // Top-level: {"amdhsa.version": [1, 0],
        //             "amdhsa.target": "amdgcn-amd-amdhsa--gfx906",
        //             "amdhsa.kernels": [{...}]}
        let mut b = Vec::new();
        // fixmap len=3
        b.push(0x83);
        // key "amdhsa.version"
        push_fixstr(&mut b, "amdhsa.version");
        // value: [1, 0]
        b.push(0x92);
        b.push(0x01);
        b.push(0x00);
        // key "amdhsa.target"
        push_fixstr(&mut b, "amdhsa.target");
        push_fixstr(&mut b, "amdgcn-amd-amdhsa--gfx906");
        // key "amdhsa.kernels"
        push_fixstr(&mut b, "amdhsa.kernels");
        // value: [kernel]
        b.push(0x91); // array len=1
        push_kernel(
            &mut b,
            "vector_add",
            "vector_add.kd",
            24,
            12,
            16,
            &[
                ("a", "global_buffer"),
                ("b", "global_buffer"),
                ("c", "by_value"),
            ],
        );
        b
    }

    fn push_fixstr(b: &mut Vec<u8>, s: &str) {
        let len = s.len();
        if len <= 31 {
            b.push(0xa0 | (len as u8));
        } else {
            b.push(0xd9);
            b.push(len as u8);
        }
        b.extend_from_slice(s.as_bytes());
    }

    fn push_kernel(
        b: &mut Vec<u8>,
        name: &str,
        symbol: &str,
        kernarg_size: u64,
        vgpr_count: u32,
        sgpr_count: u32,
        args: &[(&str, &str)],
    ) {
        // fixmap with 6 entries: name, symbol, kernarg_segment_size,
        // vgpr_count, sgpr_count, args.
        b.push(0x86);
        push_fixstr(b, ".name");
        push_fixstr(b, name);
        push_fixstr(b, ".symbol");
        push_fixstr(b, symbol);
        push_fixstr(b, ".kernarg_segment_size");
        push_uint(b, kernarg_size);
        push_fixstr(b, ".vgpr_count");
        push_uint(b, vgpr_count as u64);
        push_fixstr(b, ".sgpr_count");
        push_uint(b, sgpr_count as u64);
        push_fixstr(b, ".args");
        b.push(0x90 | (args.len() as u8));
        for (name, kind) in args {
            // fixmap with 2 entries: name, value_kind.
            b.push(0x82);
            push_fixstr(b, ".name");
            push_fixstr(b, name);
            push_fixstr(b, ".value_kind");
            push_fixstr(b, kind);
        }
    }

    fn push_uint(b: &mut Vec<u8>, n: u64) {
        if n < 128 {
            b.push(n as u8);
        } else if n <= u8::MAX as u64 {
            b.push(0xcc);
            b.push(n as u8);
        } else if n <= u16::MAX as u64 {
            b.push(0xcd);
            b.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            b.push(0xce);
            b.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }

    #[test]
    fn synthesises_and_round_trips_metadata() {
        let bytes = synth_metadata();
        let md = AmdMetadata::parse(&bytes).expect("parse");
        assert_eq!(md.version, Some((1, 0)));
        assert_eq!(md.target.as_deref(), Some("amdgcn-amd-amdhsa--gfx906"));
        assert_eq!(md.kernels.len(), 1);
        let k = &md.kernels[0];
        assert_eq!(k.name.as_deref(), Some("vector_add"));
        assert_eq!(k.symbol.as_deref(), Some("vector_add.kd"));
        assert_eq!(k.kernarg_segment_size, Some(24));
        assert_eq!(k.vgpr_count, Some(12));
        assert_eq!(k.sgpr_count, Some(16));
        assert_eq!(k.args.len(), 3);
        assert_eq!(k.args[0].name.as_deref(), Some("a"));
        assert_eq!(k.args[0].value_kind.as_deref(), Some("global_buffer"));
        assert_eq!(k.args[2].value_kind.as_deref(), Some("by_value"));
    }

    #[test]
    fn missing_keys_yield_none_not_panic() {
        // Just an empty top-level map.
        let bytes = vec![0x80];
        let md = AmdMetadata::parse(&bytes).unwrap();
        assert_eq!(md.version, None);
        assert_eq!(md.target, None);
        assert!(md.kernels.is_empty());
    }
}
