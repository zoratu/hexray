//! HIP / Clang Offload Bundle parser.
//!
//! HIP host binaries (output of `hipcc`/`clang -fhip`) embed device code
//! using the *Clang Offload Bundle* container, the AMD analogue of
//! NVIDIA's [`super::fatbin`] wrapper. The host ELF carries the bundle
//! as the contents of an `__hip_fatbin` global symbol or a section
//! commonly named `.hip_fatbin`. Each bundle holds one host payload
//! plus zero or more AMDGPU code objects, one per `gfx*` target.
//!
//! Layout (per `clang/include/clang/Driver/OffloadBundler.h`):
//!
//! ```text
//! struct __ClangOffloadBundleHeader {
//!     char  magic[24];                 // "__CLANG_OFFLOAD_BUNDLE__"
//!     u64   num_bundles;
//!     __ClangOffloadBundleEntry entries[num_bundles];
//! };
//! struct __ClangOffloadBundleEntry {
//!     u64   offset;                    // payload offset, from start of bundle
//!     u64   size;                      // payload size in bytes
//!     u64   triple_size;               // length of `triple`
//!     char  triple[triple_size];       // e.g. "host-x86_64-..." or
//!                                      // "hipv4-amdgcn-amd-amdhsa--gfx906"
//! };
//! ```
//!
//! All integers are little-endian; `triple` is plain ASCII without a
//! NUL terminator. The host bundle's triple starts with `host-` and the
//! AMDGPU bundles' triples start with `hip-` or `hipv4-`. We classify
//! each entry into [`HipBundleEntryKind`] and best-effort decode the
//! `gfx*` token into a [`hexray_core::GfxArchitecture`]; unknown
//! bundle kinds are kept as [`HipBundleEntryKind::Other`] for
//! forward-compatibility.
//!
//! This parser is deliberately tolerant: bad magic, truncated headers,
//! or out-of-range entry offsets surface as a [`HipBundleError`]
//! instead of panicking. We do **not** decompress LZ4 / zstd-compressed
//! bundle payloads here — those are rare for HIP and tracked as a
//! follow-up. Compressed bundle headers carry a different magic
//! (`CCOB`) and would be detected before this parser is reached.
//!
//! References: LLVM `clang/lib/Driver/OffloadBundler.cpp` (the writer
//! and reader of these bundles) and ROCm's `clang-offload-bundler`
//! command-line tool.

use hexray_core::GfxArchitecture;

/// Magic bytes at the start of an uncompressed Clang offload bundle.
pub const HIP_BUNDLE_MAGIC: &[u8; 24] = b"__CLANG_OFFLOAD_BUNDLE__";

/// Length of the bundle magic, in bytes.
pub const HIP_BUNDLE_MAGIC_LEN: usize = 24;

/// Length of the fixed bundle header (magic + `num_bundles`).
pub const HIP_BUNDLE_HEADER_SIZE: usize = HIP_BUNDLE_MAGIC_LEN + 8;

/// Length of the fixed portion of an entry record (the three `u64`s
/// that precede the variable-length triple string).
pub const HIP_BUNDLE_ENTRY_FIXED_SIZE: usize = 24;

/// Errors from parsing a HIP / Clang offload bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HipBundleError {
    /// Input too short to hold the requested structure.
    Truncated {
        /// What we tried to read (header / entry record / triple / payload).
        what: &'static str,
        /// Bytes required, including the prior cursor offset.
        needed: usize,
        /// Bytes available in the input buffer.
        have: usize,
    },
    /// First 24 bytes weren't `__CLANG_OFFLOAD_BUNDLE__`.
    BadMagic,
    /// An entry's triple or fixed record extends past the input buffer.
    EntryOverflow {
        entry_index: usize,
        entry_end: usize,
        buffer_len: usize,
    },
    /// An entry's payload (`offset + size`) extends past the input buffer.
    PayloadOverflow {
        entry_index: usize,
        payload_end: usize,
        buffer_len: usize,
    },
}

impl std::fmt::Display for HipBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { what, needed, have } => write!(
                f,
                "hip bundle truncated reading {what}: need {needed} bytes, have {have}"
            ),
            Self::BadMagic => f.write_str("hip bundle bad magic (expected __CLANG_OFFLOAD_BUNDLE__)"),
            Self::EntryOverflow {
                entry_index,
                entry_end,
                buffer_len,
            } => write!(
                f,
                "hip bundle entry #{entry_index} extends past buffer (end={entry_end}, len={buffer_len})"
            ),
            Self::PayloadOverflow {
                entry_index,
                payload_end,
                buffer_len,
            } => write!(
                f,
                "hip bundle entry #{entry_index} payload extends past buffer (end={payload_end}, len={buffer_len})"
            ),
        }
    }
}

impl std::error::Error for HipBundleError {}

/// What kind of bundle a single entry holds.
///
/// `Host` and `AmdgpuCodeObject` cover everything `hipcc` actually
/// emits today; `Other` is the forward-compat hatch for triples we
/// don't recognise (e.g. `openmp-...`, future GPU vendors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HipBundleEntryKind {
    /// `host-...` triple — wraps the host code (a copy of the host
    /// object/ELF the bundle is embedded in, for offload-bundler
    /// round-tripping). We don't try to interpret it further here.
    Host,
    /// `hip-amdgcn-...` or `hipv4-amdgcn-...` triple — the raw AMDGPU
    /// code object ELF for a single `gfx*` target.
    AmdgpuCodeObject(GfxArchitecture),
    /// Any other triple string. We keep the raw triple verbatim so
    /// callers can route on it without us having to understand it.
    Other(String),
}

/// One entry inside a HIP bundle.
#[derive(Debug, Clone)]
pub struct HipBundleEntry<'a> {
    /// The full triple string the bundle entry carried.
    ///
    /// Examples: `host-x86_64-unknown-linux-gnu`,
    /// `hipv4-amdgcn-amd-amdhsa--gfx906`,
    /// `hip-amdgcn-amd-amdhsa-gfx1030`.
    pub triple: &'a str,
    /// Byte offset of the payload, measured from the start of the
    /// bundle (i.e. from the `__CLANG_OFFLOAD_BUNDLE__` magic).
    pub offset: usize,
    /// Payload length in bytes.
    pub size: usize,
    /// Borrowed payload slice. For an AMDGPU bundle this is a complete
    /// AMDGPU code-object ELF; for the host bundle it's the host
    /// object the bundler captured.
    pub payload: &'a [u8],
    /// Decoded entry kind.
    pub kind: HipBundleEntryKind,
}

impl<'a> HipBundleEntry<'a> {
    /// Borrowed payload, regardless of kind.
    pub fn data(&self) -> &'a [u8] {
        self.payload
    }

    /// `true` if this is an AMDGPU code object entry.
    pub fn is_amdgpu(&self) -> bool {
        matches!(self.kind, HipBundleEntryKind::AmdgpuCodeObject(_))
    }

    /// `true` if this is the host bundle entry.
    pub fn is_host(&self) -> bool {
        matches!(self.kind, HipBundleEntryKind::Host)
    }

    /// Returns the gfx target if this is an AMDGPU code object.
    pub fn gfx(&self) -> Option<GfxArchitecture> {
        if let HipBundleEntryKind::AmdgpuCodeObject(g) = &self.kind {
            Some(*g)
        } else {
            None
        }
    }
}

/// A parsed HIP / Clang offload bundle wrapper.
#[derive(Debug, Clone)]
pub struct HipBundleWrapper<'a> {
    /// Raw bytes of the full bundle (header + all entries + payloads).
    pub raw: &'a [u8],
    /// Decoded entries, in the same order they appear in the bundle.
    pub entries: Vec<HipBundleEntry<'a>>,
}

impl<'a> HipBundleWrapper<'a> {
    /// Parse a HIP bundle from its own bytes. The slice must start at
    /// the `__CLANG_OFFLOAD_BUNDLE__` magic. Callers extracting from a
    /// host binary should first slice out the `.hip_fatbin` section
    /// (or the contents of the `__hip_fatbin` symbol).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HipBundleError> {
        if bytes.len() < HIP_BUNDLE_HEADER_SIZE {
            return Err(HipBundleError::Truncated {
                what: "bundle header",
                needed: HIP_BUNDLE_HEADER_SIZE,
                have: bytes.len(),
            });
        }
        if bytes.get(..HIP_BUNDLE_MAGIC_LEN) != Some(HIP_BUNDLE_MAGIC.as_slice()) {
            return Err(HipBundleError::BadMagic);
        }
        let num_bundles = read_u64_le(bytes, HIP_BUNDLE_MAGIC_LEN)? as usize;

        let mut entries = Vec::with_capacity(num_bundles.min(64));
        let mut cursor = HIP_BUNDLE_HEADER_SIZE;
        for entry_index in 0..num_bundles {
            // Fixed three u64s: offset, size, triple_size.
            let fixed_end = cursor.saturating_add(HIP_BUNDLE_ENTRY_FIXED_SIZE);
            if fixed_end > bytes.len() {
                return Err(HipBundleError::EntryOverflow {
                    entry_index,
                    entry_end: fixed_end,
                    buffer_len: bytes.len(),
                });
            }
            let offset = read_u64_le(bytes, cursor)? as usize;
            let size = read_u64_le(bytes, cursor.saturating_add(8))? as usize;
            let triple_size = read_u64_le(bytes, cursor.saturating_add(16))? as usize;

            let triple_start = fixed_end;
            let triple_end = triple_start.saturating_add(triple_size);
            if triple_end > bytes.len() {
                return Err(HipBundleError::EntryOverflow {
                    entry_index,
                    entry_end: triple_end,
                    buffer_len: bytes.len(),
                });
            }
            let triple_bytes = bytes.get(triple_start..triple_end).unwrap_or(&[]);
            // Triples are documented as ASCII; treat invalid UTF-8
            // bytes as an entry overflow rather than panicking. In
            // practice every triple seen in the wild is ASCII.
            let triple =
                std::str::from_utf8(triple_bytes).map_err(|_| HipBundleError::EntryOverflow {
                    entry_index,
                    entry_end: triple_end,
                    buffer_len: bytes.len(),
                })?;

            // Payload offsets are absolute (from start of bundle).
            let payload_end = offset.saturating_add(size);
            if payload_end > bytes.len() {
                return Err(HipBundleError::PayloadOverflow {
                    entry_index,
                    payload_end,
                    buffer_len: bytes.len(),
                });
            }
            let payload = bytes.get(offset..payload_end).unwrap_or(&[]);

            entries.push(HipBundleEntry {
                triple,
                offset,
                size,
                payload,
                kind: classify_triple(triple),
            });

            cursor = triple_end;
        }

        Ok(Self {
            raw: bytes,
            entries,
        })
    }

    /// Iterator over only AMDGPU code-object entries.
    pub fn amdgpu_objects(&self) -> impl Iterator<Item = &HipBundleEntry<'a>> {
        self.entries.iter().filter(|e| e.is_amdgpu())
    }

    /// Alias for [`Self::amdgpu_objects`], matching the NVIDIA
    /// fatbin's [`super::fatbin::FatbinWrapper::cubins`] spelling so
    /// callers can write generic format-agnostic code.
    pub fn cubins(&self) -> impl Iterator<Item = &HipBundleEntry<'a>> {
        self.amdgpu_objects()
    }

    /// Returns the host bundle's payload, if any.
    pub fn host_payload(&self) -> Option<&'a [u8]> {
        self.entries.iter().find(|e| e.is_host()).map(|e| e.payload)
    }
}

/// Classify a bundle triple into [`HipBundleEntryKind`].
///
/// We split on `-` and accept anything starting with `host-` as host,
/// anything starting with `hip-` or `hipv4-` *and* containing a `gfx*`
/// token as an AMDGPU code object, and everything else as `Other`.
fn classify_triple(triple: &str) -> HipBundleEntryKind {
    if triple.starts_with("host-") || triple == "host" {
        return HipBundleEntryKind::Host;
    }
    let is_hip = triple.starts_with("hip-") || triple.starts_with("hipv4-");
    if is_hip {
        if let Some(gfx) = parse_gfx_from_triple(triple) {
            return HipBundleEntryKind::AmdgpuCodeObject(gfx);
        }
    }
    HipBundleEntryKind::Other(triple.to_string())
}

/// Find the first `gfx<NNN>` token in a hyphen-separated triple and
/// decode it into a [`GfxArchitecture`].
///
/// Examples we accept:
///
/// - `hipv4-amdgcn-amd-amdhsa--gfx906` → `gfx906`
/// - `hipv4-amdgcn-amd-amdhsa-unknown-gfx1030` → `gfx1030`
/// - `hip-amdgcn-amd-amdhsa--gfx1100` → `gfx1100`
/// - `hipv4-amdgcn-amd-amdhsa--gfx90a:xnack+` → `gfx90a` (features
///   are not parsed here; the bundler also encodes them out-of-band).
fn parse_gfx_from_triple(triple: &str) -> Option<GfxArchitecture> {
    for token in triple.split('-') {
        if let Some(gfx) = parse_gfx_token(token) {
            return Some(gfx);
        }
    }
    None
}

/// Decode a single `gfxNNN` (or `gfxNNN:feature±`) token.
fn parse_gfx_token(token: &str) -> Option<GfxArchitecture> {
    // Strip an optional `:xnack+` / `:sramecc-` style feature suffix.
    let core = token.split(':').next()?;
    let digits = core.strip_prefix("gfx")?;
    if digits.is_empty() {
        return None;
    }
    // The gfx target encoding is positional:
    //   stepping = last hex digit (one nibble)
    //   minor    = next-to-last hex digit (one nibble)
    //   major    = whatever remains, as decimal
    //
    // Rationale: for `gfx906` major=9 minor=0 stepping=6; for `gfx90a`
    // major=9 minor=0 stepping=0xA; for `gfx1030` major=10 minor=3
    // stepping=0; for `gfx1100` major=11 minor=0 stepping=0. The
    // major part is decimal (so `gfx10*` is "ten", not "one-zero"),
    // while minor and stepping are single-hex-digit.
    if digits.len() < 2 {
        return None;
    }
    let bytes = digits.as_bytes();
    // bytes is non-empty by the digits-string check above; using
    // .last() and split_last avoids the explicit subtraction.
    let (last, rest) = bytes.split_last()?;
    let (penult, _) = rest.split_last()?;
    let stepping = hex_nibble(*last)?;
    let minor = hex_nibble(*penult)?;
    let major_str = digits.get(..digits.len().saturating_sub(2)).unwrap_or("");
    let major: u8 = major_str.parse().ok()?;
    Some(GfxArchitecture::new(major, minor, stepping))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, HipBundleError> {
    let end = offset.checked_add(8).ok_or(HipBundleError::Truncated {
        what: "u64 field",
        needed: usize::MAX,
        have: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(HipBundleError::Truncated {
            what: "u64 field",
            needed: end,
            have: bytes.len(),
        });
    }
    let chunk = bytes.get(offset..end).ok_or(HipBundleError::Truncated {
        what: "u64 field",
        needed: end,
        have: bytes.len(),
    })?;
    Ok(u64::from_le_bytes(chunk.try_into().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesise a minimal Clang offload bundle from a list of
    /// `(triple, payload)` pairs. Layout matches what
    /// `clang-offload-bundler` writes: fixed 32-byte header
    /// (magic + `num_bundles`), then per-entry `(offset, size,
    /// triple_size, triple_bytes)` records, and finally the
    /// concatenated payloads. Offsets are absolute from the start of
    /// the bundle.
    pub(super) fn build_bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
        // First pass: compute the size of the entry table so we know
        // where the payload region starts.
        let mut entry_table_size = 0usize;
        for (triple, _) in entries {
            entry_table_size += HIP_BUNDLE_ENTRY_FIXED_SIZE + triple.len();
        }
        let payload_region_start = HIP_BUNDLE_HEADER_SIZE + entry_table_size;

        let mut out = Vec::new();
        out.extend_from_slice(HIP_BUNDLE_MAGIC);
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());

        // Compute each entry's absolute payload offset before we emit
        // the entry records (so the table is internally consistent).
        let mut payload_offsets: Vec<usize> = Vec::with_capacity(entries.len());
        let mut running = payload_region_start;
        for (_, payload) in entries {
            payload_offsets.push(running);
            running += payload.len();
        }

        for (i, (triple, payload)) in entries.iter().enumerate() {
            out.extend_from_slice(&(payload_offsets[i] as u64).to_le_bytes());
            out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            out.extend_from_slice(&(triple.len() as u64).to_le_bytes());
            out.extend_from_slice(triple.as_bytes());
        }

        for (_, payload) in entries {
            out.extend_from_slice(payload);
        }
        out
    }

    /// Tiny ELF-ish stub bytes — not a real AMDGPU code object, but
    /// enough to round-trip the payload bytes through the parser.
    fn fake_amdgpu_payload(label: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x7fELF"); // ELF magic so it looks plausible
        v.extend_from_slice(label);
        v
    }

    #[test]
    fn parses_a_round_tripped_bundle() {
        let host = b"HOSTOBJ_PLACEHOLDER";
        let gfx906 = fake_amdgpu_payload(b"-gfx906");
        let gfx1030 = fake_amdgpu_payload(b"-gfx1030");

        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", host),
            ("hipv4-amdgcn-amd-amdhsa--gfx906", &gfx906),
            ("hip-amdgcn-amd-amdhsa-gfx1030", &gfx1030),
        ]);

        let w = HipBundleWrapper::parse(&blob).expect("round-trip parse");
        assert_eq!(w.entries.len(), 3);

        // Order is preserved.
        assert!(w.entries[0].is_host());
        assert!(w.entries[1].is_amdgpu());
        assert!(w.entries[2].is_amdgpu());

        // Payloads round-trip bit-for-bit.
        assert_eq!(w.entries[0].payload, host);
        assert_eq!(w.entries[1].payload, gfx906.as_slice());
        assert_eq!(w.entries[2].payload, gfx1030.as_slice());

        // Triple round-trip.
        assert_eq!(w.entries[0].triple, "host-x86_64-unknown-linux-gnu");
        assert_eq!(w.entries[1].triple, "hipv4-amdgcn-amd-amdhsa--gfx906");
        assert_eq!(w.entries[2].triple, "hip-amdgcn-amd-amdhsa-gfx1030");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = build_bundle(&[("host-x86_64", b"x")]);
        blob[0] = b'X';
        assert!(matches!(
            HipBundleWrapper::parse(&blob),
            Err(HipBundleError::BadMagic)
        ));
    }

    #[test]
    fn rejects_truncated_header() {
        // 8 bytes is well under the 32-byte fixed header.
        assert!(matches!(
            HipBundleWrapper::parse(&[0u8; 8]),
            Err(HipBundleError::Truncated {
                what: "bundle header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_payload_overflow() {
        let host = b"HOST";
        let mut blob = build_bundle(&[("host-x86_64-foo", host)]);
        // Patch the first entry's `size` (8 bytes after offset, which
        // is at HIP_BUNDLE_HEADER_SIZE) to a value that pushes the
        // payload off the end of the buffer.
        let size_field = HIP_BUNDLE_HEADER_SIZE + 8;
        blob[size_field..size_field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            HipBundleWrapper::parse(&blob),
            Err(HipBundleError::PayloadOverflow { .. })
        ));
    }

    #[test]
    fn rejects_entry_overflow_when_triple_runs_off_end() {
        let host = b"HOST";
        let mut blob = build_bundle(&[("host-x86_64-foo", host)]);
        // Patch the first entry's `triple_size` (16 bytes after
        // offset) to claim a huge triple — the table walk should see
        // its end past the buffer.
        let triple_size_field = HIP_BUNDLE_HEADER_SIZE + 16;
        blob[triple_size_field..triple_size_field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            HipBundleWrapper::parse(&blob),
            Err(HipBundleError::EntryOverflow { .. })
        ));
    }

    #[test]
    fn extracts_two_amdgpu_entries_with_correct_gfx_targets() {
        let host = b"HOSTOBJ";
        let gfx906 = fake_amdgpu_payload(b"-906");
        let gfx1030 = fake_amdgpu_payload(b"-1030");
        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", host),
            ("hipv4-amdgcn-amd-amdhsa--gfx906", &gfx906),
            ("hipv4-amdgcn-amd-amdhsa-unknown-gfx1030", &gfx1030),
        ]);
        let w = HipBundleWrapper::parse(&blob).unwrap();
        let gpus: Vec<_> = w.amdgpu_objects().collect();
        assert_eq!(gpus.len(), 2);
        let arches: Vec<_> = gpus.iter().filter_map(|e| e.gfx()).collect();
        assert_eq!(arches[0], GfxArchitecture::new(9, 0, 6));
        assert_eq!(arches[1], GfxArchitecture::new(10, 3, 0));
        // Canonical names round-trip.
        assert_eq!(arches[0].canonical_name(), "gfx906");
        assert_eq!(arches[1].canonical_name(), "gfx1030");
    }

    #[test]
    fn host_triple_is_classified_as_host_kind() {
        let host = b"HOSTOBJ";
        let gfx906 = fake_amdgpu_payload(b"-gfx906");
        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", host),
            ("hipv4-amdgcn-amd-amdhsa--gfx906", &gfx906),
        ]);
        let w = HipBundleWrapper::parse(&blob).unwrap();
        assert_eq!(w.entries[0].kind, HipBundleEntryKind::Host);
        assert!(w.entries[0].is_host());
        assert_eq!(w.host_payload(), Some(host.as_slice()));
    }

    #[test]
    fn parses_gfx90a_with_hex_stepping() {
        let host = b"H";
        let gfx90a = fake_amdgpu_payload(b"-90a");
        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", host),
            ("hipv4-amdgcn-amd-amdhsa--gfx90a", &gfx90a),
        ]);
        let w = HipBundleWrapper::parse(&blob).unwrap();
        let arch = w.amdgpu_objects().next().unwrap().gfx().unwrap();
        assert_eq!(arch, GfxArchitecture::new(9, 0, 0xA));
        assert_eq!(arch.canonical_name(), "gfx90a");
    }

    #[test]
    fn parses_gfx1100_modern_rdna3() {
        let host = b"H";
        let gfx1100 = fake_amdgpu_payload(b"-1100");
        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", host),
            ("hip-amdgcn-amd-amdhsa--gfx1100", &gfx1100),
        ]);
        let w = HipBundleWrapper::parse(&blob).unwrap();
        let arch = w.amdgpu_objects().next().unwrap().gfx().unwrap();
        assert_eq!(arch, GfxArchitecture::new(11, 0, 0));
        assert_eq!(arch.canonical_name(), "gfx1100");
    }

    #[test]
    fn unknown_triple_falls_back_to_other() {
        // OpenMP offload bundles share the same container but use a
        // different prefix; we keep them as `Other(...)` rather than
        // misclassifying.
        let payload = b"OPENMP_OBJ";
        let blob = build_bundle(&[
            ("host-x86_64-unknown-linux-gnu", b"H"),
            ("openmp-amdgcn-amd-amdhsa--gfx906", payload),
        ]);
        let w = HipBundleWrapper::parse(&blob).unwrap();
        assert!(matches!(w.entries[1].kind, HipBundleEntryKind::Other(_)));
        if let HipBundleEntryKind::Other(t) = &w.entries[1].kind {
            assert_eq!(t, "openmp-amdgcn-amd-amdhsa--gfx906");
        }
        assert_eq!(w.amdgpu_objects().count(), 0);
    }

    #[test]
    fn parses_gfx_token_directly() {
        assert_eq!(
            parse_gfx_token("gfx906"),
            Some(GfxArchitecture::new(9, 0, 6))
        );
        assert_eq!(
            parse_gfx_token("gfx90a"),
            Some(GfxArchitecture::new(9, 0, 0xA))
        );
        assert_eq!(
            parse_gfx_token("gfx1030"),
            Some(GfxArchitecture::new(10, 3, 0))
        );
        assert_eq!(
            parse_gfx_token("gfx1100"),
            Some(GfxArchitecture::new(11, 0, 0))
        );
        assert_eq!(
            parse_gfx_token("gfx942:xnack-"),
            Some(GfxArchitecture::new(9, 4, 2))
        );
        assert_eq!(parse_gfx_token("amdhsa"), None);
        assert_eq!(parse_gfx_token("gfx"), None);
        assert_eq!(parse_gfx_token("gfxZZ"), None);
    }
}
