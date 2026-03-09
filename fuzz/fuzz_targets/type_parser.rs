#![no_main]

use hexray_types::parser::parse_header;
use libfuzzer_sys::fuzz_target;

fn ident(bytes: &[u8], fallback: &str) -> String {
    let mut ident = String::new();

    for (idx, byte) in bytes.iter().take(16).enumerate() {
        let ch = if idx == 0 {
            if byte.is_ascii_alphabetic() || *byte == b'_' {
                *byte as char
            } else {
                fallback.chars().next().unwrap_or('t')
            }
        } else if byte.is_ascii_alphanumeric() || *byte == b'_' {
            *byte as char
        } else {
            '_'
        };
        ident.push(ch);
    }

    if ident.is_empty() {
        fallback.to_string()
    } else {
        ident
    }
}

fn structured_header(data: &[u8]) -> String {
    let name = ident(data, "generated_type");
    let field_count = data.first().map(|byte| (byte % 4 + 1) as usize).unwrap_or(1);

    match data.get(1).copied().unwrap_or(0) % 3 {
        0 => format!("typedef unsigned int {};", name),
        1 => {
            let mut header = format!("struct {} {{", name);
            for idx in 0..field_count {
                header.push_str(&format!(" int field_{};", idx));
            }
            header.push_str(" };");
            header
        }
        _ => {
            let params = (0..field_count)
                .map(|idx| format!("int arg_{}", idx))
                .collect::<Vec<_>>()
                .join(", ");
            format!("int {}({});", name, params)
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let raw_input = String::from_utf8_lossy(data);
    let _ = parse_header(&raw_input);

    let generated = structured_header(data);
    if let Ok(db) = parse_header(&generated) {
        let _ = db.stats();
        let _ = db.type_names().count();
        let _ = db.typedef_names().count();
        let _ = db.function_names().count();
        let _ = db.to_json();
    }
});
