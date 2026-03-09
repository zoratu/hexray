//! Property-based tests for the C header parser.

use proptest::prelude::*;
use proptest::string::string_regex;

use hexray_types::parser::parse_header;

fn ident() -> impl Strategy<Value = String> {
    string_regex("[A-Za-z_][A-Za-z0-9_]{0,15}").expect("identifier regex should compile")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn parse_header_never_panics_on_ascii(data in prop::collection::vec(0x20u8..0x7fu8, 0..512)) {
        let input = String::from_utf8(data).expect("ASCII bytes should be valid UTF-8");
        let _ = parse_header(&input);
    }

    #[test]
    fn generated_typedefs_are_registered(name in ident()) {
        let input = format!("typedef unsigned int {};", name);
        let db = parse_header(&input).expect("generated typedef should parse");
        prop_assert!(db.has_type(&name));
    }

    #[test]
    fn generated_structs_are_registered(struct_name in ident(), field_count in 1usize..5) {
        let mut input = format!("struct {} {{", struct_name);
        for field_idx in 0..field_count {
            input.push_str(&format!(" int field_{};", field_idx));
        }
        input.push_str(" };");

        let db = parse_header(&input).expect("generated struct should parse");
        let type_name = format!("struct {}", struct_name);
        prop_assert!(db.has_type(&type_name));
    }

    #[test]
    fn generated_function_decls_are_registered(function_name in ident(), param_count in 0usize..5) {
        let params = if param_count == 0 {
            "void".to_string()
        } else {
            (0..param_count)
                .map(|idx| format!("int arg_{}", idx))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let input = format!("int {}({});", function_name, params);

        let db = parse_header(&input).expect("generated function declaration should parse");
        prop_assert!(db.has_function(&function_name));
    }
}
