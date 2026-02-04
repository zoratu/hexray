//! Simplified C header parser.
//!
//! This parser handles a subset of C:
//! - struct, union, enum definitions
//! - typedef declarations
//! - function declarations
//! - Basic type specifiers (int, char, etc.)
//! - Pointers and arrays
//!
//! It does NOT handle:
//! - Preprocessor directives (#include, #define, etc.)
//! - Complex expressions
//! - Function bodies
//! - Attributes

use crate::database::TypeDatabase;
use crate::types::*;
use thiserror::Error;

/// Errors that can occur during parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Unexpected token: expected {expected}, got {got}")]
    UnexpectedToken { expected: String, got: String },

    #[error("Unexpected end of input")]
    UnexpectedEof,

    #[error("Invalid type: {0}")]
    InvalidType(String),

    #[error("Unknown type: {0}")]
    UnknownType(String),

    #[error("Syntax error at position {pos}: {message}")]
    SyntaxError { pos: usize, message: String },
}

/// Result type for parsing operations.
pub type ParseResult<T> = Result<T, ParseError>;

/// Token types for the lexer.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Struct,
    Union,
    Enum,
    Typedef,
    Const,
    Volatile,
    Static,
    Extern,
    Signed,
    Unsigned,
    Void,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,

    // Punctuation
    Semicolon,
    Comma,
    Star,
    OpenBrace,
    CloseBrace,
    OpenBracket,
    CloseBracket,
    OpenParen,
    CloseParen,
    Equals,
    Ellipsis,
    Colon,

    // Identifiers and literals
    Ident(String),
    Number(i64),

    // End of input
    Eof,
}

/// A simple lexer for C headers.
struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.next_char();
            } else if ch == '/' {
                // Skip comments
                let next_pos = self.pos + 1;
                if next_pos < self.input.len() {
                    let next = self.input[next_pos..].chars().next();
                    if next == Some('/') {
                        // Line comment
                        while let Some(ch) = self.next_char() {
                            if ch == '\n' {
                                break;
                            }
                        }
                    } else if next == Some('*') {
                        // Block comment
                        self.pos += 2;
                        while self.pos + 1 < self.input.len() {
                            if &self.input[self.pos..self.pos + 2] == "*/" {
                                self.pos += 2;
                                break;
                            }
                            self.pos += 1;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self) -> ParseResult<Token> {
        self.skip_whitespace();

        let ch = match self.peek_char() {
            Some(ch) => ch,
            None => return Ok(Token::Eof),
        };

        // Single-character tokens
        let token = match ch {
            ';' => {
                self.next_char();
                Token::Semicolon
            }
            ',' => {
                self.next_char();
                Token::Comma
            }
            '*' => {
                self.next_char();
                Token::Star
            }
            '{' => {
                self.next_char();
                Token::OpenBrace
            }
            '}' => {
                self.next_char();
                Token::CloseBrace
            }
            '[' => {
                self.next_char();
                Token::OpenBracket
            }
            ']' => {
                self.next_char();
                Token::CloseBracket
            }
            '(' => {
                self.next_char();
                Token::OpenParen
            }
            ')' => {
                self.next_char();
                Token::CloseParen
            }
            '=' => {
                self.next_char();
                Token::Equals
            }
            ':' => {
                self.next_char();
                Token::Colon
            }
            '.' => {
                // Check for ellipsis
                if self.input[self.pos..].starts_with("...") {
                    self.pos += 3;
                    Token::Ellipsis
                } else {
                    return Err(ParseError::SyntaxError {
                        pos: self.pos,
                        message: "Unexpected '.'".to_string(),
                    });
                }
            }
            _ if ch.is_ascii_digit() || ch == '-' => self.parse_number()?,
            _ if ch.is_ascii_alphabetic() || ch == '_' => self.parse_ident_or_keyword(),
            _ => {
                return Err(ParseError::SyntaxError {
                    pos: self.pos,
                    message: format!("Unexpected character: '{}'", ch),
                });
            }
        };

        Ok(token)
    }

    fn parse_number(&mut self) -> ParseResult<Token> {
        let start = self.pos;
        let mut is_negative = false;

        if self.peek_char() == Some('-') {
            is_negative = true;
            self.next_char();
        }

        // Check for hex
        if self.input[self.pos..].starts_with("0x") || self.input[self.pos..].starts_with("0X") {
            self.pos += 2;
            let hex_start = self.pos;
            while let Some(ch) = self.peek_char() {
                if ch.is_ascii_hexdigit() {
                    self.next_char();
                } else {
                    break;
                }
            }
            let hex_str = &self.input[hex_start..self.pos];
            let value = i64::from_str_radix(hex_str, 16).map_err(|_| ParseError::SyntaxError {
                pos: start,
                message: "Invalid hex number".to_string(),
            })?;
            return Ok(Token::Number(if is_negative { -value } else { value }));
        }

        // Decimal number
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                self.next_char();
            } else {
                break;
            }
        }

        // Skip suffixes like L, UL, LL, etc.
        while let Some(ch) = self.peek_char() {
            if ch == 'L' || ch == 'l' || ch == 'U' || ch == 'u' {
                self.next_char();
            } else {
                break;
            }
        }

        let num_str = &self.input[start..self.pos];
        let num_str = num_str.trim_end_matches(['L', 'l', 'U', 'u']);
        let value: i64 = num_str.parse().map_err(|_| ParseError::SyntaxError {
            pos: start,
            message: format!("Invalid number: {}", num_str),
        })?;

        Ok(Token::Number(value))
    }

    fn parse_ident_or_keyword(&mut self) -> Token {
        let start = self.pos;
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                self.next_char();
            } else {
                break;
            }
        }

        let ident = &self.input[start..self.pos];
        match ident {
            "struct" => Token::Struct,
            "union" => Token::Union,
            "enum" => Token::Enum,
            "typedef" => Token::Typedef,
            "const" => Token::Const,
            "volatile" => Token::Volatile,
            "static" => Token::Static,
            "extern" => Token::Extern,
            "signed" => Token::Signed,
            "unsigned" => Token::Unsigned,
            "void" => Token::Void,
            "char" => Token::Char,
            "short" => Token::Short,
            "int" => Token::Int,
            "long" => Token::Long,
            "float" => Token::Float,
            "double" => Token::Double,
            _ => Token::Ident(ident.to_string()),
        }
    }
}

/// C header parser.
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token,
    database: TypeDatabase,
}

impl<'a> Parser<'a> {
    /// Create a new parser for the given input.
    pub fn new(input: &'a str) -> ParseResult<Self> {
        let mut lexer = Lexer::new(input);
        let current = lexer.next_token()?;
        Ok(Self {
            lexer,
            current,
            database: TypeDatabase::new(),
        })
    }

    /// Parse all declarations and return the type database.
    pub fn parse(mut self) -> ParseResult<TypeDatabase> {
        while self.current != Token::Eof {
            self.parse_declaration()?;
        }
        Ok(self.database)
    }

    fn advance(&mut self) -> ParseResult<Token> {
        let prev = std::mem::replace(&mut self.current, Token::Eof);
        self.current = self.lexer.next_token()?;
        Ok(prev)
    }

    fn expect(&mut self, expected: Token) -> ParseResult<()> {
        if self.current == expected {
            self.advance()?;
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                expected: format!("{:?}", expected),
                got: format!("{:?}", self.current),
            })
        }
    }

    fn parse_declaration(&mut self) -> ParseResult<()> {
        // Skip qualifiers
        while matches!(self.current, Token::Static | Token::Extern) {
            self.advance()?;
        }

        match &self.current {
            Token::Typedef => self.parse_typedef(),
            Token::Struct => self.parse_struct_declaration(),
            Token::Union => self.parse_union_declaration(),
            Token::Enum => self.parse_enum_declaration(),
            _ => self.parse_function_or_variable(),
        }
    }

    fn parse_typedef(&mut self) -> ParseResult<()> {
        self.expect(Token::Typedef)?;

        let base_type = self.parse_type()?;

        // Get the typedef name (after any pointer/array modifiers)
        let (final_type, name) = self.parse_declarator(base_type)?;

        self.expect(Token::Semicolon)?;

        self.database.add_typedef(&name, final_type);
        Ok(())
    }

    fn parse_struct_declaration(&mut self) -> ParseResult<()> {
        let st = self.parse_struct()?;
        if let CType::Struct(ref s) = st {
            if let Some(name) = &s.name {
                self.database
                    .add_type(format!("struct {}", name), st.clone());
            }
        }

        // Check for variable declaration after struct definition
        if self.current != Token::Semicolon {
            let (_, _name) = self.parse_declarator(st)?;
        }

        self.expect(Token::Semicolon)?;
        Ok(())
    }

    fn parse_union_declaration(&mut self) -> ParseResult<()> {
        let un = self.parse_union()?;
        if let CType::Union(ref u) = un {
            if let Some(name) = &u.name {
                self.database
                    .add_type(format!("union {}", name), un.clone());
            }
        }

        // Check for variable declaration after union definition
        if self.current != Token::Semicolon {
            let (_, _name) = self.parse_declarator(un)?;
        }

        self.expect(Token::Semicolon)?;
        Ok(())
    }

    fn parse_enum_declaration(&mut self) -> ParseResult<()> {
        let en = self.parse_enum()?;
        if let CType::Enum(ref e) = en {
            if let Some(name) = &e.name {
                self.database.add_type(format!("enum {}", name), en.clone());
            }
        }

        // Check for variable declaration after enum definition
        if self.current != Token::Semicolon {
            let (_, _name) = self.parse_declarator(en)?;
        }

        self.expect(Token::Semicolon)?;
        Ok(())
    }

    fn parse_function_or_variable(&mut self) -> ParseResult<()> {
        let base_type = self.parse_type()?;

        if self.current == Token::Semicolon {
            self.advance()?;
            return Ok(());
        }

        let (final_type, name) = self.parse_declarator(base_type)?;

        // Check if this is a function declaration
        if self.current == Token::OpenParen {
            let params = self.parse_parameter_list()?;
            self.expect(Token::Semicolon)?;

            let mut proto = FunctionPrototype::new(&name, final_type);
            for (param_name, param_type) in params.0 {
                proto.parameters.push((param_name, param_type));
            }
            proto.variadic = params.1;

            self.database.add_function(proto);
        } else {
            // Variable declaration - skip
            while self.current != Token::Semicolon && self.current != Token::Eof {
                self.advance()?;
            }
            if self.current == Token::Semicolon {
                self.advance()?;
            }
        }

        Ok(())
    }

    fn parse_type(&mut self) -> ParseResult<CType> {
        // Skip const/volatile
        while matches!(self.current, Token::Const | Token::Volatile) {
            self.advance()?;
        }

        let mut is_signed = true;
        let mut have_sign = false;

        // Check for signed/unsigned
        if self.current == Token::Signed {
            is_signed = true;
            have_sign = true;
            self.advance()?;
        } else if self.current == Token::Unsigned {
            is_signed = false;
            have_sign = true;
            self.advance()?;
        }

        // Skip const/volatile again
        while matches!(self.current, Token::Const | Token::Volatile) {
            self.advance()?;
        }

        let base = match &self.current {
            Token::Void => {
                self.advance()?;
                CType::Void
            }
            Token::Char => {
                self.advance()?;
                CType::Int(IntType::new(1, is_signed))
            }
            Token::Short => {
                self.advance()?;
                // Skip optional 'int'
                if self.current == Token::Int {
                    self.advance()?;
                }
                CType::Int(IntType::new(2, is_signed))
            }
            Token::Int => {
                self.advance()?;
                CType::Int(IntType::new(4, is_signed))
            }
            Token::Long => {
                self.advance()?;
                // Check for 'long long'
                if self.current == Token::Long {
                    self.advance()?;
                    // Skip optional 'int'
                    if self.current == Token::Int {
                        self.advance()?;
                    }
                    CType::Int(IntType::new(8, is_signed))
                } else {
                    // Skip optional 'int'
                    if self.current == Token::Int {
                        self.advance()?;
                    }
                    CType::Int(IntType::new(8, is_signed)) // Assuming LP64
                }
            }
            Token::Float => {
                self.advance()?;
                CType::Float(FloatType::float())
            }
            Token::Double => {
                self.advance()?;
                CType::Float(FloatType::double())
            }
            Token::Struct => self.parse_struct()?,
            Token::Union => self.parse_union()?,
            Token::Enum => self.parse_enum()?,
            Token::Ident(name) => {
                let name = name.clone();
                self.advance()?;
                CType::Named(name)
            }
            _ if have_sign => {
                // Just 'signed' or 'unsigned' alone means int
                CType::Int(IntType::new(4, is_signed))
            }
            _ => {
                return Err(ParseError::InvalidType(format!("{:?}", self.current)));
            }
        };

        Ok(base)
    }

    fn parse_struct(&mut self) -> ParseResult<CType> {
        self.expect(Token::Struct)?;

        let name = if let Token::Ident(n) = &self.current {
            let n = n.clone();
            self.advance()?;
            Some(n)
        } else {
            None
        };

        // Check for forward declaration or reference
        if self.current != Token::OpenBrace {
            return Ok(CType::Named(format!("struct {}", name.unwrap_or_default())));
        }

        self.expect(Token::OpenBrace)?;

        let mut st = StructType::new(name);

        while self.current != Token::CloseBrace && self.current != Token::Eof {
            let field_type = self.parse_type()?;
            let (final_type, field_name) = self.parse_declarator(field_type)?;

            // Check for bit field
            if self.current == Token::Colon {
                self.advance()?;
                if let Token::Number(_) = self.current {
                    self.advance()?;
                }
            }

            st.add_field(field_name, final_type);
            self.expect(Token::Semicolon)?;
        }

        self.expect(Token::CloseBrace)?;
        st.finalize();

        Ok(CType::Struct(st))
    }

    fn parse_union(&mut self) -> ParseResult<CType> {
        self.expect(Token::Union)?;

        let name = if let Token::Ident(n) = &self.current {
            let n = n.clone();
            self.advance()?;
            Some(n)
        } else {
            None
        };

        // Check for forward declaration or reference
        if self.current != Token::OpenBrace {
            return Ok(CType::Named(format!("union {}", name.unwrap_or_default())));
        }

        self.expect(Token::OpenBrace)?;

        let mut un = UnionType::new(name);

        while self.current != Token::CloseBrace && self.current != Token::Eof {
            let member_type = self.parse_type()?;
            let (final_type, member_name) = self.parse_declarator(member_type)?;
            un.add_member(member_name, final_type);
            self.expect(Token::Semicolon)?;
        }

        self.expect(Token::CloseBrace)?;
        un.finalize();

        Ok(CType::Union(un))
    }

    fn parse_enum(&mut self) -> ParseResult<CType> {
        self.expect(Token::Enum)?;

        let name = if let Token::Ident(n) = &self.current {
            let n = n.clone();
            self.advance()?;
            Some(n)
        } else {
            None
        };

        // Check for forward declaration or reference
        if self.current != Token::OpenBrace {
            return Ok(CType::Named(format!("enum {}", name.unwrap_or_default())));
        }

        self.expect(Token::OpenBrace)?;

        let mut en = EnumType::new(name);
        let mut next_value: i64 = 0;

        while self.current != Token::CloseBrace && self.current != Token::Eof {
            let enum_name = if let Token::Ident(n) = &self.current {
                let n = n.clone();
                self.advance()?;
                n
            } else {
                return Err(ParseError::UnexpectedToken {
                    expected: "identifier".to_string(),
                    got: format!("{:?}", self.current),
                });
            };

            if self.current == Token::Equals {
                self.advance()?;
                if let Token::Number(v) = self.current {
                    next_value = v;
                    self.advance()?;
                }
            }

            en.add_value(enum_name, next_value);
            next_value += 1;

            if self.current == Token::Comma {
                self.advance()?;
            }
        }

        self.expect(Token::CloseBrace)?;

        Ok(CType::Enum(en))
    }

    fn parse_declarator(&mut self, base_type: CType) -> ParseResult<(CType, String)> {
        // Count pointers
        let mut ptr_count = 0;
        while self.current == Token::Star {
            self.advance()?;
            ptr_count += 1;
            // Skip const/volatile after *
            while matches!(self.current, Token::Const | Token::Volatile) {
                self.advance()?;
            }
        }

        // Get name
        let name = if let Token::Ident(n) = &self.current {
            let n = n.clone();
            self.advance()?;
            n
        } else {
            String::new()
        };

        // Build type with pointers
        let mut ty = base_type;
        for _ in 0..ptr_count {
            ty = CType::Pointer(Box::new(ty));
        }

        // Check for array dimensions
        while self.current == Token::OpenBracket {
            self.advance()?;
            let length = if let Token::Number(n) = self.current {
                self.advance()?;
                Some(n as usize)
            } else {
                None
            };
            self.expect(Token::CloseBracket)?;
            ty = CType::Array(ArrayType::new(ty, length));
        }

        Ok((ty, name))
    }

    fn parse_parameter_list(&mut self) -> ParseResult<(Vec<(String, CType)>, bool)> {
        self.expect(Token::OpenParen)?;

        let mut params = Vec::new();
        let mut variadic = false;

        if self.current == Token::Void {
            self.advance()?;
            if self.current == Token::CloseParen {
                self.advance()?;
                return Ok((params, false));
            }
        }

        while self.current != Token::CloseParen && self.current != Token::Eof {
            if self.current == Token::Ellipsis {
                self.advance()?;
                variadic = true;
                break;
            }

            let param_type = self.parse_type()?;
            let (final_type, name) = self.parse_declarator(param_type)?;
            params.push((name, final_type));

            if self.current == Token::Comma {
                self.advance()?;
            }
        }

        self.expect(Token::CloseParen)?;

        Ok((params, variadic))
    }
}

/// Parse a C header string into a type database.
pub fn parse_header(input: &str) -> ParseResult<TypeDatabase> {
    Parser::new(input)?.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_typedef() {
        let input = "typedef unsigned long size_t;";
        let db = parse_header(input).unwrap();
        assert!(db.has_type("size_t"));
    }

    #[test]
    fn test_parse_struct() {
        let input = r#"
            struct point {
                int x;
                int y;
            };
        "#;
        let db = parse_header(input).unwrap();
        assert!(db.has_type("struct point"));

        let ty = db.get_type("struct point").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 2);
            assert_eq!(s.fields[0].name, "x");
            assert_eq!(s.fields[1].name, "y");
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn test_parse_function() {
        let input = "int printf(const char *format, ...);";
        let db = parse_header(input).unwrap();
        assert!(db.has_function("printf"));

        let func = db.get_function("printf").unwrap();
        assert!(func.variadic);
        assert_eq!(func.parameters.len(), 1);
    }

    #[test]
    fn test_parse_enum() {
        let input = r#"
            enum color {
                RED,
                GREEN = 5,
                BLUE
            };
        "#;
        let db = parse_header(input).unwrap();
        assert!(db.has_type("enum color"));

        let ty = db.get_type("enum color").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.value_of("RED"), Some(0));
            assert_eq!(e.value_of("GREEN"), Some(5));
            assert_eq!(e.value_of("BLUE"), Some(6));
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn test_parse_pointer() {
        let input = "typedef char *string;";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("string").unwrap();
        assert!(ty.is_pointer());
    }

    #[test]
    fn test_parse_array() {
        let input = r#"
            struct buffer {
                char data[256];
                int size;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct buffer").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 2);
            if let CType::Array(a) = &s.fields[0].field_type {
                assert_eq!(a.length, Some(256));
            } else {
                panic!("Expected array type");
            }
        } else {
            panic!("Expected struct type");
        }
    }

    // --- Extended Typedef Tests ---

    #[test]
    fn test_parse_typedef_signed() {
        let input = "typedef signed int ssize_t;";
        let db = parse_header(input).unwrap();
        assert!(db.has_type("ssize_t"));

        let ty = db.get_type("ssize_t").unwrap();
        if let CType::Int(i) = ty {
            assert!(i.signed);
            assert_eq!(i.size, 4);
        } else {
            panic!("Expected int type");
        }
    }

    #[test]
    fn test_parse_typedef_unsigned() {
        let input = "typedef unsigned int uint32_t;";
        let db = parse_header(input).unwrap();
        assert!(db.has_type("uint32_t"));

        let ty = db.get_type("uint32_t").unwrap();
        if let CType::Int(i) = ty {
            assert!(!i.signed);
            assert_eq!(i.size, 4);
        } else {
            panic!("Expected int type");
        }
    }

    #[test]
    fn test_parse_typedef_long_long() {
        let input = "typedef long long int64_t;";
        let db = parse_header(input).unwrap();
        assert!(db.has_type("int64_t"));

        let ty = db.get_type("int64_t").unwrap();
        if let CType::Int(i) = ty {
            assert_eq!(i.size, 8);
        } else {
            panic!("Expected int type");
        }
    }

    #[test]
    fn test_parse_typedef_unsigned_long_long() {
        let input = "typedef unsigned long long uint64_t;";
        let db = parse_header(input).unwrap();
        assert!(db.has_type("uint64_t"));

        let ty = db.get_type("uint64_t").unwrap();
        if let CType::Int(i) = ty {
            assert!(!i.signed);
            assert_eq!(i.size, 8);
        } else {
            panic!("Expected int type");
        }
    }

    #[test]
    fn test_parse_typedef_short() {
        let input = "typedef short int16_t;";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("int16_t").unwrap();
        if let CType::Int(i) = ty {
            assert_eq!(i.size, 2);
        } else {
            panic!("Expected int type");
        }
    }

    #[test]
    fn test_parse_typedef_pointer_to_pointer() {
        let input = "typedef char **string_array;";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("string_array").unwrap();
        if let CType::Pointer(inner) = ty {
            assert!(inner.is_pointer());
        } else {
            panic!("Expected pointer type");
        }
    }

    #[test]
    fn test_parse_typedef_void_pointer() {
        let input = "typedef void *ptr_t;";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("ptr_t").unwrap();
        if let CType::Pointer(inner) = ty {
            assert!(inner.is_void());
        } else {
            panic!("Expected pointer type");
        }
    }

    #[test]
    fn test_parse_typedef_const_pointer() {
        let input = "typedef const char *cstring;";
        let db = parse_header(input).unwrap();

        assert!(db.has_type("cstring"));
        let ty = db.get_type("cstring").unwrap();
        assert!(ty.is_pointer());
    }

    // --- Extended Struct Tests ---

    #[test]
    fn test_parse_struct_with_pointers() {
        let input = r#"
            struct node {
                int value;
                struct node *next;
                struct node *prev;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct node").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 3);
            assert_eq!(s.fields[0].name, "value");
            assert!(s.fields[1].field_type.is_pointer());
            assert!(s.fields[2].field_type.is_pointer());
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn test_parse_struct_empty() {
        let input = "struct empty {};";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct empty").unwrap();
        if let CType::Struct(s) = ty {
            assert!(s.fields.is_empty());
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn test_parse_struct_with_array_and_pointer() {
        let input = r#"
            struct complex {
                char name[64];
                int *values;
                unsigned int count;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct complex").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 3);
            assert!(matches!(&s.fields[0].field_type, CType::Array(_)));
            assert!(s.fields[1].field_type.is_pointer());
            assert!(s.fields[2].field_type.is_integer());
        } else {
            panic!("Expected struct type");
        }
    }

    #[test]
    fn test_parse_struct_with_nested_array() {
        let input = r#"
            struct matrix {
                int data[3][3];
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct matrix").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 1);
            // First level should be array
            if let CType::Array(outer) = &s.fields[0].field_type {
                assert_eq!(outer.length, Some(3));
                // Inner level should also be array
                if let CType::Array(inner) = outer.element.as_ref() {
                    assert_eq!(inner.length, Some(3));
                } else {
                    panic!("Expected inner array");
                }
            } else {
                panic!("Expected outer array");
            }
        } else {
            panic!("Expected struct type");
        }
    }

    // --- Union Tests ---

    #[test]
    fn test_parse_union() {
        let input = r#"
            union value {
                int i;
                float f;
                char *s;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("union value").unwrap();
        if let CType::Union(u) = ty {
            assert_eq!(u.members.len(), 3);
            assert_eq!(u.members[0].name, "i");
            assert_eq!(u.members[1].name, "f");
            assert_eq!(u.members[2].name, "s");
        } else {
            panic!("Expected union type");
        }
    }

    #[test]
    fn test_parse_union_empty() {
        let input = "union empty {};";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("union empty").unwrap();
        if let CType::Union(u) = ty {
            assert!(u.members.is_empty());
        } else {
            panic!("Expected union type");
        }
    }

    // --- Extended Enum Tests ---

    #[test]
    fn test_parse_enum_all_explicit() {
        let input = r#"
            enum values {
                A = 10,
                B = 20,
                C = 30
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("enum values").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.value_of("A"), Some(10));
            assert_eq!(e.value_of("B"), Some(20));
            assert_eq!(e.value_of("C"), Some(30));
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn test_parse_enum_mixed_values() {
        let input = r#"
            enum mixed {
                FIRST,
                SECOND = 100,
                THIRD,
                FOURTH = 200,
                FIFTH
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("enum mixed").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.value_of("FIRST"), Some(0));
            assert_eq!(e.value_of("SECOND"), Some(100));
            assert_eq!(e.value_of("THIRD"), Some(101));
            assert_eq!(e.value_of("FOURTH"), Some(200));
            assert_eq!(e.value_of("FIFTH"), Some(201));
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn test_parse_enum_negative_values() {
        let input = r#"
            enum negative {
                ERROR = -1,
                OK = 0,
                WARNING = 1
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("enum negative").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.value_of("ERROR"), Some(-1));
            assert_eq!(e.value_of("OK"), Some(0));
            assert_eq!(e.value_of("WARNING"), Some(1));
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn test_parse_enum_single_value() {
        let input = "enum single { ONLY = 42 };";
        let db = parse_header(input).unwrap();

        let ty = db.get_type("enum single").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.values.len(), 1);
            assert_eq!(e.value_of("ONLY"), Some(42));
        } else {
            panic!("Expected enum type");
        }
    }

    // --- Extended Function Tests ---

    #[test]
    fn test_parse_function_void_return() {
        let input = "void exit(int status);";
        let db = parse_header(input).unwrap();

        let func = db.get_function("exit").unwrap();
        assert!(func.return_type.is_void());
        assert_eq!(func.parameters.len(), 1);
    }

    #[test]
    fn test_parse_function_no_params() {
        let input = "int getchar(void);";
        let db = parse_header(input).unwrap();

        let func = db.get_function("getchar").unwrap();
        assert!(func.return_type.is_integer());
        assert!(func.parameters.is_empty());
        assert!(!func.variadic);
    }

    #[test]
    fn test_parse_function_multiple_params() {
        let input = "int memcmp(const void *s1, const void *s2, unsigned long n);";
        let db = parse_header(input).unwrap();

        let func = db.get_function("memcmp").unwrap();
        assert!(func.return_type.is_integer());
        assert_eq!(func.parameters.len(), 3);
        assert!(!func.variadic);
    }

    #[test]
    fn test_parse_function_pointer_return() {
        let input = "char *strcpy(char *dest, const char *src);";
        let db = parse_header(input).unwrap();

        let func = db.get_function("strcpy").unwrap();
        assert!(func.return_type.is_pointer());
        assert_eq!(func.parameters.len(), 2);
    }

    #[test]
    fn test_parse_function_double_return() {
        let input = "double sin(double x);";
        let db = parse_header(input).unwrap();

        let func = db.get_function("sin").unwrap();
        assert!(func.return_type.is_float());
        assert_eq!(func.parameters.len(), 1);
    }

    // --- Comment Tests ---

    #[test]
    fn test_parse_with_line_comments() {
        let input = r#"
            // This is a comment
            typedef int myint; // inline comment
            // Another comment
        "#;
        let db = parse_header(input).unwrap();
        assert!(db.has_type("myint"));
    }

    #[test]
    fn test_parse_with_block_comments() {
        let input = r#"
            /* Block comment */
            typedef int myint;
            /*
             * Multi-line
             * block comment
             */
        "#;
        let db = parse_header(input).unwrap();
        assert!(db.has_type("myint"));
    }

    #[test]
    fn test_parse_with_comment_inside_struct() {
        let input = r#"
            struct test {
                int a; // first field
                /* padding */ int b;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct test").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 2);
        } else {
            panic!("Expected struct type");
        }
    }

    // --- Multiple Declarations Tests ---

    #[test]
    fn test_parse_multiple_declarations() {
        let input = r#"
            typedef int int32_t;
            typedef unsigned int uint32_t;
            struct point { int x; int y; };
            int abs(int x);
        "#;
        let db = parse_header(input).unwrap();

        assert!(db.has_type("int32_t"));
        assert!(db.has_type("uint32_t"));
        assert!(db.has_type("struct point"));
        assert!(db.has_function("abs"));
    }

    #[test]
    fn test_parse_struct_and_typedef() {
        let input = r#"
            struct _point { int x; int y; };
            typedef struct _point point_t;
        "#;
        let db = parse_header(input).unwrap();

        assert!(db.has_type("struct _point"));
        assert!(db.has_type("point_t"));
    }

    // --- Edge Cases ---

    #[test]
    fn test_parse_empty_input() {
        let input = "";
        let db = parse_header(input).unwrap();
        assert_eq!(db.stats().type_count, 0);
        assert_eq!(db.stats().typedef_count, 0);
        assert_eq!(db.stats().function_count, 0);
    }

    #[test]
    fn test_parse_whitespace_only() {
        let input = "   \n\t\n   ";
        let db = parse_header(input).unwrap();
        assert_eq!(db.stats().type_count, 0);
    }

    #[test]
    fn test_parse_comments_only() {
        let input = "// just comments\n/* more comments */";
        let db = parse_header(input).unwrap();
        assert_eq!(db.stats().type_count, 0);
    }

    #[test]
    fn test_parse_hex_number() {
        let input = r#"
            enum flags {
                FLAG_A = 0x01,
                FLAG_B = 0x02,
                FLAG_ALL = 0xff
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("enum flags").unwrap();
        if let CType::Enum(e) = ty {
            assert_eq!(e.value_of("FLAG_A"), Some(1));
            assert_eq!(e.value_of("FLAG_B"), Some(2));
            assert_eq!(e.value_of("FLAG_ALL"), Some(255));
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn test_parse_extern_declaration() {
        let input = "extern int errno;";
        // Should not crash - extern declarations might be parsed or skipped
        let _ = parse_header(input);
    }

    #[test]
    fn test_parse_static_declaration() {
        let input = "static int global_count;";
        // Should not crash - static declarations might be parsed or skipped
        let _ = parse_header(input);
    }

    // --- Error Handling Tests ---

    #[test]
    fn test_parse_missing_semicolon() {
        let input = "typedef int myint";
        let result = parse_header(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_brace() {
        let input = "struct test { int x;";
        let result = parse_header(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_unexpected_token() {
        let err = ParseError::UnexpectedToken {
            expected: "Semicolon".to_string(),
            got: "OpenBrace".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Unexpected token"));
        assert!(msg.contains("Semicolon"));
    }

    #[test]
    fn test_parse_error_unexpected_eof() {
        let err = ParseError::UnexpectedEof;
        let msg = format!("{}", err);
        assert!(msg.contains("Unexpected end"));
    }

    #[test]
    fn test_parse_error_invalid_type() {
        let err = ParseError::InvalidType("badtype".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid type"));
        assert!(msg.contains("badtype"));
    }

    #[test]
    fn test_parse_error_syntax_error() {
        let err = ParseError::SyntaxError {
            pos: 42,
            message: "test error".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Syntax error"));
        assert!(msg.contains("42"));
        assert!(msg.contains("test error"));
    }

    // --- Token Tests ---

    #[test]
    fn test_token_equality() {
        assert_eq!(Token::Struct, Token::Struct);
        assert_ne!(Token::Struct, Token::Union);
        assert_eq!(
            Token::Ident("foo".to_string()),
            Token::Ident("foo".to_string())
        );
        assert_ne!(
            Token::Ident("foo".to_string()),
            Token::Ident("bar".to_string())
        );
        assert_eq!(Token::Number(42), Token::Number(42));
    }

    #[test]
    fn test_token_debug() {
        let token = Token::Struct;
        assert!(format!("{:?}", token).contains("Struct"));

        let token = Token::Ident("test".to_string());
        assert!(format!("{:?}", token).contains("test"));
    }

    // --- Float Type Tests ---

    #[test]
    fn test_parse_float_field() {
        let input = r#"
            struct floats {
                float f;
                double d;
            };
        "#;
        let db = parse_header(input).unwrap();

        let ty = db.get_type("struct floats").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 2);
            assert!(s.fields[0].field_type.is_float());
            assert!(s.fields[1].field_type.is_float());
        } else {
            panic!("Expected struct type");
        }
    }
}
