use std::fmt;

#[derive(Debug)]
pub enum ShItem {
    ByteSequence(Vec<u8>),
    Integer(u64),
    String(String),
}

// should be https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-10#section-4.1.5
impl fmt::Display for ShItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShItem::ByteSequence(bytes) => {
                write!(f, "*{}*", ::base64::encode(bytes))
            },
            ShItem::Integer(x) => write!(f, "{}", x),
            ShItem::String(x) => {
                write!(f, "\"")?;
                for c in x.chars() {
                    match c {
                        '\\' | '\"' => {
                            write!(f, "\\{}", c)?;
                        },
                        '\u{20}'..='\u{21}' | '\u{23}'..='\u{5b}' | '\u{5d}'..='\u{7e}' => {
                            write!(f, "{}", c)?;
                        },
                        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{10ffff}' => {
                            return Err(std::fmt::Error);
                        },
                    };
                }
                write!(f, "\"")
            },
        }
    }
}

