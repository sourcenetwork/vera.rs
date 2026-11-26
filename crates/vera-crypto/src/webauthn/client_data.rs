//! A strict parser for the client data of a WebAuthn assertion.
//!
//! The input is UTF-8 with no byte order mark and holds one RFC 8259 object
//! followed only by whitespace. A member name may appear once, whatever its
//! spelling: names compare after unescaping, so `"type"` repeats
//! `"type"`. `type`, `challenge` and `origin` are required strings;
//! `crossOrigin` may only be `false` and `topOrigin` may not appear. Any
//! other member is allowed with a string, number, boolean or null value.
//! Escapes are decoded, and an unpaired surrogate is refused.

use super::{MAX_CLIENT_DATA_BYTES, MAX_ORIGIN_BYTES, WebauthnError};

/// The members an assertion's verdict compares, unescaped. `origin` is
/// required but not compared.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ClientData {
    pub ceremony: String,
    pub challenge: String,
}

/// A member value.
enum Scalar {
    String(String),
    Boolean(bool),
    Other,
}

const fn malformed(reason: &'static str) -> WebauthnError {
    WebauthnError::ClientData(reason)
}

pub(super) fn parse(bytes: &[u8]) -> Result<ClientData, WebauthnError> {
    if bytes.len() > MAX_CLIENT_DATA_BYTES {
        return Err(malformed("longer than 1,024 bytes"));
    }
    if bytes.starts_with(b"\xef\xbb\xbf") {
        return Err(malformed("starts with a byte order mark"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("not UTF-8"))?;
    let mut parser = Parser { text, at: 0 };
    let mut names: Vec<String> = Vec::new();
    let (mut ceremony, mut challenge, mut origin) = (None, None, false);
    parser.whitespace();
    parser.expect(b'{')?;
    parser.whitespace();
    if !parser.eat(b'}') {
        loop {
            parser.whitespace();
            let name = parser.string()?;
            if names.contains(&name) {
                return Err(malformed("repeats a member"));
            }
            parser.whitespace();
            parser.expect(b':')?;
            parser.whitespace();
            let value = parser.scalar()?;
            match (name.as_str(), value) {
                ("type", Scalar::String(value)) => ceremony = Some(value),
                ("challenge", Scalar::String(value)) => challenge = Some(value),
                ("origin", Scalar::String(value)) if value.len() <= MAX_ORIGIN_BYTES => {
                    origin = true;
                }
                ("origin", Scalar::String(_)) => return Err(malformed("origin is too long")),
                ("type" | "challenge" | "origin", _) => {
                    return Err(malformed("type, challenge and origin must be strings"));
                }
                ("crossOrigin", Scalar::Boolean(false)) => {}
                ("crossOrigin" | "topOrigin", _) => return Err(WebauthnError::CrossOrigin),
                _ => {}
            }
            names.push(name);
            parser.whitespace();
            if parser.eat(b',') {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    parser.whitespace();
    if parser.at != text.len() {
        return Err(malformed("data follows the object"));
    }
    match (ceremony, challenge, origin) {
        (Some(ceremony), Some(challenge), true) => Ok(ClientData {
            ceremony,
            challenge,
        }),
        _ => Err(malformed("type, challenge and origin are required")),
    }
}

struct Parser<'a> {
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.at += usize::from(found);
        found
    }

    fn expect(&mut self, byte: u8) -> Result<(), WebauthnError> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(malformed("not a JSON object"))
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn scalar(&mut self) -> Result<Scalar, WebauthnError> {
        match self.peek() {
            Some(b'"') => self.string().map(Scalar::String),
            Some(b't') => self.literal("true").map(|()| Scalar::Boolean(true)),
            Some(b'f') => self.literal("false").map(|()| Scalar::Boolean(false)),
            Some(b'n') => self.literal("null").map(|()| Scalar::Other),
            Some(b'-' | b'0'..=b'9') => self.number().map(|()| Scalar::Other),
            Some(b'{' | b'[') => Err(malformed("member values must be scalars")),
            _ => Err(malformed("not a JSON value")),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), WebauthnError> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(malformed("not a JSON value"))
        }
    }

    /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`
    fn number(&mut self) -> Result<(), WebauthnError> {
        self.eat(b'-');
        if !self.eat(b'0') && self.digits() == 0 {
            return Err(malformed("not a JSON number"));
        }
        if self.eat(b'.') && self.digits() == 0 {
            return Err(malformed("not a JSON number"));
        }
        if self.eat(b'e') || self.eat(b'E') {
            let _ = self.eat(b'+') || self.eat(b'-');
            if self.digits() == 0 {
                return Err(malformed("not a JSON number"));
            }
        }
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn string(&mut self) -> Result<String, WebauthnError> {
        if !self.eat(b'"') {
            return Err(malformed("member names must be strings"));
        }
        let mut value = String::new();
        loop {
            let Some(character) = self.text[self.at..].chars().next() else {
                return Err(malformed("unterminated string"));
            };
            self.at += character.len_utf8();
            match character {
                '"' => return Ok(value),
                '\\' => value.push(self.escape()?),
                '\0'..='\u{1f}' => return Err(malformed("unescaped control character")),
                _ => value.push(character),
            }
        }
    }

    fn escape(&mut self) -> Result<char, WebauthnError> {
        let Some(byte) = self.peek() else {
            return Err(malformed("unterminated string"));
        };
        self.at += 1;
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode(),
            _ => return Err(malformed("invalid escape")),
        })
    }

    fn unicode(&mut self) -> Result<char, WebauthnError> {
        let high = self.hex4()?;
        let code = match high {
            0xd800..=0xdbff => {
                if !(self.eat(b'\\') && self.eat(b'u')) {
                    return Err(malformed("unpaired surrogate"));
                }
                let low = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(malformed("unpaired surrogate"));
                }
                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(malformed("unpaired surrogate")),
            _ => high,
        };
        char::from_u32(code).ok_or(malformed("invalid escape"))
    }

    fn hex4(&mut self) -> Result<u32, WebauthnError> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(malformed("invalid escape"))?;
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|_| malformed("invalid escape"))
    }
}
