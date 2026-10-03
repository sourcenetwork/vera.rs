use super::*;

struct Token<'a> {
    text: &'a str,
    start: usize,
    end: usize,
    quoted: bool,
}
struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    index: usize,
}
fn invalid(message: impl Into<String>) -> AcpError {
    AcpError::InvalidAccessRequest {
        reason: message.into(),
    }
}

pub(super) fn parse(source: &str) -> Result<Vec<Theorem>> {
    if source.len() > 64 << 10 {
        return Err(invalid("theorem source exceeds 64 KiB"));
    }
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        let rest = &source[offset..];
        let c = rest.chars().next().expect("nonempty source suffix");
        if c.is_whitespace() {
            offset += c.len_utf8();
            continue;
        }
        if rest.starts_with("//") {
            offset += rest.find('\n').unwrap_or(rest.len());
            continue;
        }
        let start = offset;
        let quoted = c == '"';
        let text = if quoted {
            let length = rest[1..]
                .find('"')
                .ok_or_else(|| invalid("unterminated object identifier"))?;
            offset += length + 2;
            &rest[1..length + 1]
        } else if rest.starts_with("did:") {
            let length = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-')))
                .unwrap_or(rest.len());
            offset += length;
            &rest[..length]
        } else if matches!(c, '{' | '}' | '!' | ':' | '#' | '@' | '>') {
            offset += 1;
            &rest[..1]
        } else if c.is_ascii_alphabetic() {
            let length = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            offset += length;
            &rest[..length]
        } else {
            return Err(invalid(format!("invalid theorem token at byte {offset}")));
        };
        tokens.push(Token {
            text,
            start,
            end: offset,
            quoted,
        });
    }
    let mut parser = Parser { tokens, index: 0 };
    let mut theorems = Vec::new();
    for (name, kind) in [
        ("Authorizations", TheoremKind::Authorization),
        ("Delegations", TheoremKind::Delegation),
    ] {
        parser.expect(name)?;
        parser.expect("{")?;
        while !parser.at("}") {
            if theorems.len() == 64 {
                return Err(invalid("theorem count exceeds 64"));
            }
            let start = parser.current()?.start;
            let assert_true = if parser.at("!") {
                parser.index += 1;
                false
            } else {
                true
            };
            let (actor, operation) = match kind {
                TheoremKind::Authorization => {
                    let operation = parser.operation()?;
                    parser.expect("@")?;
                    (parser.actor()?, operation)
                }
                TheoremKind::Delegation => {
                    let actor = parser.actor()?;
                    parser.expect(">")?;
                    (actor, parser.operation()?)
                }
            };
            let end = parser.tokens[parser.index - 1].end;
            theorems.push(Theorem {
                kind: kind.clone(),
                actor,
                operation,
                assert_true,
                start,
                end,
            });
        }
        parser.expect("}")?;
    }
    if parser.at("ImpliedRelations") {
        parser.index += 1;
        parser.expect("{")?;
        if !parser.at("}") {
            return Err(invalid("reachability assertions are not supported"));
        }
        parser.expect("}")?;
    }
    if parser.index != parser.tokens.len() {
        return Err(invalid("unexpected input after theorem"));
    }
    Ok(theorems)
}

impl<'a> Parser<'a> {
    fn current(&self) -> Result<&Token<'a>> {
        self.tokens
            .get(self.index)
            .ok_or_else(|| invalid("unexpected end of theorem"))
    }
    fn at(&self, value: &str) -> bool {
        self.tokens
            .get(self.index)
            .is_some_and(|token| !token.quoted && token.text == value)
    }
    fn expect(&mut self, value: &str) -> Result<()> {
        if !self.at(value) {
            return Err(invalid(format!("expected '{value}' in theorem")));
        }
        self.index += 1;
        Ok(())
    }
    fn identifier(&mut self, allow_quoted: bool) -> Result<String> {
        let token = self.current()?;
        if !(token.quoted && allow_quoted)
            && (token.quoted
                || !token.text.starts_with(|c: char| c.is_ascii_alphabetic())
                || !token
                    .text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            return Err(invalid("invalid theorem identifier"));
        }
        if token.text.is_empty() {
            return Err(invalid("empty theorem identifier"));
        }
        let value = token.text.to_owned();
        self.index += 1;
        Ok(value)
    }
    fn actor(&mut self) -> Result<Actor> {
        let token = self.current()?;
        if token.quoted {
            return Err(invalid("actor must be an unquoted DID"));
        }
        let actor = Did::new(token.text).map_err(|e| invalid(e.to_string()))?;
        self.index += 1;
        Ok(Actor(actor))
    }
    fn operation(&mut self) -> Result<Operation> {
        let resource = self.identifier(false)?;
        self.expect(":")?;
        let id = self.identifier(true)?;
        self.expect("#")?;
        let permission = self.identifier(false)?;
        Ok(Operation {
            object: Object { resource, id },
            permission,
        })
    }
}
