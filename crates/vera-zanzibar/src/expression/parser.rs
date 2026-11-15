use super::{RelationExpression, MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_OPERANDS};
use crate::error::{Error, Result};

/// Maximum nesting of parentheses in a parsed expression.
pub const MAX_PARENTHESIS_DEPTH: usize = 32;

impl RelationExpression {
    /// Parse an expression from string format.
    ///
    /// Grammar:
    /// - `_this` -> This
    /// - `relation_name` -> ComputedUserset
    /// - `relation->computed` -> TupleToUserset
    /// - `expr + expr` -> Union
    /// - `expr & expr` -> Intersection
    /// - `expr - expr` -> Difference (note: "->" is NOT a difference operator)
    ///
    /// All operators have equal precedence and are evaluated left-to-right,
    /// matching Go zanzi behavior. Use parentheses to override.
    ///
    /// The result nests at most [`MAX_EXPRESSION_DEPTH`] operators and names
    /// at most [`MAX_EXPRESSION_OPERANDS`] operands, and the input nests at
    /// most [`MAX_PARENTHESIS_DEPTH`] parentheses. A chain of one repeated `+`
    /// or `&` is a single level whatever its length.
    pub fn parse(input: &str) -> Result<Self> {
        let mut operands = MAX_EXPRESSION_OPERANDS;
        parse_group(input, MAX_PARENTHESIS_DEPTH, &mut operands).map(|(expression, _)| expression)
    }
}

/// Parse one parenthesis level, returning the expression and its depth.
/// `operands` is how many more operands the whole expression may name.
fn parse_group(input: &str, parentheses: usize, operands: &mut usize) -> Result<Parsed> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::InvalidExpression("empty expression".into()));
    }

    if is_fully_parenthesized(input) {
        let Some(parentheses) = parentheses.checked_sub(1) else {
            return Err(Error::InvalidExpression(format!(
                "expression nests more than {MAX_PARENTHESIS_DEPTH} parentheses"
            )));
        };
        return parse_group(&input[1..input.len() - 1], parentheses, operands);
    }

    let operators = top_level_operators(input);
    if operators.len() >= *operands {
        return Err(too_many_operands());
    }
    if operators.is_empty() {
        *operands -= 1;
        return parse_term(input).map(|term| (term, 0));
    }

    let mut folded = parse_group(&input[..operators[0].0], parentheses, operands)?;
    for (index, (position, operator)) in operators.iter().enumerate() {
        let end = operators
            .get(index + 1)
            .map_or(input.len(), |(next, _)| *next);
        let operand = parse_group(&input[position + 1..end], parentheses, operands)?;
        folded = combine(*operator, folded, operand);
        if folded.1 > MAX_EXPRESSION_DEPTH {
            return Err(Error::InvalidExpression(format!(
                "expression nests more than {MAX_EXPRESSION_DEPTH} operators"
            )));
        }
    }
    Ok(folded)
}

fn too_many_operands() -> Error {
    Error::InvalidExpression(format!(
        "expression names more than {MAX_EXPRESSION_OPERANDS} operands"
    ))
}

type Parsed = (RelationExpression, usize);

fn combine(operator: char, left: Parsed, right: Parsed) -> Parsed {
    match operator {
        '+' => {
            let (operands, depth) = append(left, right, |expression| match expression {
                RelationExpression::Union(inner) => Ok(inner),
                other => Err(other),
            });
            (RelationExpression::Union(operands), depth)
        }
        '&' => {
            let (operands, depth) = append(left, right, |expression| match expression {
                RelationExpression::Intersection(inner) => Ok(inner),
                other => Err(other),
            });
            (RelationExpression::Intersection(operands), depth)
        }
        _ => (
            RelationExpression::difference(left.0, right.0),
            left.1.max(right.1) + 1,
        ),
    }
}

/// Merge two operands of one associative operator, splicing in a side that is
/// already that operator so a chain stays one level deep. The left side's
/// list is reused, so folding a chain costs its length once.
fn append(
    left: Parsed,
    right: Parsed,
    same_operator: impl Fn(
        RelationExpression,
    ) -> std::result::Result<Vec<RelationExpression>, RelationExpression>,
) -> (Vec<RelationExpression>, usize) {
    let (mut operands, mut depth) = match same_operator(left.0) {
        Ok(inner) => (inner, left.1),
        Err(other) => (vec![other], left.1 + 1),
    };
    match same_operator(right.0) {
        Ok(inner) => {
            operands.extend(inner);
            depth = depth.max(right.1);
        }
        Err(other) => {
            operands.push(other);
            depth = depth.max(right.1 + 1);
        }
    }
    (operands, depth)
}

fn is_fully_parenthesized(input: &str) -> bool {
    if !input.starts_with('(') || !input.ends_with(')') {
        return false;
    }

    let mut depth = 0;
    let chars: Vec<char> = input.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i < chars.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Byte positions of the operators outside every parenthesis, in order.
fn top_level_operators(input: &str) -> Vec<(usize, char)> {
    let mut depth = 0;
    let mut operators = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((position, c)) = chars.next() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '+' | '&' if depth == 0 => operators.push((position, c)),
            '-' if depth == 0 && chars.peek().is_none_or(|(_, next)| *next != '>') => {
                operators.push((position, c));
            }
            _ => {}
        }
    }
    operators
}

fn parse_term(input: &str) -> Result<RelationExpression> {
    let input = input.trim();

    if input == "_this" {
        return Ok(RelationExpression::This);
    }

    if let Some(arrow_pos) = input.find("->") {
        let tuple_relation = input[..arrow_pos].trim();
        let computed_relation = input[arrow_pos + 2..].trim();

        if tuple_relation.is_empty() {
            return Err(Error::InvalidExpression(
                "empty tuple relation in TupleToUserset".into(),
            ));
        }
        if computed_relation.is_empty() {
            return Err(Error::InvalidExpression(
                "empty computed relation in TupleToUserset".into(),
            ));
        }

        validate_identifier(tuple_relation)?;
        validate_identifier(computed_relation)?;

        return Ok(RelationExpression::TupleToUserset {
            tuple_relation: tuple_relation.into(),
            computed_relation: computed_relation.into(),
        });
    }

    validate_identifier(input)?;
    Ok(RelationExpression::ComputedUserset {
        relation: input.into(),
    })
}

fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::InvalidExpression("empty identifier".into()));
    }

    let first = s.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(Error::InvalidExpression(format!(
            "identifier must start with letter or underscore: '{}'",
            s
        )));
    }

    for c in s.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(Error::InvalidExpression(format!(
                "invalid character '{}' in identifier: '{}'",
                c, s
            )));
        }
    }

    Ok(())
}
