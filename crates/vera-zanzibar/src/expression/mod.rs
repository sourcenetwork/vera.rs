mod parser;

pub use parser::MAX_PARENTHESIS_DEPTH;

use serde::{Deserialize, Serialize};

/// Maximum nesting of set operators in one relation's expression.
///
/// Policies are stored as JSON, whose decoder refuses deep nesting, and every
/// level is one active evaluation against the engine's depth limit.
pub const MAX_EXPRESSION_DEPTH: usize = 16;

/// Maximum operands, counted at the leaves, in one relation's expression.
///
/// Evaluating an operand is at least one step, so an expression longer than
/// the engine's step limit could never be evaluated in full.
pub const MAX_EXPRESSION_OPERANDS: usize = 4096;

const _: () = assert!(MAX_EXPRESSION_OPERANDS <= crate::engine::MAX_EVALUATION_STEPS);

/// A relation expression defining how to compute membership.
///
/// These expressions implement Zanzibar's userset rewrite rules:
/// - `This`: Direct lookup of stored tuples
/// - `ComputedUserset`: Check a different relation on the same object
/// - `TupleToUserset`: Follow a relation, then check another relation
/// - `Union`: OR of multiple expressions (short-circuit)
/// - `Intersection`: AND of multiple expressions
/// - `Difference`: Left AND NOT right
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelationExpression {
    This,

    ComputedUserset {
        relation: String,
    },

    TupleToUserset {
        tuple_relation: String,
        computed_relation: String,
    },

    Union(Vec<RelationExpression>),

    Intersection(Vec<RelationExpression>),

    Difference {
        base: Box<RelationExpression>,
        subtract: Box<RelationExpression>,
    },
}

impl RelationExpression {
    pub fn this() -> Self {
        Self::This
    }

    pub fn computed_userset(relation: impl Into<String>) -> Self {
        Self::ComputedUserset {
            relation: relation.into(),
        }
    }

    pub fn tuple_to_userset(
        tuple_relation: impl Into<String>,
        computed_relation: impl Into<String>,
    ) -> Self {
        Self::TupleToUserset {
            tuple_relation: tuple_relation.into(),
            computed_relation: computed_relation.into(),
        }
    }

    pub fn union(exprs: Vec<RelationExpression>) -> Self {
        Self::Union(exprs)
    }

    pub fn intersection(exprs: Vec<RelationExpression>) -> Self {
        Self::Intersection(exprs)
    }

    pub fn difference(base: RelationExpression, subtract: RelationExpression) -> Self {
        Self::Difference {
            base: Box::new(base),
            subtract: Box::new(subtract),
        }
    }

    pub fn is_this(&self) -> bool {
        matches!(self, Self::This)
    }

    /// Number of leaves: stored-tuple lookups and relation references.
    pub fn operands(&self) -> usize {
        match self {
            Self::This | Self::ComputedUserset { .. } | Self::TupleToUserset { .. } => 1,
            Self::Union(exprs) | Self::Intersection(exprs) => {
                exprs.iter().map(Self::operands).sum()
            }
            Self::Difference { base, subtract } => base.operands() + subtract.operands(),
        }
    }

    /// Number of set operators on the longest path to a leaf.
    pub fn depth(&self) -> usize {
        match self {
            Self::This | Self::ComputedUserset { .. } | Self::TupleToUserset { .. } => 0,
            Self::Union(exprs) | Self::Intersection(exprs) => {
                1 + exprs.iter().map(Self::depth).max().unwrap_or(0)
            }
            Self::Difference { base, subtract } => 1 + base.depth().max(subtract.depth()),
        }
    }
}

impl std::fmt::Display for RelationExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::This => write!(f, "_this"),
            Self::ComputedUserset { relation } => write!(f, "{}", relation),
            Self::TupleToUserset {
                tuple_relation,
                computed_relation,
            } => write!(f, "{}->{}", tuple_relation, computed_relation),
            Self::Union(exprs) => {
                let parts: Vec<_> = exprs.iter().map(|e| e.to_string()).collect();
                write!(f, "({})", parts.join(" + "))
            }
            Self::Intersection(exprs) => {
                let parts: Vec<_> = exprs.iter().map(|e| e.to_string()).collect();
                write!(f, "({})", parts.join(" & "))
            }
            Self::Difference { base, subtract } => {
                write!(f, "({} - {})", base, subtract)
            }
        }
    }
}
