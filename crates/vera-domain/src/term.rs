//! The term a block was proposed in.
//!
//! Every device of an account can finalize blocks under the deployment's
//! consensus key, and one of them is active at a time. A switch of the active
//! device raises the term, so the blocks of the device that was replaced are
//! told apart from its successor's.

/// Whether a block of `term` may extend a parent of term `parent`: a term
/// never decreases along a chain.
#[must_use]
pub const fn term_extends(parent: u64, term: u64) -> bool {
    term >= parent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_never_decreases_along_a_chain() {
        assert!(term_extends(4, 4));
        assert!(term_extends(4, 5));
        assert!(!term_extends(4, 3));
    }
}
