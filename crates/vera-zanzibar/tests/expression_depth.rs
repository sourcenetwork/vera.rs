use vera_zanzibar::{
    engine::MAX_EVALUATION_STEPS,
    expression::{MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_OPERANDS, MAX_PARENTHESIS_DEPTH},
    Policy, Relation, RelationExpression, Resource,
};

fn chain(operators: &[&str], terms: usize) -> String {
    let mut expression = "a".to_string();
    for index in 1..terms {
        expression.push_str(&format!(" {} a", operators[index % operators.len()]));
    }
    expression
}

fn policy_with(expression: RelationExpression) -> Policy {
    Policy::new("p", "p").with_resource(
        Resource::new("document")
            .with_relation(Relation::direct("a"))
            .with_relation(Relation::computed("permission", expression)),
    )
}

#[test]
fn a_chain_of_one_associative_operator_is_a_single_level() {
    for operator in ["+", "&"] {
        let parsed = RelationExpression::parse(&chain(&[operator], 4096)).unwrap();
        assert_eq!(parsed.depth(), 1);
        let (RelationExpression::Union(operands) | RelationExpression::Intersection(operands)) =
            parsed
        else {
            panic!("expected a flat chain");
        };
        assert_eq!(operands.len(), 4096);
    }
}

#[test]
fn an_expression_names_a_bounded_number_of_operands() {
    const { assert!(MAX_EXPRESSION_OPERANDS <= MAX_EVALUATION_STEPS) };
    for operators in [&["+"][..], &["&"], &["+", "&"]] {
        let longest = chain(operators, MAX_EXPRESSION_OPERANDS);
        if operators.len() == 1 {
            let parsed = RelationExpression::parse(&longest).unwrap();
            assert_eq!(parsed.operands(), MAX_EXPRESSION_OPERANDS);
        }
        assert!(RelationExpression::parse(&format!("{longest} + a")).is_err());
    }
    let grouped = format!(
        "({}) + ({})",
        chain(&["&"], MAX_EXPRESSION_OPERANDS / 2),
        chain(&["&"], MAX_EXPRESSION_OPERANDS / 2)
    );
    assert_eq!(
        RelationExpression::parse(&grouped).unwrap().operands(),
        MAX_EXPRESSION_OPERANDS
    );
    assert!(RelationExpression::parse(&format!("{grouped} + (a - a->a)")).is_err());

    let a = || RelationExpression::computed_userset("a");
    policy_with(RelationExpression::union(vec![
        a();
        MAX_EXPRESSION_OPERANDS
    ]))
    .validate()
    .unwrap();
    assert!(policy_with(RelationExpression::union(vec![
        a();
        MAX_EXPRESSION_OPERANDS + 1
    ]))
    .validate()
    .is_err());
}

#[test]
fn a_flat_chain_filling_a_policy_definition_is_refused_in_linear_time() {
    let started = std::time::Instant::now();
    for operator in ["a+", "a&", "a-"] {
        let mut flat = operator.repeat(32 * 1024);
        flat.truncate(64 * 1024 - 1);
        assert_eq!(flat.len(), 64 * 1024 - 1);
        assert!(RelationExpression::parse(&flat).is_err());
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn subtraction_chains_are_bounded_by_tree_depth() {
    let deepest = RelationExpression::parse(&chain(&["-"], MAX_EXPRESSION_DEPTH + 1)).unwrap();
    assert_eq!(deepest.depth(), MAX_EXPRESSION_DEPTH);
    assert!(RelationExpression::parse(&chain(&["-"], MAX_EXPRESSION_DEPTH + 2)).is_err());
    assert!(RelationExpression::parse(&chain(&["+", "&"], MAX_EXPRESSION_DEPTH + 2)).is_err());
    assert!(RelationExpression::parse(&chain(&["-"], 16 * 1024)).is_err());
}

#[test]
fn parentheses_are_bounded_separately_from_operators() {
    let wrap = |depth: usize| format!("{}a{}", "(".repeat(depth), ")".repeat(depth));
    assert_eq!(
        RelationExpression::parse(&wrap(MAX_PARENTHESIS_DEPTH)).unwrap(),
        RelationExpression::computed_userset("a")
    );
    assert!(RelationExpression::parse(&wrap(MAX_PARENTHESIS_DEPTH + 1)).is_err());
    assert!(RelationExpression::parse(&wrap(32 * 1024)).is_err());

    let mut nested = "a".to_string();
    for _ in 0..MAX_EXPRESSION_DEPTH + 1 {
        nested = format!("a - ({nested})");
    }
    assert!(RelationExpression::parse(&nested).is_err());
}

#[test]
fn operators_keep_equal_precedence_from_left_to_right() {
    let a = || RelationExpression::computed_userset("a");
    assert_eq!(
        RelationExpression::parse("a + a - a & a->a").unwrap(),
        RelationExpression::intersection(vec![
            RelationExpression::difference(RelationExpression::union(vec![a(), a()]), a()),
            RelationExpression::tuple_to_userset("a", "a"),
        ])
    );
    assert_eq!(
        RelationExpression::parse("a + (a + a) + (a & a)").unwrap(),
        RelationExpression::union(vec![
            a(),
            a(),
            a(),
            RelationExpression::intersection(vec![a(), a()])
        ])
    );
    for malformed in ["", "a +", "+ a", "a - - a", "(a", "a)", "()", "a ^ a"] {
        assert!(RelationExpression::parse(malformed).is_err(), "{malformed}");
    }
}

#[test]
fn a_stored_policy_at_the_depth_limit_decodes_again() {
    let a = RelationExpression::computed_userset("a");
    let mut expression = a.clone();
    for _ in 0..MAX_EXPRESSION_DEPTH {
        expression = RelationExpression::difference(a.clone(), expression);
    }
    assert_eq!(expression.depth(), MAX_EXPRESSION_DEPTH);
    let policy = policy_with(expression.clone());
    policy.validate().unwrap();
    let encoded = serde_json::to_vec(&policy).unwrap();
    serde_json::from_slice::<Policy>(&encoded).unwrap();

    let too_deep = policy_with(RelationExpression::union(vec![expression]));
    assert!(too_deep.validate().is_err());
}
