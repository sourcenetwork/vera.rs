use crate::did::Did;
use crate::thread_bounds::MaybeBoxFuture;

use super::cache::{CheckCache, CheckKey, NodeId, NodeTrail};
use super::outcome::{Assumed, Outcome};
use super::PermissionEngine;
use crate::error::{Error, Result};
use crate::expression::RelationExpression;
use crate::store::ZanzibarStore;
use crate::types::Subject;

/// One object and the subject whose access to it is being decided.
#[derive(Clone, Copy)]
pub(crate) struct Goal<'a> {
    pub(crate) policy_id: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) object_id: &'a str,
    pub(crate) subject: &'a Did,
}

impl<S: ZanzibarStore + ?Sized> PermissionEngine<S> {
    /// Evaluate `relation` on the goal's object as one node of the search.
    pub(crate) fn evaluate_node<'a>(
        &'a self,
        goal: Goal<'a>,
        relation: &'a str,
        trail: &'a NodeTrail,
        cache: &'a CheckCache,
    ) -> MaybeBoxFuture<'a, Result<Outcome>> {
        Box::pin(async move {
            let node = NodeId::new(goal.resource, goal.object_id, relation);
            if let Some(position) = trail.position(&node) {
                return Ok(Outcome::truncated(position));
            }
            let key = CheckKey::new(goal.policy_id, node.clone(), goal.subject);
            if let Some(known) = cache.get(&key).await {
                cache.budget.charge()?;
                return Ok(known);
            }
            let expression = self
                .lookup
                .get_expression(goal.policy_id, goal.resource, relation)?;
            let (trail, position) = trail.with_node(node)?;
            let outcome = self
                .evaluate_expression(goal, relation, expression, &trail, cache)
                .await?
                .settle(position);
            cache.close(key, position, outcome).await;
            Ok(outcome)
        })
    }

    fn evaluate_expression<'a>(
        &'a self,
        goal: Goal<'a>,
        relation: &'a str,
        expression: &'a RelationExpression,
        trail: &'a NodeTrail,
        cache: &'a CheckCache,
    ) -> MaybeBoxFuture<'a, Result<Outcome>> {
        Box::pin(async move {
            let _evaluation = cache.budget.enter()?;
            match expression {
                RelationExpression::This => self.evaluate_this(goal, relation, trail, cache).await,

                RelationExpression::ComputedUserset { relation } => {
                    self.evaluate_node(goal, relation, trail, cache).await
                }

                RelationExpression::TupleToUserset {
                    tuple_relation,
                    computed_relation,
                } => {
                    self.evaluate_tuple_to_userset(
                        goal,
                        tuple_relation,
                        computed_relation,
                        trail,
                        cache,
                    )
                    .await
                }

                RelationExpression::Union(exprs) => {
                    let mut assumed = Assumed::default();
                    for expr in exprs {
                        match self
                            .evaluate_expression(goal, relation, expr, trail, cache)
                            .await?
                        {
                            Outcome::Granted => return Ok(Outcome::Granted),
                            Outcome::Denied(nodes) => assumed = assumed.union(nodes),
                        }
                    }
                    Ok(Outcome::Denied(assumed))
                }

                RelationExpression::Intersection(exprs) => {
                    for expr in exprs {
                        let outcome = self
                            .evaluate_expression(goal, relation, expr, trail, cache)
                            .await?;
                        if matches!(outcome, Outcome::Denied(_)) {
                            return Ok(outcome);
                        }
                    }
                    Ok(Outcome::Granted)
                }

                RelationExpression::Difference { base, subtract } => {
                    let base = self
                        .evaluate_expression(goal, relation, base, trail, cache)
                        .await?;
                    if matches!(base, Outcome::Denied(_)) {
                        return Ok(base);
                    }
                    // A truncated cycle is not proof of absence. Negating it
                    // could grant the very permission being excluded.
                    self.evaluate_expression(goal, relation, subtract, trail, cache)
                        .await?
                        .as_exact()
                        .map(|excluded| Outcome::exact(!excluded))
                        .ok_or(Error::IndeterminateExclusion)
                }
            }
        })
    }

    async fn evaluate_this(
        &self,
        goal: Goal<'_>,
        relation: &str,
        trail: &NodeTrail,
        cache: &CheckCache,
    ) -> Result<Outcome> {
        let Goal {
            policy_id,
            resource,
            object_id,
            subject,
        } = goal;
        if self
            .store
            .check_permission_direct(policy_id, resource, object_id, relation, subject)
            .await?
        {
            return Ok(Outcome::Granted);
        }
        let subjects = self
            .store
            .get_relation_subjects(policy_id, resource, object_id, relation)
            .await?;
        // A typed wildcard grants before any userset is followed, so a failing
        // userset cannot mask it.
        if subjects.iter().any(Subject::is_typed_wildcard) {
            return Ok(Outcome::Granted);
        }
        let mut assumed = Assumed::default();
        for target in &subjects {
            cache.budget.charge()?;
            let Subject::EntitySet {
                resource,
                object_id,
                relation,
            } = target
            else {
                continue;
            };
            if relation.is_empty() {
                if self.lookup.is_actor_resource(policy_id, resource)
                    && object_id == subject.as_str()
                {
                    return Ok(Outcome::Granted);
                }
                continue;
            }
            let target = Goal {
                resource,
                object_id,
                ..goal
            };
            match self.evaluate_node(target, relation, trail, cache).await? {
                Outcome::Granted => return Ok(Outcome::Granted),
                Outcome::Denied(nodes) => assumed = assumed.union(nodes),
            }
        }
        Ok(Outcome::Denied(assumed))
    }

    async fn evaluate_tuple_to_userset(
        &self,
        goal: Goal<'_>,
        tuple_relation: &str,
        computed_relation: &str,
        trail: &NodeTrail,
        cache: &CheckCache,
    ) -> Result<Outcome> {
        let subjects = self
            .store
            .get_relation_subjects(
                goal.policy_id,
                goal.resource,
                goal.object_id,
                tuple_relation,
            )
            .await?;
        if subjects.iter().any(Subject::is_any_wildcard) {
            return Ok(Outcome::Granted);
        }
        let mut assumed = Assumed::default();
        for target in &subjects {
            cache.budget.charge()?;
            let Subject::EntitySet {
                resource,
                object_id,
                ..
            } = target
            else {
                continue;
            };
            // A tuple may name an actor as an object of the actor resource,
            // which need not declare the computed relation.
            if self.lookup.is_actor_resource(goal.policy_id, resource)
                && !self
                    .lookup
                    .declares(goal.policy_id, resource, computed_relation)
            {
                continue;
            }
            let target = Goal {
                resource,
                object_id,
                ..goal
            };
            match self
                .evaluate_node(target, computed_relation, trail, cache)
                .await?
            {
                Outcome::Granted => return Ok(Outcome::Granted),
                Outcome::Denied(nodes) => assumed = assumed.union(nodes),
            }
        }
        Ok(Outcome::Denied(assumed))
    }
}
