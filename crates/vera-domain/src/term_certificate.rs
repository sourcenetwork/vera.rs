//! The certificate that records a switch of the active device.

use alloy_primitives::{B256, FixedBytes};
use commonware_cryptography::{Hasher as _, Sha256};
use serde::{Deserialize, Serialize};

const SIGNING_NAMESPACE: &[u8] = b"vera/term/v1\0";

/// The last block of the term before: the block a new term builds on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermCut {
    /// Height of the block.
    pub height: u64,
    /// Identifier of the block.
    pub block: B256,
}

/// A switch of the active device, as every approval signs it.
///
/// It names the device that proposes from `term` on and the block that term
/// builds on. It changes no key: the blocks of the new term verify against
/// the consensus key the deployment had before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermChange {
    /// Identifier of the deployment's genesis block.
    pub genesis_id: B256,
    /// The term that starts. The first switch of a deployment starts term 1.
    pub term: u64,
    /// Transport key of the device that is active in the term.
    pub holder: B256,
    /// The block the term builds on. Blocks above it in a lower term are void.
    pub cut: TermCut,
}

impl TermChange {
    /// SHA-256 of the signing namespace, the genesis identifier, the term,
    /// the holder, and the cut's height and block. Integers are 8 bytes,
    /// big-endian.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        Sha256::hash(&[
            SIGNING_NAMESPACE,
            self.genesis_id.as_slice(),
            &self.term.to_be_bytes(),
            self.holder.as_slice(),
            &self.cut.height.to_be_bytes(),
            self.cut.block.as_slice(),
        ])
        .0
    }
}

/// One operator's signature over [`TermChange::signing_digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermApproval {
    /// Index of the signing key in the deployment's operator policy.
    pub signer: u16,
    /// The 64-byte signature, in the encoding the key's type signs
    /// administrative requests with.
    pub signature: FixedBytes<64>,
}

/// A term change approved under the deployment's operator policy.
///
/// The policy is not part of the certificate. A verifier reads it from state
/// it has verified and passes its threshold and size to [`Self::verify`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermCertificate {
    /// The switch every approval signs.
    pub change: TermChange,
    /// Approvals in ascending signer order, one for each operator that signed.
    pub approvals: Vec<TermApproval>,
}

/// Why a term certificate does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TermError {
    /// The certificate names another deployment.
    #[error("term certificate names another deployment")]
    Deployment,
    /// Term 0 is the term a deployment starts in; no certificate starts it.
    #[error("term certificate starts term 0")]
    Term,
    /// Too few approvals, more than the policy has keys, or a signer listed twice or out of order.
    #[error("term certificate needs {threshold} approvals in ascending signer order")]
    Approvals {
        /// Approvals the operator policy requires.
        threshold: u16,
    },
    /// An approval is not a signature of the change by the operator it names.
    #[error("term approval by operator {0} does not verify")]
    Signature(u16),
}

impl TermCertificate {
    /// Verify the certificate for the deployment `genesis_id` under an
    /// operator policy of `operators` keys that requires `threshold` of them.
    ///
    /// `approved` checks one signature of the 32-byte digest against the
    /// policy's key at the given index. Every listed approval must verify,
    /// not only the first `threshold`.
    pub fn verify(
        &self,
        genesis_id: &B256,
        threshold: u16,
        operators: usize,
        mut approved: impl FnMut(u16, &[u8; 32], &[u8; 64]) -> bool,
    ) -> Result<(), TermError> {
        if self.change.genesis_id != *genesis_id {
            return Err(TermError::Deployment);
        }
        if self.change.term == 0 {
            return Err(TermError::Term);
        }
        if threshold == 0
            || self.approvals.len() < usize::from(threshold)
            || self.approvals.len() > operators
            || self
                .approvals
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(TermError::Approvals { threshold });
        }
        let digest = self.change.signing_digest();
        for approval in &self.approvals {
            if usize::from(approval.signer) >= operators
                || !approved(approval.signer, &digest, &approval.signature.0)
            {
                return Err(TermError::Signature(approval.signer));
            }
        }
        Ok(())
    }

    /// Whether a block at `height` may carry `term` once this certificate is
    /// accepted: above the cut, no term below the certificate's.
    #[must_use]
    pub const fn admits(&self, height: u64, term: u64) -> bool {
        height <= self.change.cut.height || term >= self.change.term
    }

    /// Whether a block a verifier accepted earlier is still part of the
    /// chain the certificate's term builds on.
    ///
    /// A block above the cut, or another block at the cut's height, was
    /// finalized by the device that was replaced and is void. A block below
    /// the cut cannot be judged from the certificate.
    #[must_use]
    pub fn keeps(&self, height: u64, block: &B256) -> bool {
        height < self.change.cut.height
            || (height == self.change.cut.height && *block == self.change.cut.block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(signers: &[u16]) -> TermCertificate {
        TermCertificate {
            change: TermChange {
                genesis_id: B256::repeat_byte(1),
                term: 2,
                holder: B256::repeat_byte(2),
                cut: TermCut {
                    height: 40,
                    block: B256::repeat_byte(3),
                },
            },
            approvals: signers
                .iter()
                .map(|&signer| TermApproval {
                    signer,
                    signature: FixedBytes::repeat_byte(signer as u8),
                })
                .collect(),
        }
    }

    /// Accepts the signature `certificate` gives the operator at each index.
    fn matching(signer: u16, _: &[u8; 32], signature: &[u8; 64]) -> bool {
        signature == &[signer as u8; 64]
    }

    #[test]
    fn the_digest_covers_every_field() {
        let change = certificate(&[]).change;
        let digest = change.signing_digest();
        assert_eq!(
            hex::encode(digest),
            "5cf1b99be00fbad5b194bee6e0dd32f523f43a7ff0babea6803c742fbc7687ef",
            "the signing digest is a fixed format"
        );
        let mut other = change;
        other.genesis_id.0[0] ^= 1;
        assert_ne!(other.signing_digest(), digest);
        other = change;
        other.term += 1;
        assert_ne!(other.signing_digest(), digest);
        other = change;
        other.holder.0[31] ^= 1;
        assert_ne!(other.signing_digest(), digest);
        other = change;
        other.cut.height += 1;
        assert_ne!(other.signing_digest(), digest);
        other = change;
        other.cut.block.0[0] ^= 1;
        assert_ne!(other.signing_digest(), digest);
    }

    #[test]
    fn a_certificate_verifies_at_any_threshold_the_policy_sets() {
        let genesis = B256::repeat_byte(1);
        assert_eq!(certificate(&[0]).verify(&genesis, 1, 1, matching), Ok(()));
        assert_eq!(
            certificate(&[0, 2]).verify(&genesis, 2, 3, matching),
            Ok(())
        );
        assert_eq!(
            certificate(&[0]).verify(&genesis, 2, 3, matching),
            Err(TermError::Approvals { threshold: 2 })
        );
        assert_eq!(
            certificate(&[]).verify(&genesis, 0, 3, matching),
            Err(TermError::Approvals { threshold: 0 })
        );
    }

    #[test]
    fn an_operator_counts_once_and_every_approval_must_verify() {
        let genesis = B256::repeat_byte(1);
        for signers in [&[1, 1][..], &[2, 1], &[0, 1, 2, 3]] {
            assert_eq!(
                certificate(signers).verify(&genesis, 2, 3, matching),
                Err(TermError::Approvals { threshold: 2 }),
                "{signers:?}"
            );
        }
        assert_eq!(
            certificate(&[0, 3]).verify(&genesis, 1, 3, matching),
            Err(TermError::Signature(3))
        );
        let mut forged = certificate(&[0, 1]);
        forged.approvals[1].signature = FixedBytes::repeat_byte(9);
        assert_eq!(
            forged.verify(&genesis, 1, 3, matching),
            Err(TermError::Signature(1))
        );
    }

    #[test]
    fn another_deployment_and_term_zero_are_refused() {
        let certificate = certificate(&[0]);
        assert_eq!(
            certificate.verify(&B256::repeat_byte(9), 1, 1, matching),
            Err(TermError::Deployment)
        );
        let mut initial = certificate;
        initial.change.term = 0;
        assert_eq!(
            initial.verify(&B256::repeat_byte(1), 1, 1, matching),
            Err(TermError::Term)
        );
    }

    #[test]
    fn blocks_above_the_cut_need_the_term_and_earlier_ones_are_kept() {
        let certificate = certificate(&[0]);
        assert!(certificate.admits(40, 1));
        assert!(!certificate.admits(41, 1));
        assert!(certificate.admits(41, 2));
        assert!(certificate.keeps(39, &B256::ZERO));
        assert!(certificate.keeps(40, &B256::repeat_byte(3)));
        assert!(!certificate.keeps(40, &B256::repeat_byte(4)));
        assert!(!certificate.keeps(41, &B256::repeat_byte(3)));
    }

    #[test]
    fn the_json_form_is_stable() {
        let certificate = certificate(&[1]);
        let json = serde_json::to_value(&certificate).unwrap();
        assert_eq!(json["change"]["term"], 2);
        assert_eq!(json["change"]["cut"]["height"], 40);
        assert_eq!(json["approvals"][0]["signer"], 1);
        assert_eq!(
            json["approvals"][0]["signature"],
            format!("0x{}", "01".repeat(64))
        );
        assert_eq!(
            serde_json::from_value::<TermCertificate>(json).unwrap(),
            certificate
        );
    }
}
