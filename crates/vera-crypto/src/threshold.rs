//! Verification of the threshold signatures used by Orbis service rings.

use group::{Group, GroupEncoding};
use jubjub::{Fr, SubgroupPoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha512};

/// Signature formats supported by existing Orbis rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdScheme {
    /// Orbis FROST over the prime-order subgroup of Jubjub.
    #[serde(rename = "jubjub_frost")]
    JubjubFrost,
    /// Public-key-augmented BLS matching current Orbis threshold signing.
    #[serde(rename = "bls12_381_g1_pk_g2_sig_aug_v1")]
    Bls12381AugV1,
}

/// The encoding, group element or signature equation is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid threshold signature")]
pub struct InvalidThresholdSignature;

/// Verify an aggregate signature against the existing ring key.
pub fn verify(
    scheme: ThresholdScheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidThresholdSignature> {
    let valid = match scheme {
        ThresholdScheme::Bls12381AugV1 => {
            if public_key.len() != 48 || signature.len() != 96 {
                return Err(InvalidThresholdSignature);
            }
            let key = blst::min_pk::PublicKey::from_bytes(public_key)
                .map_err(|_| InvalidThresholdSignature)?;
            let signature = blst::min_pk::Signature::from_bytes(signature)
                .map_err(|_| InvalidThresholdSignature)?;
            signature.verify(
                true,
                message,
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
                public_key,
                &key,
                true,
            ) == blst::BLST_ERROR::BLST_SUCCESS
        }
        ThresholdScheme::JubjubFrost => {
            if public_key.len() != 32 || signature.len() != 64 {
                return Err(InvalidThresholdSignature);
            }
            let key = decode_jubjub_point(public_key)?;
            let r = decode_jubjub_point(&signature[..32])?;
            let scalar_bytes = signature[32..]
                .try_into()
                .map_err(|_| InvalidThresholdSignature)?;
            let z = Option::<Fr>::from(Fr::from_bytes(scalar_bytes))
                .ok_or(InvalidThresholdSignature)?;
            if key == SubgroupPoint::identity() {
                return Err(InvalidThresholdSignature);
            }
            let mut challenge = Sha512::new();
            challenge.update(b"FROST-jubjub-challenge");
            challenge.update(&signature[..32]);
            challenge.update(public_key);
            challenge.update(message);
            let c = Fr::from_bytes_wide(&challenge.finalize().into());
            SubgroupPoint::generator() * z == r + key * c
        }
    };
    if valid {
        Ok(())
    } else {
        Err(InvalidThresholdSignature)
    }
}

fn decode_jubjub_point(bytes: &[u8]) -> Result<SubgroupPoint, InvalidThresholdSignature> {
    let encoded = bytes.try_into().map_err(|_| InvalidThresholdSignature)?;
    // Checked decoding rejects noncanonical encodings and points with torsion;
    // clearing the cofactor would change the statement being verified.
    Option::<SubgroupPoint>::from(SubgroupPoint::from_bytes(encoded))
        .ok_or(InvalidThresholdSignature)
}

#[cfg(test)]
mod tests;
