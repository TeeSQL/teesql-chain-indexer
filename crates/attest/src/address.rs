//! secp256k1 verifying key → 20-byte Ethereum address.
//!
//! Mirror of `dns-controller/src/manifest.rs::verifying_key_to_address` —
//! kept here so consumers verifying signed envelopes against the indexer's
//! signer pubkey use the byte-identical derivation. Keeping a local copy
//! avoids a cross-crate dep on the dns-controller for a four-line helper.

use k256::ecdsa::VerifyingKey;
use sha3::{Digest, Keccak256};

/// `keccak256(uncompressed_pubkey_xy)[-20:]` — the standard Ethereum
/// address derivation. The encoded uncompressed point is
/// `0x04 || X(32) || Y(32)`; we drop the leading tag byte before hashing.
pub fn verifying_key_to_address(vk: &VerifyingKey) -> [u8; 20] {
    let encoded = vk.to_encoded_point(false);
    let xy = &encoded.as_bytes()[1..];
    let mut h = Keccak256::new();
    h.update(xy);
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn deterministic_for_fixed_key() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap();
        let a = verifying_key_to_address(sk.verifying_key());
        let b = verifying_key_to_address(sk.verifying_key());
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 20]);
    }

    #[test]
    fn different_keys_give_different_addresses() {
        let sk_a = SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap();
        let sk_b = SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap();
        assert_ne!(
            verifying_key_to_address(sk_a.verifying_key()),
            verifying_key_to_address(sk_b.verifying_key())
        );
    }
}
