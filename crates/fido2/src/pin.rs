// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! CTAP2 PIN/UV protocol cryptographic operations.
//!
//! Provides ECDH P-256 key agreement, AES-CBC encryption/decryption,
//! and HKDF-SHA256 key derivation used by PIN protocols V1 and V2.

use aes::Aes128;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::utils;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("Invalid key data")]
    InvalidKeyData,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Invalid PIN: {0}")]
    InvalidPin(String),
}

/// Result of ECDH P-256 key agreement.
pub struct EcdhResult {
    /// The public key to send (x coordinate, 32 bytes).
    pub public_key_x: Vec<u8>,
    /// The public key to send (y coordinate, 32 bytes).
    pub public_key_y: Vec<u8>,
    /// The raw shared secret (x coordinate of ECDH result, 32 bytes).
    pub shared_secret: Vec<u8>,
}

/// Perform ECDH P-256 key agreement with a peer's public key.
///
/// Generates an ephemeral P-256 keypair, performs ECDH with the peer's
/// public key, and returns the ephemeral public key and shared secret.
pub fn ecdh_p256(peer_x: &[u8], peer_y: &[u8]) -> Result<EcdhResult, PinError> {
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{EncodedPoint, PublicKey};

    // Build peer's public key from x,y coordinates
    let peer_point = EncodedPoint::from_affine_coordinates(
        peer_x.into(),
        peer_y.into(),
        false,
    );
    let peer_pk = PublicKey::from_sec1_bytes(peer_point.as_bytes())
        .map_err(|_| PinError::InvalidKeyData)?;

    // Generate ephemeral keypair and compute shared secret
    let secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let our_pk = secret.public_key();
    let our_point = our_pk.to_encoded_point(false);

    let shared = secret.diffie_hellman(&peer_pk);

    Ok(EcdhResult {
        public_key_x: our_point.x().unwrap().to_vec(),
        public_key_y: our_point.y().unwrap().to_vec(),
        shared_secret: shared.raw_secret_bytes().to_vec(),
    })
}

/// General AES-CBC decrypt with a provided IV.
/// Supports 16-byte (AES-128) and 32-byte (AES-256) keys.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PinError> {
    if iv.len() != 16 {
        return Err(PinError::DecryptionError);
    }
    match key.len() {
        16 => {
            let dec = Aes128CbcDec::new(key.into(), iv.into());
            dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| PinError::DecryptionError)
        }
        32 => {
            let dec = Aes256CbcDec::new(key.into(), iv.into());
            dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| PinError::DecryptionError)
        }
        _ => Err(PinError::DecryptionError),
    }
}

/// AES-CBC encrypt with a zero IV (PIN protocol V1).
pub fn aes_cbc_encrypt_v1(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PinError> {
    let iv = [0u8; 16];
    match key.len() {
        16 => {
            let enc = Aes128CbcEnc::new(key.into(), &iv.into());
            Ok(enc
                .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext))
        }
        32 => {
            let enc = Aes256CbcEnc::new(key.into(), &iv.into());
            Ok(enc
                .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext))
        }
        _ => Err(PinError::EncryptionError),
    }
}

/// AES-CBC decrypt with a zero IV (PIN protocol V1).
pub fn aes_cbc_decrypt_v1(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PinError> {
    let iv = [0u8; 16];
    match key.len() {
        16 => {
            let dec = Aes128CbcDec::new(key.into(), &iv.into());
            dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| PinError::DecryptionError)
        }
        32 => {
            let dec = Aes256CbcDec::new(key.into(), &iv.into());
            dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| PinError::DecryptionError)
        }
        _ => Err(PinError::DecryptionError),
    }
}

/// AES-256-CBC encrypt with a random IV (PIN protocol V2).
/// Returns IV (16 bytes) prepended to ciphertext.
pub fn aes_cbc_encrypt_v2(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PinError> {
    if key.len() != 32 {
        return Err(PinError::EncryptionError);
    }
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).map_err(|_| PinError::EncryptionError)?;

    let enc = Aes256CbcEnc::new(key.into(), &iv.into());
    let ciphertext =
        enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext);

    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// AES-256-CBC decrypt (PIN protocol V2).
/// Expects IV (16 bytes) prepended to ciphertext.
pub fn aes_cbc_decrypt_v2(key: &[u8], data: &[u8]) -> Result<Vec<u8>, PinError> {
    if key.len() != 32 || data.len() < 16 {
        return Err(PinError::DecryptionError);
    }
    let (iv, ciphertext) = data.split_at(16);

    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|_| PinError::DecryptionError)
}

/// HKDF-SHA256 key derivation.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF output length should be valid");
    okm
}

/// PIN protocol V1 KDF: SHA-256 of the shared secret.
pub fn kdf_v1(z: &[u8]) -> Vec<u8> {
    utils::sha256(z).to_vec()
}

/// PIN protocol V2 KDF: HKDF-SHA256 to derive HMAC key (32 bytes) + AES key (32 bytes).
/// Returns 64 bytes: hmac_key || aes_key.
pub fn kdf_v2(z: &[u8]) -> Vec<u8> {
    let salt = [0u8; 32];
    let hmac_key = hkdf_sha256(&salt, z, b"CTAP2 HMAC key", 32);
    let aes_key = hkdf_sha256(&salt, z, b"CTAP2 AES key", 32);

    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&hmac_key);
    result.extend_from_slice(&aes_key);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_cbc_v1_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = [0xABu8; 32]; // 2 blocks

        let ciphertext = aes_cbc_encrypt_v1(&key, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = aes_cbc_decrypt_v1(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_v1_16byte_key() {
        let key = [0x42u8; 16];
        let plaintext = [0xABu8; 16];

        let ciphertext = aes_cbc_encrypt_v1(&key, &plaintext).unwrap();
        let decrypted = aes_cbc_decrypt_v1(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_v2_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = [0xABu8; 32];

        let encrypted = aes_cbc_encrypt_v2(&key, &plaintext).unwrap();
        // IV (16) + ciphertext (32)
        assert_eq!(encrypted.len(), 48);

        let decrypted = aes_cbc_decrypt_v2(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_kdf_v1() {
        let z = b"shared secret data";
        let result = kdf_v1(z);
        assert_eq!(result.len(), 32);
        assert_eq!(result, utils::sha256(z));
    }

    #[test]
    fn test_kdf_v2() {
        let z = b"shared secret data";
        let result = kdf_v2(z);
        assert_eq!(result.len(), 64);
        // Verify the two halves are different
        assert_ne!(&result[..32], &result[32..]);
    }

    #[test]
    fn test_hkdf_sha256() {
        let salt = [0u8; 32];
        let ikm = b"input key material";
        let info = b"CTAP2 HMAC key";
        let result = hkdf_sha256(&salt, ikm, info, 32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_ecdh_p256() {
        // Generate a "peer" keypair for testing
        use p256::ecdh::EphemeralSecret;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let peer_secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let peer_pk = peer_secret.public_key();
        let peer_point = peer_pk.to_encoded_point(false);

        let result = ecdh_p256(
            peer_point.x().unwrap(),
            peer_point.y().unwrap(),
        )
        .unwrap();

        assert_eq!(result.public_key_x.len(), 32);
        assert_eq!(result.public_key_y.len(), 32);
        assert_eq!(result.shared_secret.len(), 32);
    }
}
