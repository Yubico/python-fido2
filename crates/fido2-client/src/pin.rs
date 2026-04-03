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
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ctap::CtapError;
use crate::ctap2::Ctap2;
use fido2_server::cbor::Value;
use fido2_server::utils;

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
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EcdhResult {
    /// The public key to send (x coordinate, 32 bytes).
    #[zeroize(skip)]
    pub public_key_x: [u8; 32],
    /// The public key to send (y coordinate, 32 bytes).
    #[zeroize(skip)]
    pub public_key_y: [u8; 32],
    /// The raw shared secret (x coordinate of ECDH result, 32 bytes).
    pub shared_secret: [u8; 32],
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
    let peer_point = EncodedPoint::from_affine_coordinates(peer_x.into(), peer_y.into(), false);
    let peer_pk =
        PublicKey::from_sec1_bytes(peer_point.as_bytes()).map_err(|_| PinError::InvalidKeyData)?;

    // Generate ephemeral keypair and compute shared secret
    let secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let our_pk = secret.public_key();
    let our_point = our_pk.to_encoded_point(false);

    let shared = secret.diffie_hellman(&peer_pk);

    Ok(EcdhResult {
        public_key_x: (*our_point.x().unwrap()).into(),
        public_key_y: (*our_point.y().unwrap()).into(),
        shared_secret: (*shared.raw_secret_bytes()).into(),
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
            Ok(enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext))
        }
        32 => {
            let enc = Aes256CbcEnc::new(key.into(), &iv.into());
            Ok(enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext))
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
    let ciphertext = enc.encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(plaintext);

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

// --- Higher-level protocol abstractions ---

impl From<PinError> for CtapError {
    fn from(e: PinError) -> Self {
        CtapError::InvalidResponse(e.to_string())
    }
}

/// COSE key agreement public key (EC2 P-256).
pub struct CoseKeyAgreement {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl CoseKeyAgreement {
    /// Build a CBOR Value representing this key as a COSE Key map:
    /// {1: 2, 3: -25, -1: 1, -2: x_bytes, -3: y_bytes}
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(3), Value::Int(-25)),
            (Value::Int(-1), Value::Int(1)),
            (Value::Int(-2), Value::Bytes(self.x.to_vec())),
            (Value::Int(-3), Value::Bytes(self.y.to_vec())),
        ])
    }
}

/// PIN/UV protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    V1,
    V2,
}

impl PinProtocol {
    /// Protocol version number (1 or 2).
    pub fn version(&self) -> u32 {
        match self {
            PinProtocol::V1 => 1,
            PinProtocol::V2 => 2,
        }
    }

    /// Derive shared secret from raw ECDH output.
    pub fn kdf(&self, z: &[u8]) -> Vec<u8> {
        match self {
            PinProtocol::V1 => kdf_v1(z),
            PinProtocol::V2 => kdf_v2(z),
        }
    }

    /// Perform ECDH with a peer public key, return (key_agreement, shared_secret).
    pub fn encapsulate(
        &self,
        peer_x: &[u8],
        peer_y: &[u8],
    ) -> Result<(CoseKeyAgreement, Vec<u8>), PinError> {
        let ecdh = ecdh_p256(peer_x, peer_y)?;
        let shared_secret = self.kdf(&ecdh.shared_secret);
        let key_agreement = CoseKeyAgreement {
            x: ecdh.public_key_x,
            y: ecdh.public_key_y,
        };
        Ok((key_agreement, shared_secret))
    }

    /// Encrypt plaintext with the shared secret.
    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PinError> {
        match self {
            PinProtocol::V1 => aes_cbc_encrypt_v1(key, plaintext),
            PinProtocol::V2 => aes_cbc_encrypt_v2(&key[32..], plaintext),
        }
    }

    /// Decrypt ciphertext with the shared secret.
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PinError> {
        match self {
            PinProtocol::V1 => aes_cbc_decrypt_v1(key, ciphertext),
            PinProtocol::V2 => aes_cbc_decrypt_v2(&key[32..], ciphertext),
        }
    }

    /// Compute authentication tag (HMAC-SHA256 based).
    pub fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            PinProtocol::V1 => utils::hmac_sha256(key, message)[..16].to_vec(),
            PinProtocol::V2 => utils::hmac_sha256(&key[..32], message).to_vec(),
        }
    }

    /// Validate a PIN/UV token length for this protocol version.
    pub fn validate_token(&self, token: &[u8]) -> Result<Vec<u8>, PinError> {
        match self {
            PinProtocol::V1 => {
                if token.len() != 16 && token.len() != 32 {
                    return Err(PinError::InvalidPin(
                        "V1 token must be 16 or 32 bytes".to_string(),
                    ));
                }
                Ok(token.to_vec())
            }
            PinProtocol::V2 => {
                if token.len() != 32 {
                    return Err(PinError::InvalidPin(
                        "V2 token must be 32 bytes".to_string(),
                    ));
                }
                Ok(token.to_vec())
            }
        }
    }
}

/// Sub-command identifiers for the clientPin CTAP2 command.
pub mod client_pin_cmd {
    pub const GET_PIN_RETRIES: u32 = 0x01;
    pub const GET_KEY_AGREEMENT: u32 = 0x02;
    pub const SET_PIN: u32 = 0x03;
    pub const CHANGE_PIN: u32 = 0x04;
    pub const GET_TOKEN_USING_PIN_LEGACY: u32 = 0x05;
    pub const GET_TOKEN_USING_UV: u32 = 0x06;
    pub const GET_UV_RETRIES: u32 = 0x07;
    pub const GET_TOKEN_USING_PIN: u32 = 0x09;
}

/// Result key identifiers for clientPin responses.
pub mod client_pin_result {
    pub const KEY_AGREEMENT: i64 = 0x01;
    pub const PIN_UV_TOKEN: i64 = 0x02;
    pub const PIN_RETRIES: i64 = 0x03;
    pub const POWER_CYCLE_STATE: i64 = 0x04;
    pub const UV_RETRIES: i64 = 0x05;
}

/// Look up a value by integer key in a CBOR map.
fn cbor_map_get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
        .map(|(_, v)| v)
}

/// Pad a PIN string to a multiple of 16 bytes (minimum 64 bytes).
fn pad_pin(pin: &str) -> Result<Vec<u8>, PinError> {
    if pin.len() < 4 {
        return Err(PinError::InvalidPin(
            "PIN must be >= 4 characters".to_string(),
        ));
    }
    let pin_bytes = pin.as_bytes();
    let mut padded = pin_bytes.to_vec();
    padded.resize(64.max(padded.len()), 0);
    // Round up to multiple of 16
    let remainder = padded.len() % 16;
    if remainder != 0 {
        padded.resize(padded.len() + 16 - remainder, 0);
    }
    if padded.len() > 255 {
        return Err(PinError::InvalidPin("PIN must be <= 255 bytes".to_string()));
    }
    Ok(padded)
}

/// High-level client for the CTAP2 clientPin command.
pub struct ClientPin<'a> {
    ctap: &'a Ctap2<'a>,
    protocol: PinProtocol,
}

impl<'a> ClientPin<'a> {
    /// Create a new ClientPin instance.
    ///
    /// If `protocol` is None, the best supported protocol is chosen
    /// (preferring V2 over V1).
    pub fn new(ctap: &'a Ctap2<'a>, protocol: Option<PinProtocol>) -> Result<Self, CtapError> {
        let protocol = match protocol {
            Some(p) => p,
            None => {
                let protos = &ctap.info().pin_uv_protocols;
                if protos.contains(&2) {
                    PinProtocol::V2
                } else if protos.contains(&1) {
                    PinProtocol::V1
                } else {
                    return Err(CtapError::InvalidResponse(
                        "No supported PIN/UV protocol".to_string(),
                    ));
                }
            }
        };
        Ok(Self { ctap, protocol })
    }

    /// Get a reference to the current protocol.
    pub fn protocol(&self) -> &PinProtocol {
        &self.protocol
    }

    /// Get the key agreement and shared secret from the authenticator.
    pub fn _get_shared_secret(&self) -> Result<(CoseKeyAgreement, Vec<u8>), CtapError> {
        let resp = self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::GET_KEY_AGREEMENT,
            None,
            None,
            None,
            None,
            None,
            None,
            &mut |_| {},
            None,
        )?;

        let map = match &resp {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Expected map response".to_string(),
                ));
            }
        };

        let ka = cbor_map_get(map, client_pin_result::KEY_AGREEMENT)
            .ok_or_else(|| CtapError::InvalidResponse("Missing key agreement".to_string()))?;

        let ka_map = match ka {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Key agreement is not a map".to_string(),
                ));
            }
        };

        let peer_x = cbor_map_get(ka_map, -2)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| CtapError::InvalidResponse("Missing peer x".to_string()))?;
        let peer_y = cbor_map_get(ka_map, -3)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| CtapError::InvalidResponse("Missing peer y".to_string()))?;

        let (key_agreement, shared_secret) = self.protocol.encapsulate(peer_x, peer_y)?;
        Ok((key_agreement, shared_secret))
    }

    /// Get a PIN/UV token using a PIN.
    pub fn get_pin_token(
        &self,
        pin: &str,
        permissions: Option<u32>,
        permissions_rpid: Option<&str>,
    ) -> Result<Vec<u8>, CtapError> {
        let (key_agreement, shared_secret) = self._get_shared_secret()?;

        let pin_hash = utils::sha256(pin.as_bytes());
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, &pin_hash[..16])?;

        let sub_cmd = if permissions.is_some() {
            client_pin_cmd::GET_TOKEN_USING_PIN
        } else {
            client_pin_cmd::GET_TOKEN_USING_PIN_LEGACY
        };

        let resp = self.ctap.client_pin(
            self.protocol.version(),
            sub_cmd,
            Some(key_agreement.to_value()),
            None,
            None,
            Some(&pin_hash_enc),
            permissions,
            permissions_rpid,
            &mut |_| {},
            None,
        )?;

        let map = match &resp {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Expected map response".to_string(),
                ));
            }
        };

        let encrypted_token = cbor_map_get(map, client_pin_result::PIN_UV_TOKEN)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| CtapError::InvalidResponse("Missing PIN token".to_string()))?;

        let token = self.protocol.decrypt(&shared_secret, encrypted_token)?;
        let token = self.protocol.validate_token(&token)?;
        Ok(token)
    }

    /// Get a PIN/UV token using built-in user verification.
    pub fn get_uv_token(
        &self,
        permissions: u32,
        permissions_rpid: Option<&str>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        let (key_agreement, shared_secret) = self._get_shared_secret()?;

        let resp = self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::GET_TOKEN_USING_UV,
            Some(key_agreement.to_value()),
            None,
            None,
            None,
            Some(permissions),
            permissions_rpid,
            on_keepalive,
            cancel,
        )?;

        let map = match &resp {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Expected map response".to_string(),
                ));
            }
        };

        let encrypted_token = cbor_map_get(map, client_pin_result::PIN_UV_TOKEN)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| CtapError::InvalidResponse("Missing UV token".to_string()))?;

        let token = self.protocol.decrypt(&shared_secret, encrypted_token)?;
        let token = self.protocol.validate_token(&token)?;
        Ok(token)
    }

    /// Get the number of PIN retries remaining.
    pub fn get_pin_retries(&self) -> Result<(u32, Option<u32>), CtapError> {
        let resp = self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::GET_PIN_RETRIES,
            None,
            None,
            None,
            None,
            None,
            None,
            &mut |_| {},
            None,
        )?;

        let map = match &resp {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Expected map response".to_string(),
                ));
            }
        };

        let retries = cbor_map_get(map, client_pin_result::PIN_RETRIES)
            .and_then(|v| v.as_int())
            .ok_or_else(|| CtapError::InvalidResponse("Missing PIN retries".to_string()))?
            as u32;

        let power_cycle = cbor_map_get(map, client_pin_result::POWER_CYCLE_STATE)
            .and_then(|v| v.as_int())
            .map(|v| v as u32);

        Ok((retries, power_cycle))
    }

    /// Get the number of UV retries remaining.
    pub fn get_uv_retries(&self) -> Result<u32, CtapError> {
        let resp = self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::GET_UV_RETRIES,
            None,
            None,
            None,
            None,
            None,
            None,
            &mut |_| {},
            None,
        )?;

        let map = match &resp {
            Value::Map(m) => m,
            _ => {
                return Err(CtapError::InvalidResponse(
                    "Expected map response".to_string(),
                ));
            }
        };

        let retries = cbor_map_get(map, client_pin_result::UV_RETRIES)
            .and_then(|v| v.as_int())
            .ok_or_else(|| CtapError::InvalidResponse("Missing UV retries".to_string()))?
            as u32;

        Ok(retries)
    }

    /// Set a new PIN (when no PIN is currently set).
    pub fn set_pin(&self, pin: &str) -> Result<(), CtapError> {
        let padded = pad_pin(pin)?;

        let (key_agreement, shared_secret) = self._get_shared_secret()?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &padded)?;
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &new_pin_enc);

        self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::SET_PIN,
            Some(key_agreement.to_value()),
            Some(&pin_uv_param),
            Some(&new_pin_enc),
            None,
            None,
            None,
            &mut |_| {},
            None,
        )?;

        Ok(())
    }

    /// Change an existing PIN.
    pub fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<(), CtapError> {
        let padded = pad_pin(new_pin)?;

        let (key_agreement, shared_secret) = self._get_shared_secret()?;

        let pin_hash = utils::sha256(old_pin.as_bytes());
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, &pin_hash[..16])?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &padded)?;

        let mut auth_data = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_data.extend_from_slice(&new_pin_enc);
        auth_data.extend_from_slice(&pin_hash_enc);
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &auth_data);

        self.ctap.client_pin(
            self.protocol.version(),
            client_pin_cmd::CHANGE_PIN,
            Some(key_agreement.to_value()),
            Some(&pin_uv_param),
            Some(&new_pin_enc),
            Some(&pin_hash_enc),
            None,
            None,
            &mut |_| {},
            None,
        )?;

        Ok(())
    }
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
        assert_eq!(*result, utils::sha256(z));
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

        let result = ecdh_p256(peer_point.x().unwrap(), peer_point.y().unwrap()).unwrap();

        assert_eq!(result.public_key_x.len(), 32);
        assert_eq!(result.public_key_y.len(), 32);
        assert_eq!(result.shared_secret.len(), 32);
    }
}
