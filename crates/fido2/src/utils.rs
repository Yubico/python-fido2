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

//! Utility functions for cryptography and encoding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Encode bytes as base64url without padding.
pub fn websafe_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode a base64url-encoded string (with or without padding).
/// Also accepts standard base64 characters (+/) for compatibility.
/// Invalid characters are silently ignored, matching Python's behavior.
pub fn websafe_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized: String = data
        .chars()
        .filter_map(|c| match c {
            '+' => Some('-'),
            '/' => Some('_'),
            '=' => None,
            c if c.is_ascii_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(&normalized)
}

/// Constant-time byte comparison to prevent timing attacks.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Use XOR accumulator to avoid short-circuit evaluation
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// AES-256-GCM encrypt.
/// Returns nonce (12 bytes) + ciphertext + tag.
#[allow(deprecated)]
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if key.len() != 32 {
        return Err("Key must be 32 bytes");
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 12 bytes");
    }

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| "Encryption failed")
}

/// AES-256-GCM decrypt.
#[allow(deprecated)]
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if key.len() != 32 {
        return Err("Key must be 32 bytes");
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 12 bytes");
    }

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| "Decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(&hash[..4], &[0x2c, 0xf2, 0x4d, 0xba], "SHA-256 of 'hello'");
    }

    #[test]
    fn test_hmac_sha256() {
        let mac = hmac_sha256(b"key", b"message");
        assert_eq!(mac.len(), 32);
        // Verify determinism
        assert_eq!(mac, hmac_sha256(b"key", b"message"));
        // Different key = different result
        assert_ne!(mac, hmac_sha256(b"other", b"message"));
    }

    #[test]
    fn test_websafe_roundtrip() {
        let data = b"\x00\x01\x02\xff\xfe\xfd";
        let encoded = websafe_encode(data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = websafe_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_websafe_decode_with_padding() {
        let encoded = websafe_encode(b"test");
        let with_padding = format!("{encoded}==");
        assert_eq!(
            websafe_decode(&with_padding).unwrap(),
            websafe_decode(&encoded).unwrap()
        );
    }
}
