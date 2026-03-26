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

//! COSE key types and signature verification for FIDO2.
//!
//! Supports EC (P-256, P-384, P-521, secp256k1), RSA (PKCS1v15, PSS),
//! and EdDSA (Ed25519) key types.

use std::collections::BTreeMap;

use crate::cbor;

/// COSE key parameter indices.
pub mod params {
    /// Key type (1=OKP, 2=EC2, 3=RSA).
    pub const KTY: i64 = 1;
    /// Algorithm identifier.
    pub const ALG: i64 = 3;
    /// Curve identifier (EC2/OKP) or RSA modulus n.
    pub const PARAM_1: i64 = -1;
    /// X coordinate (EC2), public key (OKP), or RSA public exponent e.
    pub const PARAM_2: i64 = -2;
    /// Y coordinate (EC2).
    pub const PARAM_3: i64 = -3;
}

/// COSE algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    ES256 = -7,
    ESP256 = -9,
    Ed25519Alg = -19,
    ES384 = -35,
    ES512 = -36,
    PS256 = -37,
    ES256K = -47,
    ESP384 = -51,
    ESP512 = -52,
    EdDSA = -8,
    RS256 = -257,
    RS1 = -65535,
}

impl Algorithm {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            -7 => Some(Self::ES256),
            -9 => Some(Self::ESP256),
            -8 => Some(Self::EdDSA),
            -19 => Some(Self::Ed25519Alg),
            -35 => Some(Self::ES384),
            -36 => Some(Self::ES512),
            -37 => Some(Self::PS256),
            -47 => Some(Self::ES256K),
            -51 => Some(Self::ESP384),
            -52 => Some(Self::ESP512),
            -257 => Some(Self::RS256),
            -65535 => Some(Self::RS1),
            _ => None,
        }
    }

    /// Algorithms included in `supported_algorithms()`.
    pub fn supported() -> &'static [Algorithm] {
        &[
            Algorithm::ES256,
            Algorithm::EdDSA,
            Algorithm::ES384,
            Algorithm::ES512,
            Algorithm::PS256,
            Algorithm::RS256,
            Algorithm::ES256K,
        ]
    }
}

/// COSE EC2 curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256 = 1,
    P384 = 2,
    P521 = 3,
    Ed25519 = 6,
    Ed448 = 7,
    Secp256k1 = 8,
}

#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    #[error("Missing COSE algorithm identifier")]
    MissingAlgorithm,
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i64),
    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(i64),
    #[error("Missing key parameter {0}")]
    MissingParameter(i64),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid key data")]
    InvalidKeyData,
    #[error("CBOR error: {0}")]
    Cbor(#[from] cbor::CborError),
}

/// A COSE-formatted public key stored as a CBOR map (integer keys to values).
#[derive(Debug, Clone)]
pub struct CoseKey {
    params: BTreeMap<i64, cbor::Value>,
}

impl CoseKey {
    /// Parse a COSE key from a CBOR Value (must be a Map).
    pub fn from_cbor(value: &cbor::Value) -> Result<Self, CoseError> {
        let entries = value.as_map().ok_or(CoseError::InvalidKeyData)?;
        let mut params = BTreeMap::new();
        for (k, v) in entries {
            let key = k.as_int().ok_or(CoseError::InvalidKeyData)?;
            params.insert(key, v.clone());
        }
        Ok(Self { params })
    }

    /// Create a COSE key from a map of integer keys to CBOR values.
    pub fn from_map(params: BTreeMap<i64, cbor::Value>) -> Self {
        Self { params }
    }

    /// Get the algorithm identifier.
    pub fn algorithm(&self) -> Result<i64, CoseError> {
        self.get_int(params::ALG)
            .ok_or(CoseError::MissingAlgorithm)
    }

    /// Get a parameter value.
    pub fn get(&self, key: i64) -> Option<&cbor::Value> {
        self.params.get(&key)
    }

    /// Get a parameter as an integer.
    pub fn get_int(&self, key: i64) -> Option<i64> {
        self.params.get(&key).and_then(|v| v.as_int())
    }

    /// Get a parameter as bytes.
    pub fn get_bytes(&self, key: i64) -> Option<&[u8]> {
        self.params.get(&key).and_then(|v| v.as_bytes())
    }

    /// Encode as a CBOR map.
    pub fn to_cbor(&self) -> cbor::Value {
        cbor::Value::Map(
            self.params
                .iter()
                .map(|(k, v)| (cbor::Value::Int(*k), v.clone()))
                .collect(),
        )
    }

    /// Verify a signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        let alg = self.algorithm()?;
        match Algorithm::from_i64(alg) {
            Some(Algorithm::ES256 | Algorithm::ESP256) => {
                self.verify_p256(signature, message)
            }
            Some(Algorithm::ES384 | Algorithm::ESP384) => {
                self.verify_p384(signature, message)
            }
            Some(Algorithm::ES512 | Algorithm::ESP512) => {
                self.verify_p521(signature, message)
            }
            Some(Algorithm::ES256K) => self.verify_k256(signature, message),
            Some(Algorithm::EdDSA | Algorithm::Ed25519Alg) => {
                self.verify_ed25519(signature, message)
            }
            Some(Algorithm::RS256) => self.verify_rsa_pkcs1v15::<sha2::Sha256>(signature, message),
            Some(Algorithm::PS256) => self.verify_rsa_pss::<sha2::Sha256>(signature, message),
            Some(Algorithm::RS1) => self.verify_rsa_pkcs1v15::<sha1::Sha1>(signature, message),
            None => Err(CoseError::UnsupportedAlgorithm(alg)),
        }
    }

    /// Create an ES256 key from a 65-byte CTAP1 uncompressed public key.
    pub fn from_ctap1(data: &[u8]) -> Result<Self, CoseError> {
        if data.len() != 65 || data[0] != 0x04 {
            return Err(CoseError::InvalidKeyData);
        }
        let mut params = BTreeMap::new();
        params.insert(params::KTY, cbor::Value::Int(2));
        params.insert(params::ALG, cbor::Value::Int(Algorithm::ES256 as i64));
        params.insert(params::PARAM_1, cbor::Value::Int(Curve::P256 as i64));
        params.insert(params::PARAM_2, cbor::Value::Bytes(data[1..33].to_vec()));
        params.insert(params::PARAM_3, cbor::Value::Bytes(data[33..65].to_vec()));
        Ok(Self { params })
    }

    fn require_curve(&self, expected: i64) -> Result<(), CoseError> {
        let curve = self
            .get_int(params::PARAM_1)
            .ok_or(CoseError::MissingParameter(params::PARAM_1))?;
        if curve != expected {
            return Err(CoseError::UnsupportedCurve(curve));
        }
        Ok(())
    }

    fn require_bytes(&self, param: i64) -> Result<&[u8], CoseError> {
        self.get_bytes(param)
            .ok_or(CoseError::MissingParameter(param))
    }

    fn ec_sec1_uncompressed(&self) -> Result<Vec<u8>, CoseError> {
        let x = self.require_bytes(params::PARAM_2)?;
        let y = self.require_bytes(params::PARAM_3)?;
        let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        Ok(sec1)
    }

    fn verify_p256(&self, signature: &[u8], message: &[u8]) -> Result<(), CoseError> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        self.require_curve(Curve::P256 as i64)?;
        let sec1 = self.ec_sec1_uncompressed()?;
        let vk =
            VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CoseError::InvalidKeyData)?;
        let sig = Signature::from_slice(signature)
            .or_else(|_| Signature::from_der(signature))
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_p384(&self, signature: &[u8], message: &[u8]) -> Result<(), CoseError> {
        use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        self.require_curve(Curve::P384 as i64)?;
        let sec1 = self.ec_sec1_uncompressed()?;
        let vk =
            VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CoseError::InvalidKeyData)?;
        let sig = Signature::from_slice(signature)
            .or_else(|_| Signature::from_der(signature))
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_p521(&self, signature: &[u8], message: &[u8]) -> Result<(), CoseError> {
        use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        self.require_curve(Curve::P521 as i64)?;
        let sec1 = self.ec_sec1_uncompressed()?;
        let vk =
            VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CoseError::InvalidKeyData)?;
        let sig = Signature::from_slice(signature)
            .or_else(|_| Signature::from_der(signature))
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_k256(&self, signature: &[u8], message: &[u8]) -> Result<(), CoseError> {
        use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        self.require_curve(Curve::Secp256k1 as i64)?;
        let sec1 = self.ec_sec1_uncompressed()?;
        let vk =
            VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CoseError::InvalidKeyData)?;
        let sig = Signature::from_slice(signature)
            .or_else(|_| Signature::from_der(signature))
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_ed25519(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CoseError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        self.require_curve(Curve::Ed25519 as i64)?;
        let pub_bytes = self.require_bytes(params::PARAM_2)?;

        let key_bytes: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| CoseError::InvalidKeyData)?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CoseError::InvalidKeyData)?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CoseError::VerificationFailed)?;
        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_rsa_pkcs1v15<D>(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CoseError>
    where
        D: digest::Digest + digest::const_oid::AssociatedOid,
        rsa::pkcs1v15::VerifyingKey<D>: rsa::signature::Verifier<rsa::pkcs1v15::Signature>,
    {
        use rsa::signature::Verifier;

        let key = self.build_rsa_public_key()?;
        let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(key);
        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn verify_rsa_pss<D>(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), CoseError>
    where
        D: digest::Digest + digest::FixedOutputReset,
        rsa::pss::VerifyingKey<D>: rsa::signature::Verifier<rsa::pss::Signature>,
    {
        use rsa::signature::Verifier;

        let key = self.build_rsa_public_key()?;
        let vk = rsa::pss::VerifyingKey::<D>::new(key);
        let sig = rsa::pss::Signature::try_from(signature)
            .map_err(|_| CoseError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| CoseError::VerificationFailed)
    }

    fn build_rsa_public_key(&self) -> Result<rsa::RsaPublicKey, CoseError> {
        let n_bytes = self.require_bytes(params::PARAM_1)?;
        let e_bytes = self.require_bytes(params::PARAM_2)?;

        let n = rsa::BigUint::from_bytes_be(n_bytes);
        let e = rsa::BigUint::from_bytes_be(e_bytes);

        rsa::RsaPublicKey::new(n, e).map_err(|_| CoseError::InvalidKeyData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ec_key(alg: i64, curve: i64, x: &[u8], y: &[u8]) -> CoseKey {
        let mut params = BTreeMap::new();
        params.insert(params::KTY, cbor::Value::Int(2));
        params.insert(params::ALG, cbor::Value::Int(alg));
        params.insert(params::PARAM_1, cbor::Value::Int(curve));
        params.insert(params::PARAM_2, cbor::Value::Bytes(x.to_vec()));
        params.insert(params::PARAM_3, cbor::Value::Bytes(y.to_vec()));
        CoseKey::from_map(params)
    }

    #[test]
    fn test_es256_sign_verify() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let key = make_ec_key(
            Algorithm::ES256 as i64,
            Curve::P256 as i64,
            point.x().unwrap(),
            point.y().unwrap(),
        );

        let message = b"test message";
        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_es256_bad_signature() {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let key = make_ec_key(
            Algorithm::ES256 as i64,
            Curve::P256 as i64,
            point.x().unwrap(),
            point.y().unwrap(),
        );

        let result = key.verify(b"test", &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_es384_sign_verify() {
        use p384::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let key = make_ec_key(
            Algorithm::ES384 as i64,
            Curve::P384 as i64,
            point.x().unwrap(),
            point.y().unwrap(),
        );

        let message = b"test message";
        let sig: p384::ecdsa::Signature = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_es512_sign_verify() {
        use p521::ecdsa::{signature::Signer, SigningKey, VerifyingKey};

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let point = verifying_key.to_encoded_point(false);

        let key = make_ec_key(
            Algorithm::ES512 as i64,
            Curve::P521 as i64,
            point.x().unwrap(),
            point.y().unwrap(),
        );

        let message = b"test message";
        let sig: p521::ecdsa::Signature = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_es256k_sign_verify() {
        use k256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let key = make_ec_key(
            Algorithm::ES256K as i64,
            Curve::Secp256k1 as i64,
            point.x().unwrap(),
            point.y().unwrap(),
        );

        let message = b"test message";
        let sig: k256::ecdsa::Signature = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_ed25519_sign_verify() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut params = BTreeMap::new();
        params.insert(params::KTY, cbor::Value::Int(1));
        params.insert(params::ALG, cbor::Value::Int(Algorithm::EdDSA as i64));
        params.insert(params::PARAM_1, cbor::Value::Int(Curve::Ed25519 as i64));
        params.insert(
            params::PARAM_2,
            cbor::Value::Bytes(verifying_key.as_bytes().to_vec()),
        );
        let key = CoseKey::from_map(params);

        let message = b"test message";
        let sig = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_from_ctap1() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let key = CoseKey::from_ctap1(point.as_bytes()).unwrap();
        assert_eq!(key.algorithm().unwrap(), Algorithm::ES256 as i64);

        let message = b"ctap1 test";
        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        key.verify(message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_cbor_roundtrip() {
        let mut params = BTreeMap::new();
        params.insert(params::KTY, cbor::Value::Int(2));
        params.insert(params::ALG, cbor::Value::Int(-7));
        params.insert(params::PARAM_1, cbor::Value::Int(1));
        params.insert(params::PARAM_2, cbor::Value::Bytes(vec![1; 32]));
        params.insert(params::PARAM_3, cbor::Value::Bytes(vec![2; 32]));
        let key = CoseKey::from_map(params);

        let cbor_val = key.to_cbor();
        let encoded = cbor_val.encode();
        let decoded = cbor::decode(&encoded).unwrap();
        let key2 = CoseKey::from_cbor(&decoded).unwrap();

        assert_eq!(key2.algorithm().unwrap(), -7);
        assert_eq!(key2.get_int(params::PARAM_1), Some(1));
    }

    #[test]
    fn test_unsupported_algorithm() {
        let mut params = BTreeMap::new();
        params.insert(params::ALG, cbor::Value::Int(-9999));
        let key = CoseKey::from_map(params);
        let result = key.verify(b"test", b"sig");
        assert!(matches!(result, Err(CoseError::UnsupportedAlgorithm(-9999))));
    }

    #[test]
    fn test_wrong_curve() {
        let key = make_ec_key(-7, 2, &[0; 32], &[0; 32]); // ES256 with P-384 curve
        let result = key.verify(b"test", &[0; 64]);
        assert!(matches!(result, Err(CoseError::UnsupportedCurve(2))));
    }
}
