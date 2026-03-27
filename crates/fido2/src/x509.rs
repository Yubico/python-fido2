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

//! X.509 certificate parsing and verification for FIDO2 attestation.

use std::collections::BTreeMap;

use rsa::traits::PublicKeyParts;
use x509_cert::Certificate as X509Cert;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{self, Decode, Encode};

use crate::cbor;
use crate::cose::{CoseKey, params};

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error("DER parsing error: {0}")]
    Der(#[from] der::Error),
    #[error("Invalid certificate: {0}")]
    Invalid(String),
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("Signature verification failed")]
    VerificationFailed,
}

// Well-known OIDs
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

// EC curves
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

// Signature algorithms
const OID_SHA1_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// A parsed X.509 certificate.
pub struct Certificate {
    inner: X509Cert,
}

impl Certificate {
    /// Parse a certificate from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, X509Error> {
        let inner = X509Cert::from_der(data)?;
        Ok(Self { inner })
    }

    /// Extract the public key as a CoseKey with the given COSE algorithm identifier.
    pub fn public_key_as_cose(&self, alg: i64) -> Result<CoseKey, X509Error> {
        let spki = &self.inner.tbs_certificate.subject_public_key_info;
        let alg_oid = spki.algorithm.oid;

        if alg_oid == OID_EC_PUBLIC_KEY {
            return self.ec_public_key_as_cose(alg);
        }
        if alg_oid == OID_RSA_ENCRYPTION {
            return self.rsa_public_key_as_cose(alg);
        }
        if alg_oid == OID_ED25519 {
            return self.okp_public_key_as_cose(alg, 6); // crv=Ed25519
        }
        if alg_oid == OID_ED448 {
            return self.okp_public_key_as_cose(alg, 7); // crv=Ed448
        }

        Err(X509Error::UnsupportedKeyType(alg_oid.to_string()))
    }

    fn ec_public_key_as_cose(&self, alg: i64) -> Result<CoseKey, X509Error> {
        let spki = &self.inner.tbs_certificate.subject_public_key_info;
        let curve_oid: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| X509Error::Invalid("Missing EC curve parameter".into()))?
            .decode_as()
            .map_err(|e| X509Error::Invalid(format!("Invalid curve OID: {e}")))?;

        let crv: i64 = if curve_oid == OID_SECP256R1 {
            1
        } else if curve_oid == OID_SECP384R1 {
            2
        } else if curve_oid == OID_SECP521R1 {
            3
        } else if curve_oid == OID_SECP256K1 {
            8
        } else {
            return Err(X509Error::Invalid(format!(
                "Unsupported curve: {curve_oid}"
            )));
        };

        let point = spki.subject_public_key.raw_bytes();
        if point.is_empty() || point[0] != 0x04 {
            return Err(X509Error::Invalid("Expected uncompressed EC point".into()));
        }
        let coord_len = (point.len() - 1) / 2;

        let mut map = BTreeMap::new();
        map.insert(params::KTY, cbor::Value::Int(2));
        map.insert(params::ALG, cbor::Value::Int(alg));
        map.insert(params::PARAM_1, cbor::Value::Int(crv));
        map.insert(
            params::PARAM_2,
            cbor::Value::Bytes(point[1..1 + coord_len].to_vec()),
        );
        map.insert(
            params::PARAM_3,
            cbor::Value::Bytes(point[1 + coord_len..].to_vec()),
        );
        Ok(CoseKey::from_map(map))
    }

    fn rsa_public_key_as_cose(&self, alg: i64) -> Result<CoseKey, X509Error> {
        let spki = &self.inner.tbs_certificate.subject_public_key_info;
        let key_bytes = spki.subject_public_key.raw_bytes();

        use rsa::pkcs1::DecodeRsaPublicKey;
        let pk = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
            .map_err(|e| X509Error::Invalid(format!("Invalid RSA key: {e}")))?;

        let mut map = BTreeMap::new();
        map.insert(params::KTY, cbor::Value::Int(3));
        map.insert(params::ALG, cbor::Value::Int(alg));
        map.insert(params::PARAM_1, cbor::Value::Bytes(pk.n().to_bytes_be()));
        map.insert(params::PARAM_2, cbor::Value::Bytes(pk.e().to_bytes_be()));
        Ok(CoseKey::from_map(map))
    }

    fn okp_public_key_as_cose(&self, alg: i64, crv: i64) -> Result<CoseKey, X509Error> {
        let spki = &self.inner.tbs_certificate.subject_public_key_info;
        let key_bytes = spki.subject_public_key.raw_bytes();

        let mut map = BTreeMap::new();
        map.insert(params::KTY, cbor::Value::Int(1));
        map.insert(params::ALG, cbor::Value::Int(alg));
        map.insert(params::PARAM_1, cbor::Value::Int(crv));
        map.insert(params::PARAM_2, cbor::Value::Bytes(key_bytes.to_vec()));
        Ok(CoseKey::from_map(map))
    }

    /// Get a subject attribute value by OID string (e.g., "2.5.4.3" for CN).
    pub fn subject_string(&self, oid_str: &str) -> Option<String> {
        name_get_string(&self.inner.tbs_certificate.subject, oid_str)
    }

    /// Check if the subject has no attributes.
    pub fn subject_is_empty(&self) -> bool {
        self.inner.tbs_certificate.subject.0.is_empty()
    }

    /// Get the certificate version (0=v1, 1=v2, 2=v3).
    pub fn version(&self) -> u8 {
        self.inner.tbs_certificate.version as u8
    }

    /// Get an extension's raw value by OID string.
    /// Returns (critical, raw_value_bytes) if found.
    pub fn extension_value(&self, oid_str: &str) -> Option<(bool, Vec<u8>)> {
        let target_oid = ObjectIdentifier::new(oid_str).ok()?;
        if let Some(extensions) = &self.inner.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == target_oid {
                    return Some((ext.critical, ext.extn_value.as_bytes().to_vec()));
                }
            }
        }
        None
    }

    /// Check BasicConstraints CA flag. Returns None if extension missing.
    pub fn basic_constraints_ca(&self) -> Option<bool> {
        let (_, value) = self.extension_value("2.5.29.19")?;
        let bc = x509_cert::ext::pkix::BasicConstraints::from_der(&value).ok()?;
        Some(bc.ca)
    }

    /// Check if ExtendedKeyUsage contains a specific OID.
    pub fn extended_key_usage_contains(&self, oid_str: &str) -> bool {
        let target_oid = match ObjectIdentifier::new(oid_str) {
            Ok(o) => o,
            Err(_) => return false,
        };
        if let Some((_, value)) = self.extension_value("2.5.29.37") {
            // EKU is SEQUENCE OF OID - parse manually
            if let Ok(oids) = parse_eku_oids(&value) {
                return oids.contains(&target_oid);
            }
        }
        false
    }

    /// Check if SubjectAlternativeName extension is present.
    pub fn has_subject_alternative_name(&self) -> bool {
        self.extension_value("2.5.29.17").is_some()
    }

    /// Get the DER-encoded issuer name.
    pub fn issuer_der(&self) -> Result<Vec<u8>, X509Error> {
        self.inner
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(X509Error::Der)
    }

    /// Get the DER-encoded subject name.
    pub fn subject_der(&self) -> Result<Vec<u8>, X509Error> {
        self.inner
            .tbs_certificate
            .subject
            .to_der()
            .map_err(X509Error::Der)
    }

    /// Compute the Subject Key Identifier (SHA-1 of public key bytes).
    pub fn subject_key_identifier(&self) -> Vec<u8> {
        use sha1::Digest;
        let pk_bytes = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        sha1::Sha1::digest(pk_bytes).to_vec()
    }
}

fn name_get_string(name: &x509_cert::name::Name, oid_str: &str) -> Option<String> {
    let target_oid = ObjectIdentifier::new(oid_str).ok()?;
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == target_oid {
                if let Ok(s) = atv.value.decode_as::<x509_cert::der::asn1::Utf8StringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv
                    .value
                    .decode_as::<x509_cert::der::asn1::PrintableStringRef>()
                {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv.value.decode_as::<x509_cert::der::asn1::Ia5StringRef>() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Verify an X.509 certificate chain.
/// `chain[0]` is the leaf, `chain[last]` is the root.
pub fn verify_x509_chain(chain: &[Vec<u8>]) -> Result<(), X509Error> {
    if chain.len() < 2 {
        return Ok(());
    }
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<_, _>>()?;

    for i in 0..certs.len() - 1 {
        verify_cert_signature(&certs[i], &certs[i + 1])?;
    }
    Ok(())
}

fn verify_cert_signature(child: &Certificate, parent: &Certificate) -> Result<(), X509Error> {
    let tbs_bytes = child
        .inner
        .tbs_certificate
        .to_der()
        .map_err(X509Error::Der)?;
    let sig_alg = child.inner.signature_algorithm.oid;
    let signature = child.inner.signature.raw_bytes();

    let parent_spki = &parent.inner.tbs_certificate.subject_public_key_info;
    let parent_alg_oid = parent_spki.algorithm.oid;
    let parent_key_bytes = parent_spki.subject_public_key.raw_bytes();

    if parent_alg_oid == OID_RSA_ENCRYPTION {
        use rsa::pkcs1::DecodeRsaPublicKey;
        let pk = rsa::RsaPublicKey::from_pkcs1_der(parent_key_bytes)
            .map_err(|_| X509Error::Invalid("Invalid RSA public key".into()))?;

        if sig_alg == OID_SHA256_RSA {
            return verify_rsa::<sha2::Sha256>(&pk, &tbs_bytes, signature);
        }
        if sig_alg == OID_SHA384_RSA {
            return verify_rsa::<sha2::Sha384>(&pk, &tbs_bytes, signature);
        }
        if sig_alg == OID_SHA512_RSA {
            return verify_rsa::<sha2::Sha512>(&pk, &tbs_bytes, signature);
        }
        if sig_alg == OID_SHA1_RSA {
            return verify_rsa::<sha1::Sha1>(&pk, &tbs_bytes, signature);
        }
    }

    if parent_alg_oid == OID_EC_PUBLIC_KEY {
        let curve_oid: ObjectIdentifier = parent_spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as().ok())
            .ok_or_else(|| X509Error::Invalid("Missing EC curve parameter".into()))?;

        // Hash the TBS bytes according to the signature algorithm
        let prehash = ecdsa_prehash(sig_alg, &tbs_bytes)?;

        // Verify with the appropriate curve using prehash
        return verify_ecdsa_prehash(curve_oid, parent_key_bytes, &prehash, signature);
    }

    Err(X509Error::Invalid(format!(
        "Unsupported signature key type: {parent_alg_oid}"
    )))
}

fn verify_rsa<D>(pk: &rsa::RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<(), X509Error>
where
    D: digest::Digest + digest::const_oid::AssociatedOid,
    rsa::pkcs1v15::VerifyingKey<D>: rsa::signature::Verifier<rsa::pkcs1v15::Signature>,
{
    use rsa::signature::Verifier;
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(pk.clone());
    let sig =
        rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| X509Error::VerificationFailed)?;
    vk.verify(message, &sig)
        .map_err(|_| X509Error::VerificationFailed)
}

fn ecdsa_prehash(sig_alg: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, X509Error> {
    use sha2::Digest;
    if sig_alg == OID_ECDSA_SHA256 {
        Ok(sha2::Sha256::digest(data).to_vec())
    } else if sig_alg == OID_ECDSA_SHA384 {
        Ok(sha2::Sha384::digest(data).to_vec())
    } else if sig_alg == OID_ECDSA_SHA512 {
        Ok(sha2::Sha512::digest(data).to_vec())
    } else {
        Err(X509Error::Invalid(format!(
            "Unsupported ECDSA signature algorithm: {sig_alg}"
        )))
    }
}

fn verify_ecdsa_prehash(
    curve_oid: ObjectIdentifier,
    key: &[u8],
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), X509Error> {
    use ecdsa::signature::hazmat::PrehashVerifier;

    if curve_oid == OID_SECP256R1 {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .map_err(|_| X509Error::Invalid("Invalid P-256 key".into()))?;
        let sig = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| X509Error::VerificationFailed)?;
        return vk
            .verify_prehash(prehash, &sig)
            .map_err(|_| X509Error::VerificationFailed);
    }
    if curve_oid == OID_SECP384R1 {
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .map_err(|_| X509Error::Invalid("Invalid P-384 key".into()))?;
        let sig = p384::ecdsa::Signature::from_der(signature)
            .map_err(|_| X509Error::VerificationFailed)?;
        return vk
            .verify_prehash(prehash, &sig)
            .map_err(|_| X509Error::VerificationFailed);
    }
    if curve_oid == OID_SECP521R1 {
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(key)
            .map_err(|_| X509Error::Invalid("Invalid P-521 key".into()))?;
        let sig = p521::ecdsa::Signature::from_der(signature)
            .map_err(|_| X509Error::VerificationFailed)?;
        return vk
            .verify_prehash(prehash, &sig)
            .map_err(|_| X509Error::VerificationFailed);
    }
    Err(X509Error::Invalid(format!(
        "Unsupported EC curve: {curve_oid}"
    )))
}

fn parse_eku_oids(value: &[u8]) -> Result<Vec<ObjectIdentifier>, X509Error> {
    use x509_cert::der::Reader;
    let mut reader = der::SliceReader::new(value).map_err(X509Error::Der)?;
    let mut oids = Vec::new();
    reader
        .sequence(|r| {
            while !r.is_finished() {
                let oid: ObjectIdentifier = r.decode()?;
                oids.push(oid);
            }
            Ok(())
        })
        .map_err(X509Error::Der)?;
    Ok(oids)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed_ec_cert() -> Vec<u8> {
        // Generate a self-signed P-256 certificate for testing
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        // Build a minimal self-signed certificate DER
        // This is a simplified builder - in practice you'd use a proper X.509 builder
        build_test_cert(&signing_key, point.as_bytes())
    }

    fn build_test_cert(signing_key: &p256::ecdsa::SigningKey, public_key: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;

        // Build TBS certificate
        let mut tbs = Vec::new();

        // Version [0] EXPLICIT INTEGER v3 (2)
        tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);

        // Serial number
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]);

        // Signature algorithm: ecdsa-with-SHA256
        tbs.extend_from_slice(&[0x30, 0x0a, 0x06, 0x08]);
        tbs.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

        // Issuer: CN=Test
        let cn_value = b"Test";
        let cn_atv_len = 2 + 3 + 2 + cn_value.len(); // OID + UTF8String
        let cn_set_len = 2 + cn_atv_len;
        tbs.push(0x30); // SEQUENCE (Name)
        tbs.push(cn_set_len as u8 + 2);
        tbs.push(0x31); // SET
        tbs.push(cn_atv_len as u8 + 2);
        tbs.push(0x30); // SEQUENCE (AttributeTypeAndValue)
        tbs.push(cn_atv_len as u8);
        tbs.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID 2.5.4.3 (CN)
        tbs.push(0x0c); // UTF8String
        tbs.push(cn_value.len() as u8);
        tbs.extend_from_slice(cn_value);

        // Validity
        tbs.extend_from_slice(&[
            0x30, 0x1e, // SEQUENCE
            0x17, 0x0d, // UTCTime
        ]);
        tbs.extend_from_slice(b"200101000000Z");
        tbs.extend_from_slice(&[
            0x17, 0x0d, // UTCTime
        ]);
        tbs.extend_from_slice(b"300101000000Z");

        // Subject: CN=Test (same as issuer)
        tbs.push(0x30);
        tbs.push(cn_set_len as u8 + 2);
        tbs.push(0x31);
        tbs.push(cn_atv_len as u8 + 2);
        tbs.push(0x30);
        tbs.push(cn_atv_len as u8);
        tbs.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        tbs.push(0x0c);
        tbs.push(cn_value.len() as u8);
        tbs.extend_from_slice(cn_value);

        // SubjectPublicKeyInfo
        let spki_alg = [
            0x30, 0x13, // SEQUENCE (AlgorithmIdentifier)
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID id-ecPublicKey
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID secp256r1
        ];
        let spki_len = spki_alg.len() + 2 + 1 + public_key.len(); // alg + BIT STRING header + unused bits + key
        tbs.push(0x30); // SEQUENCE
        tbs.push(spki_len as u8);
        tbs.extend_from_slice(&spki_alg);
        tbs.push(0x03); // BIT STRING
        tbs.push((1 + public_key.len()) as u8);
        tbs.push(0x00); // unused bits
        tbs.extend_from_slice(public_key);

        // Wrap TBS in SEQUENCE
        let tbs_seq = wrap_sequence(&tbs);

        // Sign the TBS
        let sig: p256::ecdsa::Signature = signing_key.sign(&tbs_seq);
        let sig_der = sig.to_der();

        // Build the full certificate
        let mut cert = Vec::new();
        cert.extend_from_slice(&tbs_seq);

        // Signature algorithm
        cert.extend_from_slice(&[0x30, 0x0a, 0x06, 0x08]);
        cert.extend_from_slice(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

        // Signature value (BIT STRING)
        cert.push(0x03);
        cert.push((1 + sig_der.as_bytes().len()) as u8);
        cert.push(0x00);
        cert.extend_from_slice(sig_der.as_bytes());

        wrap_sequence(&cert)
    }

    fn wrap_sequence(content: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE
        if content.len() < 128 {
            result.push(content.len() as u8);
        } else if content.len() < 256 {
            result.push(0x81);
            result.push(content.len() as u8);
        } else {
            result.push(0x82);
            result.push((content.len() >> 8) as u8);
            result.push(content.len() as u8);
        }
        result.extend_from_slice(content);
        result
    }

    #[test]
    fn test_parse_self_signed_cert() {
        let cert_der = self_signed_ec_cert();
        let cert = Certificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.version(), 2); // v3
        assert_eq!(cert.subject_string("2.5.4.3").unwrap(), "Test");
        assert!(!cert.subject_is_empty());
    }

    #[test]
    fn test_public_key_extraction() {
        let cert_der = self_signed_ec_cert();
        let cert = Certificate::from_der(&cert_der).unwrap();
        let cose_key = cert.public_key_as_cose(-7).unwrap(); // ES256
        assert_eq!(cose_key.get_int(params::KTY), Some(2)); // EC2
        assert_eq!(cose_key.get_int(params::ALG), Some(-7));
        assert_eq!(cose_key.get_int(params::PARAM_1), Some(1)); // P-256
        assert!(cose_key.get_bytes(params::PARAM_2).is_some()); // x
        assert!(cose_key.get_bytes(params::PARAM_3).is_some()); // y
    }

    #[test]
    fn test_verify_self_signed() {
        let cert_der = self_signed_ec_cert();
        // Self-signed: chain is [cert, cert]
        let result = verify_x509_chain(&[cert_der.clone(), cert_der]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extension_not_found() {
        let cert_der = self_signed_ec_cert();
        let cert = Certificate::from_der(&cert_der).unwrap();
        assert!(cert.extension_value("2.5.29.19").is_none()); // No BasicConstraints
        assert!(cert.basic_constraints_ca().is_none());
    }
}
