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

//! CTAP2 Bio Enrollment API.

use crate::cbor::{self, Value};
use crate::ctap::CtapError;
use crate::ctap2::{ctap2_cmd, Ctap2};
use crate::pin::PinProtocol;

/// BioEnrollment result keys.
pub mod bio_result {
    pub const MODALITY: i64 = 0x01;
    pub const FINGERPRINT_KIND: i64 = 0x02;
    pub const MAX_SAMPLES_REQUIRED: i64 = 0x03;
    pub const TEMPLATE_ID: i64 = 0x04;
    pub const LAST_SAMPLE_STATUS: i64 = 0x05;
    pub const REMAINING_SAMPLES: i64 = 0x06;
    pub const TEMPLATE_INFOS: i64 = 0x07;
    pub const MAX_TEMPLATE_FRIENDLY_NAME: i64 = 0x08;
}

/// Bio enrollment modality.
pub const MODALITY_FINGERPRINT: u32 = 0x01;

/// FP enrollment sub-commands.
pub mod fp_cmd {
    pub const ENROLL_BEGIN: u32 = 0x01;
    pub const ENROLL_CAPTURE_NEXT: u32 = 0x02;
    pub const ENROLL_CANCEL: u32 = 0x03;
    pub const ENUMERATE_ENROLLMENTS: u32 = 0x04;
    pub const SET_NAME: u32 = 0x05;
    pub const REMOVE_ENROLLMENT: u32 = 0x06;
    pub const GET_SENSOR_INFO: u32 = 0x07;
}

/// FP enrollment parameter keys.
pub mod fp_param {
    pub const TEMPLATE_ID: i64 = 0x01;
    pub const TEMPLATE_NAME: i64 = 0x02;
    pub const TIMEOUT_MS: i64 = 0x03;
}

/// Template info keys.
pub mod template_info {
    pub const ID: i64 = 0x01;
    pub const NAME: i64 = 0x02;
}

/// Fingerprint Bio Enrollment API.
pub struct FPBioEnrollment<'a> {
    ctap: &'a Ctap2<'a>,
    protocol: &'a PinProtocol,
    pin_uv_token: &'a [u8],
    cmd_byte: u8,
    modality: u32,
}

impl<'a> FPBioEnrollment<'a> {
    /// Create a new FPBioEnrollment instance.
    pub fn new(
        ctap: &'a Ctap2<'a>,
        protocol: &'a PinProtocol,
        pin_uv_token: &'a [u8],
    ) -> Result<Self, CtapError> {
        let info = ctap.info();
        let cmd_byte = if info.options.contains_key("bioEnroll") {
            ctap2_cmd::BIO_ENROLLMENT
        } else if info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && info.options.contains_key("userVerificationMgmtPreview")
        {
            ctap2_cmd::BIO_ENROLLMENT_PRE
        } else {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support BioEnroll".to_string(),
            ));
        };

        // Verify modality
        let modality_resp = ctap.bio_enrollment(
            cmd_byte,
            None,
            None,
            None,
            None,
            None,
            Some(Value::Bool(true)),
            &mut |_| {},
        )?;
        let modality = cbor_map_get_int(&modality_resp, bio_result::MODALITY)
            .ok_or_else(|| CtapError::InvalidResponse("Missing modality".to_string()))?
            as u32;
        if modality != MODALITY_FINGERPRINT {
            return Err(CtapError::InvalidResponse(
                "Device does not support fingerprint".to_string(),
            ));
        }

        Ok(Self {
            ctap,
            protocol,
            pin_uv_token,
            cmd_byte,
            modality,
        })
    }

    fn _call(
        &self,
        sub_cmd: u32,
        params: Option<Value>,
        auth: bool,
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Value, CtapError> {
        let (pin_uv_protocol, pin_uv_param) = if auth {
            let mut msg = vec![self.modality as u8, sub_cmd as u8];
            if let Some(ref p) = params {
                msg.extend_from_slice(&cbor::encode(p));
            }
            (
                Some(Value::Int(self.protocol.version() as i64)),
                Some(Value::Bytes(
                    self.protocol.authenticate(self.pin_uv_token, &msg),
                )),
            )
        } else {
            (None, None)
        };
        self.ctap.bio_enrollment(
            self.cmd_byte,
            Some(Value::Int(self.modality as i64)),
            Some(Value::Int(sub_cmd as i64)),
            params,
            pin_uv_protocol,
            pin_uv_param,
            None,
            on_keepalive,
        )
    }

    /// Get fingerprint sensor info.
    pub fn get_fingerprint_sensor_info(
        &self,
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Value, CtapError> {
        self._call(fp_cmd::GET_SENSOR_INFO, None, false, on_keepalive)
    }

    /// Begin fingerprint enrollment.
    /// Returns (template_id, last_sample_status, remaining_samples).
    pub fn enroll_begin(
        &self,
        timeout: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<(Vec<u8>, u32, u32), CtapError> {
        let params = timeout.map(|t| {
            Value::Map(vec![(
                Value::Int(fp_param::TIMEOUT_MS),
                Value::Int(t as i64),
            )])
        });
        let resp = self._call(fp_cmd::ENROLL_BEGIN, params, true, on_keepalive)?;
        let template_id = cbor_map_get_bytes(&resp, bio_result::TEMPLATE_ID)
            .ok_or_else(|| CtapError::InvalidResponse("Missing template ID".to_string()))?;
        let status = cbor_map_get_int(&resp, bio_result::LAST_SAMPLE_STATUS)
            .ok_or_else(|| CtapError::InvalidResponse("Missing sample status".to_string()))?
            as u32;
        let remaining = cbor_map_get_int(&resp, bio_result::REMAINING_SAMPLES)
            .ok_or_else(|| CtapError::InvalidResponse("Missing remaining samples".to_string()))?
            as u32;
        Ok((template_id, status, remaining))
    }

    /// Capture next fingerprint sample.
    /// Returns (last_sample_status, remaining_samples).
    pub fn enroll_capture_next(
        &self,
        template_id: &[u8],
        timeout: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<(u32, u32), CtapError> {
        let mut entries = vec![(
            Value::Int(fp_param::TEMPLATE_ID),
            Value::Bytes(template_id.to_vec()),
        )];
        if let Some(t) = timeout {
            entries.push((Value::Int(fp_param::TIMEOUT_MS), Value::Int(t as i64)));
        }
        let params = Value::Map(entries);
        let resp = self._call(fp_cmd::ENROLL_CAPTURE_NEXT, Some(params), true, on_keepalive)?;
        let status = cbor_map_get_int(&resp, bio_result::LAST_SAMPLE_STATUS)
            .ok_or_else(|| CtapError::InvalidResponse("Missing sample status".to_string()))?
            as u32;
        let remaining = cbor_map_get_int(&resp, bio_result::REMAINING_SAMPLES)
            .ok_or_else(|| CtapError::InvalidResponse("Missing remaining samples".to_string()))?
            as u32;
        Ok((status, remaining))
    }

    /// Cancel ongoing enrollment.
    pub fn enroll_cancel(&self) -> Result<(), CtapError> {
        self._call(fp_cmd::ENROLL_CANCEL, None, false, &mut |_| {})?;
        Ok(())
    }

    /// Enumerate enrolled fingerprints.
    /// Returns the raw response Value containing template infos.
    pub fn enumerate_enrollments(&self) -> Result<Value, CtapError> {
        self._call(fp_cmd::ENUMERATE_ENROLLMENTS, None, true, &mut |_| {})
    }

    /// Set name for a template.
    pub fn set_name(&self, template_id: &[u8], name: &str) -> Result<(), CtapError> {
        let params = Value::Map(vec![
            (
                Value::Int(template_info::ID),
                Value::Bytes(template_id.to_vec()),
            ),
            (
                Value::Int(template_info::NAME),
                Value::Text(name.to_string()),
            ),
        ]);
        self._call(fp_cmd::SET_NAME, Some(params), true, &mut |_| {})?;
        Ok(())
    }

    /// Remove an enrollment.
    pub fn remove_enrollment(&self, template_id: &[u8]) -> Result<(), CtapError> {
        let params = Value::Map(vec![(
            Value::Int(template_info::ID),
            Value::Bytes(template_id.to_vec()),
        )]);
        self._call(fp_cmd::REMOVE_ENROLLMENT, Some(params), true, &mut |_| {})?;
        Ok(())
    }
}

fn cbor_map_get_int(val: &Value, key: i64) -> Option<i64> {
    match val {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
            .and_then(|(_, v)| v.as_int()),
        _ => None,
    }
}

fn cbor_map_get_bytes(val: &Value, key: i64) -> Option<Vec<u8>> {
    match val {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
            .and_then(|(_, v)| v.as_bytes().map(|b| b.to_vec())),
        _ => None,
    }
}
