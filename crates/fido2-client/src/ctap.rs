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

//! CTAP device trait and error types.

/// CTAP HID command codes.
pub mod cmd {
    pub const MSG: u8 = 0x03;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
}

/// CTAP HID capability flags.
pub mod capability {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    pub const NMSG: u8 = 0x08;
}

/// Keep-alive status codes.
pub mod keepalive {
    pub const PROCESSING: u8 = 1;
    pub const UPNEEDED: u8 = 2;
}

/// Trait for a CTAP-capable device.
///
/// This unifies USB HID and NFC transports behind a single interface.
pub trait CtapDevice {
    /// Send a command and receive the response.
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError>;

    /// Get device capability flags.
    fn capabilities(&self) -> u8;

    /// Close the device.
    fn close(&mut self) {}
}

impl CtapDevice for Box<dyn CtapDevice + Send> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }

    fn capabilities(&self) -> u8 {
        (**self).capabilities()
    }

    fn close(&mut self) {
        (**self).close();
    }
}

impl CtapDevice for Box<dyn CtapDevice + Send + Sync> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }

    fn capabilities(&self) -> u8 {
        (**self).capabilities()
    }

    fn close(&mut self) {
        (**self).close();
    }
}

/// CTAP error status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapStatus {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    FpDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepaliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PuatRequired = 0x36,
    PinPolicyViolation = 0x37,
    PinTokenExpired = 0x38,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3A,
    UpRequired = 0x3B,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    Other = 0x7F,
}

impl CtapStatus {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Success,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x17 => Self::FpDatabaseFull,
            0x18 => Self::LargeBlobStorageFull,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepaliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x35 => Self::PinNotSet,
            0x36 => Self::PuatRequired,
            0x37 => Self::PinPolicyViolation,
            0x38 => Self::PinTokenExpired,
            0x39 => Self::RequestTooLarge,
            0x3A => Self::ActionTimeout,
            0x3B => Self::UpRequired,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            0x7F => Self::Other,
            _ => Self::Other,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for CtapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:02X} - {:?}", *self as u8, self)
    }
}

/// CTAP error.
#[derive(Debug, thiserror::Error)]
pub enum CtapError {
    #[error("CTAP error: {0}")]
    StatusError(CtapStatus),
    #[error("Transport error: {0}")]
    TransportError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

impl CtapError {
    pub fn status(code: u8) -> Self {
        Self::StatusError(CtapStatus::from_byte(code))
    }

    pub fn get_status(&self) -> Option<CtapStatus> {
        match self {
            Self::StatusError(s) => Some(*s),
            _ => None,
        }
    }
}

/// APDU response codes for CTAP1/U2F.
pub mod apdu {
    pub const OK: u16 = 0x9000;
    pub const USE_NOT_SATISFIED: u16 = 0x6985;
    pub const WRONG_DATA: u16 = 0x6A80;
}

/// APDU error.
#[derive(Debug, thiserror::Error)]
#[error("APDU error: 0x{code:04X}")]
pub struct ApduError {
    pub code: u16,
    pub data: Vec<u8>,
}

impl ApduError {
    pub fn new(code: u16, data: Vec<u8>) -> Self {
        Self { code, data }
    }
}
