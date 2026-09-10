use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Result, VaultError};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonRequest {
    Status { protocol_version: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonResponse {
    Status(DaemonStatus),
    Error {
        protocol_version: u16,
        code: DaemonErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonErrorCode {
    UnsupportedProtocol,
    PeerRejected,
    InvalidRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonStatus {
    pub protocol_version: u16,
    pub daemon_version: String,
    pub daemon_uid: u32,
    pub peer: PeerIdentity,
    pub capabilities: DaemonCapabilities,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerIdentity {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonCapabilities {
    pub kernel_peer_credentials: CapabilityState,
    pub pam_authentication: CapabilityState,
    pub dedicated_uid: CapabilityState,
    pub encrypted_mount: CapabilityState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Enabled,
    Disabled,
}

impl CapabilityState {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl DaemonCapabilities {
    #[must_use]
    pub const fn alpha_status_only() -> Self {
        Self {
            kernel_peer_credentials: CapabilityState::Enabled,
            pam_authentication: CapabilityState::Disabled,
            dedicated_uid: CapabilityState::Disabled,
            encrypted_mount: CapabilityState::Disabled,
        }
    }
}

/// Writes one bounded, length-prefixed JSON message.
///
/// # Errors
///
/// Returns an error when serialization fails, the frame is outside the allowed size, or the writer
/// cannot accept the complete message.
pub fn write_message<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<()> {
    let payload = serde_json::to_vec(message)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(VaultError::Protocol(format!(
            "message length must be between 1 and {MAX_FRAME_BYTES} bytes"
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| VaultError::Protocol("message length exceeds u32".into()))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads one bounded, length-prefixed JSON message.
///
/// # Errors
///
/// Returns an error for invalid lengths, truncated input, malformed JSON, unknown fields, or an I/O
/// failure.
pub fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|error| protocol_io("message header is truncated", &error))?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(VaultError::Protocol(format!(
            "invalid message length {length}; maximum is {MAX_FRAME_BYTES}"
        )));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| protocol_io("message payload is truncated", &error))?;
    serde_json::from_slice(&payload)
        .map_err(|error| VaultError::Protocol(format!("invalid JSON message: {error}")))
}

fn protocol_io(context: &str, error: &std::io::Error) -> VaultError {
    VaultError::Protocol(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        CapabilityState, DaemonCapabilities, DaemonRequest, DaemonResponse, DaemonStatus,
        MAX_FRAME_BYTES, PROTOCOL_VERSION, PeerIdentity, read_message, write_message,
    };
    use crate::VaultError;

    #[test]
    fn framed_message_round_trip() {
        let message = DaemonRequest::Status {
            protocol_version: PROTOCOL_VERSION,
        };
        let mut bytes = Vec::new();
        write_message(&mut bytes, &message).expect("write message");
        let decoded = read_message(&mut Cursor::new(bytes)).expect("read message");
        assert_eq!(message, decoded);
    }

    #[test]
    fn rejects_oversized_and_truncated_frames_before_json_parsing() {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("frame limit fits u32")
            .to_be_bytes();
        assert!(matches!(
            read_message::<DaemonRequest>(&mut Cursor::new(oversized)),
            Err(VaultError::Protocol(_))
        ));

        let truncated = [0_u8, 0, 0, 8, b'{', b'}'];
        assert!(matches!(
            read_message::<DaemonRequest>(&mut Cursor::new(truncated)),
            Err(VaultError::Protocol(_))
        ));
    }

    #[test]
    fn status_response_round_trip_preserves_capability_states() {
        let response = DaemonResponse::Status(DaemonStatus {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "0.2.0-alpha.1".into(),
            daemon_uid: 1000,
            peer: PeerIdentity {
                pid: 42,
                uid: 1000,
                gid: 1000,
            },
            capabilities: DaemonCapabilities::alpha_status_only(),
        });
        let mut bytes = Vec::new();
        write_message(&mut bytes, &response).expect("write response");
        let decoded = read_message(&mut Cursor::new(bytes)).expect("read response");
        assert_eq!(response, decoded);
        assert!(CapabilityState::Enabled.is_enabled());
        assert!(!CapabilityState::Disabled.is_enabled());
    }
}
