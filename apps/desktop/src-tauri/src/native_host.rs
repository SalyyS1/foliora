//! Browser native-messaging companion. It contains no vault logic and forwards
//! one bounded request at a time to the authenticated desktop broker.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const RENDEZVOUS_FILE: &str = "native-bridge.json";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Rendezvous {
    pub protocol_version: u16,
    pub port: u16,
    pub capability: String,
}

#[derive(Serialize)]
struct BrokerEnvelope<'a> {
    capability: &'a str,
    request: &'a Value,
}

pub fn run() -> Result<(), String> {
    let path = bridge_file_path()?;
    let rendezvous: Rendezvous = serde_json::from_slice(
        &fs::read(path).map_err(|_| "Foliora Desktop is not running".to_string())?,
    )
    .map_err(|_| "Foliora bridge metadata is invalid".to_string())?;
    if rendezvous.protocol_version != 1 || rendezvous.capability.len() != 64 {
        return Err("Foliora bridge metadata is invalid".into());
    }
    while let Some(request) = read_frame(&mut io::stdin().lock())? {
        let response = forward(&rendezvous, &request)?;
        write_frame(&mut io::stdout().lock(), &response)?;
    }
    Ok(())
}

fn bridge_file_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("FOLIORA_BRIDGE_FILE") {
        return Ok(PathBuf::from(path));
    }
    dirs::data_dir()
        .map(|directory| directory.join("app.foliora.desktop").join(RENDEZVOUS_FILE))
        .ok_or_else(|| "user application-data directory is unavailable".to_string())
}

fn forward(rendezvous: &Rendezvous, request: &Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", rendezvous.port))
        .map_err(|_| "Foliora Desktop bridge is unavailable".to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let envelope = serde_json::to_value(BrokerEnvelope {
        capability: &rendezvous.capability,
        request,
    })
    .map_err(|error| error.to_string())?;
    write_frame(&mut stream, &envelope)?;
    read_frame(&mut stream)?.ok_or_else(|| "Foliora Desktop closed the bridge".to_string())
}

pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Option<Value>, String> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err("native message size is invalid".into());
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "native message JSON is invalid".to_string())
}

pub(crate) fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let length: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| "native response is too large".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err("native response size is invalid".into());
    }
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| error.to_string())
}

pub(crate) fn write_rendezvous(path: &Path, rendezvous: &Rendezvous) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "bridge path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    // Remove the temporary filename used by pre-0.1 bridge builds. It may hold
    // an expired capability after an interrupted startup.
    let _ = fs::remove_file(path.with_extension("json.tmp"));
    let bytes = serde_json::to_vec(rendezvous).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips_and_rejects_oversize() {
        let value = serde_json::json!({"type": "prepareFillPreview", "value": "xin chào"});
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &value).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(value));
        let mut oversized = ((MAX_MESSAGE_BYTES as u32) + 1).to_le_bytes().to_vec();
        oversized.push(0);
        assert!(read_frame(&mut oversized.as_slice()).is_err());
    }
}
