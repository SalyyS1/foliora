use crate::extension_bridge::PrepareFillRequest;
use crate::native_host::{read_frame, write_frame, write_rendezvous, Rendezvous, RENDEZVOUS_FILE};
use crate::session::DesktopSession;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use subtle::ConstantTimeEq;

pub struct NativeBridgeServer {
    stop: Arc<AtomicBool>,
    port: u16,
    rendezvous_path: PathBuf,
    thread: Option<JoinHandle<()>>,
}

#[derive(Deserialize)]
struct Envelope {
    capability: String,
    request: Value,
}

impl NativeBridgeServer {
    pub fn start(directory: PathBuf, session: Arc<Mutex<DesktopSession>>) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        let capability = hex(&secret);
        let rendezvous_path = directory.join(RENDEZVOUS_FILE);
        write_rendezvous(
            &rendezvous_path,
            &Rendezvous {
                protocol_version: 1,
                port,
                capability: capability.clone(),
            },
        )?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("foliora-native-bridge".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        handle(stream, &capability, &session);
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            stop,
            port,
            rendezvous_path,
            thread: Some(thread),
        })
    }
}

impl Drop for NativeBridgeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.rendezvous_path);
    }
}

fn handle(mut stream: TcpStream, capability: &str, session: &Arc<Mutex<DesktopSession>>) {
    let response = process(&mut stream, capability, session)
        .unwrap_or_else(|error| json!({"type": "error", "error": error}));
    let _ = write_frame(&mut stream, &response);
}

fn process(
    stream: &mut TcpStream,
    capability: &str,
    session: &Arc<Mutex<DesktopSession>>,
) -> Result<Value, String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let value = read_frame(stream)?.ok_or_else(|| "empty bridge request".to_string())?;
    let envelope: Envelope =
        serde_json::from_value(value).map_err(|_| "invalid bridge envelope".to_string())?;
    if envelope.capability.len() != capability.len()
        || !bool::from(envelope.capability.as_bytes().ct_eq(capability.as_bytes()))
    {
        return Err("bridge authentication failed".into());
    }
    let request_type = envelope.request.get("type").and_then(Value::as_str);
    if request_type != Some("prepareFillPreview") {
        return Err("unsupported bridge request".into());
    }
    let request: PrepareFillRequest = serde_json::from_value(envelope.request)
        .map_err(|_| "invalid extension preview request".to_string())?;
    let preview = session
        .lock()
        .map_err(|_| "desktop session is unavailable".to_string())?
        .prepare_extension(request)?;
    serde_json::to_value(preview).map_err(|error| error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_host::{read_frame, write_frame, Rendezvous};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "foliora-bridge-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn authenticated_native_round_trip_releases_only_the_granted_claim() {
        let directory = temp_path("data");
        let vault_path = temp_path("vault").with_extension("vault");
        let source_path = temp_path("source").with_extension("txt");
        fs::write(&source_path, "a@example.com").unwrap();
        let session = Arc::new(Mutex::new(DesktopSession::new(Duration::from_secs(300))));
        {
            let mut session = session.lock().unwrap();
            session
                .create(&vault_path, "correct horse battery staple".into())
                .unwrap();
            let snapshot = session.import_document(&source_path).unwrap();
            session
                .create_candidate(
                    &snapshot.sources[0].id,
                    "contact.email".into(),
                    "me".into(),
                    None,
                    0,
                    13,
                )
                .unwrap();
            let claim_id = session.workspace().unwrap().claims[0].id.clone();
            session.transition_claim(&claim_id, "confirmed").unwrap();
            session
                .authorize_extension("https://forms.example", vec![claim_id], 60_000)
                .unwrap();
        }
        let server = NativeBridgeServer::start(directory.clone(), Arc::clone(&session)).unwrap();
        let rendezvous: Rendezvous =
            serde_json::from_slice(&fs::read(directory.join(RENDEZVOUS_FILE)).unwrap()).unwrap();
        let request = json!({
            "type": "prepareFillPreview", "protocolVersion": 1, "tabId": 4,
            "topOrigin": "https://forms.example", "documentToken": "doc:1",
            "domRevision": 0, "fieldFingerprint": "fingerprint",
            "fields": [{"fieldId":"field:1","tag":"input","type":"email","name":"email","autocomplete":"email","disabled":false,"readOnly":false,"hidden":false,"frameOrigin":"https://forms.example"}]
        });
        let send = |capability: &str| {
            let mut stream = TcpStream::connect(("127.0.0.1", rendezvous.port)).unwrap();
            write_frame(
                &mut stream,
                &json!({"capability": capability, "request": request.clone()}),
            )
            .unwrap();
            read_frame(&mut stream).unwrap().unwrap()
        };
        assert_eq!(send("wrong")["type"], "error");
        let response = send(&rendezvous.capability);
        assert_eq!(response["type"], "fillPreview");
        assert_eq!(response["claims"].as_array().unwrap().len(), 1);
        assert_eq!(response["claims"][0]["value"], "a@example.com");
        drop(server);
        drop(session);
        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(vault_path);
        let _ = fs::remove_dir_all(directory);
    }
}
