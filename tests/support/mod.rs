use std::{
    fmt::Write,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::{Value, json};
use tiny_http::{Header, Response, Server};

pub struct LocalResponses {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalResponses {
    pub fn start() -> Self {
        let server = Server::http("127.0.0.1:0").expect("bind loopback fixture");
        let url = format!("http://{}", server.server_addr());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = Arc::clone(&requests);
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let Some(mut request) = server
                    .recv_timeout(Duration::from_millis(100))
                    .expect("receive request")
                else {
                    continue;
                };
                assert_eq!(request.method().as_str(), "POST");
                assert_eq!(request.url(), "/responses");
                assert!(
                    !request
                        .headers()
                        .iter()
                        .any(|header| header.field.equiv("Authorization"))
                );
                let mut body = String::new();
                request
                    .as_reader()
                    .take(1_048_576)
                    .read_to_string(&mut body)
                    .expect("read JSON request");
                recorded
                    .lock()
                    .expect("requests lock")
                    .push(serde_json::from_str(&body).expect("parse request"));
                // Event shapes match upstream rust-v0.153.4 core/tests/common/responses.rs.
                let events = [
                    json!({"type":"response.created","response":{"id":"resp_fixture"}}),
                    json!({"type":"response.output_item.done","item":{"type":"message","role":"assistant","id":"msg_fixture","content":[{"type":"output_text","text":"fixture-reply"}]}}),
                    json!({"type":"response.completed","response":{"id":"resp_fixture","usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}),
                ];
                let mut sse = String::new();
                for event in &events {
                    writeln!(&mut sse, "data: {event}\n").expect("format event");
                }
                request
                    .respond(
                        Response::from_string(sse).with_header(
                            Header::from_bytes("Content-Type", "text/event-stream")
                                .expect("content type"),
                        ),
                    )
                    .expect("respond");
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn take_requests(&self) -> Vec<Value> {
        std::mem::take(&mut *self.requests.lock().expect("requests lock"))
    }
}

impl Drop for LocalResponses {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("fixture server failed");
            }
        }
    }
}
