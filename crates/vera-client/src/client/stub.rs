//! Scripted JSON-RPC endpoint answering one request per connection.

use std::io::{BufRead, Read, Write};

use serde_json::{Value, json};
use vera_domain::NativeTx;

pub(super) enum Reply {
    Result(Value),
    Error(Value),
    /// Answer `vera_sendNativeTx` with the submitted request's own identifier.
    Admit,
    Disconnect,
}

pub(super) struct Stub {
    pub(super) url: String,
    server: std::thread::JoinHandle<Vec<Value>>,
}

impl Stub {
    pub(super) fn serve(replies: Vec<Reply>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            replies
                .into_iter()
                .map(|reply| answer(&listener, reply))
                .collect()
        });
        Self { url, server }
    }

    /// Requests received, once every scripted reply has been consumed.
    pub(super) fn requests(self) -> Vec<Value> {
        self.server.join().unwrap()
    }
}

fn answer(listener: &std::net::TcpListener, reply: Reply) -> Value {
    let (mut stream, _) = listener.accept().unwrap();
    let mut input = std::io::BufReader::new(&mut stream);
    let mut length = 0;
    loop {
        let mut line = String::new();
        assert_ne!(input.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    input.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let outcome = match reply {
        Reply::Disconnect => return request,
        Reply::Result(result) => json!({ "result": result }),
        Reply::Error(error) => json!({ "error": error }),
        Reply::Admit => json!({ "result": format!("{:?}", submitted(&request).tx_id().0) }),
    };
    let mut response = json!({ "jsonrpc": "2.0", "id": request["id"] });
    response
        .as_object_mut()
        .unwrap()
        .extend(outcome.as_object().unwrap().clone());
    let response = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .unwrap();
    request
}

/// Decode the native request carried by a recorded `vera_sendNativeTx` call.
pub(super) fn submitted(request: &Value) -> NativeTx {
    let wire = request["params"][0].as_str().unwrap();
    NativeTx::decode_wire(&hex::decode(wire.trim_start_matches("0x")).unwrap()).unwrap()
}
