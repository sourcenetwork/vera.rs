//! A TCP relay that a test opens and closes to cut two devices off from each other.

use std::{
    io::{Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Relays connections to `target` while open. Closing it cuts the
/// connections it relays and refuses new ones.
pub(crate) struct Relay {
    address: SocketAddr,
    open: Arc<AtomicBool>,
    live: Arc<Mutex<Vec<TcpStream>>>,
}

impl Relay {
    pub(crate) fn new(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let open = Arc::new(AtomicBool::new(true));
        let live = Arc::new(Mutex::new(Vec::new()));
        let (accepting, tracked) = (open.clone(), live.clone());
        std::thread::spawn(move || {
            for inbound in listener.incoming() {
                let Ok(inbound) = inbound else { continue };
                if !accepting.load(Ordering::Acquire) {
                    let _ = inbound.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(outbound) = TcpStream::connect_timeout(&target, Duration::from_secs(1))
                else {
                    let _ = inbound.shutdown(Shutdown::Both);
                    continue;
                };
                let mut live = tracked.lock().unwrap();
                live.push(inbound.try_clone().unwrap());
                live.push(outbound.try_clone().unwrap());
                drop(live);
                pump(inbound.try_clone().unwrap(), outbound.try_clone().unwrap());
                pump(outbound, inbound);
            }
        });
        Self {
            address,
            open,
            live,
        }
    }

    /// The address devices dial instead of the target's.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn close(&self) {
        self.open.store(false, Ordering::Release);
        for stream in self.live.lock().unwrap().drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn open(&self) {
        self.open.store(true, Ordering::Release);
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match from.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if to.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(Shutdown::Both);
    });
}
