use std::collections::HashMap;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};

pub struct BridgeManager {
    pending: Mutex<HashMap<String, oneshot::Sender<TcpStream>>>,
}

impl BridgeManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub async fn register(&self, conn_id: String) -> oneshot::Receiver<TcpStream> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(conn_id, tx);
        rx
    }

    pub async fn resolve(&self, conn_id: &str, stream: TcpStream) -> bool {
        let mut map = self.pending.lock().await;
        if let Some(tx) = map.remove(conn_id) {
            tx.send(stream).is_ok()
        } else {
            false
        }
    }

    pub async fn remove(&self, conn_id: &str) {
        self.pending.lock().await.remove(conn_id);
    }
}
