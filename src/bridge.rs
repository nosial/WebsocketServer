use std::collections::HashMap;
use std::sync::Arc;

use log::{debug, trace, warn};
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
        self.pending.lock().await.insert(conn_id.clone(), tx);
        trace!(
            "BridgeManager: registered pending bridge for connection ID {}",
            conn_id
        );
        rx
    }

    pub async fn resolve(&self, conn_id: &str, stream: TcpStream) -> bool {
        let mut map = self.pending.lock().await;
        if let Some(tx) = map.remove(conn_id) {
            let result = tx.send(stream).is_ok();
            if result {
                trace!(
                    "BridgeManager: resolved bridge for connection ID {}",
                    conn_id
                );
            } else {
                warn!(
                    "BridgeManager: failed to resolve bridge for connection ID {} — receiver dropped",
                    conn_id
                );
            }
            result
        } else {
            trace!(
                "BridgeManager: no pending registration found for connection ID {}",
                conn_id
            );
            false
        }
    }

    pub async fn remove(&self, conn_id: &str) {
        let mut map = self.pending.lock().await;
        if map.remove(conn_id).is_some() {
            debug!(
                "BridgeManager: removed pending bridge registration for connection ID {}",
                conn_id
            );
        } else {
            trace!(
                "BridgeManager: no pending bridge to remove for connection ID {}",
                conn_id
            );
        }
    }
}
