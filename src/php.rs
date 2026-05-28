use std::collections::HashMap;

use log::{debug, error, trace, warn};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

pub struct PhpConfig {
    pub executable: String,
    pub script: String,
    pub arguments: Vec<String>,
    pub capture_stdout: bool,
}

pub struct PhpProcess {
    pub child: Child,
    pub stdout: Option<ChildStdout>,
}

pub fn spawn_php(
    config: &PhpConfig,
    env_vars: HashMap<String, String>,
    conn_id: &str,
) -> std::io::Result<PhpProcess> {
    trace!(
        "Connection {}: spawning PHP process: {} {} {:?}",
        conn_id,
        config.executable,
        config.script,
        config.arguments
    );

    let mut cmd = Command::new(&config.executable);
    cmd.arg(&config.script);
    for arg in &config.arguments {
        cmd.arg(arg);
    }
    cmd.stdin(std::process::Stdio::null());

    if config.capture_stdout {
        cmd.stdout(std::process::Stdio::piped());
    } else {
        cmd.stdout(std::process::Stdio::null());
    }

    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    cmd.envs(&env_vars);

    debug!(
        "Connection {}: spawned PHP process (executable={}, script={}, capture_stdout={}, env_vars={})",
        conn_id,
        config.executable,
        config.script,
        config.capture_stdout,
        env_vars.len()
    );

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Connection {}: failed to spawn PHP process '{}': {e}",
                conn_id, config.executable
            );
            return Err(e);
        }
    };

    let stdout = if config.capture_stdout {
        child.stdout.take()
    } else {
        None
    };

    if let Some(pid) = child.id() {
        trace!("Connection {}: PHP process PID={}", conn_id, pid);
    }

    if let Some(stderr) = child.stderr.take() {
        let cid = conn_id.to_string();
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("[PHP stderr:{}] {line}", cid);
            }
            trace!("Connection {}: PHP stderr reader finished", cid);
        });
    }

    Ok(PhpProcess { child, stdout })
}
