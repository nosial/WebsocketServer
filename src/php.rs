use std::collections::HashMap;

use log::debug;
use log::warn;
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
        "Connection {}: spawned PHP with {} env vars",
        conn_id,
        env_vars.len()
    );

    let mut child = cmd.spawn()?;

    let stdout = if config.capture_stdout {
        child.stdout.take()
    } else {
        None
    };

    if let Some(stderr) = child.stderr.take() {
        let cid = conn_id.to_string();
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("[PHP {cid}] {line}");
            }
        });
    }

    Ok(PhpProcess { child, stdout })
}
