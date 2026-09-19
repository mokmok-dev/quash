use crate::error::{Error, Result};
use crate::link::{Link, LinkEnd, new_session_id};
use crate::session::SessionState;
use crate::tls;
use bytes::Bytes;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, warn};

pub struct ClientOptions {
    pub remote: SocketAddr,
    pub server_name: String,
    pub fingerprint: Option<String>,
    pub bootstrap: Option<Bootstrap>,
}

pub struct Bootstrap {
    pub ssh_target: String,
    pub ssh_port: u16,
    pub command: String,
}

/// Keep retrying for this long after a link drops before giving up, so a
/// transient network handover is transparent but a dead server still surfaces
/// an error to SSH instead of hanging forever.
const MAX_RECONNECT_WINDOW: Duration = Duration::from_secs(600);

pub async fn run(opts: ClientOptions) -> Result<()> {
    let fingerprint = if let Some(fp) = &opts.fingerprint {
        tls::parse_fingerprint(fp)?
    } else {
        let bootstrap = opts
            .bootstrap
            .as_ref()
            .ok_or(Error::MissingAuthentication)?;
        let fp = fetch_fingerprint(bootstrap).await?;
        debug!("bootstrapped fingerprint: {}", hex::encode(fp));
        fp
    };

    let client_config = tls::client_config(fingerprint)?;
    let bind: SocketAddr = "0.0.0.0:0".parse().map_err(Error::Address)?;
    let mut endpoint =
        quinn::Endpoint::client(bind).map_err(|source| Error::Bind { addr: bind, source })?;
    endpoint.set_default_client_config(client_config);

    let state = Arc::new(SessionState::new());
    let stdin_task = spawn_stdin_reader(Arc::clone(&state));

    let mut stdout = tokio::io::stdout();
    let outcome = proxy_loop(&endpoint, &opts, &state, &mut stdout, &stdin_task).await;

    stdin_task.abort();
    outcome?;

    // The peer may already be gone, in which case `wait_idle` never resolves.
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    Ok(())
}

/// Reads stdin for the whole session, buffering into the send queue even while
/// the link is down so a reconnect can replay the backlog.
fn spawn_stdin_reader(state: Arc<SessionState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            state
                .send
                .lock()
                .await
                .push(Bytes::copy_from_slice(&buf[..n]));
            state.send_ready.notify_one();
        }
        state.fin.store(true, Ordering::SeqCst);
        state.send_ready.notify_one();
    })
}

async fn proxy_loop(
    endpoint: &quinn::Endpoint,
    opts: &ClientOptions,
    state: &Arc<SessionState>,
    stdout: &mut tokio::io::Stdout,
    stdin_task: &tokio::task::JoinHandle<()>,
) -> Result<()> {
    let mut resume = false;
    let mut session_id = new_session_id();
    let mut backoff = Duration::from_millis(250);
    // Set when a link drops; bounds how long we keep retrying before letting
    // SSH see the failure.
    let mut give_up_at: Option<tokio::time::Instant> = None;
    let gave_up = |give_up_at: &Option<tokio::time::Instant>| {
        give_up_at.is_some_and(|t| tokio::time::Instant::now() >= t)
    };
    loop {
        let mut link = match Link::connect(endpoint, opts.remote, &opts.server_name).await {
            Ok(link) => link,
            Err(err) => {
                if stdin_task.is_finished() {
                    return Ok(());
                }
                if gave_up(&give_up_at) {
                    return Err(Error::ReconnectGaveUp);
                }
                warn!("connect failed ({err:#}); retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        match link.client_handshake(state, &session_id, resume).await {
            Ok(()) => {}
            Err(Error::SessionRejected) => {
                // The server forgot the session (restart or idle reap). Start a
                // fresh one; already-sent bytes cannot be recovered, but the
                // SSH layer will notice and reconnect.
                warn!("session expired on the server; starting a new session");
                session_id = new_session_id();
                resume = false;
                state.send.lock().await.reset();
                state.recv.lock().await.reset();
                link.close();
                continue;
            }
            Err(err) => {
                if gave_up(&give_up_at) {
                    return Err(Error::ReconnectGaveUp);
                }
                warn!("handshake failed ({err:#}); retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        }
        backoff = Duration::from_millis(250);
        debug!("link established (resume={resume})");

        let end = link.run(state, stdout, true).await;
        link.close();
        match end {
            Ok(LinkEnd::PeerFin) => {
                debug!("peer finished; closing");
                return Ok(());
            }
            Ok(LinkEnd::Disconnected) => {
                resume = true;
                give_up_at = Some(tokio::time::Instant::now() + MAX_RECONNECT_WINDOW);
                debug!("link lost; reconnecting");
            }
            Err(err) => return Err(err),
        }
    }
}

async fn fetch_fingerprint(bootstrap: &Bootstrap) -> Result<[u8; 32]> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-T")
        .arg("-p")
        .arg(bootstrap.ssh_port.to_string())
        .arg("-o")
        .arg("ProxyCommand=none")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg(&bootstrap.ssh_target)
        .args(bootstrap.command.split_whitespace())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    debug!(
        "bootstrapping fingerprint via ssh {}: {}",
        bootstrap.ssh_target, bootstrap.command
    );
    let output = cmd.output().await.map_err(Error::BootstrapSpawn)?;
    if !output.status.success() {
        return Err(Error::BootstrapExit(output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let last = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or(Error::BootstrapEmpty)?;
    tls::parse_fingerprint(last)
}
