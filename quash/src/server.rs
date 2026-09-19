use crate::error::{Error, Result};
use crate::link::{Link, LinkEnd};
use crate::proto::{Frame, SESSION_ID_LEN};
use crate::session::SessionState;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Sessions keep sshd's TCP connection alive between QUIC links. After this
/// idle period a disconnected session is reaped so reconnects eventually fail
/// cleanly instead of leaking sockets.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(21_600);

type Sessions = Arc<Mutex<HashMap<[u8; SESSION_ID_LEN], Arc<ServerSession>>>>;

struct ServerSession {
    state: Arc<SessionState>,
    /// The current link's QUIC connection. When a new link takes over, the
    /// previous connection is closed so its driver stops promptly even if the
    /// network dropped silently and the idle timeout has not fired yet.
    current_conn: StdMutex<Option<quinn::Connection>>,
    /// Held only while a link is writing to sshd, so the socket outlives the
    /// links that carry it.
    tcp_write: Mutex<OwnedWriteHalf>,
    last_seen: StdMutex<Instant>,
    tcp_closed: AtomicBool,
}

pub async fn run(
    listen: SocketAddr,
    proxy_to: SocketAddr,
    cert_dir: &std::path::Path,
) -> Result<()> {
    let identity = crate::cert::load_or_create(cert_dir)?;
    info!("certificate fingerprint: {}", identity.fingerprint_hex());

    let server_config = crate::tls::server_config(&identity)?;
    let endpoint =
        quinn::Endpoint::server(server_config, listen).map_err(|source| Error::Bind {
            addr: listen,
            source,
        })?;
    info!("listening on {listen}, proxying to {proxy_to}");

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(reaper(Arc::clone(&sessions)));

    while let Some(incoming) = endpoint.accept().await {
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    warn!("handshake failed: {err}");
                    return;
                }
            };
            debug!("accepted connection from {}", conn.remote_address());
            if let Err(err) = serve_link(conn, proxy_to, sessions).await {
                debug!("link ended: {err:#}");
            }
        });
    }

    Ok(())
}

async fn serve_link(
    conn: quinn::Connection,
    proxy_to: SocketAddr,
    sessions: Sessions,
) -> Result<()> {
    let mut link = Link::accept(conn).await?;
    let Frame::Hello {
        session_id,
        applied,
        resume,
    } = link.read_hello().await?
    else {
        return Err(Error::LinkClosed);
    };

    let Some(session) =
        create_or_get_session(&sessions, &session_id, resume, proxy_to, &mut link).await?
    else {
        return Ok(());
    };

    handle_link(link, &session, applied).await
}

/// Returns the session for `session_id`, creating it (and its sshd connection)
/// on first use. Returns `None` if a resume request referenced an unknown
/// session, after rejecting the client.
async fn create_or_get_session(
    sessions: &Sessions,
    session_id: &[u8; SESSION_ID_LEN],
    resume: bool,
    proxy_to: SocketAddr,
    link: &mut Link,
) -> Result<Option<Arc<ServerSession>>> {
    let mut map = sessions.lock().await;
    if let Some(existing) = map.get(session_id) {
        return Ok(Some(Arc::clone(existing)));
    }
    if resume {
        debug!("resume requested for unknown session");
        link.send_reject().await?;
        return Ok(None);
    }
    let tcp = TcpStream::connect(proxy_to)
        .await
        .map_err(|source| Error::TcpConnect {
            addr: proxy_to,
            source,
        })?;
    info!("new session {session_id:02x?} -> {proxy_to}");
    let (read, write) = tcp.into_split();
    let session = Arc::new(ServerSession {
        state: Arc::new(SessionState::new()),
        current_conn: StdMutex::new(None),
        tcp_write: Mutex::new(write),
        last_seen: StdMutex::new(Instant::now()),
        tcp_closed: AtomicBool::new(false),
    });
    tokio::spawn(pump_tcp(Arc::clone(&session), read));
    map.insert(*session_id, Arc::clone(&session));
    drop(map);
    Ok(Some(session))
}

/// Runs one QUIC link for a session. Installing this link as current preempts
/// any previous link (closing its connection) so a reconnect after a silent
/// network drop takes over immediately instead of waiting for the old idle
/// timeout. On disconnect the session stays alive for the next link.
async fn handle_link(
    mut link: Link,
    session: &Arc<ServerSession>,
    client_applied: u64,
) -> Result<()> {
    let conn = link.connection();
    {
        let mut current = session
            .current_conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = current.replace(conn) {
            previous.close(0u32.into(), b"superseded");
        }
    }
    *session
        .last_seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();

    // Client is gone for good; nothing left to resume.
    if session.tcp_closed.load(Ordering::SeqCst) {
        link.close();
        return Ok(());
    }

    {
        let mut send = session.state.send.lock().await;
        send.ack(client_applied);
        send.rewind();
    }
    let applied = session.state.recv.lock().await.applied();
    link.send_welcome(applied).await?;

    let end = {
        let mut tcp_write = session.tcp_write.lock().await;
        let end = link.run(&session.state, &mut *tcp_write, false).await?;
        if matches!(end, LinkEnd::PeerFin) {
            let _ = tcp_write.shutdown().await;
        }
        drop(tcp_write);
        end
    };
    *session
        .last_seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();

    match end {
        LinkEnd::PeerFin => {
            session.tcp_closed.store(true, Ordering::SeqCst);
            link.close();
        }
        LinkEnd::Disconnected => {
            link.close();
        }
    }
    Ok(())
}

async fn pump_tcp(session: Arc<ServerSession>, mut read: tokio::net::tcp::OwnedReadHalf) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                session
                    .state
                    .send
                    .lock()
                    .await
                    .push(Bytes::copy_from_slice(&buf[..n]));
                session.state.send_ready.notify_one();
            }
        }
    }
    session.state.fin.store(true, Ordering::SeqCst);
    session.state.send_ready.notify_one();
}

async fn reaper(sessions: Sessions) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let now = Instant::now();
        let mut map = sessions.lock().await;
        let mut expired = Vec::new();
        for (id, session) in map.iter() {
            let drained = session.state.send.lock().await.is_drained();
            let closed = session.tcp_closed.load(Ordering::SeqCst) && drained;
            let last_seen = *session
                .last_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if closed || now.saturating_duration_since(last_seen) > SESSION_IDLE_TIMEOUT {
                expired.push(*id);
            }
        }
        for id in expired {
            debug!("reaping session");
            map.remove(&id);
        }
    }
}
