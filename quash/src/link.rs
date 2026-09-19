use crate::error::{Error, Result};
use crate::proto::{self, Frame, SESSION_ID_LEN};
use crate::session::SessionState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// How long to wait for a QUIC handshake before giving up and retrying.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[must_use]
pub fn new_session_id() -> [u8; SESSION_ID_LEN] {
    let mut id = [0u8; SESSION_ID_LEN];
    // Zero only if the OS RNG is unavailable, which is unreachable on the
    // platforms this tool supports.
    let _ = getrandom::fill(&mut id);
    id
}

pub enum LinkEnd {
    /// The peer finished sending; the session can end cleanly.
    PeerFin,
    /// The transport failed; the session should resume on a new connection.
    Disconnected,
}

/// One QUIC connection carrying a session. After a link fails the caller
/// reconnects and handshakes again with the same `SessionState`.
pub struct Link {
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Link {
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<Self> {
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, async {
            endpoint
                .connect(remote, server_name)
                .map_err(|source| Error::Connect {
                    addr: remote,
                    source,
                })?
                .await
                .map_err(Error::Handshake)
        })
        .await
        .map_err(|_| Error::ConnectTimeout(remote))??;
        let (send, recv) = conn.open_bi().await.map_err(Error::OpenStream)?;
        Ok(Self { conn, send, recv })
    }

    pub async fn accept(conn: quinn::Connection) -> Result<Self> {
        let (send, recv) = conn.accept_bi().await.map_err(Error::AcceptStream)?;
        Ok(Self { conn, send, recv })
    }

    #[must_use]
    pub fn connection(&self) -> quinn::Connection {
        self.conn.clone()
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"done");
    }

    async fn read_frame(&mut self) -> Result<Option<Frame>> {
        proto::read_frame(&mut self.recv).await.map_err(Error::from)
    }

    async fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        proto::write_frame(&mut self.send, frame)
            .await
            .map_err(Error::from)
    }

    pub async fn read_hello(&mut self) -> Result<Frame> {
        match self.read_frame().await? {
            Some(hello @ Frame::Hello { .. }) => Ok(hello),
            _ => Err(Error::LinkClosed),
        }
    }

    /// Sends HELLO and waits for WELCOME/REJECT, negotiating both resume points.
    pub async fn client_handshake(
        &mut self,
        state: &Arc<SessionState>,
        session_id: &[u8; SESSION_ID_LEN],
        resume: bool,
    ) -> Result<()> {
        let applied = state.recv.lock().await.applied();
        self.write_frame(&Frame::Hello {
            session_id: *session_id,
            applied,
            resume,
        })
        .await?;
        loop {
            match self.read_frame().await? {
                Some(Frame::Welcome { applied }) => {
                    {
                        let mut send = state.send.lock().await;
                        send.ack(applied);
                        send.rewind();
                    }
                    return Ok(());
                }
                Some(Frame::Reject) => return Err(Error::SessionRejected),
                Some(_) => debug!("ignoring frame before WELCOME"),
                None => return Err(Error::LinkClosed),
            }
        }
    }

    /// Server side: reports the resume point for the inbound direction. The
    /// caller has already applied the client's resume point to its send queue.
    pub async fn send_welcome(&mut self, applied: u64) -> Result<()> {
        self.write_frame(&Frame::Welcome { applied }).await
    }

    pub async fn send_reject(&mut self) -> Result<()> {
        self.write_frame(&Frame::Reject).await
    }

    /// Flushes not-yet-acknowledged chunks; returns whether transport I/O
    /// failed (in which case the session should resume on a new link).
    async fn flush_send(&mut self, state: &Arc<SessionState>) -> bool {
        let pending = state.send.lock().await.take_pending();
        for (offset, payload) in pending {
            if self
                .write_frame(&Frame::Data { offset, payload })
                .await
                .is_err()
            {
                return true;
            }
        }
        if state.fin.load(Ordering::SeqCst) && state.send.lock().await.is_drained() {
            let _ = self.write_frame(&Frame::Fin).await;
        }
        false
    }

    /// Services the link until it fails or the session is complete. `sink`
    /// receives the reassembled inbound bytes; a sink error is fatal.
    ///
    /// `exit_on_peer_fin` distinguishes the two roles. The client exits as soon
    /// as the server finishes, since the server is the one that decides when a
    /// request/response exchange is over. The server treats a client FIN as
    /// "no more input" and keeps the link alive to deliver the remaining sshd
    /// output before sending its own FIN.
    pub async fn run<W>(
        &mut self,
        state: &Arc<SessionState>,
        sink: &mut W,
        exit_on_peer_fin: bool,
    ) -> Result<LinkEnd>
    where
        W: AsyncWrite + Unpin,
    {
        let conn = self.connection();
        if self.flush_send(state).await {
            return Ok(LinkEnd::Disconnected);
        }
        let mut peer_fin = false;
        loop {
            tokio::select! {
                biased;
                frame = self.read_frame() => {
                    let Some(frame) = (match frame {
                        Ok(frame) => frame,
                        Err(_) => return Ok(LinkEnd::Disconnected),
                    }) else {
                        return Ok(LinkEnd::Disconnected);
                    };
                    match frame {
                        Frame::Data { offset, payload } => {
                            let chunks = state.recv.lock().await.accept(offset, payload);
                            for chunk in chunks {
                                sink.write_all(chunk.as_ref()).await.map_err(Error::StdoutWrite)?;
                            }
                            sink.flush().await.map_err(Error::StdoutWrite)?;
                            let applied = state.recv.lock().await.applied();
                            if self.write_frame(&Frame::Ack { offset: applied }).await.is_err() {
                                return Ok(LinkEnd::Disconnected);
                            }
                        }
                        Frame::Ack { offset } => {
                            state.send.lock().await.ack(offset);
                            let _ = self.flush_send(state).await;
                        }
                        Frame::Fin => {
                            peer_fin = true;
                            if exit_on_peer_fin {
                                sink.flush().await.map_err(Error::StdoutWrite)?;
                                return Ok(LinkEnd::PeerFin);
                            }
                            // Propagate "client is done writing" to the local
                            // peer (sshd) as a TCP half-close so it can finish
                            // and send its remaining output.
                            let _ = sink.shutdown().await;
                        }
                        _ => debug!("ignoring unexpected frame"),
                    }
                }
                () = state.send_ready.notified() => {
                    if self.flush_send(state).await {
                        return Ok(LinkEnd::Disconnected);
                    }
                }
                _ = conn.closed() => return Ok(LinkEnd::Disconnected),
            }
            // The server ends once its output is fully sent and acknowledged,
            // and the client has signalled it is done reading. Give the FIN
            // time to reach the client before tearing the connection down,
            // otherwise `conn.close()` can discard it and the client waits
            // forever for a completion that never arrives.
            if !exit_on_peer_fin
                && peer_fin
                && state.fin.load(Ordering::SeqCst)
                && state.send.lock().await.is_drained()
            {
                sink.flush().await.map_err(Error::StdoutWrite)?;
                let _ = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
                return Ok(LinkEnd::PeerFin);
            }
        }
    }
}
