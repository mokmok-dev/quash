use crate::cert;
use crate::error::{Error, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn run(
    listen: SocketAddr,
    proxy_to: SocketAddr,
    cert_dir: &std::path::Path,
) -> Result<()> {
    let identity = cert::load_or_create(cert_dir)?;
    info!("certificate fingerprint: {}", identity.fingerprint_hex());

    let server_config = crate::tls::server_config(&identity)?;
    let endpoint =
        quinn::Endpoint::server(server_config, listen).map_err(|source| Error::Bind {
            addr: listen,
            source,
        })?;
    info!("listening on {listen}, proxying to {proxy_to}");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    debug!("accepted connection from {}", conn.remote_address());
                    if let Err(err) = serve_connection(conn, proxy_to).await {
                        debug!("connection closed: {err:#}");
                    }
                }
                Err(err) => warn!("handshake failed: {err}"),
            }
        });
    }

    Ok(())
}

async fn serve_connection(conn: quinn::Connection, proxy_to: SocketAddr) -> Result<()> {
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Err(err) = proxy_stream(send, recv, proxy_to).await {
                debug!("stream closed: {err:#}");
            }
        });
    }
    Ok(())
}

async fn proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    proxy_to: SocketAddr,
) -> Result<()> {
    let tcp = TcpStream::connect(proxy_to)
        .await
        .map_err(|source| Error::TcpConnect {
            addr: proxy_to,
            source,
        })?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let to_remote = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = recv
                .read(&mut buf)
                .await
                .map_err(Error::QuicRead)?
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            tcp_write
                .write_all(&buf[..n])
                .await
                .map_err(Error::TcpWrite)?;
        }
        let _ = tcp_write.shutdown().await;
        Ok::<_, Error>(())
    };

    let to_local = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tcp_read.read(&mut buf).await.map_err(Error::TcpRead)?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await.map_err(Error::QuicWrite)?;
        }
        let _ = send.finish();
        Ok::<_, Error>(())
    };

    let (to_remote_res, to_local_res) = tokio::join!(to_remote, to_local);
    to_remote_res?;
    to_local_res?;
    Ok(())
}
