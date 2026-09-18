use crate::error::{Error, Result};
use crate::tls;
use std::net::SocketAddr;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{debug, info};

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

    info!("connecting to {} over QUIC", opts.remote);
    let conn = endpoint
        .connect(opts.remote, &opts.server_name)
        .map_err(|source| Error::Connect {
            addr: opts.remote,
            source,
        })?
        .await
        .map_err(Error::Handshake)?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(Error::OpenStream)?;

    let to_quic = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = stdin.read(&mut buf).await.map_err(Error::StdinRead)?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await.map_err(Error::QuicWrite)?;
        }
        let _ = send.finish();
        Ok::<_, Error>(())
    };

    let to_stdout = async {
        let mut stdout = tokio::io::stdout();
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
            stdout
                .write_all(&buf[..n])
                .await
                .map_err(Error::StdoutWrite)?;
        }
        stdout.flush().await.ok();
        Ok::<_, Error>(())
    };

    tokio::select! {
        r = to_quic => r?,
        r = to_stdout => r?,
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
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
