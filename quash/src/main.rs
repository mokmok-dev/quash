mod cert;
mod client;
mod error;
mod server;
mod tls;

use crate::cert as cert_mod;
use crate::client::{Bootstrap, ClientOptions};
use crate::error::{Error, Result};
use crate::tls as tls_mod;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "quash", version, about = "QUIC transport for SSH")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the QUIC server that forwards to a local sshd.
    Server(ServerArgs),
    /// Run the QUIC client, typically as an SSH `ProxyCommand`.
    Client(ClientArgs),
}

#[derive(Parser)]
struct ServerArgs {
    /// Address to listen on.
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: SocketAddr,

    /// Local sshd address to forward to.
    #[arg(short = 'p', long, default_value = "127.0.0.1:22")]
    proxy_to: SocketAddr,

    /// Directory holding the server certificate and key.
    #[arg(long)]
    cert_dir: Option<PathBuf>,

    /// Print the certificate fingerprint and exit.
    #[arg(long)]
    print_fingerprint: bool,
}

#[derive(Parser)]
struct ClientArgs {
    /// QUIC server address, e.g. 192.0.2.10:4433.
    #[arg(long)]
    remote: SocketAddr,

    /// TLS server name used for the QUIC handshake.
    #[arg(long, default_value = "quash")]
    server_name: String,

    /// Expected server certificate fingerprint (hex sha256).
    #[arg(long)]
    fingerprint: Option<String>,

    /// SSH target used to bootstrap the fingerprint, e.g. user@host.
    #[arg(long)]
    ssh_target: Option<String>,

    /// SSH port used for the bootstrap connection.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// Command run on the server over SSH to print the fingerprint.
    #[arg(long, default_value = "quash server --print-fingerprint")]
    bootstrap_command: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    tls_mod::install_crypto_provider();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;

    runtime.block_on(async move {
        match cli.command {
            Commands::Server(args) => run_server(args).await,
            Commands::Client(args) => run_client(args).await,
        }
    })
}

async fn run_server(args: ServerArgs) -> Result<()> {
    let cert_dir = args.cert_dir.unwrap_or_else(cert_mod::default_cert_dir);

    if args.print_fingerprint {
        println!("{}", cert_mod::fingerprint_hex(&cert_dir)?);
        return Ok(());
    }

    server::run(args.listen, args.proxy_to, &cert_dir).await
}

async fn run_client(args: ClientArgs) -> Result<()> {
    let bootstrap = args.ssh_target.map(|target| Bootstrap {
        ssh_target: target,
        ssh_port: args.ssh_port,
        command: args.bootstrap_command,
    });

    client::run(ClientOptions {
        remote: args.remote,
        server_name: args.server_name,
        fingerprint: args.fingerprint,
        bootstrap,
    })
    .await
}
