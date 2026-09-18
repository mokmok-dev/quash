use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to create certificate directory {path}: {source}")]
    CreateCertDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to set permissions on {path}: {source}")]
    SetPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse certificate PEM: {0}")]
    ParseCertificate(#[source] std::io::Error),

    #[error("no certificate found in PEM")]
    NoCertificate,

    #[error("failed to parse private key PEM: {0}")]
    ParsePrivateKey(#[source] std::io::Error),

    #[error("no private key found in PEM")]
    NoPrivateKey,

    #[error("only PKCS#8 private keys are supported")]
    UnsupportedKeyFormat,

    #[error("failed to generate self-signed certificate: {0}")]
    GenerateCertificate(#[source] rcgen::Error),

    #[error("failed to build rustls server config: {0}")]
    BuildServerConfig(#[source] rustls::Error),

    #[error("failed to convert rustls config to QUIC: {0}")]
    QuicConfig(#[source] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(#[source] hex::FromHexError),

    #[error("fingerprint must be 32 bytes (64 hex chars), got {0}")]
    FingerprintLength(usize),

    #[error("address parse failed: {0}")]
    Address(#[source] std::net::AddrParseError),

    #[error("failed to bind QUIC endpoint on {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("either --fingerprint or --ssh-target is required")]
    MissingAuthentication,

    #[error("failed to start QUIC connection to {addr}: {source}")]
    Connect {
        addr: std::net::SocketAddr,
        #[source]
        source: quinn::ConnectError,
    },

    #[error("QUIC handshake failed: {0}")]
    Handshake(#[source] quinn::ConnectionError),

    #[error("failed to open QUIC stream: {0}")]
    OpenStream(#[source] quinn::ConnectionError),

    #[error("failed to read from QUIC stream: {0}")]
    QuicRead(#[source] quinn::ReadError),

    #[error("failed to write to QUIC stream: {0}")]
    QuicWrite(#[source] quinn::WriteError),

    #[error("failed to connect to {addr}: {source}")]
    TcpConnect {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("TCP read failed: {0}")]
    TcpRead(#[source] std::io::Error),

    #[error("TCP write failed: {0}")]
    TcpWrite(#[source] std::io::Error),

    #[error("stdin read failed: {0}")]
    StdinRead(#[source] std::io::Error),

    #[error("stdout write failed: {0}")]
    StdoutWrite(#[source] std::io::Error),

    #[error("failed to run bootstrap ssh: {0}")]
    BootstrapSpawn(#[source] std::io::Error),

    #[error("bootstrap ssh exited with {0}")]
    BootstrapExit(std::process::ExitStatus),

    #[error("bootstrap ssh returned no fingerprint")]
    BootstrapEmpty,

    #[error("failed to build tokio runtime: {0}")]
    Runtime(#[source] std::io::Error),
}
