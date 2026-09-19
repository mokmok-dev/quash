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

    #[error("timed out connecting to {0}")]
    ConnectTimeout(std::net::SocketAddr),

    #[error("server rejected the session id; it may have expired")]
    SessionRejected,

    #[error("link closed")]
    LinkClosed,

    #[error("gave up reconnecting after the connection stayed down")]
    ReconnectGaveUp,

    #[error("session I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to open QUIC stream: {0}")]
    OpenStream(#[source] quinn::ConnectionError),

    #[error("failed to accept QUIC stream: {0}")]
    AcceptStream(#[source] quinn::ConnectionError),

    #[error("failed to connect to {addr}: {source}")]
    TcpConnect {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

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
