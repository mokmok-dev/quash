use crate::cert::Identity;
use crate::error::Error;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;

type CrateResult<T> = std::result::Result<T, Error>;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn der_cert(cert_der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(cert_der.to_vec())
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    // Disable MTU discovery and pin the payload to the smallest safe value.
    // Tailscale and other tunnels cap the path MTU (tailscale0 is 1280), and a
    // larger probe is silently dropped, which deadlocks the in-flight window.
    transport.min_mtu(1200);
    transport.initial_mtu(1200);
    transport.mtu_discovery_config(None);
    Arc::new(transport)
}

pub fn server_config(identity: &Identity) -> CrateResult<quinn::ServerConfig> {
    let cert = der_cert(&identity.cert_der);
    let key = PrivateKeyDer::Pkcs8(identity.key_pkcs8_der.clone().into());
    let rustls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(Error::BuildServerConfig)?;
    let quic = QuicServerConfig::try_from(rustls_config).map_err(Error::QuicConfig)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport_config());
    Ok(config)
}

pub fn client_config(expected_fingerprint: [u8; 32]) -> CrateResult<quinn::ClientConfig> {
    let rustls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
            expected: expected_fingerprint,
        }))
        .with_no_client_auth();
    let quic = QuicClientConfig::try_from(rustls_config).map_err(Error::QuicConfig)?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(transport_config());
    Ok(config)
}

#[derive(Debug)]
struct PinnedCertVerifier {
    expected: [u8; 32],
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {}",
                hex::encode(self.expected),
                hex::encode(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn parse_fingerprint(text: &str) -> CrateResult<[u8; 32]> {
    let trimmed = text.trim();
    let bytes = hex::decode(trimmed).map_err(Error::InvalidFingerprint)?;
    if bytes.len() != 32 {
        return Err(Error::FingerprintLength(bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
