use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

impl Identity {
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.cert_der).into()
    }

    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }
}

#[must_use]
pub fn default_cert_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("QUASH_CERT_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
        || {
            let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
            home.join(".config")
        },
        PathBuf::from,
    );
    base.join("quash")
}

pub fn load_or_create(dir: &Path) -> Result<Identity> {
    std::fs::create_dir_all(dir).map_err(|source| Error::CreateCertDir {
        path: dir.to_path_buf(),
        source,
    })?;

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        return Ok(Identity {
            cert_der: read_cert_der(&cert_path)?,
            key_pkcs8_der: read_key_pkcs8_der(&key_path)?,
        });
    }

    let certified = rcgen::generate_simple_self_signed(vec!["quash".to_string()])
        .map_err(Error::GenerateCertificate)?;
    let cert_der = certified.cert.der().to_vec();
    let key_pkcs8_der = certified.signing_key.serialize_der();

    std::fs::write(&cert_path, certified.cert.pem()).map_err(|source| Error::WriteFile {
        path: cert_path.clone(),
        source,
    })?;
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).map_err(|source| {
        Error::WriteFile {
            path: key_path.clone(),
            source,
        }
    })?;
    set_cert_permissions(&cert_path, &key_path)?;

    Ok(Identity {
        cert_der,
        key_pkcs8_der,
    })
}

#[cfg(unix)]
fn set_cert_permissions(cert_path: &Path, key_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let cert_mode = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(cert_path, cert_mode).map_err(|source| Error::SetPermissions {
        path: cert_path.to_path_buf(),
        source,
    })?;

    let key_mode = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(key_path, key_mode).map_err(|source| Error::SetPermissions {
        path: key_path.to_path_buf(),
        source,
    })?;

    Ok(())
}

#[cfg(not(unix))]
fn set_cert_permissions(_cert_path: &Path, _key_path: &Path) -> Result<()> {
    Ok(())
}

/// Read only the public certificate so that the fingerprint can be printed
/// without access to the private key. Falls back to creating the identity when
/// no certificate exists yet.
pub fn fingerprint_hex(dir: &Path) -> Result<String> {
    let cert_path = dir.join("cert.pem");
    if !cert_path.exists() {
        return Ok(load_or_create(dir)?.fingerprint_hex());
    }
    let cert_der = read_cert_der(&cert_path)?;
    Ok(hex::encode(Sha256::digest(&cert_der)))
}

fn read_cert_der(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or(Error::NoCertificate)?
        .map_err(Error::ParseCertificate)?;
    Ok(cert.to_vec())
}

fn read_key_pkcs8_der(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(Error::ParsePrivateKey)?
        .ok_or(Error::NoPrivateKey)?;
    match key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(k) => Ok(k.secret_pkcs8_der().to_vec()),
        _ => Err(Error::UnsupportedKeyFormat),
    }
}
