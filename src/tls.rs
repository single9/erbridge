//! TLS for the reverse-tunnel control channel (A <-> B).
//!
//! The link is encrypted with an ephemeral self-signed certificate generated
//! fresh on every run. There is no certificate authority and the client does
//! not verify the server's certificate chain: identity is instead proven by
//! the shared token exchanged right after the handshake (see `reverse::mod`).
//! This defeats passive eavesdropping but, unlike a properly pinned or
//! CA-signed setup, does not by itself stop an on-path attacker who can also
//! intercept the token. That tradeoff was chosen deliberately to avoid
//! certificate management for an internal tool; revisit if the link ever
//! crosses an untrusted network without an existing VPN/tunnel underneath.

use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

/// Installs the process-wide default crypto provider. Must be called once
/// before building any TLS config; safe to call more than once.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct SelfSignedCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

pub fn generate_self_signed() -> Result<SelfSignedCert> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["erbridge".to_string()])
            .context("generating self-signed certificate")?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::from(signing_key);
    Ok(SelfSignedCert { cert_der, key_der })
}

pub fn server_tls_config(cert: &SelfSignedCert) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key())
        .context("building TLS server config")?;
    Ok(Arc::new(config))
}

pub fn client_tls_config() -> Result<Arc<ClientConfig>> {
    let provider = CryptoProvider::get_default()
        .context("no default crypto provider installed")?
        .clone();
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Accepts any server certificate: the TLS layer here only provides
/// confidentiality/integrity, not peer identity. See module docs.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
