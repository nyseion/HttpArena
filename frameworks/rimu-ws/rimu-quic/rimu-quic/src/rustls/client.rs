//! The test client's TLS (`client` feature): rustls's QUIC client, which accepts any certificate.
//! For tests and interop only: it verifies nothing and is not a supported client.

use super::{KeyMode, RustlsSession, provider, provider_backend};
use crate::{
  CipherSuite,
  tls::{CryptoSession, TlsAlert},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use rustls::{
  Error as RlsError,
  pki_types::{CertificateDer, ServerName},
  quic as rq,
};

/// The TLS configuration of the test client.
#[derive(Clone, Debug)]
pub struct RustlsClientConfig {
  inner: Arc<rustls::ClientConfig>,
}

impl RustlsClientConfig {
  /// A client that offers `alpn` and `suites`, accepts any certificate and neither resumes nor
  /// sends early data.
  #[inline]
  pub fn new(alpn: &[u8], suites: &[CipherSuite]) -> Result<Self, super::ConfigError> {
    Self::with_mode(KeyMode::Capture, alpn, suites)
  }

  pub(crate) fn with_mode(
    mode: KeyMode,
    alpn: &[u8],
    suites: &[CipherSuite],
  ) -> Result<Self, super::ConfigError> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider(mode, suites))
      .with_protocol_versions(&[&rustls::version::TLS13])?
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(AnyCert))
      .with_no_client_auth();
    config.alpn_protocols = if alpn.is_empty() { Vec::new() } else { vec![alpn.to_vec()] };
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.cert_decompressors = Vec::new();
    config.cert_compressors = Vec::new();
    Ok(Self { inner: Arc::new(config) })
  }

  /// The rustls configuration.
  #[inline]
  pub fn rustls_config(&self) -> &Arc<rustls::ClientConfig> {
    &self.inner
  }

  /// A client session for `server_name` that sends `local_transport_params`.
  #[inline]
  pub fn new_session(
    &self,
    server_name: &str,
    local_transport_params: &[u8],
  ) -> Result<Box<dyn CryptoSession>, TlsAlert> {
    let name =
      ServerName::try_from(String::from(server_name)).map_err(|_| TlsAlert::INTERNAL_ERROR)?;
    let conn = rq::ClientConnection::new(
      Arc::clone(&self.inner),
      rq::Version::V1,
      name,
      local_transport_params.to_vec(),
    )
    .map_err(|_| TlsAlert::INTERNAL_ERROR)?;
    Ok(Box::new(RustlsSession { conn: conn.into(), hello: None }))
  }
}

#[derive(Debug)]
pub(crate) struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
  fn verify_server_cert(
    &self,
    _: &CertificateDer<'_>,
    _: &[CertificateDer<'_>],
    _: &ServerName<'_>,
    _: &[u8],
    _: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, RlsError> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _: &[u8],
    _: &CertificateDer<'_>,
    _: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, RlsError> {
    Err(RlsError::General("TLS 1.2".into()))
  }

  fn verify_tls13_signature(
    &self,
    msg: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, RlsError> {
    rustls::crypto::verify_tls13_signature(
      msg,
      cert,
      dss,
      &provider_backend::default_provider().signature_verification_algorithms,
    )
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    provider_backend::default_provider().signature_verification_algorithms.supported_schemes()
  }
}
