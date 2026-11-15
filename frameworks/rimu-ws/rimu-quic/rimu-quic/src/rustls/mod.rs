//! TLS 1.3 through rustls's QUIC API, with the packet protection keys captured (`rustls`
//! feature).
//!
//! [`RustlsConfig`] is a [`ServerSessionFactory`]: build it with [`RustlsConfig::builder`], which
//! applies every setting the transport needs, and give it to the endpoint. rustls does the whole
//! handshake (certificates, signatures, transcript, ALPN, the `quic_transport_parameters`
//! extension); the keys it derives are captured as bytes and expanded by the
//! transport into its own key types, so no packet goes through rustls.
//!
//! The configuration refuses resumption and 0-RTT, which the transport does not support: no
//! session tickets (`send_tls13_tickets = 0`, the default never-ticketer), no session cache
//! (`NoServerSessionStorage`), no early data (`max_early_data_size = 0`), no half-RTT data, TLS
//! 1.3 only, no certificate compression.

mod capture;
#[cfg(any(test, feature = "client"))]
mod client;
mod hello;
#[cfg(any(test, feature = "__fuzz"))]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "client"))]
pub use client::RustlsClientConfig;

use crate::{
  CipherSuite,
  tls::{CryptoSession, KeyChange, KeyPair, KeyUpdater, ServerSessionFactory, TlsAlert},
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use capture::{CaptureAlg, capture};
use hello::HelloScan;
use rustls::{
  CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite,
  crypto::CryptoProvider,
  pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
  quic::{self as rq},
};
use std::sync::OnceLock;

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use rustls::crypto::aws_lc_rs as provider_backend;
#[cfg(feature = "ring")]
use rustls::crypto::ring as provider_backend;

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("the `rustls` feature of rimu-quic needs a crypto backend: `ring` or `aws-lc-rs`");

/// Why a [`RustlsConfig`] could not be built.
#[derive(Debug)]
pub enum ConfigError {
  /// No certificate was given, or the PEM input held none.
  NoCertificate,
  /// No private key was given, or the PEM input held none.
  NoPrivateKey,
  /// A PEM input could not be read.
  Pem(rustls::pki_types::pem::Error),
  /// No cipher suite or no application protocol was given.
  Empty,
  /// rustls refused the configuration (a key that does not match the certificate, for one).
  Rustls(rustls::Error),
}

impl core::fmt::Display for ConfigError {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::NoCertificate => f.write_str("no certificate"),
      Self::NoPrivateKey => f.write_str("no private key"),
      Self::Pem(el) => write!(f, "PEM: {el}"),
      Self::Empty => f.write_str("no cipher suite or no application protocol"),
      Self::Rustls(el) => write!(f, "rustls: {el}"),
    }
  }
}

impl std::error::Error for ConfigError {}

impl From<rustls::Error> for ConfigError {
  #[inline]
  fn from(value: rustls::Error) -> Self {
    Self::Rustls(value)
  }
}

// What a suite's `quic::Algorithm` does with the keys rustls derives
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyMode {
  // Records the bytes and gives rustls zero-sized dummy keys
  Capture,
  // Records the bytes and gives rustls the provider's own keys (tests compare them)
  #[cfg(test)]
  CaptureDelegate,
}

const BASE_SUITES: [(CipherSuite, SupportedCipherSuite); 3] = [
  (CipherSuite::Aes128GcmSha256, provider_backend::cipher_suite::TLS13_AES_128_GCM_SHA256),
  (CipherSuite::Aes256GcmSha384, provider_backend::cipher_suite::TLS13_AES_256_GCM_SHA384),
  (
    CipherSuite::Chacha20Poly1305Sha256,
    provider_backend::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
  ),
];

// The TLS 1.3 suite of `suite` whose `quic` algorithm captures, made once (leaked: rustls takes
// `&'static` suites).
pub(crate) fn tls13_suite(mode: KeyMode, suite: CipherSuite) -> Option<&'static Tls13CipherSuite> {
  static CELLS: [OnceLock<[Option<&'static Tls13CipherSuite>; 3]>; 2] =
    [OnceLock::new(), OnceLock::new()];
  let (idx, delegate) = match mode {
    KeyMode::Capture => (0, false),
    #[cfg(test)]
    KeyMode::CaptureDelegate => (1, true),
  };
  let suites = CELLS.get(idx)?.get_or_init(|| {
    BASE_SUITES.map(|(ours, base)| {
      let base = base.tls13()?;
      let inner = base.quic?;
      let quic: &'static dyn rq::Algorithm =
        Box::leak(Box::new(CaptureAlg { delegate, inner, suite: ours }));
      Some(&*Box::leak(Box::new(Tls13CipherSuite {
        common: CipherSuiteCommon {
          suite: base.common.suite,
          hash_provider: base.common.hash_provider,
          confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: base.hkdf_provider,
        aead_alg: base.aead_alg,
        quic: Some(quic),
      })))
    })
  });
  let pos = BASE_SUITES.iter().position(|el| el.0 == suite)?;
  *suites.get(pos)?
}

// The provider of the backend with `suites` (in that order of preference) as capturing suites.
pub(crate) fn provider(mode: KeyMode, suites: &[CipherSuite]) -> Arc<CryptoProvider> {
  Arc::new(CryptoProvider {
    cipher_suites: suites
      .iter()
      .filter_map(|el| tls13_suite(mode, *el))
      .map(SupportedCipherSuite::Tls13)
      .collect(),
    ..provider_backend::default_provider()
  })
}

/// The TLS configuration of a QUIC server on rustls: a [`ServerSessionFactory`].
#[derive(Clone, Debug)]
pub struct RustlsConfig {
  inner: Arc<rustls::ServerConfig>,
}

impl RustlsConfig {
  /// A builder with ALPN `h3` and every supported cipher suite.
  #[inline]
  pub fn builder() -> RustlsConfigBuilder {
    RustlsConfigBuilder {
      alpn: vec![b"h3".to_vec()],
      certs: Vec::new(),
      key: None,
      #[cfg(test)]
      mode: KeyMode::Capture,
      pem_error: None,
      suites: CipherSuite::PRIORITY.to_vec(),
    }
  }

  /// The rustls configuration.
  #[inline]
  pub fn rustls_config(&self) -> &Arc<rustls::ServerConfig> {
    &self.inner
  }
}

impl ServerSessionFactory for RustlsConfig {
  #[inline]
  fn new_session(&self, local_transport_params: &[u8]) -> Result<Box<dyn CryptoSession>, TlsAlert> {
    let conn = rq::ServerConnection::new(
      Arc::clone(&self.inner),
      rq::Version::V1,
      local_transport_params.to_vec(),
    )
    .map_err(|_| TlsAlert::INTERNAL_ERROR)?;
    Ok(Box::new(RustlsSession { conn: conn.into(), hello: Some(HelloScan::new()) }))
  }
}

/// Builds a [`RustlsConfig`]: certificate chain and private key (PEM or DER), application
/// protocols, cipher suites.
#[derive(Debug)]
pub struct RustlsConfigBuilder {
  alpn: Vec<Vec<u8>>,
  certs: Vec<CertificateDer<'static>>,
  key: Option<PrivateKeyDer<'static>>,
  #[cfg(test)]
  mode: KeyMode,
  pem_error: Option<rustls::pki_types::pem::Error>,
  suites: Vec<CipherSuite>,
}

impl RustlsConfigBuilder {
  /// The application protocols that the server accepts, in order of preference (default: `h3`).
  /// A client that offers none of them is refused (`no_application_protocol`).
  #[inline]
  #[must_use]
  pub fn alpn(mut self, protocols: &[&[u8]]) -> Self {
    self.alpn = protocols.iter().map(|el| el.to_vec()).collect();
    self
  }

  /// The cipher suites, in order of preference (default: [`CipherSuite::PRIORITY`]).
  #[inline]
  #[must_use]
  pub fn cipher_suites(mut self, suites: &[CipherSuite]) -> Self {
    self.suites = suites.to_vec();
    self
  }

  /// The certificate chain, leaf first, as PEM.
  #[inline]
  #[must_use]
  pub fn cert_chain_pem(mut self, pem: &[u8]) -> Self {
    match CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>() {
      Ok(elem) => self.certs = elem,
      Err(err) => self.pem_error = Some(err),
    }
    self
  }

  /// The certificate chain, leaf first, as DER.
  #[inline]
  #[must_use]
  pub fn cert_chain_der(mut self, certs: &[&[u8]]) -> Self {
    self.certs = certs.iter().map(|el| CertificateDer::from(el.to_vec())).collect();
    self
  }

  /// The private key of the leaf certificate as PEM (PKCS #8, SEC 1 or PKCS #1).
  #[inline]
  #[must_use]
  pub fn private_key_pem(mut self, pem: &[u8]) -> Self {
    match PrivateKeyDer::from_pem_slice(pem) {
      Ok(elem) => self.key = Some(elem),
      Err(err) => self.pem_error = Some(err),
    }
    self
  }

  /// The private key of the leaf certificate as PKCS #8 DER.
  #[inline]
  #[must_use]
  pub fn private_key_pkcs8_der(mut self, der: &[u8]) -> Self {
    self.key = Some(PrivateKeyDer::Pkcs8(der.to_vec().into()));
    self
  }

  #[cfg(test)]
  pub(crate) fn key_mode(mut self, mode: KeyMode) -> Self {
    self.mode = mode;
    self
  }

  /// The configuration, with every setting that the transport needs applied.
  #[inline]
  pub fn build(self) -> Result<RustlsConfig, ConfigError> {
    if let Some(err) = self.pem_error {
      return Err(ConfigError::Pem(err));
    }
    if self.certs.is_empty() {
      return Err(ConfigError::NoCertificate);
    }
    let Some(key) = self.key else {
      return Err(ConfigError::NoPrivateKey);
    };
    if self.suites.is_empty() || self.alpn.is_empty() {
      return Err(ConfigError::Empty);
    }
    #[cfg(test)]
    let mode = self.mode;
    #[cfg(not(test))]
    let mode = KeyMode::Capture;
    let mut config = rustls::ServerConfig::builder_with_provider(provider(mode, &self.suites))
      .with_protocol_versions(&[&rustls::version::TLS13])?
      .with_no_client_auth()
      .with_single_cert(self.certs, key)?;
    apply_server_settings(&mut config, self.alpn);
    Ok(RustlsConfig { inner: Arc::new(config) })
  }
}

// What the transport needs of a server configuration: no resumption, no 0-RTT, no tickets.
fn apply_server_settings(config: &mut rustls::ServerConfig, alpn: Vec<Vec<u8>>) {
  config.alpn_protocols = alpn;
  // QUIC requires 0 or u32::MAX; 0 never offers early data
  config.max_early_data_size = 0;
  // Tickets would go out in 1-RTT CRYPTO frames, which the transport never sends
  config.send_tls13_tickets = 0;
  config.send_half_rtt_data = false;
  config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
  // The default ticketer never produces tickets, and is kept
  config.cert_compressors = Vec::new();
  config.cert_decompressors = Vec::new();
}

/// A rustls handshake (server, or the test client) behind [`CryptoSession`].
pub(crate) struct RustlsSession {
  conn: rq::Connection,
  // A server's scan of the ClientHello, until it is read (see `hello`)
  hello: Option<HelloScan>,
}

impl core::fmt::Debug for RustlsSession {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("RustlsSession").finish_non_exhaustive()
  }
}

impl CryptoSession for RustlsSession {
  #[inline]
  fn read_handshake(&mut self, data: &[u8]) -> Result<(), TlsAlert> {
    // Keys are derived in `write_hs` only; a capture here would be a broken assumption
    let (rslt, captures) = capture(|| self.conn.read_hs(data));
    if captures.len != 0 || captures.overflow != 0 {
      return Err(TlsAlert::INTERNAL_ERROR);
    }
    rslt
      .map_err(|_| self.conn.alert().map_or(TlsAlert::INTERNAL_ERROR, |el| TlsAlert(el.into())))?;
    // rustls takes the extension of the drafts for the one of RFC 9001 (section 8.2)
    if let Some(scan) = &mut self.hello
      && let Some(found) = scan.feed(data)
    {
      self.hello = None;
      if !found {
        return Err(TlsAlert::MISSING_EXTENSION);
      }
    }
    Ok(())
  }

  #[inline]
  fn write_handshake(&mut self, out: &mut Vec<u8>) -> Result<Option<KeyChange>, TlsAlert> {
    let conn = &mut self.conn;
    let (change, captures) = capture(|| conn.write_hs(out));
    match change {
      None => {
        if captures.len != 0 || captures.overflow != 0 {
          return Err(TlsAlert::INTERNAL_ERROR);
        }
        Ok(None)
      }
      Some(rq::KeyChange::Handshake { keys }) => {
        drop(keys);
        Ok(Some(KeyChange::Handshake { keys: captures.level_keys()? }))
      }
      Some(rq::KeyChange::OneRtt { keys, next }) => {
        drop(keys);
        let keys = captures.level_keys()?;
        Ok(Some(KeyChange::OneRtt { keys, updater: Box::new(RustlsUpdater { secrets: next }) }))
      }
    }
  }

  #[inline]
  fn peer_transport_params(&self) -> Option<&[u8]> {
    self.conn.quic_transport_parameters()
  }

  #[inline]
  fn alpn(&self) -> Option<&[u8]> {
    self.conn.alpn_protocol()
  }

  #[inline]
  fn is_handshaking(&self) -> bool {
    self.conn.is_handshaking()
  }
}

/// The keys of the key updates, from rustls's `Secrets`.
pub(crate) struct RustlsUpdater {
  secrets: rq::Secrets,
}

impl KeyUpdater for RustlsUpdater {
  #[inline]
  fn next_keys(&mut self) -> Result<KeyPair, TlsAlert> {
    let (set, captures) = capture(|| self.secrets.next_packet_keys());
    drop(set);
    captures.update_keys()
  }
}
