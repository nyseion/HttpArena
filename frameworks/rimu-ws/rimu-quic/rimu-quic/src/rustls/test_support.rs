//! TLS for the in-tree test harnesses and model checks (tests and the `client` feature): the test
//! certificates, a cached server configuration and the sessions of test clients and servers.

use super::{RustlsClientConfig, RustlsConfig};
use crate::{CipherSuite, conn_tls::ConnTls, rng::ChaCha20, tls::ServerSessionFactory};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use std::sync::Mutex;

/// The test certificate (ECDSA P-256, `localhost`, self-signed).
pub(crate) static CERT_PEM: &[u8] = include_bytes!("../../tests/certs/ecdsa-cert.pem");
/// The key of [`CERT_PEM`].
pub(crate) static KEY_PEM: &[u8] = include_bytes!("../../tests/certs/ecdsa-key.pem");
/// A test certificate with an RSA-2048 key.
#[cfg(test)]
pub(crate) static RSA_CERT_PEM: &[u8] = include_bytes!("../../tests/certs/rsa-cert.pem");
/// The key of [`RSA_CERT_PEM`].
#[cfg(test)]
pub(crate) static RSA_KEY_PEM: &[u8] = include_bytes!("../../tests/certs/rsa-key.pem");

/// The configuration of the test certificate, offering only `suite` if given (made once per suite
/// and shared).
pub(crate) fn server_config(suite: Option<CipherSuite>) -> Arc<RustlsConfig> {
  static CACHE: Mutex<Vec<(Option<CipherSuite>, Arc<RustlsConfig>)>> = Mutex::new(Vec::new());
  let mut cache = CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
  if let Some((_, elem)) = cache.iter().find(|el| el.0 == suite) {
    return Arc::clone(elem);
  }
  let mut builder = RustlsConfig::builder().cert_chain_pem(CERT_PEM).private_key_pem(KEY_PEM);
  if let Some(elem) = suite {
    builder = builder.cipher_suites(&[elem]);
  }
  #[allow(clippy::unwrap_used, reason = "the test certificate is valid")]
  let config = Arc::new(builder.build().unwrap());
  cache.push((suite, Arc::clone(&config)));
  config
}

/// The client configuration that offers `alpn` (nothing if empty), made once per ALPN.
pub(crate) fn client_config(alpn: &[u8]) -> RustlsClientConfig {
  static CACHE: Mutex<Vec<(Vec<u8>, RustlsClientConfig)>> = Mutex::new(Vec::new());
  let mut cache = CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
  if let Some((_, elem)) = cache.iter().find(|el| el.0 == alpn) {
    return elem.clone();
  }
  #[allow(clippy::unwrap_used, reason = "the test configuration is valid")]
  let elem = RustlsClientConfig::new(alpn, &CipherSuite::PRIORITY).unwrap();
  cache.push((alpn.to_vec(), elem.clone()));
  elem
}

/// The TLS session of a test client that offers `alpn` and sends the transport parameters `tp`.
pub(crate) fn client_tls(
  alpn: &[u8],
  tp: &[u8],
  rng: &mut ChaCha20,
) -> crate::Result<Box<ConnTls>> {
  let session =
    client_config(alpn).new_session("localhost", tp).map_err(|_| crate::Error::ProgrammingError)?;
  Ok(Box::new(ConnTls::new(session, rng)?))
}

/// The TLS session of a test server of `config` that sends the transport parameters `tp`.
pub(crate) fn server_tls(
  config: &dyn ServerSessionFactory,
  tp: &[u8],
  rng: &mut ChaCha20,
) -> crate::Result<Box<ConnTls>> {
  let session = config.new_session(tp).map_err(|_| crate::Error::ProgrammingError)?;
  Ok(Box::new(ConnTls::new(session, rng)?))
}
