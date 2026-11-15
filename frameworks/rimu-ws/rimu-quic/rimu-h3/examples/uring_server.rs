//! An HTTP/3 server on rimu-quic's io_uring driver: one worker per CPU, each with its own
//! `SO_REUSEPORT` socket, steered by connection ID.
//!
//! Routes:
//! - `GET /` and `GET /hello`: `hello`;
//! - `GET /baseline2?a=1&b=2`: the sum of the values of the query (`3`), as HttpArena's
//!   baseline-h3;
//! - `GET /static/<file>`: the files of a directory, loaded in memory at start (one copy per
//!   worker, sent by reference), with the `.br` or `.gz` twin of a file chosen by
//!   `accept-encoding` (the higher q-value, `br` on a tie), `content-encoding` and
//!   `vary: accept-encoding`, as HttpArena's static-h3 asks;
//! - `POST /echo`: the body of the request back (up to 16 MiB).
//!
//! `cargo run --release -p rimu-h3 --features uring --example uring_server -- [ADDR]` (default
//! `[::]:8443`). Environment: `CERT_DIR` (`server.crt` and `server.key`, default `/certs`),
//! `STATIC_DIR` (default `/data/static`), `WORKERS` (default: one per CPU), `PIN` (`0` to leave the
//! workers unpinned), `H3_HEADERS` (`full` for RFC 9110's `date` and `content-length`; default
//! `min`: `:status` and `content-type` only). SIGINT or SIGTERM drains the connections and ends
//! the server; SIGUSR1 prints the counters (`h3-stats name=value ...`).

use rimu_h3::{
  Body, BodyRef, H3Params, Handler, ReqCtx, ReqOutcome, Request, ResponseFields, SharedBytes,
  uring::{ServeParams, serve},
};
use rimu_quic::{QuicParams, rustls::RustlsConfig, uring::Pinning};
use std::{collections::HashMap, path::Path, sync::Arc};

/// A file of the static directory and its compressed twins, as read at start.
struct FileBytes {
  identity: Vec<u8>,
  br: Option<Vec<u8>>,
  gzip: Option<Vec<u8>>,
  mime: &'static [u8],
}

/// A file of a worker: its bytes shared by its responses, never copied.
struct File {
  identity: SharedBytes,
  br: Option<SharedBytes>,
  gzip: Option<SharedBytes>,
  mime: &'static [u8],
}

/// The handler of a worker.
struct App {
  files: HashMap<Vec<u8>, File>,
  sum: String,
}

impl Handler for App {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> rimu_h3::Result<ReqOutcome> {
    let (path, query) = match req.path.iter().position(|el| *el == b'?') {
      Some(idx) => (&req.path[..idx], &req.path[idx + 1..]),
      None => (req.path, &b""[..]),
    };
    let get = matches!(req.method, b"GET" | b"HEAD");
    match path {
      b"/" | b"/hello" if get => text(cx, 200, b"hello"),
      b"/baseline2" if get => match sum(query) {
        Some(value) => {
          use std::fmt::Write as _;
          self.sum.clear();
          let _ = write!(self.sum, "{value}");
          text(cx, 200, self.sum.as_bytes())
        }
        None => text(cx, 400, b"bad query"),
      },
      b"/echo" if req.method == b"POST" => {
        let fields = ResponseFields::with_type(200, b"application/octet-stream");
        cx.respond_with(&fields, Body::Bytes(req.body))?;
        Ok(ReqOutcome::Responded)
      }
      b"/echo" => text(cx, 405, b"POST only"),
      _ => match path.strip_prefix(b"/static/") {
        Some(name) if get => self.static_file(cx, req, name),
        Some(_) => text(cx, 405, b"GET only"),
        None => text(cx, 404, b"not found"),
      },
    }
  }
}

impl App {
  fn static_file(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
    name: &[u8],
  ) -> rimu_h3::Result<ReqOutcome> {
    let Some(file) = self.files.get(name) else {
      return text(cx, 404, b"not found");
    };
    let accepted = req.fields.get(b"accept-encoding").map(Accepted::parse).unwrap_or_default();
    let mut chosen = (None, &file.identity);
    for coding in accepted.order() {
      let twin = match coding {
        Coding::Br => file.br.as_ref(),
        Coding::Gzip => file.gzip.as_ref(),
      };
      if let Some(bytes) = twin {
        chosen = (Some(coding.token()), bytes);
        break;
      }
    }
    let (encoding, bytes) = chosen;
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let fields = ResponseFields {
      content_encoding: encoding,
      vary: Some(b"accept-encoding"),
      ..ResponseFields::with_type(200, file.mime)
    };
    cx.respond_with(&fields, Body::Ref(BodyRef::new(bytes.clone(), 0..len)?))?;
    Ok(ReqOutcome::Responded)
  }
}

fn text(cx: &mut ReqCtx<'_, '_>, status: u16, body: &[u8]) -> rimu_h3::Result<ReqOutcome> {
  cx.respond_with(&ResponseFields::with_type(status, b"text/plain"), Body::Bytes(body))?;
  Ok(ReqOutcome::Responded)
}

/// The sum of the values of the parameters of `query`; `None` if one is not an integer.
fn sum(query: &[u8]) -> Option<i64> {
  let mut rslt: i64 = 0;
  for pair in query.split(|el| *el == b'&').filter(|el| !el.is_empty()) {
    let value = pair.iter().position(|el| *el == b'=').map_or(&b""[..], |idx| &pair[idx + 1..]);
    let value: i64 = std::str::from_utf8(value).ok()?.parse().ok()?;
    rslt = rslt.wrapping_add(value);
  }
  Some(rslt)
}

#[derive(Clone, Copy)]
enum Coding {
  Br,
  Gzip,
}

impl Coding {
  const fn token(self) -> &'static [u8] {
    match self {
      Self::Br => b"br",
      Self::Gzip => b"gzip",
    }
  }
}

/// The q-values, in thousandths, of the codings of an `accept-encoding` that have twins.
#[derive(Clone, Copy, Default)]
struct Accepted {
  br: Option<u16>,
  gzip: Option<u16>,
  any: Option<u16>,
}

impl Accepted {
  fn parse(value: &[u8]) -> Self {
    let mut rslt = Self::default();
    for item in value.split(|el| *el == b',') {
      let mut params = item.split(|el| *el == b';');
      let coding = params.next().unwrap_or_default().trim_ascii();
      let mut q = Some(1000);
      for param in params {
        let param = param.trim_ascii();
        if let Some(value) = param.strip_prefix(b"q=").or_else(|| param.strip_prefix(b"Q=")) {
          q = qvalue(value.trim_ascii());
        }
      }
      let Some(q) = q else {
        continue;
      };
      if coding.eq_ignore_ascii_case(b"br") {
        rslt.br = Some(q);
      } else if coding.eq_ignore_ascii_case(b"gzip") || coding.eq_ignore_ascii_case(b"x-gzip") {
        rslt.gzip = Some(q);
      } else if coding == b"*" {
        rslt.any = Some(q);
      }
    }
    rslt
  }

  /// The codings to try, the preferred first: the higher q-value, `br` on a tie; none of q=0.
  fn order(self) -> impl Iterator<Item = Coding> {
    let br = self.br.or(self.any).unwrap_or(0);
    let gzip = self.gzip.or(self.any).unwrap_or(0);
    let pair = if gzip > br {
      [(Coding::Gzip, gzip), (Coding::Br, br)]
    } else {
      [(Coding::Br, br), (Coding::Gzip, gzip)]
    };
    pair.into_iter().filter(|el| el.1 > 0).map(|el| el.0)
  }
}

/// A q-value (RFC 9110 section 12.4.2: `0`, `0.8`, `1.000`) in thousandths; `None` if malformed.
fn qvalue(value: &[u8]) -> Option<u16> {
  let (int, frac) = match value.iter().position(|el| *el == b'.') {
    Some(idx) => (&value[..idx], &value[idx + 1..]),
    None => (value, &b""[..]),
  };
  if frac.len() > 3 || !frac.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let whole: u16 = match int {
    b"0" => 0,
    b"1" => 1000,
    _ => return None,
  };
  let mut thousandths = whole;
  for (digit, scale) in frac.iter().zip([100u16, 10, 1]) {
    thousandths += u16::from(digit - b'0') * scale;
  }
  (thousandths <= 1000).then_some(thousandths)
}

fn mime(name: &str) -> &'static [u8] {
  match name.rsplit_once('.').map(|el| el.1.to_ascii_lowercase()).as_deref() {
    Some("css") => b"text/css",
    Some("js" | "mjs") => b"text/javascript",
    Some("html" | "htm") => b"text/html",
    Some("json" | "map") => b"application/json",
    Some("svg") => b"image/svg+xml",
    Some("webp") => b"image/webp",
    Some("png") => b"image/png",
    Some("jpg" | "jpeg") => b"image/jpeg",
    Some("gif") => b"image/gif",
    Some("ico") => b"image/x-icon",
    Some("woff2") => b"font/woff2",
    Some("woff") => b"font/woff",
    Some("txt") => b"text/plain",
    Some("xml") => b"application/xml",
    Some("wasm") => b"application/wasm",
    _ => b"application/octet-stream",
  }
}

/// The files of `dir` (not its subdirectories) and their `.br`/`.gz` twins; nothing if it does not
/// exist.
fn load_static(dir: &Path) -> std::io::Result<Vec<(String, FileBytes)>> {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return Ok(Vec::new());
  };
  let mut rslt = Vec::new();
  for entry in entries {
    let entry = entry?;
    if !entry.file_type()?.is_file() {
      continue;
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    if name.ends_with(".br") || name.ends_with(".gz") {
      continue;
    }
    let twin = |suffix: &str| std::fs::read(dir.join(format!("{name}{suffix}"))).ok();
    let bytes = FileBytes {
      identity: std::fs::read(entry.path())?,
      br: twin(".br"),
      gzip: twin(".gz"),
      mime: mime(&name),
    };
    rslt.push((name, bytes));
  }
  Ok(rslt)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let addr = std::env::args().nth(1).unwrap_or_else(|| "[::]:8443".into()).parse()?;
  let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());
  let cert_dir = env("CERT_DIR", "/certs");
  let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
  let key = std::fs::read(format!("{cert_dir}/server.key"))?;
  let tls =
    RustlsConfig::builder().alpn(&[b"h3"]).cert_chain_pem(&cert).private_key_pem(&key).build()?;
  let static_dir = env("STATIC_DIR", "/data/static");
  let files = Arc::new(load_static(Path::new(&static_dir))?);

  let mut params = ServeParams::new(addr);
  if let Ok(workers) = std::env::var("WORKERS") {
    params.server.workers = Some(workers.parse()?);
  }
  if env("PIN", "1") == "0" {
    params.server.pin = Pinning::None;
  }
  params.h3 = H3Params {
    max_request_body: 16 << 20,
    ..H3Params::default().rfc9110_headers(env("H3_HEADERS", "min") == "full")
  };
  eprintln!(
    "uring_server: {addr}, {} workers, {} static files from {static_dir}",
    params.server.workers.map_or_else(|| "one per CPU:".into(), |el| el.to_string()),
    files.len()
  );
  serve(params, QuicParams::default(), tls, |_worker| {
    // A copy of the files per worker: the reference counts of a response's body stay on its core
    let files = files
      .iter()
      .map(|(name, file)| {
        let shared = |bytes: &Vec<u8>| SharedBytes::from_slice(bytes);
        let file = File {
          identity: shared(&file.identity),
          br: file.br.as_ref().map(shared),
          gzip: file.gzip.as_ref().map(shared),
          mime: file.mime,
        };
        (name.as_bytes().to_vec(), file)
      })
      .collect();
    App { files, sum: String::with_capacity(24) }
  })?;
  eprintln!("uring_server: stopped");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::{Accepted, Coding, qvalue, sum};

  #[test]
  fn queries_sum() {
    assert_eq!(sum(b"a=1&b=2"), Some(3));
    assert_eq!(sum(b""), Some(0));
    assert_eq!(sum(b"a=-5&b=2&c=10"), Some(7));
    assert_eq!(sum(b"a=x"), None);
  }

  #[test]
  fn accept_encoding_orders_codings() {
    let order =
      |value: &[u8]| -> Vec<&[u8]> { Accepted::parse(value).order().map(Coding::token).collect() };
    assert_eq!(order(b"br;q=1, gzip;q=0.8"), [&b"br"[..], b"gzip"]);
    assert_eq!(order(b"gzip, br;q=0.5"), [&b"gzip"[..], b"br"]);
    assert_eq!(order(b"gzip, br"), [&b"br"[..], b"gzip"]);
    assert_eq!(order(b"identity"), Vec::<&[u8]>::new());
    assert_eq!(order(b"*;q=0.1, br;q=0"), [&b"gzip"[..]]);
    assert_eq!(qvalue(b"0.125"), Some(125));
    assert_eq!(qvalue(b"1.5"), None);
  }
}
