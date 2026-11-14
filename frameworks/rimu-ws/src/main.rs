//! rimu-ws for HttpArena: a WebSocket echo server on 8080 (`/ws`), an HTTP/2 server on 8082 (h2c)
//! and 8443 (h2 over TLS) and an HTTP/3 server on UDP 8443, the last two with `/baseline2`,
//! `/json/{count}` and `/static/{*file}`.
//!
//! Everything runs with the library defaults plus the settings `docs/production.md` of rimu-ws
//! recommends for this deployment shape: the server has dedicated cores and its clients speak first.
//! - Every listener: `TCP_DEFER_ACCEPT` (clients speak first).
//! - The WebSocket runtimes spin 20 µs before sleeping (dedicated cores, clients that reconnect
//!   often) and skip the peer-address lookup (no handler uses it). The HTTP/2 runtimes keep the
//!   defaults: spin measured level there.
//! - HTTP/3 is the library's `Http3ServerFramework` on its defaults: the same paths and handlers as
//!   h2, one worker per CPU of the container, each with its own `SO_REUSEPORT` UDP socket on
//!   `[::]:8443` (dual-stack, replies leave from the address the client used). Its responses carry
//!   `content-type` only, like cnetmod and zix: the default of the framework leaves out `date` and
//!   `content-length` and is not RFC 9110-compliant, and the router has no `server` middleware.
//!   Full RFC 9110 headers: `set_rfc9110_headers(true)`.
//!
//! Environment: `CERT_DIR` (default `/certs`, with `server.crt` and `server.key`), `DATASET_PATH`
//! (default `/data/dataset.json`), `STATIC_DIR` (default `/data/static`).

use core::ops::ControlFlow;
use rimu_ws::{
    collections::{ArrayVectorU8, VectorUsize},
    executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
    http::{
        Header, KnownHeaderName, MsgBufferString, MsgDataMut as _, Request, Response, StatusCode,
        WebSocketServerFramework,
        http2_server_framework::{
            Get, Http2ServerFramework, HttpRouter, JsonReply, Middleware, Path, State,
            StaticFiles, VerbatimParams, get,
        },
        http3_server_framework::Http3ServerFramework,
    },
    misc::JsonWriter,
    net::TcpParams,
    quic::rustls::RustlsConfig,
    rng::{ChaCha20, CryptoSeedableRng as _},
    sync::Arc,
    tls::{PlaintextCtx, TlsConfig},
    web_socket::{
        Fill, OpCode, WebSocket, WebSocketCommonMut, WebSocketPayloadOrigin, WebSocketReaderMut,
        WebSocketWriterMut,
    },
};

type LocalWebSocket = WebSocket<(), UringTcpStream, PlaintextCtx, false>;
type Common<'i> = WebSocketCommonMut<'i, (), UringTcpStream, PlaintextCtx, false>;
type Reader<'i> = WebSocketReaderMut<'i, (), UringTcpStream, PlaintextCtx, false>;
type Writer<'i> = WebSocketWriterMut<'i, (), UringTcpStream, PlaintextCtx, false>;

macro_rules! paths {
    () => {
        rimu_ws::paths!(
            ("/baseline2", get(endpoint_baseline2)),
            ("/json/{count}", get(endpoint_json)),
            ("/static/{*file}", Get(StaticFiles::new(static_dir())?))
        )
    };
}

macro_rules! router {
    () => {
        HttpRouter::new(paths!(), ServerHeader)
    };
    (no_middleware) => {
        HttpRouter::paths(paths!())
    };
}

fn main() -> rimu_ws::Result<()> {
    let ws = std::thread::spawn(|| -> rimu_ws::Result<()> {
        WebSocketServerFramework::new(
            UringExecutor::default(),
            ChaCha20::from_std_random()?,
            TlsConfig::plaintext(),
        )?
        .set_tcp_params(tcp_params())
        .set_local_runtime_cb(|| {
            UringRuntime::with_params(
                UringParams::default()
                    .set_peer_addrs(false)
                    .set_spin(core::time::Duration::from_micros(20)),
            )
        })
        .run_in_threads("0.0.0.0:8080", (("/ws", ws),))
    });
    let dataset = load_dataset();
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());
    let (tls, h3) = if std::path::Path::new(&cert_dir).join("server.crt").exists() {
        let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
        let key = std::fs::read(format!("{cert_dir}/server.key"))?;
        let (h2_data, h3_data) = (dataset.clone(), dataset.clone());
        let (h2_cert, h2_key) = (cert.clone(), key.clone());
        let h2 = std::thread::spawn(move || -> rimu_ws::Result<()> {
            Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
                UringExecutor::default(),
                ChaCha20::from_std_random()?,
                TlsConfig::from_keys_pem(&h2_cert, h2_key.as_slice())?,
            )?
            .set_data(ConnAux { dataset: h2_data })
            .set_tcp_params(tcp_params())
            .run_in_threads("0.0.0.0:8443", router!()?)
        });
        let h3 = std::thread::spawn(move || -> rimu_ws::Result<()> {
            // QUIC's TLS is rustls (rimu-quic), configured from the same PEM pair
            let tls = RustlsConfig::builder()
                .cert_chain_pem(&cert)
                .private_key_pem(&key)
                .build()
                .map_err(|err| rimu_ws::Error::from(std::io::Error::other(err)))?;
            let rslt = Http3ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _>::new(
                UringExecutor::default(),
                ChaCha20::from_std_random()?,
                tls,
            )?
            .set_data(ConnAux { dataset: h3_data })
            // The data is an `Arc` of the dataset that no handler changes: the clones of the
            // requests that ended go to the next ones (no allocation per request)
            .set_reuse_data(true)
            .run_in_threads("[::]:8443", router!(no_middleware)?);
            if let Err(err) = &rslt {
                eprintln!("rimu-ws: the HTTP/3 server ended: {err}");
            }
            rslt
        });
        (Some(h2), Some(h3))
    } else {
        eprintln!("rimu-ws: no {cert_dir}/server.crt, TLS on 8443 (h2) and UDP 8443 (h3) disabled");
        (None, None)
    };
    Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        TlsConfig::plaintext(),
    )?
    .set_data(ConnAux { dataset })
    .set_tcp_params(tcp_params())
    .run_in_threads("0.0.0.0:8082", router!()?)?;
    if let Some(elem) = tls {
        elem.join().map_err(|_| std::io::Error::other("TLS thread panicked"))??;
    }
    if let Some(elem) = h3 {
        elem.join().map_err(|_| std::io::Error::other("HTTP/3 thread panicked"))??;
    }
    ws.join().map_err(|_| std::io::Error::other("WebSocket thread panicked"))??;
    Ok(())
}

/// The defaults with `TCP_DEFER_ACCEPT`: every client here speaks first (an upgrade request or the
/// HTTP/2 preface), so a connection reaches `accept` with its first bytes.
fn tcp_params() -> TcpParams {
    TcpParams::default().set_tcp_defer_accept(Some(1))
}

fn static_dir() -> String {
    std::env::var("STATIC_DIR").unwrap_or_else(|_| "/data/static".into())
}

/// Echoes every frame that arrived with the last read, without awaiting.
///
/// Kept out of the async handler, so the per-frame values stay in registers instead of moving
/// through the handler's state machine. Buffered frames are never close or compressed frames and
/// this connection negotiates no compression, so `queue_frame` always queues them.
#[inline(never)]
fn drain<'i>(
    reader: &mut Reader<'i>,
    writer: &mut Writer<'i>,
    common: &mut Common<'i>,
    buffer: &mut VectorUsize<u8>,
) -> rimu_ws::Result<()> {
    while let Some(mut frame) =
        reader.read_buffered_frame(buffer, common, WebSocketPayloadOrigin::Adaptive)?
    {
        if !writer.queue_frame(common, &mut frame)? {
            return Err(rimu_ws::Error::UnexpectedBufferState);
        }
    }
    // Hand the echoes to the socket now; if it has no room they go out before `fill` waits.
    let _ = writer.try_flush(common)?;
    Ok(())
}

async fn ws(mut buffer: VectorUsize<u8>, mut ws: LocalWebSocket) -> rimu_ws::Result<()> {
    let (mut common, mut reader, mut writer) = ws.split_mut();
    let origin = WebSocketPayloadOrigin::Adaptive;
    loop {
        drain(&mut reader, &mut writer, &mut common, &mut buffer)?;
        // Data frames are parsed by `drain`; `fill` only waits for their bytes.
        match reader.fill(&mut common).await {
            Ok(Fill::Buffered) => continue,
            Ok(Fill::ReadFrame) => {}
            Ok(Fill::Closed) | Err(_) => return Ok(()),
        }
        let Ok(mut frame) = reader.read_frame(&mut buffer, &mut common, origin).await else {
            return Ok(());
        };
        match frame.op_code() {
            OpCode::Binary | OpCode::Text => {
                if writer
                    .write_frame_buffered(&mut common, &mut frame)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            OpCode::Close => return Ok(()),
            _ => {}
        }
    }
}

/// Adds `server: rimu-ws` to every response.
struct ServerHeader;

impl Middleware<ConnAux, rimu_ws::Error> for ServerHeader {
    type Aux = ();

    fn aux(&self) -> Self::Aux {}

    async fn req(
        &self,
        _: &mut ConnAux,
        _: &mut Self::Aux,
        _: &mut Request<MsgBufferString>,
    ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
        Ok(ControlFlow::Continue(()))
    }

    async fn res(
        &self,
        _: &mut ConnAux,
        _: &mut Self::Aux,
        res: Response<&mut MsgBufferString>,
    ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
        res
            .msg_data
            .headers
            .push_from_iter(Header::from_name_and_value(KnownHeaderName::Server.into(), ["rimu-ws"]))?;
        Ok(ControlFlow::Continue(()))
    }
}

#[derive(Clone, rimu_ws::Lease)]
struct ConnAux {
    dataset: Arc<VectorUsize<DatasetItem>>,
}

async fn endpoint_baseline2(state: State<'_, ConnAux>) -> rimu_ws::Result<VerbatimParams> {
    let mut sum: i64 = 0;
    for (_, value) in state.req.msg_data.uri.query_params() {
        sum = sum.wrapping_add(value.parse()?);
    }
    state.req.msg_data.clear();
    std::io::Write::write_fmt(&mut state.req.msg_data.body, format_args!("{sum}"))?;
    state.req.msg_data.headers.push_from_iter(Header::from_name_and_value(
        KnownHeaderName::ContentType.into(),
        ["text/plain"],
    ))?;
    Ok(VerbatimParams(StatusCode::Ok))
}

async fn endpoint_json(
    state: State<'_, ConnAux>,
    Path(count): Path<usize>,
) -> rimu_ws::Result<JsonReply> {
    let mut m: i64 = 1;
    for (key, value) in state.req.msg_data.uri.query_params() {
        if key == "m" {
            m = value.parse()?;
            break;
        }
    }
    let dataset = &state.data.dataset;
    state.req.msg_data.clear();
    write_json(&mut state.req.msg_data.body, dataset, count, m)?;
    Ok(JsonReply(StatusCode::Ok))
}

/// `{"items":[..],"count":n}` for the first `count` items, with `total = price * quantity * m`,
/// serialized on every request. The dataset's numbers are integers (HttpArena made them so to keep
/// float formatting out of the test) and are written as such.
fn write_json(
    buf: &mut VectorUsize<u8>,
    dataset: &[DatasetItem],
    count: usize,
    m: i64,
) -> rimu_ws::Result<()> {
    let clamped = count.min(dataset.len());
    let mut w = JsonWriter::new(buf);
    // Every item and tag is written with a trailing comma; `end_seq` turns the last one into the
    // closing bracket.
    w.raw(b"{\"items\":[")?;
    for el in dataset.iter().take(clamped) {
        w.raw(b"{\"id\":")?;
        w.i64(el.id)?;
        w.raw(b",\"name\":\"")?;
        w.str_contents(&el.name)?;
        w.raw(b"\",\"category\":\"")?;
        w.str_contents(&el.category)?;
        w.raw(b"\",\"price\":")?;
        w.i64(el.price)?;
        w.raw(b",\"quantity\":")?;
        w.i64(el.quantity)?;
        w.raw(b",\"active\":")?;
        w.bool(el.active)?;
        w.raw(b",\"tags\":[")?;
        for tag in el.tags.iter() {
            w.raw(b"\"")?;
            w.str_contents(tag)?;
            w.raw(b"\",")?;
        }
        w.end_seq(b']')?;
        w.raw(b",\"rating\":{\"score\":")?;
        w.i64(el.rating.score)?;
        w.raw(b",\"count\":")?;
        w.i64(el.rating.count)?;
        w.raw(b"},\"total\":")?;
        w.i64(el.price.wrapping_mul(el.quantity).wrapping_mul(m))?;
        w.raw(b"},")?;
    }
    w.end_seq(b']')?;
    w.raw(b",\"count\":")?;
    w.u64(u64::try_from(clamped).unwrap_or(u64::MAX))?;
    w.raw(b"}")
}

fn load_dataset() -> Arc<VectorUsize<DatasetItem>> {
    let path = std::env::var("DATASET_PATH").unwrap_or_else(|_| "/data/dataset.json".to_string());
    Arc::new(match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => VectorUsize::new(),
    })
}

#[derive(serde::Deserialize)]
struct DatasetItem {
    id: i64,
    name: String,
    category: String,
    price: i64,
    quantity: i64,
    active: bool,
    tags: ArrayVectorU8<String, 6>,
    rating: Rating,
}

#[derive(serde::Deserialize)]
struct Rating {
    score: i64,
    count: i64,
}
