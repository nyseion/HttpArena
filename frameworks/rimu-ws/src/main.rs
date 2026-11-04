use rimu_ws::{
    collections::VectorUsize,
    executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
    http::WebSocketServerFramework,
    net::TcpParams,
    rng::{ChaCha20, CryptoSeedableRng},
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

fn main() -> rimu_ws::Result<()> {
    let nodelay = std::env::var("RIMU_NODELAY")
        .map(|v| v != "0")
        .unwrap_or(true);
    WebSocketServerFramework::new(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        TlsConfig::plaintext(),
    )?
    .set_tcp_params(TcpParams::default().set_tcp_nodelay(nodelay))
    .set_local_runtime_cb(|| {
        // Accept into direct descriptors, so closes are queued instead of making a syscall, and
        // busy-poll 20 us before sleeping. Each reactor shares its core with an SMT sibling, so a
        // long spin slows the busy thread beside it: on a 12-core Ryzen 100 us cost 3% on
        // echo-ws-limited where 20 us tied no spin, and on a 16-core EPYC 20 us gained 1-2% there
        // (it saves the sleep between reconnects). Neither spin moved the other profiles. `0`
        // turns either off.
        let spin_us = std::env::var("RIMU_SPIN_US")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let direct = std::env::var("RIMU_DIRECT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16384);
        // `RIMU_RINGS=sq,cq` overrides the ring sizes (smaller rings lock less memory).
        let ring = std::env::var("RIMU_RINGS")
            .ok()
            .and_then(|v| {
                let (sq, cq) = v.split_once(',')?;
                Some((sq.parse().ok()?, cq.parse().ok()?))
            })
            .unwrap_or((4096, 16384));
        let params = UringParams::new()
            .set_direct_files(direct)
            .set_peer_addrs(false)
            .set_ring_entries(ring.0, ring.1)
            .set_spin(std::time::Duration::from_micros(spin_us));
        UringRuntime::with_params(params)
    })
    .run_in_threads("0.0.0.0:8080", (("/ws", ws),))
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
