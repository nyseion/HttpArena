//! A sans-I/O QUIC version 1 server transport (RFC 9000, 9001, 9002): the wire codecs, packet
//! protection, the connection core and its streams, flow control, loss recovery and congestion
//! control, and the multi-worker endpoint, with TLS 1.3 through rustls.
//!
//! Everything here is sans-I/O: decoders return slices of their input, encoders write into
//! buffers of the caller, and endpoints are fed datagrams and drained into a [`TxArena`]. Any UDP
//! socket drives it; see the README for an example.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// The test harnesses run both sides of the handshake on rustls
#[cfg(all(test, not(feature = "rustls")))]
compile_error!("the tests of rimu-quic need the `rustls` feature");

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod hex;

mod app;
#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench_support;
mod bytes;
mod cc;
mod cid;
mod cid_table;
#[cfg(any(test, feature = "client"))]
pub mod client;
mod conn;
mod conn_tls;
#[allow(unsafe_code, reason = "wiping key material and the AES-NI intrinsics")]
pub mod crypto;
pub mod diag;
mod endpoint;
mod error;
mod flow;
mod frame;
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub mod frame_check;
mod key_phase;
mod limits;
mod packet;
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub mod packet_check;
mod pmtud;
mod pools;
#[allow(unsafe_code, reason = "wiping key material")]
mod protection;
mod quic_error;
mod recovery;
mod recv_tracker;
pub mod rng;
#[cfg(feature = "rustls")]
pub mod rustls;
mod sent;
mod shared_bytes;
#[cfg(target_os = "linux")]
mod steer;
mod stream;
mod suite;
mod sync;
#[allow(unsafe_code, reason = "the counting global allocator")]
#[cfg(test)]
pub(crate) mod testing;
mod timer_wheel;
pub mod tls;
mod token;
mod transport_params;
mod tx_arena;
#[cfg(all(feature = "uring", target_os = "linux"))]
pub mod uring;
pub mod varint;
mod writer;

pub use app::{BodyRef, ConnCtx, ConnHandle, QuicApp};
pub(crate) use bytes::ArrayBytes;
pub use cid::{Cid, MAX_CID_LEN};
pub use conn::FlushOutcome;
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub use conn::check as conn_check;
pub(crate) use conn::{ConnParams, ConnState, QuicConn};
use core::net::{IpAddr, SocketAddr};
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub use endpoint::check as endpoint_check;
pub use endpoint::{Endpoint, EndpointStats, RecvOutcome, WorkerLoads};
pub use error::{Error, Result};
pub(crate) use frame::{AckFrame, Frame, FrameReader, FrameWriter, Space};
pub use limits::{QuicLimits, QuicParams};
pub(crate) use packet::{
  PacketTy, QUIC_V1, decode_pn, parse_header, pn_len_for, write_retry, write_version_negotiation,
};
pub(crate) use protection::{
  DirectionalKeys, HpBatch, PacketKeys, initial_keys, open_payload, protect, protect_deferred,
  remove_header_protection, wipe,
};
pub use quic_error::{QuicError, TransportErrorCode};
pub use shared_bytes::SharedBytes;
#[cfg(target_os = "linux")]
pub use steer::{STEERING_PROGRAM_LEN, SteeringProgram, steering_cbpf};
pub use stream::StreamId;
pub use suite::CipherSuite;
pub use token::EndpointKeys;
pub use transport_params::TransportParams;
pub use tx_arena::{TrainId, TxArena, TxTrain};
#[allow(unused_imports, reason = "for tests")]
pub(crate) use varint::{VARINT_MAX, decode_varint, encode_varint, varint_len};

/// Where a datagram came from and went to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramMeta {
  /// The address of the peer.
  pub peer: SocketAddr,
  /// The local address that the peer sent the datagram to, if the socket reports it: replies
  /// leave from it.
  pub local: Option<IpAddr>,
  /// The size of the datagrams that the kernel coalesced into this one (generic receive
  /// offload), if it did.
  pub segment_size: Option<u16>,
}
