//! rimu-quic micro-benchmarks: packet seal/open with header protection, batched header
//! protection, frame decoding and the server's handshake cost, comparable with the tables of
//! `docs/spike-tls.md` (same packet shapes: 8-byte DCID, 2-byte packet number).
//!
//! `cargo run --release -p rimu-quic-bench [-- ROUNDS]`; pin to a core (`taskset -c N`) for steadier
//! numbers. Each table interleaves its variants round by round; cells are median / min over the
//! rounds.

use rimu_quic::{CipherSuite, bench_support as b};

const SUITES: [(CipherSuite, &str); 3] = [
  (CipherSuite::Aes128GcmSha256, "AES-128-GCM"),
  (CipherSuite::Aes256GcmSha384, "AES-256-GCM"),
  (CipherSuite::Chacha20Poly1305Sha256, "ChaCha20-Poly1305"),
];
const PACKETS: u64 = 20_000;

static ECDSA_CERT: &[u8] = include_bytes!("../../rimu-quic/tests/certs/ecdsa-cert.pem");
static ECDSA_KEY: &[u8] = include_bytes!("../../rimu-quic/tests/certs/ecdsa-key.pem");
static RSA_CERT: &[u8] = include_bytes!("../../rimu-quic/tests/certs/rsa-cert.pem");
static RSA_KEY: &[u8] = include_bytes!("../../rimu-quic/tests/certs/rsa-key.pem");

fn stats(mut values: Vec<f64>) -> String {
  values.sort_by(f64::total_cmp);
  let median = values[values.len() / 2];
  let min = values[0];
  if median >= 100.0 {
    format!("{median:.0} / {min:.0}")
  } else {
    format!("{median:.1} / {min:.1}")
  }
}

// Runs every variant `rounds` times, interleaved, rotating the order each round.
fn interleave(rounds: usize, variants: &[&dyn Fn() -> f64]) -> Vec<String> {
  let mut samples = vec![Vec::new(); variants.len()];
  for round in 0..rounds {
    for offset in 0..variants.len() {
      let idx = (round + offset) % variants.len();
      samples[idx].push(variants[idx]());
    }
  }
  samples.into_iter().map(stats).collect()
}

fn main() {
  let rounds: usize = std::env::args().nth(1).and_then(|el| el.parse().ok()).unwrap_or(21);
  println!("rimu-quic micro-benchmarks, {rounds} rounds (median / min)\n");

  println!("Seal + header protection, ns per 1-RTT packet\n");
  println!("| suite | packet | `protect` | HP deferred ×8 (flush path) |");
  println!("|---|---|---|---|");
  for (suite, name) in SUITES {
    for (len, label) in
      [(1200 - 11 - 16, "1,200 B"), (1350 - 11 - 16, "1,350 B"), (64 - 11 - 16, "64 B ACK")]
    {
      let cells = interleave(
        rounds,
        &[&|| b::seal(suite, len, PACKETS), &|| b::seal_deferred(suite, len, PACKETS)],
      );
      println!("| {name} | {label} | {} | {} |", cells[0], cells[1]);
    }
  }

  println!("\nRemove header protection + open, ns per 1-RTT packet (incl. a copy)\n");
  println!("| suite | packet | open |");
  println!("|---|---|---|");
  for (suite, name) in SUITES {
    for (len, label) in
      [(1200 - 11 - 16, "1,200 B"), (1350 - 11 - 16, "1,350 B"), (64 - 11 - 16, "64 B ACK")]
    {
      let cells = interleave(rounds, &[&|| b::open(suite, len, PACKETS)]);
      println!("| {name} | {label} | {} |", cells[0]);
    }
  }

  println!("\nHeader protection of a batch, ns per packet\n");
  println!("| suite | packets | batched (AES-NI, 8 lanes) | one at a time, backend key |");
  println!("|---|---|---|---|");
  for (suite, name) in SUITES {
    for packets in [8, 16, 32, 64] {
      let cells = interleave(
        rounds,
        &[&|| b::hp_masks(suite, packets, true, PACKETS), &|| {
          b::hp_masks(suite, packets, false, PACKETS)
        }],
      );
      println!("| {name} | {packets} | {} | {} |", cells[0], cells[1]);
    }
  }

  println!("\nFrame decoding, ns per 1-RTT payload\n");
  println!("| payload | bytes | decode |");
  println!("|---|---|---|");
  for (stream, small, label) in [
    (1100, 0, "ACK + MAX_STREAM_DATA + STREAM 1,100 B"),
    (0, 40, "ACK + 40 × (PING, MAX_DATA, RESET_STREAM)"),
  ] {
    let payload = b::frame_payload(stream, small);
    let cells = interleave(rounds, &[&|| b::frame_decode(&payload, PACKETS)]);
    println!("| {label} | {} | {} |", payload.len(), cells[0]);
  }

  println!("\nServer handshake cost, µs per handshake (rustls client, not timed)\n");
  println!("| certificate | µs per handshake |");
  println!("|---|---|");
  for (cert, key, label) in
    [(ECDSA_CERT, ECDSA_KEY, "ECDSA P-256"), (RSA_CERT, RSA_KEY, "RSA-2048")]
  {
    let (server, client) = b::handshake_configs(cert, key);
    let _warm = b::handshake(&server, &client, 20);
    let cells = interleave(rounds.min(11), &[&|| b::handshake(&server, &client, 100)]);
    println!("| {label} | {} |", cells[0]);
  }
}
