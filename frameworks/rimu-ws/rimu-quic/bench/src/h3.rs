//! rimu-h3 micro-benchmarks: the HTTP/3 work of a request without the transport, ns per request:
//! the decode of its head (QPACK, the checks of RFC 9114, the head buffer), with and without
//! rimu-qpack's decode memo, and the encode of the head of its response with the HEADERS and DATA
//! frames that carry it, lean (`:status`, `content-type`, kept encoded), with RFC 9110's `date` and
//! `content-length`, or by a dynamic table.
//!
//! `cargo run --release -p rimu-quic-bench --bin rimu-h3-bench [-- ROUNDS]`; pin to a core
//! (`taskset -c N`) for steadier numbers. Cells are median / min over the rounds, interleaved.

use rimu_h3::bench_support::{self as b, Head};

const ITERATIONS: u64 = 200_000;

fn stats(mut values: Vec<f64>) -> String {
  values.sort_by(f64::total_cmp);
  format!("{:.0} / {:.0}", values[values.len() / 2], values[0])
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
  println!("rimu-h3 micro-benchmarks, {rounds} rounds of {ITERATIONS} (median / min, ns)\n");
  // h2load's request, and a browser's
  let small = b::request_section(b"/", &[(b"user-agent", b"h2load nghttp2/1.66.0")]);
  let browser = b::request_section(
    b"/index.html?query=1",
    &[
      (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"),
      (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
      (b"accept-language", b"en-US,en;q=0.5"),
      (b"accept-encoding", b"gzip, deflate, br, zstd"),
      (b"sec-fetch-dest", b"document"),
      (b"sec-fetch-mode", b"navigate"),
      (b"priority", b"u=0, i"),
    ],
  );
  println!("Request head decode, ns per request\n");
  println!("| request | section bytes | no memo | memo |");
  println!("|---|---|---|---|");
  for (name, section) in [("h2load GET", &small), ("browser GET", &browser)] {
    let cells = interleave(
      rounds,
      &[&|| b::decode_request(section, false, ITERATIONS), &|| {
        b::decode_request(section, true, ITERATIONS)
      }],
    );
    println!("| {name} | {} | {} | {} |", section.len(), cells[0], cells[1]);
  }
  println!("\nResponse head and frames encode, ns per response (5-byte body)\n");
  println!("| lean | RFC 9110 | dynamic table |");
  println!("|---|---|---|");
  let cells = interleave(
    rounds,
    &[
      &|| b::encode_response(Head::Lean, b"hello", ITERATIONS),
      &|| b::encode_response(Head::Rfc9110, b"hello", ITERATIONS),
      &|| b::encode_response(Head::Dynamic, b"hello", ITERATIONS),
    ],
  );
  println!("| {} | {} | {} |", cells[0], cells[1], cells[2]);
  println!("\nPer request, decode + encode (lean head), ns\n");
  println!("| request | no memo | memo |");
  println!("|---|---|---|");
  for (name, section) in [("h2load GET", &small), ("browser GET", &browser)] {
    let cells = interleave(
      rounds,
      &[&|| b::request_response(section, false, Head::Lean, ITERATIONS), &|| {
        b::request_response(section, true, Head::Lean, ITERATIONS)
      }],
    );
    println!("| {name} | {} | {} |", cells[0], cells[1]);
  }
}
