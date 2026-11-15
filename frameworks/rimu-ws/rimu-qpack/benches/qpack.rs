//! Decode and encode of realistic header lists: the browser requests of the netbsd QIF (from the
//! qifs interop corpus), a load generator's request, and server response heads.
//!
//! `cargo bench --bench qpack`; pin it to one core, e.g. `taskset -c 6 cargo bench --bench qpack`.

use rimu_qpack::{
  DecodeOutcome, DecodedField, Decoder, DecoderConfig, Encoder, EncoderConfig, Error, Field,
  InsertPolicy, encode_static, encode_static_line,
};
use std::{hint::black_box, time::Instant};

type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

fn parse_qif(text: &[u8]) -> Vec<HeaderList> {
  let mut lists = Vec::new();
  let mut current = Vec::new();
  for line in text.split(|el| *el == b'\n') {
    if line.first() == Some(&b'#') {
      continue;
    }
    if line.is_empty() {
      if !current.is_empty() {
        lists.push(std::mem::take(&mut current));
      }
      continue;
    }
    let tab = line.iter().position(|el| *el == b'\t').unwrap();
    current.push((line[..tab].to_vec(), line[tab + 1..].to_vec()));
  }
  if !current.is_empty() {
    lists.push(current);
  }
  lists
}

fn fields(list: &HeaderList) -> Vec<Field<'_>> {
  list.iter().map(|(name, value)| Field::new(name, value)).collect()
}

/// Runs `op` (which does `per_op` operations) for about 300 ms per sample, 7 samples after a
/// warm-up; prints the median time per operation.
fn bench(name: &str, per_op: usize, bytes_per_op: usize, mut op: impl FnMut()) {
  let start = Instant::now();
  let mut calls = 0u64;
  while start.elapsed().as_millis() < 200 {
    op();
    calls += 1;
  }
  let per_sample = (calls * 3 / 2).max(1);
  let mut samples: Vec<f64> = (0..7)
    .map(|_| {
      let start = Instant::now();
      for _ in 0..per_sample {
        op();
      }
      start.elapsed().as_nanos() as f64 / (per_sample as f64 * per_op as f64)
    })
    .collect();
  samples.sort_by(f64::total_cmp);
  let median = samples[3];
  let mbps = bytes_per_op as f64 / per_op as f64 / median * 1e3;
  println!("{name:<58} {median:>9.1} ns/section {mbps:>8.0} MB/s of fields");
}

fn list_bytes(lists: &[HeaderList]) -> usize {
  lists.iter().flatten().map(|(name, value)| name.len() + value.len()).sum()
}

fn decode_all(decoder: &mut Decoder, sections: &[Vec<u8>], stream: &mut u64) {
  for section in sections {
    *stream += 4;
    let outcome = decoder
      .decode(*stream, section, |field: DecodedField<'_>| {
        black_box(field);
        Ok::<_, Error>(())
      })
      .unwrap();
    debug_assert!(matches!(outcome, DecodeOutcome::Done { .. }));
  }
  decoder.consume_decoder_stream(usize::MAX);
}

// A Section Acknowledgment of `stream`, as the peer's decoder sends it
fn section_ack(out: &mut Vec<u8>, stream: u64) {
  if stream < 127 {
    out.push(0x80 | stream as u8);
    return;
  }
  out.push(0xff);
  let mut rest = stream - 127;
  while rest >= 128 {
    out.push((rest & 0x7f) as u8 | 0x80);
    rest >>= 7;
  }
  out.push(rest as u8);
}

fn main() {
  let qif =
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/qifs/qifs/netbsd.qif")).unwrap();
  let requests = parse_qif(&qif);
  let request_bytes = list_bytes(&requests);
  let load: HeaderList = [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "localhost:8443"),
    (":path", "/baseline2?a=1&b=2"),
    ("user-agent", "h2load nghttp2/1.64.0"),
  ]
  .iter()
  .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
  .collect();
  let responses: Vec<HeaderList> = (0..4)
    .map(|idx| {
      let pairs: [(&str, String); 6] = [
        (":status", "200".into()),
        ("content-type", "text/html; charset=utf-8".into()),
        ("content-length", format!("{}", 1000 + idx * 37)),
        ("date", format!("Fri, 13 Nov 2026 14:4{idx}:00 GMT")),
        ("server", "rimu".into()),
        ("cache-control", "max-age=604800".into()),
      ];
      pairs.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    })
    .collect();
  println!(
    "{} netbsd requests ({} bytes of names and values per section on average)",
    requests.len(),
    request_bytes / requests.len()
  );

  // Sections of the netbsd requests in three encodings
  let mut raw_static = Vec::new();
  let mut huffman_static = Vec::new();
  let mut static_encoder = Encoder::new(EncoderConfig::static_only());
  for list in &requests {
    let mut section = Vec::new();
    encode_static(fields(list), &mut section);
    raw_static.push(section);
    let mut section = Vec::new();
    static_encoder.encode(0, fields(list), &mut section);
    huffman_static.push(section);
  }
  // Dynamic: the encoder of a connection after it saw every request twice, its table acknowledged
  let config = DecoderConfig {
    max_table_capacity: 4096,
    blocked_streams: 100,
    memo_sections: 0,
    ..DecoderConfig::default()
  };
  let memo_config = DecoderConfig { memo_sections: 32, ..config };
  let mut table_decoder = Decoder::new(config);
  let mut table_memo_decoder = Decoder::new(memo_config);
  let mut encoder = Encoder::new(EncoderConfig::default());
  encoder.set_peer_settings(table_decoder.settings()).unwrap();
  let mut dynamic = Vec::new();
  let mut stream = 0;
  let mut memo_stream = 1 << 40;
  let mut encoder_stream_bytes = 0;
  for round in 0..3 {
    for list in &requests {
      stream += 4;
      let mut section = Vec::new();
      encoder.encode(stream, fields(list), &mut section);
      let mut wire = Vec::new();
      encoder.drain_encoder_stream(&mut wire);
      encoder_stream_bytes += wire.len();
      table_decoder.feed_encoder_stream(&wire).unwrap();
      table_memo_decoder.feed_encoder_stream(&wire).unwrap();
      decode_all(&mut table_memo_decoder, std::slice::from_ref(&section), &mut memo_stream);
      let mut fields = rimu_qpack::FieldList::new();
      table_decoder.decode_into(stream, &section, &mut fields).unwrap();
      let mut back = Vec::new();
      table_decoder.drain_decoder_stream(&mut back);
      encoder.feed_decoder_stream(&back).unwrap();
      if round == 2 {
        dynamic.push(section);
      }
    }
  }
  let sizes = |sections: &[Vec<u8>]| sections.iter().map(Vec::len).sum::<usize>();
  println!(
    "section bytes for all {}: static raw {}, static Huffman {}, dynamic (third pass) {} (+ {} encoder-stream bytes over the three passes)",
    requests.len(),
    sizes(&raw_static),
    sizes(&huffman_static),
    sizes(&dynamic),
    encoder_stream_bytes,
  );
  println!();
  println!("decode");
  let mut plain = Decoder::new(config);
  let mut memo = Decoder::new(memo_config);
  let mut stream = 0u64;
  bench("netbsd requests, static raw, no memo", raw_static.len(), request_bytes, || {
    decode_all(&mut plain, &raw_static, &mut stream)
  });
  bench("netbsd requests, static Huffman, no memo", huffman_static.len(), request_bytes, || {
    decode_all(&mut plain, &huffman_static, &mut stream)
  });
  bench(
    "netbsd requests, static Huffman, memo (sections > 128 B)",
    huffman_static.len(),
    request_bytes,
    || decode_all(&mut memo, &huffman_static, &mut stream),
  );
  bench("netbsd requests, dynamic table, no memo", dynamic.len(), request_bytes, || {
    decode_all(&mut table_decoder, &dynamic, &mut stream)
  });
  bench("netbsd requests, dynamic table, memo", dynamic.len(), request_bytes, || {
    decode_all(&mut table_memo_decoder, &dynamic, &mut stream)
  });
  println!(
    "  memo replays: {} of {} sections",
    table_memo_decoder.stats().memo_hits,
    table_memo_decoder.stats().sections
  );
  let mut load_section = Vec::new();
  static_encoder.encode(0, fields(&load), &mut load_section);
  let load_bytes = list_bytes(std::slice::from_ref(&load));
  let load_sections = vec![load_section; 1];
  bench("load-generator request, static Huffman, no memo", 1, load_bytes, || {
    decode_all(&mut plain, &load_sections, &mut stream)
  });
  bench("load-generator request, static Huffman, memo", 1, load_bytes, || {
    decode_all(&mut memo, &load_sections, &mut stream)
  });

  println!();
  println!("encode");
  let mut out = Vec::with_capacity(4096);
  bench("netbsd requests, encode_static (raw literals)", requests.len(), request_bytes, || {
    for list in &requests {
      out.clear();
      encode_static(list.iter().map(|(n, v)| Field::new(n, v)), &mut out);
      black_box(&out);
    }
  });
  bench("netbsd requests, static-only Encoder (Huffman)", requests.len(), request_bytes, || {
    for list in &requests {
      out.clear();
      static_encoder.encode(0, list.iter().map(|(n, v)| Field::new(n, v)), &mut out);
      black_box(&out);
    }
  });
  let mut acks = Vec::new();
  let mut stream = 1_000_000u64;
  bench(
    "netbsd requests, dynamic Encoder (steady state, acked)",
    requests.len(),
    request_bytes,
    || {
      acks.clear();
      for list in &requests {
        stream += 4;
        out.clear();
        encoder.encode(stream, list.iter().map(|(n, v)| Field::new(n, v)), &mut out);
        black_box(&out);
        if out[0] != 0 {
          section_ack(&mut acks, stream);
        }
      }
      encoder.feed_decoder_stream(&acks).unwrap();
    },
  );
  let response_bytes = list_bytes(&responses);
  let mut huffman_encoder =
    Encoder::new(EncoderConfig { insert_policy: InsertPolicy::Never, ..EncoderConfig::default() });
  bench("response heads, static-only Encoder (Huffman)", responses.len(), response_bytes, || {
    for list in &responses {
      out.clear();
      huffman_encoder.encode(0, list.iter().map(|(n, v)| Field::new(n, v)), &mut out);
      black_box(&out);
    }
  });
  // Pre-encoded: the fixed lines once, then per response a copy and the changing lines
  let mut head = Vec::new();
  encode_static(
    [
      (":status", "200"),
      ("content-type", "text/html; charset=utf-8"),
      ("server", "rimu"),
      ("cache-control", "max-age=604800"),
    ],
    &mut head,
  );
  bench("response heads, pre-encoded head + 2 lines", responses.len(), response_bytes, || {
    for list in &responses {
      out.clear();
      out.extend_from_slice(&head);
      encode_static_line(b"content-length", &list[2].1, &mut out);
      encode_static_line(b"date", &list[3].1, &mut out);
      black_box(&out);
    }
  });
}
