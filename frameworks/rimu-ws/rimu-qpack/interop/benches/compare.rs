//! rimu-qpack against ls-qpack (through the ls-qpack-rs bindings) on the netbsd browser requests
//! of the qifs corpus: decode of the same section bytes, encode of the same header lists, and the
//! bytes that each encoder writes. The ls-qpack numbers include the bindings: a boxed copy of each
//! header in and out, and a hash map of streams.
//!
//! `taskset -c 6 cargo bench -p rimu-qpack-interop --bench compare`

use ls_qpack_rs::{
  StreamId,
  decoder::{Decoder as LsDecoder, DecoderOutput},
  encoder::Encoder as LsEncoder,
};
use rimu_qpack::{
  DecodedField, Decoder, DecoderConfig, Encoder, EncoderConfig, Error, Field, InsertPolicy,
  Settings,
};
use std::{hint::black_box, time::Instant};

type HeaderList = Vec<(String, String)>;

fn parse_qif(text: &str) -> Vec<HeaderList> {
  let mut lists = Vec::new();
  let mut current = Vec::new();
  for line in text.lines() {
    if line.starts_with('#') {
      continue;
    }
    if line.is_empty() {
      if !current.is_empty() {
        lists.push(std::mem::take(&mut current));
      }
      continue;
    }
    let (name, value) = line.split_once('\t').unwrap();
    current.push((name.to_owned(), value.to_owned()));
  }
  if !current.is_empty() {
    lists.push(current);
  }
  lists
}

fn as_fields(list: &HeaderList) -> Vec<Field<'_>> {
  list.iter().map(|(n, v)| Field::new(n.as_bytes(), v.as_bytes())).collect()
}

fn bench(name: &str, per_op: usize, mut op: impl FnMut()) -> f64 {
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
  println!("  {name:<44} {:>9.1} ns/section", samples[3]);
  samples[3]
}

fn rimu_decode(decoder: &mut Decoder, sections: &[Vec<u8>], stream: &mut u64) {
  for section in sections {
    *stream += 4;
    decoder
      .decode(*stream, section, |field: DecodedField<'_>| {
        black_box(field);
        Ok::<_, Error>(())
      })
      .unwrap();
  }
  decoder.consume_decoder_stream(usize::MAX);
}

fn ls_decode(decoder: &mut LsDecoder, sections: &[Vec<u8>], stream: &mut u64) {
  for section in sections {
    *stream += 4;
    match decoder.decode(StreamId::new(*stream), section).unwrap() {
      DecoderOutput::Done(buffers) => {
        black_box(buffers);
      }
      DecoderOutput::BlockedStream => panic!("blocked"),
    }
  }
}

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
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/qifs/qifs/netbsd.qif"))
      .unwrap();
  let requests = parse_qif(&qif);

  let as_pairs = |list: &HeaderList| -> Vec<(String, String)> { list.clone() };
  println!("{} netbsd requests, table 4096, 100 blocked streams", requests.len());

  // Sections written by ls-qpack's encoder after it saw every request twice, decodable by both
  // decoders, whose tables got the same encoder stream
  let mut ls_encoder = LsEncoder::new();
  let sdtc = ls_encoder.configure(4096, 4096, 100).unwrap();
  let config = DecoderConfig {
    max_table_capacity: 4096,
    blocked_streams: 100,
    memo_sections: 0,
    ..DecoderConfig::default()
  };
  let mut rimu_decoder = Decoder::new(config);
  let mut rimu_memo = Decoder::new(DecoderConfig { memo_sections: 32, ..config });
  let mut ls_decoder = LsDecoder::new(4096, 100);
  for decoder in [&mut rimu_decoder, &mut rimu_memo] {
    decoder.feed_encoder_stream(sdtc.data()).unwrap();
  }
  ls_decoder.feed(sdtc.data()).unwrap();
  let mut ls_sections = Vec::new();
  let (mut ls_section_bytes, mut ls_stream_bytes) = (0, 0);
  let mut stream = 0u64;
  for round in 0..3 {
    for list in &requests {
      stream += 4;
      let (section, encoder_stream) =
        ls_encoder.encode_all(StreamId::new(stream), as_pairs(list)).unwrap().take();
      ls_section_bytes += section.len();
      ls_stream_bytes += encoder_stream.len();
      rimu_decoder.feed_encoder_stream(&encoder_stream).unwrap();
      rimu_memo.feed_encoder_stream(&encoder_stream).unwrap();
      if !encoder_stream.is_empty() {
        ls_decoder.feed(&encoder_stream).unwrap();
      }
      match ls_decoder.decode(StreamId::new(stream), &section) {
        Ok(DecoderOutput::Done(_)) => {}
        other => panic!("setup round {round} stream {stream}: {other:?}"),
      }
      let mut fields = rimu_qpack::FieldList::new();
      rimu_decoder.decode_into(stream, &section, &mut fields).unwrap();
      let mut back = Vec::new();
      rimu_decoder.drain_decoder_stream(&mut back);
      ls_encoder.feed(&back).unwrap();
      if round == 2 {
        ls_sections.push(section.into_vec());
      }
    }
  }
  // The same for rimu-qpack's encoder
  let mut rimu_bytes = Vec::new();
  for policy in [InsertPolicy::Repeated, InsertPolicy::Always] {
    let mut encoder =
      Encoder::new(EncoderConfig { insert_policy: policy, ..EncoderConfig::default() });
    let mut decoder = Decoder::new(config);
    encoder.set_peer_settings(decoder.settings()).unwrap();
    let (mut section_bytes, mut stream_bytes) = (0, 0);
    for _ in 0..3 {
      for list in &requests {
        stream += 4;
        let mut section = Vec::new();
        encoder.encode(stream, as_fields(list), &mut section);
        let mut wire = Vec::new();
        encoder.drain_encoder_stream(&mut wire);
        section_bytes += section.len();
        stream_bytes += wire.len();
        decoder.feed_encoder_stream(&wire).unwrap();
        let mut fields = rimu_qpack::FieldList::new();
        decoder.decode_into(stream, &section, &mut fields).unwrap();
        let mut back = Vec::new();
        decoder.drain_decoder_stream(&mut back);
        encoder.feed_decoder_stream(&back).unwrap();
      }
    }
    rimu_bytes.push((policy, section_bytes, stream_bytes));
  }
  let input: usize = requests.iter().flatten().map(|(n, v)| n.len() + v.len()).sum::<usize>() * 3;
  println!("bytes written for the requests three times over ({input} bytes of names and values):");
  println!(
    "  ls-qpack                    sections {ls_section_bytes:>6}, encoder stream {ls_stream_bytes:>6}"
  );
  for (policy, sections, stream) in &rimu_bytes {
    println!(
      "  rimu-qpack {:<16} sections {sections:>6}, encoder stream {stream:>6}",
      format!("{policy:?}")
    );
  }

  println!("decode, sections written by ls-qpack (dynamic table)");
  let mut stream = 100_000;
  bench("ls-qpack", ls_sections.len(), || ls_decode(&mut ls_decoder, &ls_sections, &mut stream));
  bench("rimu-qpack", ls_sections.len(), || {
    rimu_decode(&mut rimu_decoder, &ls_sections, &mut stream)
  });
  bench("rimu-qpack with memo", ls_sections.len(), || {
    rimu_decode(&mut rimu_memo, &ls_sections, &mut stream)
  });

  println!("decode, sections written by ls-qpack without a dynamic table");
  let mut ls_static_encoder = LsEncoder::new();
  let static_sections: Vec<Vec<u8>> = requests
    .iter()
    .enumerate()
    .map(|(idx, list)| {
      ls_static_encoder
        .encode_all(StreamId::new(idx as u64), as_pairs(list))
        .unwrap()
        .take()
        .0
        .into_vec()
    })
    .collect();
  let mut ls_static_decoder = LsDecoder::new(0, 0);
  let mut rimu_static = Decoder::new(DecoderConfig {
    max_table_capacity: 0,
    memo_sections: 0,
    ..DecoderConfig::default()
  });
  bench("ls-qpack", static_sections.len(), || {
    ls_decode(&mut ls_static_decoder, &static_sections, &mut stream)
  });
  bench("rimu-qpack", static_sections.len(), || {
    rimu_decode(&mut rimu_static, &static_sections, &mut stream)
  });

  println!("encode, steady state (every request seen before, acknowledged)");
  let mut acks = Vec::new();
  let mut out = Vec::with_capacity(4096);
  bench("ls-qpack", requests.len(), || {
    acks.clear();
    for list in &requests {
      stream += 4;
      let (section, encoder_stream) = ls_encoder
        .encode_all(StreamId::new(stream), list.iter().map(|(n, v)| (n.as_str(), v.as_str())))
        .unwrap()
        .take();
      if section[0] != 0 {
        section_ack(&mut acks, stream);
      }
      black_box((section, encoder_stream));
    }
    ls_encoder.feed(&acks).unwrap();
  });
  let mut encoder = Encoder::new(EncoderConfig::default());
  encoder.set_peer_settings(Settings { max_table_capacity: 4096, blocked_streams: 100 }).unwrap();
  let mut decoder = Decoder::new(config);
  for _ in 0..3 {
    for list in &requests {
      stream += 4;
      out.clear();
      encoder.encode(stream, as_fields(list), &mut out);
      let mut wire = Vec::new();
      encoder.drain_encoder_stream(&mut wire);
      decoder.feed_encoder_stream(&wire).unwrap();
      let mut fields = rimu_qpack::FieldList::new();
      decoder.decode_into(stream, &out, &mut fields).unwrap();
      let mut back = Vec::new();
      decoder.drain_decoder_stream(&mut back);
      encoder.feed_decoder_stream(&back).unwrap();
    }
  }
  bench("rimu-qpack", requests.len(), || {
    acks.clear();
    for list in &requests {
      stream += 4;
      out.clear();
      encoder.encode(
        stream,
        list.iter().map(|(n, v)| Field::new(n.as_bytes(), v.as_bytes())),
        &mut out,
      );
      if out[0] != 0 {
        section_ack(&mut acks, stream);
      }
      black_box(&out);
    }
    encoder.feed_decoder_stream(&acks).unwrap();
  });

  println!("encode, static table only");
  bench("ls-qpack", requests.len(), || {
    for (idx, list) in requests.iter().enumerate() {
      let buffers = ls_static_encoder
        .encode_all(StreamId::new(idx as u64), list.iter().map(|(n, v)| (n.as_str(), v.as_str())))
        .unwrap();
      black_box(buffers);
    }
  });
  let mut static_encoder = Encoder::new(EncoderConfig::static_only());
  bench("rimu-qpack", requests.len(), || {
    for list in &requests {
      out.clear();
      static_encoder.encode(
        0,
        list.iter().map(|(n, v)| Field::new(n.as_bytes(), v.as_bytes())),
        &mut out,
      );
      black_box(&out);
    }
  });
}
