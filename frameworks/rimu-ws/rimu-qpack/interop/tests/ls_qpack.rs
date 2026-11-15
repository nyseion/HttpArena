//! Cross-tests with ls-qpack (the C library, through the ls-qpack-rs bindings): its encoder's
//! output decodes with rimu-qpack's decoder, and rimu-qpack's encoder output decodes with its
//! decoder, over random header lists, table sizes, blocked-stream limits and delays of the encoder
//! stream that make sections block and unblock out of order.

use ls_qpack_rs::{
  StreamId,
  decoder::{Decoder as LsDecoder, DecoderOutput},
  encoder::Encoder as LsEncoder,
};
use rimu_qpack::{
  DecodeOutcome, Decoder, DecoderConfig, Encoder, EncoderConfig, Field, FieldList, InsertPolicy,
  Settings,
};
use std::collections::{BTreeMap, VecDeque};

type HeaderList = Vec<(String, String)>;

struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }

  fn below(&mut self, n: usize) -> usize {
    (self.next() % n as u64) as usize
  }
}

const VOCABULARY: [(&str, &str); 22] = [
  (":method", "GET"),
  (":method", "POST"),
  (":scheme", "https"),
  (":authority", "www.example.com"),
  (":authority", "cdn.example.net"),
  (":path", "/"),
  (":path", "/static/app.js"),
  (":status", "200"),
  (":status", "404"),
  ("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"),
  ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
  ("accept-encoding", "gzip, deflate, br"),
  ("accept-language", "en-US,en;q=0.5"),
  ("cache-control", "max-age=0"),
  ("content-type", "application/json; charset=utf-8"),
  ("cookie", "_ga=GA1.2.1234567890.1234567890; session=abcdef0123456789"),
  ("authorization", "Basic dXNlcjpwYXNz"),
  ("server", "nginx/1.25.3"),
  ("vary", "Accept-Encoding"),
  ("x-request-id", "0f8e7d6c5b4a"),
  ("etag", "\"33a64df551425fcc55e4d42a148795d9f25f89d4\""),
  ("x-empty", ""),
];

fn header_list(rng: &mut Rng) -> HeaderList {
  let count = 1 + rng.below(14);
  (0..count)
    .map(|_| match rng.below(8) {
      0 => (format!("x-gen-{}", rng.below(20)), format!("value-{}", rng.below(50))),
      1 => {
        let len = rng.below(200);
        let value: String = (0..len).map(|_| char::from(b' ' + (rng.next() % 95) as u8)).collect();
        ("x-random".into(), value)
      }
      _ => {
        let (name, value) = VOCABULARY[rng.below(VOCABULARY.len())];
        (name.into(), value.into())
      }
    })
    .collect()
}

fn fields(list: &HeaderList) -> Vec<Field<'_>> {
  list.iter().map(|(name, value)| Field::new(name.as_bytes(), value.as_bytes())).collect()
}

/// ls-qpack encodes, rimu-qpack decodes.
fn ls_to_rimu(
  seed: u64,
  capacity: u32,
  blocked: u16,
  memo: usize,
  max_delay: usize,
) -> (usize, usize) {
  let mut rng = Rng(seed);
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: capacity,
    blocked_streams: blocked,
    memo_sections: memo,
    ..DecoderConfig::default()
  });
  let mut encoder = LsEncoder::new();
  if capacity > 0 {
    let sdtc = encoder.configure(capacity, capacity, blocked.into()).unwrap();
    decoder.feed_encoder_stream(sdtc.data()).unwrap();
  }
  // Encoder-stream chunks in flight, sections not decoded yet
  let mut in_flight: VecDeque<Vec<u8>> = VecDeque::new();
  let mut pending: BTreeMap<u64, (Vec<u8>, HeaderList)> = BTreeMap::new();
  let mut decoded = FieldList::new();
  let (mut sections, mut blocked_count) = (0, 0);
  let mut check = |decoder: &mut Decoder, stream: u64, section: &[u8], list: &HeaderList| -> bool {
    match decoder.decode_into(stream, section, &mut decoded).unwrap() {
      DecodeOutcome::Done { .. } => {
        let got: HeaderList = decoded
          .iter()
          .map(|el| {
            (
              String::from_utf8(el.name.to_vec()).unwrap(),
              String::from_utf8(el.value.to_vec()).unwrap(),
            )
          })
          .collect();
        assert_eq!(&got, list, "stream {stream}");
        true
      }
      DecodeOutcome::Blocked { .. } => false,
    }
  };
  for idx in 0..1500u64 {
    let stream = idx * 4;
    let list = header_list(&mut rng);
    let (section, encoder_stream) = encoder
      .encode_all(StreamId::new(stream), list.iter().map(|(n, v)| (n.as_str(), v.as_str())))
      .unwrap()
      .take();
    in_flight.push_back(encoder_stream.into_vec());
    // The encoder stream arrives a random number of sections late
    while in_flight.len() > rng.below(max_delay + 1) {
      decoder.feed_encoder_stream(&in_flight.pop_front().unwrap()).unwrap();
      let ready: Vec<u64> = decoder.take_unblocked().collect();
      for ready in ready {
        let (section, list) = pending.remove(&ready).unwrap();
        assert!(check(&mut decoder, ready, &section, &list));
        sections += 1;
      }
    }
    if check(&mut decoder, stream, &section, &list) {
      sections += 1;
    } else {
      blocked_count += 1;
      pending.insert(stream, (section.into_vec(), list));
    }
    let mut back = Vec::new();
    decoder.drain_decoder_stream(&mut back);
    encoder.feed(&back).unwrap();
  }
  for chunk in in_flight {
    decoder.feed_encoder_stream(&chunk).unwrap();
  }
  let ready: Vec<u64> = decoder.take_unblocked().collect();
  for ready in ready {
    let (section, list) = pending.remove(&ready).unwrap();
    assert!(check(&mut decoder, ready, &section, &list));
    sections += 1;
  }
  assert!(pending.is_empty());
  (sections, blocked_count)
}

/// rimu-qpack encodes, ls-qpack decodes.
fn rimu_to_ls(
  seed: u64,
  capacity: u32,
  blocked: u16,
  config: EncoderConfig,
  max_delay: usize,
) -> (usize, usize) {
  let mut rng = Rng(seed);
  let mut decoder = LsDecoder::new(capacity, blocked.into());
  let mut encoder = Encoder::new(config);
  encoder
    .set_peer_settings(Settings {
      max_table_capacity: capacity.into(),
      blocked_streams: blocked.into(),
    })
    .unwrap();
  let mut in_flight: VecDeque<Vec<u8>> = VecDeque::new();
  let mut pending: BTreeMap<u64, HeaderList> = BTreeMap::new();
  let (mut sections, mut blocked_count) = (0, 0);
  let done =
    |encoder: &mut Encoder, stream: u64, output: DecoderOutput, list: &HeaderList| -> bool {
      match output {
        DecoderOutput::Done(buffers) => {
          let got: HeaderList = buffers
            .headers()
            .iter()
            .map(|el| (el.name().to_owned(), el.value().to_owned()))
            .collect();
          assert_eq!(&got, list, "stream {stream}");
          encoder.feed_decoder_stream(buffers.stream()).unwrap();
          true
        }
        DecoderOutput::BlockedStream => false,
      }
    };
  let mut first = Vec::new();
  encoder.drain_encoder_stream(&mut first);
  if !first.is_empty() {
    decoder.feed(&first).unwrap();
  }
  for idx in 0..1500u64 {
    let stream = idx * 4;
    let list = header_list(&mut rng);
    let mut section = Vec::new();
    encoder.encode(stream, fields(&list), &mut section);
    let mut encoder_stream = Vec::new();
    encoder.drain_encoder_stream(&mut encoder_stream);
    in_flight.push_back(encoder_stream);
    while in_flight.len() > rng.below(max_delay + 1) {
      let chunk = in_flight.pop_front().unwrap();
      if !chunk.is_empty() {
        decoder.feed(&chunk).unwrap();
      }
      let streams: Vec<u64> = pending.keys().copied().collect();
      for ready in streams {
        if let Some(output) = decoder.unblocked(StreamId::new(ready)) {
          let list = pending[&ready].clone();
          if done(&mut encoder, ready, output.unwrap(), &list) {
            pending.remove(&ready);
            sections += 1;
          }
        }
      }
    }
    let output = decoder.decode(StreamId::new(stream), &section).unwrap();
    if done(&mut encoder, stream, output, &list) {
      sections += 1;
    } else {
      blocked_count += 1;
      pending.insert(stream, list);
    }
    assert!(encoder.blocking_streams() <= usize::from(blocked));
    assert!(encoder.table_size() <= encoder.table_capacity());
  }
  for chunk in in_flight {
    if !chunk.is_empty() {
      decoder.feed(&chunk).unwrap();
    }
  }
  let streams: Vec<u64> = pending.keys().copied().collect();
  for ready in streams {
    let list = pending.remove(&ready).unwrap();
    let output = decoder.unblocked(StreamId::new(ready)).unwrap().unwrap();
    assert!(done(&mut encoder, ready, output, &list));
    sections += 1;
  }
  assert_eq!(encoder.unacknowledged_sections(), 0);
  let stats = encoder.stats();
  // The bindings never send Insert Count Increments: an entry is acknowledged only by the Section
  // Acknowledgment of a section that referenced it, which needs a blocking reference first
  if capacity > 0
    && config.insert_policy != InsertPolicy::Never
    && blocked > 0
    && config.allow_blocking
  {
    assert!(stats.dynamic_sections > 500 && stats.inserts > 20, "{stats:?}");
  } else if capacity == 0 || config.insert_policy == InsertPolicy::Never {
    assert_eq!(stats.inserts, 0);
  }
  eprintln!("  capacity {capacity}, blocked {blocked}: {stats:?}");
  (sections, blocked_count)
}

#[test]
fn ls_qpack_encoder_to_rimu_decoder() {
  let mut total = (0, 0);
  for (seed, capacity, blocked, memo, delay) in [
    (1, 0, 0, 0, 0),
    (2, 220, 0, 0, 0),
    (3, 220, 16, 8, 3),
    (4, 4096, 100, 8, 5),
    (5, 4096, 100, 0, 20),
    (6, 4096, 0, 8, 0),
    (7, 1024, 4, 8, 8),
    (8, 65536, 100, 8, 10),
  ] {
    let (sections, blocked_count) = ls_to_rimu(seed, capacity, blocked, memo, delay);
    assert_eq!(sections, 1500);
    total.0 += sections;
    total.1 += blocked_count;
  }
  eprintln!("ls-qpack -> rimu-qpack: {} sections, {} blocked first", total.0, total.1);
  assert!(total.1 > 100, "the delays made sections block");
}

#[test]
fn rimu_encoder_to_ls_qpack_decoder() {
  let mut total = (0, 0);
  let base = EncoderConfig::default();
  let configs = [
    (11, 0, 0, base, 0),
    (12, 220, 0, base, 0),
    (13, 220, 16, EncoderConfig { insert_policy: InsertPolicy::Always, ..base }, 3),
    (14, 4096, 100, base, 5),
    (
      15,
      4096,
      100,
      EncoderConfig { insert_policy: InsertPolicy::Always, huffman: false, ..base },
      20,
    ),
    (16, 4096, 0, EncoderConfig { insert_policy: InsertPolicy::Always, ..base }, 2),
    (17, 4096, 100, EncoderConfig { allow_blocking: false, ..base }, 4),
    (
      18,
      1024,
      4,
      EncoderConfig { insert_policy: InsertPolicy::Always, index_sensitive_names: true, ..base },
      8,
    ),
    (19, 4096, 100, EncoderConfig::static_only(), 0),
  ];
  for (seed, capacity, blocked, config, delay) in configs {
    let (sections, blocked_count) = rimu_to_ls(seed, capacity, blocked, config, delay);
    assert_eq!(sections, 1500);
    total.0 += sections;
    total.1 += blocked_count;
  }
  eprintln!("rimu-qpack -> ls-qpack: {} sections, {} blocked first", total.0, total.1);
  assert!(total.1 > 100, "the delays made sections block");
}
