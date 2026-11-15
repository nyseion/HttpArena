//! The QPACK offline interop vectors of github.com/qpackers/qifs: field sections and encoder
//! streams written by other implementations (ls-qpack, nghttp3, quinn, proxygen, f5, qthingey)
//! decode to the header lists of the QIF files.
//!
//! A subset (the netbsd QIFs, every encoding of them, and the draft examples) is in
//! `tests/qifs/`; set `QIFS_DIR` to a checkout of the repository to run the whole corpus.
//!
//! The encodings predate RFC 9204 in one respect: their encoders assumed that the dynamic table
//! starts at its maximum capacity, so most encoder streams have no Set Dynamic Table Capacity. One
//! is fed first when the stream does not start with one.

use rimu_qpack::{DecodeOutcome, Decoder, DecoderConfig, FieldList};
use std::{
  collections::BTreeMap,
  fs,
  path::{Path, PathBuf},
};

type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

fn parse_qif(text: &[u8]) -> Vec<HeaderList> {
  let mut lists = Vec::new();
  let mut current = Vec::new();
  for line in text.split(|el| *el == b'\n') {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.first() == Some(&b'#') {
      continue;
    }
    if line.is_empty() {
      if !current.is_empty() {
        lists.push(std::mem::take(&mut current));
      }
      continue;
    }
    let tab = line.iter().position(|el| *el == b'\t').expect("a tab in a QIF line");
    current.push((line[..tab].to_vec(), line[tab + 1..].to_vec()));
  }
  if !current.is_empty() {
    lists.push(current);
  }
  lists
}

struct Outcome {
  sections: usize,
  blocked: usize,
  memo_hits: u64,
}

// Decodes `encoded` (blocks of an 8-byte stream id, a 4-byte length and the data; stream 0 is the
// encoder stream) with a table of `capacity` and `blocked` streams, and compares with `lists`
fn run(
  encoded: &[u8],
  lists: &[HeaderList],
  capacity: u32,
  blocked: u16,
  memo: usize,
) -> Result<Outcome, String> {
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: capacity,
    blocked_streams: blocked,
    memo_sections: memo,
    ..DecoderConfig::default()
  });
  let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
  let mut decoded: BTreeMap<u64, HeaderList> = BTreeMap::new();
  let mut fields = FieldList::new();
  let mut encoder_started = false;
  let mut blocked_count = 0;
  let mut decode =
    |decoder: &mut Decoder, stream: u64, block: &[u8], decoded: &mut BTreeMap<u64, HeaderList>| {
      match decoder
        .decode_into(stream, block, &mut fields)
        .map_err(|err| format!("stream {stream}: {err}"))?
      {
        DecodeOutcome::Done { .. } => {
          let list = fields.iter().map(|el| (el.name.to_vec(), el.value.to_vec())).collect();
          if decoded.insert(stream, list).is_some() {
            return Err(format!("stream {stream} twice"));
          }
          Ok(false)
        }
        DecodeOutcome::Blocked { .. } => Ok(true),
      }
    };
  let mut rest = encoded;
  while !rest.is_empty() {
    if rest.len() < 12 {
      return Err("truncated block header".into());
    }
    let stream = u64::from_be_bytes(rest[..8].try_into().unwrap());
    let len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
    let block = rest.get(12..12 + len).ok_or("truncated block")?;
    rest = &rest[12 + len..];
    if stream == 0 {
      if !encoder_started && block.first().is_some_and(|el| el & 0xe0 != 0x20) {
        let capacity_instruction = set_capacity(capacity);
        decoder.feed_encoder_stream(&capacity_instruction).map_err(|err| err.to_string())?;
      }
      encoder_started = true;
      decoder.feed_encoder_stream(block).map_err(|err| format!("encoder stream: {err}"))?;
      let ready: Vec<u64> = decoder.take_unblocked().collect();
      for stream in ready {
        let block = pending.remove(&stream).ok_or("unblocked an unknown stream")?;
        if decode(&mut decoder, stream, &block, &mut decoded)? {
          return Err(format!("stream {stream} reported unblocked but blocked"));
        }
      }
    } else if decode(&mut decoder, stream, block, &mut decoded)? {
      blocked_count += 1;
      pending.insert(stream, block.to_vec());
    }
    decoder.consume_decoder_stream(usize::MAX);
  }
  if !pending.is_empty() {
    return Err(format!("{} streams still blocked", pending.len()));
  }
  if decoded.len() != lists.len() {
    return Err(format!("{} header lists decoded, {} in the QIF", decoded.len(), lists.len()));
  }
  // The streams in order of their ids are the header lists in order (ids 1, 2, ... or 4, 8, ...)
  for ((stream, list), expected) in decoded.iter().zip(lists) {
    if list != expected {
      return Err(format!("stream {stream} differs"));
    }
  }
  Ok(Outcome {
    sections: decoded.len(),
    blocked: blocked_count,
    memo_hits: decoder.stats().memo_hits,
  })
}

fn run_dir(qif_dir: &Path, encoded_dir: &Path) -> (usize, usize) {
  let mut qifs: BTreeMap<String, Vec<HeaderList>> = BTreeMap::new();
  for entry in fs::read_dir(qif_dir).unwrap() {
    let path = entry.unwrap().path();
    if path.extension().is_some_and(|el| el == "qif") {
      let name = path.file_stem().unwrap().to_string_lossy().into_owned();
      qifs.insert(name, parse_qif(&fs::read(&path).unwrap()));
    }
  }
  // `examples.out.220.100.1` holds the bytes of RFC 9204 Appendix B, but draft-examples.qif is
  // older (www.ietf.org): the lists of the RFC are the reference
  let pair = |name: &str, value: &str| (name.as_bytes().to_vec(), value.as_bytes().to_vec());
  qifs.insert(
    "examples".into(),
    vec![
      vec![pair(":path", "/index.html")],
      vec![pair(":authority", "www.example.com"), pair(":path", "/sample/path")],
      vec![
        pair(":authority", "www.example.com"),
        pair(":path", "/"),
        pair("custom-key", "custom-value"),
      ],
    ],
  );
  let mut files: Vec<PathBuf> = Vec::new();
  let mut dirs = vec![encoded_dir.to_path_buf()];
  while let Some(dir) = dirs.pop() {
    for entry in fs::read_dir(&dir).unwrap() {
      let entry = entry.unwrap();
      let file_type = entry.file_type().unwrap();
      if file_type.is_dir() {
        dirs.push(entry.path());
      } else if file_type.is_file() {
        files.push(entry.path());
      }
    }
  }
  files.sort();
  let (mut ran, mut sections, mut failures) = (0, 0, Vec::new());
  let (mut blocked, mut memo_hits) = (0, 0);
  for path in &files {
    let name = path.file_name().unwrap().to_string_lossy();
    let parts: Vec<&str> = name.split('.').collect();
    let [base, "out", capacity, max_blocked, _ack] = parts.as_slice() else {
      continue;
    };
    let (Ok(capacity), Ok(max_blocked), Some(lists)) =
      (capacity.parse::<u32>(), max_blocked.parse::<u16>(), qifs.get(*base))
    else {
      continue;
    };
    let encoded = fs::read(path).unwrap();
    for memo in [0, 8] {
      match run(&encoded, lists, capacity, max_blocked, memo) {
        Ok(outcome) => {
          sections += outcome.sections;
          blocked += outcome.blocked;
          memo_hits += outcome.memo_hits;
        }
        Err(err) => failures.push(format!("{} (memo {memo}): {err}", path.display())),
      }
    }
    ran += 1;
  }
  assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
  eprintln!(
    "qifs: {ran} files, {sections} sections ({blocked} blocked first, {memo_hits} memo replays)"
  );
  (ran, sections)
}

#[test]
fn qifs_subset_decodes() {
  let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/qifs");
  let (files, sections) = run_dir(&root.join("qifs"), &root.join("encoded"));
  // Every encoding of the netbsd QIFs by six implementations, and the draft examples
  assert_eq!(files, 177);
  assert!(sections > 3_000);
}

#[test]
fn qifs_full_corpus_decodes() {
  let Some(dir) = std::env::var_os("QIFS_DIR") else {
    eprintln!("QIFS_DIR not set: skipped");
    return;
  };
  let root = PathBuf::from(dir);
  let (files, _) = run_dir(&root.join("qifs"), &root.join("encoded/qpack-05"));
  assert!(files > 500);
}

// Set Dynamic Table Capacity
fn set_capacity(capacity: u32) -> Vec<u8> {
  let mut out = Vec::new();
  if capacity < 31 {
    out.push(0x20 | capacity as u8);
    return out;
  }
  out.push(0x3f);
  let mut rest = capacity - 31;
  while rest >= 128 {
    out.push((rest & 0x7f) as u8 | 0x80);
    rest >>= 7;
  }
  out.push(rest as u8);
  out
}
