use super::{CODES, HuffmanError, decode, encode, encoded_len};
use alloc::{collections::BTreeMap, vec, vec::Vec};

fn hex(text: &str) -> Vec<u8> {
  (0..text.len())
    .step_by(2)
    .map(|idx| u8::from_str_radix(&text[idx..idx + 2], 16).unwrap())
    .collect()
}

fn decoded(src: &[u8]) -> Result<Vec<u8>, HuffmanError> {
  let mut out = Vec::new();
  decode(src, &mut out, usize::MAX).map(|()| out)
}

fn encoded(src: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  encode(src, &mut out);
  assert_eq!(out.len(), encoded_len(src));
  out
}

// A decoder that knows nothing of the state table: it reads one bit at a time and looks the bits
// read so far up among the codes.
fn reference_decode(src: &[u8]) -> Result<Vec<u8>, HuffmanError> {
  let codes: BTreeMap<(u8, u32), u16> = CODES
    .iter()
    .enumerate()
    .map(|(symbol, (code, len))| ((*len, *code), u16::try_from(symbol).unwrap()))
    .collect();
  let mut out = Vec::new();
  let (mut code, mut len) = (0u32, 0u8);
  for byte in src {
    for shift in (0..8).rev() {
      code = (code << 1) | u32::from((byte >> shift) & 1);
      len += 1;
      if let Some(symbol) = codes.get(&(len, code)) {
        if *symbol == 256 {
          return Err(HuffmanError::Invalid);
        }
        out.push(u8::try_from(*symbol).unwrap());
        (code, len) = (0, 0);
      }
    }
  }
  // Padding: at most 7 bits, all ones
  if len > 7 || code != (1u32 << len) - 1 {
    return Err(HuffmanError::Invalid);
  }
  Ok(out)
}

struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }
}

#[test]
fn rfc7541_appendix_c_examples() {
  // Every Huffman-coded string of C.4 and C.6
  let vectors: [(&str, &[u8]); 13] = [
    ("f1e3c2e5f23a6ba0ab90f4ff", b"www.example.com"),
    ("a8eb10649cbf", b"no-cache"),
    ("25a849e95ba97d7f", b"custom-key"),
    ("25a849e95bb8e8b4bf", b"custom-value"),
    ("6402", b"302"),
    ("aec3771a4b", b"private"),
    ("d07abe941054d444a8200595040b8166e082a62d1bff", b"Mon, 21 Oct 2013 20:13:21 GMT"),
    ("9d29ad171863c78f0b97c8e9ae82ae43d3", b"https://www.example.com"),
    ("640eff", b"307"),
    ("d07abe941054d444a8200595040b8166e084a62d1bff", b"Mon, 21 Oct 2013 20:13:22 GMT"),
    ("9bd9ab", b"gzip"),
    (
      "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
      b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    ),
    ("", b""),
  ];
  for (coded, plain) in vectors {
    assert_eq!(encoded(plain), hex(coded), "{}", core::str::from_utf8(plain).unwrap());
    assert_eq!(decoded(&hex(coded)).unwrap(), plain);
  }
}

#[test]
fn every_single_symbol_round_trips() {
  for byte in 0..=255u8 {
    let (_, len) = CODES[usize::from(byte)];
    let coded = encoded(&[byte]);
    assert_eq!(coded.len(), usize::from(len).div_ceil(8));
    assert_eq!(decoded(&coded).unwrap(), [byte]);
    assert_eq!(reference_decode(&coded).unwrap(), [byte]);
    // Repeated: codes that do not end on a byte boundary follow each other
    let run = [byte; 7];
    assert_eq!(decoded(&encoded(&run)).unwrap(), run);
  }
}

// Every input of one and two bytes decodes as the bit-at-a-time reference decides: to the same
// bytes, or to an error
#[test]
fn every_input_of_up_to_two_bytes_matches_the_reference() {
  assert_eq!(decoded(&[]).unwrap(), b"");
  for first in 0..=255u8 {
    assert_eq!(decoded(&[first]), reference_decode(&[first]), "{first:02x}");
    for second in 0..=255u8 {
      let src = [first, second];
      assert_eq!(decoded(&src), reference_decode(&src), "{first:02x}{second:02x}");
    }
  }
}

#[test]
fn random_inputs_match_the_reference() {
  let mut rng = Rng(0x0123_4567_89ab_cdef);
  for _ in 0..200_000 {
    let len = usize::try_from(rng.next() % 9).unwrap() + 3;
    let src: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
    assert_eq!(decoded(&src), reference_decode(&src), "{src:02x?}");
  }
}

#[test]
fn random_strings_round_trip() {
  let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
  for round in 0..20_000 {
    let len = usize::try_from(rng.next() % 300).unwrap();
    // Half of the strings are header-like text, half arbitrary bytes
    let src: Vec<u8> = (0..len)
      .map(|_| {
        let byte = rng.next() as u8;
        if round % 2 == 0 { b' ' + byte % 95 } else { byte }
      })
      .collect();
    let coded = encoded(&src);
    assert_eq!(decoded(&coded).unwrap(), src);
    if src.len() < 64 {
      assert_eq!(reference_decode(&coded).unwrap(), src);
    }
  }
}

#[test]
fn padding_and_eos_errors() {
  // 'a' is 00011 (5 bits): padded with 111 it is 0x1f
  assert_eq!(decoded(&[0x1f]).unwrap(), b"a");
  // Padding not all ones
  assert_eq!(decoded(&[0x18]), Err(HuffmanError::Invalid));
  assert_eq!(decoded(&[0x1e]), Err(HuffmanError::Invalid));
  assert_eq!(decoded(&[0x1d]), Err(HuffmanError::Invalid));
  // Padding longer than 7 bits: 'a' then 11 ones, or a whole byte of ones alone
  assert_eq!(decoded(&[0x1f, 0xff]), Err(HuffmanError::Invalid));
  assert_eq!(decoded(&[0xff]), Err(HuffmanError::Invalid));
  // '0' is 00000: 0x07 is '0' then 111, fine; 0x00 is '0' then 000, a bad padding
  assert_eq!(decoded(&[0x07]).unwrap(), b"0");
  assert_eq!(decoded(&[0x00]), Err(HuffmanError::Invalid));
  // The EOS symbol (30 ones) in the input, alone or after a symbol
  assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xff]), Err(HuffmanError::Invalid));
  assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xfc]), Err(HuffmanError::Invalid));
  let mut eos_after_a = Vec::new();
  // 00011 + 30 ones + 5 ones of padding = 40 bits
  let bits: u64 = (0b00011 << 35) | ((1 << 35) - 1);
  eos_after_a.extend_from_slice(&bits.to_be_bytes()[3..]);
  assert_eq!(decoded(&eos_after_a), Err(HuffmanError::Invalid));
  // 24 ones: a prefix of EOS longer than 7 bits is invalid padding
  assert_eq!(decoded(&[0xff, 0xff, 0xff]), Err(HuffmanError::Invalid));
  // A failed decode leaves the output as it was
  let mut out = vec![b'x'];
  assert_eq!(decode(&[0x1f, 0xff], &mut out, usize::MAX), Err(HuffmanError::Invalid));
  assert_eq!(out, b"x");
}

#[test]
fn output_limit() {
  let coded = encoded(b"hello world");
  let mut out = vec![b'>'];
  assert_eq!(decode(&coded, &mut out, 10), Err(HuffmanError::TooLong));
  assert_eq!(out, b">");
  decode(&coded, &mut out, 11).unwrap();
  assert_eq!(out, b">hello world");
}
