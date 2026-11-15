//! Hexadecimal literals decoded at compile time, for test vectors and constants.

/// The value of the hexadecimal digit `digit`; panics (at compile time) on anything else.
pub(crate) const fn hex_digit(digit: u8) -> u8 {
  match digit {
    b'0'..=b'9' => digit - b'0',
    b'a'..=b'f' => digit - b'a' + 10,
    b'A'..=b'F' => digit - b'A' + 10,
    _ => panic!("not a hexadecimal digit"),
  }
}

/// Decodes `input`, two digits per byte, into `N` bytes; panics if the lengths do not match.
pub(crate) const fn hex_decode<const N: usize>(input: &[u8]) -> [u8; N] {
  assert!(input.len() == 2 * N, "the length of a hexadecimal literal must be twice its bytes");
  let mut out = [0u8; N];
  let mut idx = 0;
  while idx < N {
    out[idx] = (hex_digit(input[2 * idx]) << 4) | hex_digit(input[2 * idx + 1]);
    idx += 1;
  }
  out
}

/// The bytes of a hexadecimal byte string literal, as an array, decoded at compile time.
macro_rules! hex {
  ($input:expr) => {
    const { $crate::hex::hex_decode::<{ $input.len() / 2 }>($input) }
  };
}
