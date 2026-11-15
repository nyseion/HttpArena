//! Whether the ClientHello of a QUIC v1 handshake carries the `quic_transport_parameters`
//! extension of RFC 9001 (0x39). rustls takes the extension of the drafts (0xffa5) in its place,
//! but RFC 9001 section 8.2 asks a server to close a v1 connection without it with
//! `missing_extension`: the server session scans the ClientHello as it arrives, without copying
//! it, and refuses it.

// The extension of RFC 9001
const TRANSPORT_PARAMETERS: u32 = 0x39;
// After the header of the message: legacy_version (2) and random (32)
const FIXED: usize = 34;

/// The field of the ClientHello that the scan reads next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
  // The type and the length of the handshake message (1 + 3 bytes)
  Header,
  SessionIdLen,
  SuitesLen,
  CompressionLen,
  ExtensionsLen,
  ExtensionType,
  ExtensionLen,
}

/// What the scan does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
  // Reads a big-endian integer of `len` bytes into `acc`, then takes it as `field`
  Read { field: Field, len: u8 },
  // Skips `left` bytes, then reads `then`
  Skip { left: usize, then: Field },
  // Done: whether the extension is there
  Done(bool),
}

/// A scan of the first handshake message of a client, fed its bytes in order: see the
/// [module documentation](self). A ClientHello that it cannot follow (not one, or malformed) is
/// left to rustls, which refuses it: the scan then says nothing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HelloScan {
  acc: u32,
  // The bytes of `acc` read so far
  have: u8,
  // The bytes of the extensions that are left
  extensions: usize,
  step: Step,
}

impl HelloScan {
  pub(crate) const fn new() -> Self {
    Self { acc: 0, have: 0, extensions: 0, step: Step::Read { field: Field::Header, len: 4 } }
  }

  /// Takes the next bytes of the handshake. `Some(false)` once a whole ClientHello was read
  /// without the extension, `Some(true)` with it, and `None` while more is needed or for what it
  /// cannot follow.
  pub(crate) fn feed(&mut self, mut data: &[u8]) -> Option<bool> {
    loop {
      match self.step {
        Step::Done(found) => return Some(found),
        Step::Skip { left, then } => {
          let take = left.min(data.len());
          data = data.get(take..).unwrap_or_default();
          let left = left.wrapping_sub(take);
          if left > 0 {
            self.step = Step::Skip { left, then };
            return None;
          }
          self.step = self.after_skip(then);
        }
        Step::Read { field, len } => {
          let (&byte, rest) = data.split_first()?;
          data = rest;
          self.acc = (self.acc << 8) | u32::from(byte);
          self.have = self.have.wrapping_add(1);
          if self.have == len {
            let value = self.acc;
            self.acc = 0;
            self.have = 0;
            self.step = self.on_value(field, value);
          }
        }
      }
    }
  }

  // The step after a skip that ends before `field`.
  fn after_skip(&self, field: Field) -> Step {
    if matches!(field, Field::ExtensionType) && self.extensions == 0 {
      return Step::Done(false);
    }
    let len = match field {
      Field::Header => 4,
      Field::SessionIdLen | Field::CompressionLen => 1,
      _ => 2,
    };
    Step::Read { field, len }
  }

  // The step after `value`, the integer of `field`.
  fn on_value(&mut self, field: Field, value: u32) -> Step {
    let value_len = usize::try_from(value).unwrap_or(usize::MAX);
    match field {
      // A ClientHello (type 1)
      Field::Header if value >> 24 == 1 => Step::Skip { left: FIXED, then: Field::SessionIdLen },
      Field::Header => Step::Done(true),
      Field::SessionIdLen => Step::Skip { left: value_len, then: Field::SuitesLen },
      Field::SuitesLen => Step::Skip { left: value_len, then: Field::CompressionLen },
      Field::CompressionLen => Step::Skip { left: value_len, then: Field::ExtensionsLen },
      Field::ExtensionsLen => {
        self.extensions = value_len;
        if value_len == 0 {
          Step::Done(false)
        } else {
          Step::Read { field: Field::ExtensionType, len: 2 }
        }
      }
      Field::ExtensionType if value == TRANSPORT_PARAMETERS => Step::Done(true),
      Field::ExtensionType => {
        self.extensions = self.extensions.saturating_sub(2);
        Step::Read { field: Field::ExtensionLen, len: 2 }
      }
      Field::ExtensionLen => {
        let Some(left) = self.extensions.checked_sub(2).and_then(|el| el.checked_sub(value_len))
        else {
          // Past the end of the extensions: malformed
          return Step::Done(true);
        };
        self.extensions = left;
        Step::Skip { left: value_len, then: Field::ExtensionType }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::HelloScan;
  use alloc::vec::Vec;

  // A ClientHello with the extensions `types`, each with 3 bytes of data.
  fn hello(types: &[u16]) -> Vec<u8> {
    let mut exts = Vec::new();
    for ty in types {
      exts.extend_from_slice(&ty.to_be_bytes());
      exts.extend_from_slice(&[0, 3, 7, 7, 7]);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[4, 1, 2, 3, 4]);
    body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&exts);
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut msg = vec![1, len[1], len[2], len[3]];
    msg.extend_from_slice(&body);
    msg
  }

  fn scan_in_pieces(msg: &[u8], piece: usize) -> Option<bool> {
    let mut scan = HelloScan::new();
    let mut rslt = None;
    for chunk in msg.chunks(piece) {
      rslt = scan.feed(chunk);
    }
    rslt
  }

  #[test]
  fn finds_the_extension_or_its_absence_in_any_pieces() {
    for piece in [1, 2, 3, 5, 64, 4096] {
      assert_eq!(scan_in_pieces(&hello(&[0x0a, 0x39, 0x2b]), piece), Some(true), "{piece}");
      assert_eq!(scan_in_pieces(&hello(&[0x0a, 0xffa5, 0x2b]), piece), Some(false), "{piece}");
      assert_eq!(scan_in_pieces(&hello(&[]), piece), Some(false), "{piece}");
    }
    // Cut short: more is needed
    let msg = hello(&[0x0a, 0xffa5]);
    assert_eq!(scan_in_pieces(&msg[..msg.len() - 1], 7), None);
  }

  #[test]
  fn leaves_what_it_cannot_follow_to_rustls() {
    // Not a ClientHello
    let mut msg = hello(&[0xffa5]);
    msg[0] = 2;
    assert_eq!(scan_in_pieces(&msg, 3), Some(true));
    // An extension longer than the extensions
    let mut msg = hello(&[0xffa5]);
    let at = msg.len() - 4;
    msg[at] = 0x40;
    assert_eq!(scan_in_pieces(&msg, 3), Some(true));
  }
}
