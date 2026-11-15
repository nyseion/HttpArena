use crate::crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey};

type Aes128GcmKeyTy = cfg_select! {
  feature = "ring" => crate::crypto::Aes128GcmKeyRing,
  feature = "aws-lc-rs" => crate::crypto::Aes128GcmKeyAlr,
  _ => crate::crypto::AeadKeyDummy::<16>,
};
type Aes256GcmKeyTy = cfg_select! {
  feature = "ring" => crate::crypto::Aes256GcmKeyRing,
  feature = "aws-lc-rs" => crate::crypto::Aes256GcmKeyAlr,
  _ => crate::crypto::AeadKeyDummy::<32>,
};
type Chacha20Poly1305KeyTy = cfg_select! {
  feature = "ring" => crate::crypto::Chacha20Poly1305KeyRing,
  feature = "aws-lc-rs" => crate::crypto::Chacha20Poly1305KeyAlr,
  _ => crate::crypto::AeadKeyDummy::<32>,
};

macro_rules! global {
  ($name:ident, $ty:ident) => {
    /// The key of the backend in use (ring, else aws-lc-rs).
    #[derive(Debug)]
    pub struct $name($ty);

    impl AeadKey for $name {
      const KEY_LEN: usize = <$ty as AeadKey>::KEY_LEN;

      #[inline]
      fn new(key: &[u8]) -> crate::Result<Self> {
        Ok(Self(<$ty as AeadKey>::new(key)?))
      }

      #[inline]
      fn open_in_place<'data>(
        &self,
        nonce: [u8; AEAD_NONCE_LEN],
        aad: &[u8],
        data: &'data mut [u8],
      ) -> crate::Result<&'data mut [u8]> {
        self.0.open_in_place(nonce, aad, data)
      }

      #[inline]
      fn seal_in_place(
        &self,
        nonce: [u8; AEAD_NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
      ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
        self.0.seal_in_place(nonce, aad, data)
      }
    }
  };
}

global!(Aes128GcmKeyGlobal, Aes128GcmKeyTy);
global!(Aes256GcmKeyGlobal, Aes256GcmKeyTy);
global!(Chacha20Poly1305KeyGlobal, Chacha20Poly1305KeyTy);
