// Licensed under the Apache-2.0 license

use caliptra_drivers::{Array4x12, Csrng, KeyId, Sha384, Sha384DigestOp};
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, sha512::Sha512Reg};
use core::{num::NonZeroUsize, marker::PhantomData};
use crypto::{AlgLen, Crypto, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher, HmacSig};

pub struct CaliptraHasher<'a>(Sha384DigestOp<'a>, Sha384, Array4x12);

impl Hasher for CaliptraHasher<'_> {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes);
        Ok(())
    }

    fn finish(mut self) -> Result<Digest, CryptoError> {
        self.0.finalize();
        Digest::new(
            <[u8; AlgLen::Bit384.size()]>::from(self.2).as_ref(),
            AlgLen::Bit384,
        )
    }
}

pub struct CaliptraCrypto<'a>(pub PhantomData<&'a ()>);

impl<'a> Crypto for CaliptraCrypto<'a> {
    type Cdi = KeyId;
    type Hasher = CaliptraHasher<'a>;
    type PrivKey = KeyId;

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        let csrng_reg = unsafe { CsrngReg::new() };
        let entropy_src_reg = unsafe { EntropySrcReg::new() };

        let mut csrng = Csrng::new(csrng_reg, entropy_src_reg).unwrap();
        let num_words = NonZeroUsize::new(dst.len() / 4).unwrap();

        let mut i = 0;
        for src in csrng.generate(num_words).unwrap() {
            dst[i] = (src & 0xFF) as u8;
            dst[i + 1] = ((src >> 8) & 0xFF) as u8;
            dst[i + 2] = ((src >> 16) & 0xFF) as u8;
            dst[i + 3] = ((src >> 24) & 0xFF) as u8;
            i += 4;
        }
        Ok(())
    }

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => {
                let mut digest = Array4x12::default();
                let mut sha = unsafe { Sha384::new(Sha512Reg::new()) };
                let hasher = sha
                    .digest_init(&mut digest)
                    .map_err(|_| CryptoError::CryptoLibError)?;
                Ok(CaliptraHasher(hasher, sha, digest))
            }
        }
    }

    fn derive_cdi(
        &mut self,
        _algs: AlgLen,
        _measurement: &Digest,
        _info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_private_key(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
    ) -> Result<Self::PrivKey, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_ecdsa_pub(&mut self, _algs: AlgLen, _priv_key: &Self::PrivKey) -> Result<EcdsaPub, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_alias(&mut self, _algs: AlgLen, _digest: &Digest) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _digest: &Digest,
        _priv_key: &Self::PrivKey,
    ) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn get_ecdsa_alias_serial(&mut self, _algs: AlgLen, _serial: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn hmac_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
        _digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
