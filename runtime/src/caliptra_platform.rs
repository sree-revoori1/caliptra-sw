// Licensed under the Apache-2.0 license

use platform::{Platform, PlatformError, MAX_CHUNK_SIZE};

pub struct CaliptraPlatform;

pub const VENDOR_ID: u32 = u32::from_be_bytes(*b"CTRA");
pub const VENDOR_SKU: u32 = u32::from_be_bytes(*b"CTRA");
pub const AUTO_INIT_LOCALITY: u32 = 0;

impl Platform for CaliptraPlatform {
    fn get_certificate_chain(
        &mut self,
        _offset: u32,
        _size: u32,
        _out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_ID)
    }

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_SKU)
    }

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError> {
        Ok(AUTO_INIT_LOCALITY)
    }
}
