// Licensed under the Apache-2.0 license

#![no_std]

pub mod dice;
mod invoke_dpe;
mod verify;

// Used by runtime tests
pub mod mailbox;

pub mod caliptra_crypto;
pub mod caliptra_platform;

use mailbox::Mailbox;

use caliptra_common::cprintln;
use caliptra_crypto::CaliptraCrypto;
use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, Ecc384, PcrBank, PcrId};
use caliptra_platform::CaliptraPlatform;
use caliptra_registers::{
    dv::DvReg,
    ecc::EccReg,
    mbox::{enums::MboxStatusE, MboxCsr},
    pv::PvReg,
    sha512_acc::Sha512AccCsr,
};
use dpe::{
    commands::{CommandExecution, DeriveChildCmd},
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance},
    support::Support,
    DPE_PROFILE,
};
use zerocopy::{AsBytes, FromBytes};
use core::marker::PhantomData;

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
}
impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

pub const DPE_SUPPORT: Support = Support {
    simulation: true,
    extend_tci: true,
    auto_init: true,
    tagging: true,
    rotate_context: true,
    x509: true,
    csr: true,
    is_symmetric: true,
    internal_info: true,
    internal_dice: true,
    is_ca: true,
};

pub const DPE_LOCALITY: u32 = 0x0;

pub struct Drivers<'a> {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub data_vault: DataVault,
    pub pcr_bank: PcrBank,
    pub dpe: DpeInstance<'a>,
}

pub struct CaliptraEnv<'a> {
    pub crypto: CaliptraCrypto<'a>,
    pub platform: CaliptraPlatform,
}

impl<'a> DpeEnv for CaliptraEnv<'a> {
    type Crypto = CaliptraCrypto<'a>;
    type Platform = CaliptraPlatform;

    fn crypto(&mut self) -> &mut Self::Crypto {
        &mut self.crypto
    }

    fn platform(&mut self) -> &mut Self::Platform {
        &mut self.platform
    }
}

impl Drivers<'_> {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers() -> Self {
        let pcr_bank = PcrBank::new(PvReg::new());

        let mut env = CaliptraEnv {
            crypto: CaliptraCrypto(PhantomData),
            platform: CaliptraPlatform,
        };
        // TODO: Replace issuer common name with FMC code to generate the runtime alias once it is written
        const CALIPTRA_ISSUER: &[u8] = b"Caliptra Issuer";
        let mut dpe = DpeInstance::new(&mut env, DPE_SUPPORT, CALIPTRA_ISSUER).unwrap();

        // TODO: Set target_locality to SoC's initial locality
        const TARGET_LOCALITY: u32 = 0;
        let data = <[u8; DPE_PROFILE.get_hash_size()]>::from(&pcr_bank.read_pcr(PcrId::PcrId1));
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data,
            flags: DeriveChildCmd::MAKE_DEFAULT
                | DeriveChildCmd::CHANGE_LOCALITY
                | DeriveChildCmd::INPUT_ALLOW_CA
                | DeriveChildCmd::INPUT_ALLOW_X509,
            tci_type: u32::from_be_bytes(*b"RTJM"),
            target_locality: TARGET_LOCALITY,
        }
        .execute(&mut dpe, &mut env, DPE_LOCALITY)
        .unwrap();
        Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            ecdsa: Ecc384::new(EccReg::new()),
            data_vault: DataVault::new(DvReg::new()),
            pcr_bank,
            dpe,
        }
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaVerifyCmd {
    pub chksum: u32,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

impl Default for EcdsaVerifyCmd {
    fn default() -> Self {
        Self {
            chksum: 0,
            pub_key_x: [0u8; 48],
            pub_key_y: [0u8; 48],
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
        }
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct InvokeDpeCmd {
    pub chksum: u32,
    pub data: [u8; 4096],
}

impl Default for InvokeDpeCmd {
    fn default() -> Self {
        Self {
            chksum: 0,
            data: [0u8; 4096],
        }
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct InvokeDpeResp {
    pub chksum: u32,
    pub data: [u8; 4096],
    pub size: u32,
}

impl Default for InvokeDpeResp {
    fn default() -> Self {
        Self {
            chksum: 0,
            data: [0u8; 4096],
            size: 0,
        }
    }
}

fn wait_for_cmd(_mbox: &mut Mailbox) {
    // TODO: Enable interrupts?
    //#[cfg(feature = "riscv")]
    //unsafe {
    //core::arch::asm!("wfi");
    //}
}

fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    let mbox = &mut drivers.mbox;

    let cmd_id = mbox.cmd();
    let dlen = mbox.dlen() as usize;
    let dlen_words = mbox.dlen_words() as usize;
    let mut buf = [0u32; 1024];
    mbox.copy_from_mbox(
        buf.get_mut(..dlen_words)
            .ok_or(CaliptraError::RUNTIME_INTERNAL)?,
    );

    if dlen > buf.len() * 4 {
        // dlen larger than max message
        Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    }

    let cmd_bytes = buf
        .as_bytes()
        .get(..dlen)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

    cprintln!("[rt] Received command=0x{:x}, len={}", cmd_id, mbox.dlen());
    match CommandId::from(cmd_id) {
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_bytes)?;
            Ok(MboxStatusE::CmdComplete)
        }
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => {
            let resp = invoke_dpe::handle_invoke_dpe_command(&mut drivers.dpe, cmd_bytes)?;
            mbox.write_response(&resp.data[..resp.size as usize])?;
            Ok(MboxStatusE::DataReady)
        }
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) {
    loop {
        wait_for_cmd(&mut drivers.mbox);

        if drivers.mbox.is_cmd_ready() {
            match handle_command(drivers) {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
        }
    }
}
