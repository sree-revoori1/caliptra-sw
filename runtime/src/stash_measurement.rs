// Licensed under the Apache-2.0 license

use crate::{
    dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers, MailboxResp, MailboxRespHeader,
    StashMeasurementReq, StashMeasurementResp, DPE_LOCALITY, TARGET_LOCALITY,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use dpe::{
    commands::{CommandExecution, DeriveChildCmd},
    context::ContextHandle,
    dpe_instance::DpeEnv,
    response::DpeErrorCode,
};
use zerocopy::FromBytes;

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = StashMeasurementReq::read_from(cmd_args) {
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto: DpeCrypto::new(&mut drivers.sha384, &mut drivers.trng),
                platform: DpePlatform,
            };
            let derive_child_resp = DeriveChildCmd {
                handle: ContextHandle::default(),
                data: cmd.measurement,
                flags: DeriveChildCmd::MAKE_DEFAULT
                    | DeriveChildCmd::CHANGE_LOCALITY
                    | DeriveChildCmd::INPUT_ALLOW_CA
                    | DeriveChildCmd::INPUT_ALLOW_X509,
                tci_type: u32::from_be_bytes(cmd.metadata),
                target_locality: TARGET_LOCALITY,
            }
            .execute(&mut drivers.dpe, &mut env, DPE_LOCALITY);

            let dpe_result = match derive_child_resp {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => e,
            } as u32;

            Ok(MailboxResp::StashMeasurement(StashMeasurementResp {
                hdr: MailboxRespHeader::default(),
                dpe_result,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
