// Licensed under the Apache-2.0 license

use crate::{InvokeDpeCmd, CaliptraEnv, CaliptraCrypto, CaliptraPlatform, InvokeDpeResp};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use dpe::dpe_instance::DpeInstance;
use zerocopy::FromBytes;
use core::marker::PhantomData;

const INVOKE_DPE_LOCALITY: u32 = 0x30020004;

/// Handle the `INVOKE_DPE_COMMAND` mailbox command
pub(crate) fn handle_invoke_dpe_command<'a>(
    dpe: &mut DpeInstance<'a>,
    cmd_args: &[u8],
) -> CaliptraResult<InvokeDpeResp> {
    if let Some(cmd) = InvokeDpeCmd::read_from(cmd_args) {
        let mut response_buf = [0u8; 4096];
        let mut env = CaliptraEnv {
            crypto: CaliptraCrypto(PhantomData),
            platform: CaliptraPlatform,
        };
        match dpe.execute_serialized_command(&mut env, INVOKE_DPE_LOCALITY, &cmd.data) {
            Ok(resp) => {
                let serialized_resp = resp.as_bytes();
                response_buf.copy_from_slice(&serialized_resp);
                Ok(InvokeDpeResp {
                    chksum: cmd.chksum,
                    size: serialized_resp.len() as u32,
                    data: response_buf,
                })
            }
            _ => Err(CaliptraError::RUNTIME_INVOKE_DPE_FAILED),
        }
    } else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }
}
