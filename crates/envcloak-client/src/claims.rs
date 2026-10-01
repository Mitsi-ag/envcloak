//! The agent markers a client process carries (SPEC §10a
//! "caller-asserted"): sent with a request, they only tighten what the
//! daemon decides, and a client that is about to read a proof refuses
//! first when any is set, since the daemon would refuse the proof.

use crate::fail::Failure;

/// The names of the agent markers set in this process's environment
/// (SPEC §10a "caller-asserted"; they only tighten), from the builtin
/// catalog and the user's extensions.
pub fn claims() -> Vec<String> {
    let catalog = match envcloak_core::vault::VaultPaths::for_user() {
        Ok(p) => envcloak_policy::AgentCatalog::load(&p.data_dir),
        Err(_) => envcloak_policy::AgentCatalog::builtin(),
    };
    envcloak_policy::Claims::from_env(&catalog)
        .markers()
        .to_vec()
}

/// This process's claims ([`claims`]), for a command about to read a
/// proof: with any marker set, the daemon refuses the proof (SPEC §10b),
/// so the command refuses first, before it reads the passphrase or shows
/// anything.
pub fn refuse_if_claimed() -> Result<Vec<String>, Failure> {
    let claims = claims();
    if claims.is_empty() {
        Ok(claims)
    } else {
        Err(envcloak_ipc::ClientError::Rpc(envcloak_ipc::RpcError::new(
            envcloak_ipc::proto::ErrorKind::ProofRefused,
        ))
        .into())
    }
}
