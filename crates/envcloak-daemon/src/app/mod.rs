//! App-role admission. A verdict belongs only to the accepted connection.
use envcloak_sys::{
    PeerIdentity,
    peer_code::{self, CodeVerdict, pins},
};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

pub(crate) fn verified(stream: &UnixStream, peer: &PeerIdentity) -> bool {
    let Ok(Some(pin)) = pins::app() else {
        return false;
    };
    let Ok(token) = peer_code::audit_token(stream.as_fd()) else {
        return false;
    };
    matches!(
        peer_code::peer_satisfies(&token, peer, &pin),
        Ok(CodeVerdict::Satisfies)
    ) && envcloak_sys::peer_unchanged(stream.as_fd(), peer).unwrap_or(false)
}
