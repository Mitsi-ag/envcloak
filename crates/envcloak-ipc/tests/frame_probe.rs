//! Gate 11 for IPC frames: encoding a request that carries a passphrase,
//! sending it over a real socket pair, reading and parsing it on the other
//! side, and answering with a response that carries a value, never free a
//! block that still holds the value or its base64 form.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that the frame code wipes every buffer it fills (frame bodies, the
//! base64 text, the decoded value); `ProbeMode::Wiping` is the gate as
//! written. One test, so no other test allocates while the probe is armed.
#![allow(clippy::unwrap_used)]

use std::os::unix::net::UnixStream;

use base64::Engine as _;
use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{self, IncomingRequest, Unlock, UnlockParams};
use envcloak_ipc::{Frame, WireSecret};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[derive(serde::Serialize, serde::Deserialize)]
struct Released {
    value: WireSecret,
}

fn round_trip(pass: &[u8], value: &[u8]) {
    let (mut client, mut server) = UnixStream::pair().unwrap();

    // Client: the request, wiped once sent.
    let request = proto::request_frame::<Unlock>(
        1,
        &UnlockParams {
            passphrase: WireSecret::new(SecretBytes::copy_from(pass)),
        },
    )
    .unwrap();
    request.write_to(&mut client).unwrap();
    drop(request);

    // Daemon: read, parse, take the passphrase, answer with a value.
    let frame = Frame::read_from(&mut server).unwrap();
    let req = IncomingRequest::parse(&frame).unwrap();
    let params: UnlockParams = req.params().unwrap();
    let got = params.passphrase.into_inner();
    assert!(got.ct_eq(pass));
    drop((got, frame));
    let response = proto::result_frame(
        1,
        &Released {
            value: WireSecret::new(SecretBytes::copy_from(value)),
        },
    )
    .unwrap();
    response.write_to(&mut server).unwrap();
    drop(response);

    // Client: read the value.
    let frame = Frame::read_from(&mut client).unwrap();
    let released: Released = proto::parse_response(&frame, 1).unwrap();
    assert!(released.value.as_secret().ct_eq(value));
    drop((released, frame));
}

#[test]
fn frames_leave_no_value_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::GITHUB_TOKEN).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value().to_vec();
    let value = by_label(&cs, labels::OPENAI_API_KEY).value().to_vec();
    // The base64 forms travel in the frames; watch for them too.
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut needles = cs.clone();
    needles.push(Canary::new("PASSPHRASE_B64", b64.encode(&pass)));
    needles.push(Canary::new("VALUE_B64", b64.encode(&value)));

    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&needles, mode);
        round_trip(&pass, &value);
        let report = session.finish();
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        }
    }
}
