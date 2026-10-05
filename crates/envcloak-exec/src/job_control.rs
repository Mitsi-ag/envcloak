//! Suspension in PTY mode (SPEC §6.1 step 8 "PTY signals"; M2 plan D-35,
//! review F-76): the order in which `envcloak run --pty` gives the person
//! their terminal back when the command stops, and takes it again when the
//! person resumes the job.
//!
//! The suspend character is relayed as a byte; the slave's line discipline
//! stops the command's group, which is not orphaned (its parent, the PTY
//! monitor, is in its session), and the monitor reports `Stopped`. Then,
//! in this order ([`command_stopped`]):
//!
//! 1. what the command wrote before it stopped is read and released
//!    through the redactor to the outer terminal;
//! 2. the outer terminal gets its saved settings back (`TCSAFLUSH`, so
//!    keys typed and not read are discarded);
//! 3. the CLI stops its own process group with SIGTSTP at its default
//!    action, so the person's shell sees its job stopped and takes the
//!    terminal back. The command is stopped already, so it never runs
//!    while its terminal is restored;
//! 4. on SIGCONT (the person's `fg`) the CLI returns from its stop, reads
//!    the outer terminal's settings again (the person's shell had it, and
//!    a `stty susp ^X` or `stty -echo` made meanwhile is what later
//!    restores put back; a control character the person changed is copied
//!    to the PTY, so the remapped suspend character suspends), puts the
//!    outer terminal back in raw mode and sends the PTY the outer
//!    terminal's size again;
//! 5. only then does it send `Resume`, after which the monitor hands the
//!    slave back to the command's group and continues it. Resumed first,
//!    the command would read and echo in a terminal still in the person's
//!    cooked mode.
//!
//! A terminal that cannot be restored is never left raw under the
//! person's shell: the CLI then does not stop itself, and resumes the
//! command at once (the terminal raw all along). A terminal that cannot be
//! put back in raw mode is never handed to the command: the command is not
//! resumed, no key is read or passed on any more, and the run ends
//! ([`Halt::Raw`]); the command, still stopped, is hung up with its
//! session. Resumed with the outer terminal cooked, the command would ask
//! for a password with its own echo off while the person's terminal
//! showed every key (Codex's review of M2-19).
//!
//! SIGTSTP sent to the CLI by another process ([`stop_requested`]) only
//! asks the monitor to stop the command (`Suspend`): the outer terminal
//! is restored by the same path once the monitor reports the stop, never
//! before, so the command never runs while the terminal is restored. A
//! command that ignores SIGTSTP (an interactive shell) does not stop, and
//! the run goes on in raw mode.
//!
//! No suspend character is ever translated into SIGSTOP.
//!
//! The steps are written against [`Suspension`], so a recording model
//! checks their order (the tests below), as the PTY monitor's loop is
//! checked against its own model.

use std::io;

/// What the suspension sequence does, step by step: implemented by the
/// relay on the real terminal, the PTY and the monitor, and by a recording
/// model in the tests.
pub(crate) trait Suspension {
    /// Reads what the command wrote before it stopped and writes what the
    /// redactor releases to the outer terminal, waiting a bounded time for
    /// its reader; what does not fit then stays for after the resume.
    fn flush_output(&mut self);
    /// Puts the outer terminal's saved settings back (`TCSAFLUSH`).
    fn restore_terminal(&mut self) -> io::Result<()>;
    /// Stops this process's own group with SIGTSTP at its default action;
    /// returns once it is continued.
    fn stop_self(&mut self) -> io::Result<()>;
    /// Reads the outer terminal's settings again, after the person's shell
    /// had it, and keeps them for later restores and raw mode; copies a
    /// control character the person changed to the PTY.
    fn refresh_settings(&mut self);
    /// Puts the outer terminal back in raw mode.
    fn enter_raw(&mut self) -> io::Result<()>;
    /// Sets the PTY's size to the outer terminal's.
    fn resend_size(&mut self);
    /// A place a test build can stop at (`envcloak_sys::pause_point`).
    fn barrier(&mut self, site: &'static str);
    /// Asks the monitor to give the command its terminal back and continue
    /// it (`Resume`).
    fn resume(&mut self) -> io::Result<()>;
    /// Asks the monitor to stop the command's group (`Suspend`).
    fn suspend(&mut self) -> io::Result<()>;
    /// Raw mode could not be taken again: no key is read from the outer
    /// terminal or passed to the command from now on, and those read and
    /// not yet passed on are wiped.
    fn end_input(&mut self);
}

/// Why [`command_stopped`] did not resume the command.
#[derive(Debug)]
pub(crate) enum Halt {
    /// The outer terminal could not be put back in raw mode: the command
    /// stays stopped, input has ended, and the run must end.
    Raw(io::Error),
    /// The monitor could not be asked to resume the command (it is gone;
    /// the relay then sees its channel end).
    Monitor,
}

/// The monitor reported the command stopped: steps 1 to 5 of the module
/// documentation.
///
/// # Errors
/// [`Halt::Raw`] when the outer terminal could not be put back in raw
/// mode: the command was not resumed and input has ended
/// ([`Suspension::end_input`]); [`Halt::Monitor`] when `Resume` could not
/// be sent.
pub(crate) fn command_stopped(s: &mut impl Suspension) -> Result<(), Halt> {
    s.barrier("exec.pty.stopped");
    s.flush_output();
    // Never stopped with the terminal raw: a terminal that cannot be put
    // back (gone, or refused) is not handed to the person's shell, and the
    // command gets its terminal back at once.
    if s.restore_terminal().is_ok() {
        // Not stopped (an orphaned group, which SIGTSTP does not stop, or
        // a failure): the command is resumed all the same.
        let _ = s.stop_self();
        // The person's shell had the terminal: what it holds now is what
        // later restores put back.
        s.refresh_settings();
    }
    // Raw again before the command can read, or the command is never
    // resumed: in the person's cooked mode the outer terminal would show
    // every key the command reads with its own echo off.
    if let Err(e) = s.enter_raw() {
        s.end_input();
        return Err(Halt::Raw(e));
    }
    s.resend_size();
    s.barrier("exec.pty.resume");
    s.resume().map_err(|_| Halt::Monitor)
}

/// SIGTSTP from another process: the command is stopped first, through the
/// monitor; the terminal is restored only when the monitor reports the
/// stop ([`command_stopped`]).
///
/// # Errors
/// The monitor could not be asked (it is gone).
pub(crate) fn stop_requested(s: &mut impl Suspension) -> io::Result<()> {
    s.suspend()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Did {
        Flush,
        Restore,
        StopSelf,
        Refresh,
        Raw,
        Size,
        Barrier(&'static str),
        Resume,
        Suspend,
        EndInput,
    }

    #[derive(Default)]
    struct Model {
        did: Vec<Did>,
        restore_fails: bool,
        raw_fails: bool,
    }

    impl Suspension for Model {
        fn flush_output(&mut self) {
            self.did.push(Did::Flush);
        }
        fn restore_terminal(&mut self) -> io::Result<()> {
            self.did.push(Did::Restore);
            if self.restore_fails {
                return Err(io::ErrorKind::Other.into());
            }
            Ok(())
        }
        fn stop_self(&mut self) -> io::Result<()> {
            self.did.push(Did::StopSelf);
            Ok(())
        }
        fn refresh_settings(&mut self) {
            self.did.push(Did::Refresh);
        }
        fn enter_raw(&mut self) -> io::Result<()> {
            self.did.push(Did::Raw);
            if self.raw_fails {
                return Err(io::ErrorKind::Other.into());
            }
            Ok(())
        }
        fn resend_size(&mut self) {
            self.did.push(Did::Size);
        }
        fn barrier(&mut self, site: &'static str) {
            self.did.push(Did::Barrier(site));
        }
        fn resume(&mut self) -> io::Result<()> {
            self.did.push(Did::Resume);
            Ok(())
        }
        fn suspend(&mut self) -> io::Result<()> {
            self.did.push(Did::Suspend);
            Ok(())
        }
        fn end_input(&mut self) {
            self.did.push(Did::EndInput);
        }
    }

    /// The order of D-35: output first, the terminal restored before the
    /// CLI stops, its settings read again once the person's shell had it,
    /// and raw mode and the size back before `Resume`.
    ///
    /// Mutations checked: stop the CLI before restoring the outer terminal
    /// (the person's shell would get a raw terminal); send `Resume` before
    /// re-entering raw mode (the command would read and echo in a cooked
    /// terminal); take raw mode from the settings saved at the start (no
    /// refresh, review of M2-19, L-09): each fails this.
    #[test]
    fn a_stop_restores_before_the_cli_stops_and_resumes_only_once_raw_again() {
        let mut m = Model::default();
        command_stopped(&mut m).unwrap();
        assert_eq!(
            m.did,
            vec![
                Did::Barrier("exec.pty.stopped"),
                Did::Flush,
                Did::Restore,
                Did::StopSelf,
                Did::Refresh,
                Did::Raw,
                Did::Size,
                Did::Barrier("exec.pty.resume"),
                Did::Resume,
            ]
        );
    }

    /// A terminal that cannot be restored is never left raw under the
    /// person's shell: the CLI does not stop, reads no settings the
    /// person's shell never had, and resumes the command.
    #[test]
    fn a_terminal_that_cannot_be_restored_is_not_handed_back_raw() {
        let mut m = Model {
            restore_fails: true,
            ..Model::default()
        };
        command_stopped(&mut m).unwrap();
        assert!(!m.did.contains(&Did::StopSelf), "{:?}", m.did);
        assert!(!m.did.contains(&Did::Refresh), "{:?}", m.did);
        assert_eq!(m.did.last(), Some(&Did::Resume));
    }

    /// Codex's review of M2-19 (high): raw mode that cannot be taken again
    /// blocks both the resume and the input: the command stays stopped, no
    /// key is passed on from then on, and the caller is told to end the
    /// run. With the terminal never restored either, the same.
    ///
    /// Mutation checked: ignore the failure and resume (as before the
    /// review): `Resume` is sent with the outer terminal cooked, and this
    /// fails.
    #[test]
    fn raw_mode_that_cannot_be_taken_again_resumes_nothing_and_ends_input() {
        for restore_fails in [false, true] {
            let mut m = Model {
                restore_fails,
                raw_fails: true,
                ..Model::default()
            };
            let halted = command_stopped(&mut m);
            assert!(matches!(halted, Err(Halt::Raw(_))), "{halted:?}");
            assert!(!m.did.contains(&Did::Resume), "{:?}", m.did);
            assert!(
                !m.did.contains(&Did::Barrier("exec.pty.resume")),
                "{:?}",
                m.did
            );
            assert_eq!(m.did.last_chunk(), Some(&[Did::Raw, Did::EndInput]));
        }
    }

    /// An outside SIGTSTP only asks the monitor to stop the command; the
    /// terminal is restored later, by the stop's report.
    ///
    /// Mutation checked: restore the outer terminal (and stop the CLI) on
    /// an outside SIGTSTP without stopping the command first: this fails.
    #[test]
    fn an_outside_sigtstp_stops_the_command_and_restores_nothing_yet() {
        let mut m = Model::default();
        stop_requested(&mut m).unwrap();
        assert_eq!(m.did, vec![Did::Suspend]);
    }
}
