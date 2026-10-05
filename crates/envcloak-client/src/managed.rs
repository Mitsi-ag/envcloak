//! What a client checks of a managed server's launch declaration before
//! it contacts the daemon (SPEC §6.6; M2 plan D-33, CR-2; task M2-27;
//! gate 13): no argument and no variable's value may look like a key. A
//! secret a host config held as a launch argument or a variable becomes a
//! binding of the managed manifest, never part of the registered launch,
//! which the record keeps and the receipt shows. `migrate-mcp` (M2-20)
//! calls these before `managed.register` and `managed.update_plan`.

use envcloak_policy::managed::LaunchChanges;

use crate::fail::Failure;
use crate::render::looks_like_value;

fn refused() -> Failure {
    Failure::new(
        "value_on_argv",
        "a launch argument or variable looks like a key: put the key in the vault and bind it \
         in the managed manifest; nothing was sent",
    )
}

/// Refuses a declaration whose `argv` element or `env` value looks like a
/// key ([`looks_like_value`]). Nothing is echoed.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped(argv: &[String], env: &[(String, String)]) -> Result<(), Failure> {
    if argv.iter().any(|a| looks_like_value(a)) || env.iter().any(|(_, v)| looks_like_value(v)) {
        return Err(refused());
    }
    Ok(())
}

/// [`refuse_key_shaped`] for the changes of an update: a new argv and the
/// variables it sets.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped_changes(changes: &LaunchChanges) -> Result<(), Failure> {
    refuse_key_shaped(changes.argv.as_deref().unwrap_or(&[]), &changes.set_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key made at run time, shaped as a generated one: no key-shaped
    /// literal is in the source.
    fn key() -> String {
        let mut x = u64::from(std::process::id()) ^ 0x9e37_79b9_7f4a_7c15;
        let tail: String = (0..40)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(
                    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                        [usize::try_from(x % 57).unwrap()],
                )
            })
            .collect();
        format!("{}_{tail}", concat!("s", "k"))
    }

    /// Gate 13 for managed launches: a key-shaped argument or variable
    /// value is refused before anything is sent, in a registration and in
    /// an update's changes; names and paths pass.
    #[test]
    fn key_shaped_arguments_and_values_are_refused() {
        let k = key();
        let argv = vec![
            "/usr/local/bin/server".to_owned(),
            "--port".to_owned(),
            "8080".to_owned(),
        ];
        assert!(refuse_key_shaped(&argv, &[("MODE".into(), "prod".into())]).is_ok());
        let mut with_key = argv.clone();
        with_key.push(format!("--api-key={k}"));
        assert_eq!(
            refuse_key_shaped(&with_key, &[]).unwrap_err().token(),
            "value_on_argv"
        );
        assert!(refuse_key_shaped(&argv, &[("API".into(), k.clone())]).is_err());
        let changes = LaunchChanges {
            set_env: vec![("API".into(), k)],
            ..LaunchChanges::default()
        };
        assert!(refuse_key_shaped_changes(&changes).is_err());
        assert!(refuse_key_shaped_changes(&LaunchChanges::default()).is_ok());
    }
}
