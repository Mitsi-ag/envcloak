# Service definitions for envcloakd

`envcloak daemon install` writes one of these for the current user and
loads it (SPEC §4.1). They are here for packagers who install the daemon
another way; the CLI compiles in the same text, and a test fails if the
two drift apart.

| File | Service manager | Installed as |
|---|---|---|
| `launchd/ai.envcloak.envcloakd.plist` | launchd (macOS) | `~/Library/LaunchAgents/ai.envcloak.envcloakd.plist`, loaded into `gui/<uid>` |
| `systemd/envcloakd.service` | systemd (Linux) | `~/.config/systemd/user/ai.envcloak.envcloakd.service` (the user manager's own config directory), enabled for `default.target` |

Placeholders, filled in when the file is written:

- `@LABEL@`: the launchd label, `ai.envcloak.envcloakd`.
- `@ENVCLOAKD@`: the absolute path to `envcloakd`. Service managers never
  search `PATH` for it, and neither does EnvCloak. In the systemd unit it
  is a quoted string with `%` and `$` escaped.
- `@ENVIRONMENT@`: `HOME` and, on Linux, the `XDG_*` base directories the
  installing shell had, so the daemon and the CLI agree on where the vault
  and the socket are. launchd gets `<key>`/`<string>` pairs, systemd
  `Environment=` lines.
- `@LOG@`: the daemon's log, `~/Library/Logs/EnvCloak/envcloakd.log`. Its
  lines are value-free. systemd keeps the log in the journal instead.

Both definitions start the daemon at login, restart it only when it
crashes (a daemon stopped with SIGTERM stays stopped), set the umask to
077, and turn core dumps off before the daemon does so itself.
