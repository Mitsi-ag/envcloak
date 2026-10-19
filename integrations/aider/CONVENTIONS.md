<!-- envcloak:begin -->
## EnvCloak

This machine keeps API keys and other secrets in EnvCloak, not in files or in the chat.

- Never read `.env` files, never print environment variables, and never ask the person to paste a key into the chat.
- If the project has an `envcloak.toml`, run anything that needs its secrets as `envcloak run -- <command>`.
- If a key is missing, run `envcloak ls` (names only) and bind it with `envcloak ref NAME=<slug>`; if it does not exist, ask the person to run `envcloak add <provider>` in their own terminal.
- If the project has plaintext `.env` files and no `envcloak.toml`, suggest `envcloak init`.
<!-- envcloak:end -->
