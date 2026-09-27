# Security policy

EnvCloak stores other people's credentials, so we treat security reports as the highest priority work in the project.

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub:
https://github.com/Mitsi-ag/envcloak/security/advisories/new

Include what you found, how to reproduce it, and the impact you expect. You will get an acknowledgement within 72 hours and a status update at least weekly until the issue is resolved. We will credit you in the advisory unless you ask us not to.

## Scope

In scope: the `envcloak` CLI, the `envcloakd` daemon, the macOS app, the MCP server, agent integrations shipped in this repository, the vault format, pairing and sync, and proxy mode.

The threat model, including what EnvCloak deliberately does not defend against, is in [docs/SPEC.md](docs/SPEC.md#10-threat-model).

## Supported versions

Until 1.0, only the latest release receives security fixes.
