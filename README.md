# keycloak-mfa-rest

A small Keycloak extension that exposes REST endpoints for enrolling TOTP and
(re)generating recovery codes, so an external UI (Thunderbird Accounts) can drive
MFA enrollment without the Keycloak browser login flow.

All secret generation, validation, and hashing is delegated to Keycloak's own
credential providers — this extension contains no hand-rolled cryptography.

> The implementation is being added via pull request. See the open PR / feature
> branch for the provider source, build, and CI.

## License

Mozilla Public License, v. 2.0. See [LICENSE](LICENSE).
