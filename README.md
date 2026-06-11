# keycloak-mfa-rest

A small Keycloak `RealmResourceProvider` that lets a **logged-in user self-manage their
own MFA** — enrol TOTP and (re)generate recovery codes — driven by a front-end app
(thunderbird-accounts) that forwards the user's OIDC access token, **without** the browser
login flow. Every operation acts on the token's subject, so a caller can only ever manage
their own account.

All secret generation, validation, and hashing is delegated to Keycloak's own
credential providers (`HmacOTP`, `CredentialHelper`, `OTPCredentialModel`,
`RecoveryAuthnCodesUtils`, `RecoveryAuthnCodesCredentialProvider`). This module
contains **no** hand-rolled cryptography.

## Endpoints

All endpoints are mounted at `/realms/{realm}/mfa`. See [Authorization](#authorization)
for who may call them.

There is intentionally **no `userId` path parameter** — each endpoint operates on the
subject of the bearer token.

| Method | Path | Body | Returns |
| ------ | ---- | ---- | ------- |
| `GET`  | `/totp/setup` | – | `{ secret, encodedSecret, otpAuthUri, qrCode, digits, period, algorithm }` |
| `POST` | `/totp/register` | `{ secret, code, deviceName? }` | `{ success, label }` |
| `POST` | `/recovery-codes/regenerate` | `{ deviceName? }` | `{ codes, total, remaining }` |

Notes:

- `setup` generates a secret and returns it; the caller holds it (transiently) and
  passes it back to `register` along with the user-entered `code`. The credential is
  only written after the code validates.
- `register` is **enrollment-only**: it validates the code via
  `CredentialValidation.validOTP` before writing, and returns
  `409 { "error": "mfa_already_configured" }` when a TOTP credential already exists.
  There is deliberately no overwrite/replace — a bearer token alone must never be able
  to swap the user's authenticator for another one. Re-enrollment ("I got a new phone")
  is remove (a privileged, step-up-gated operation in the consuming app, via the Admin
  API) followed by a fresh register.
- `recovery-codes/regenerate` is single-step: it replaces any existing recovery-codes
  credential and returns the new plaintext codes **once**. The "this resets your old
  codes" confirmation lives in the calling UI. Recovery codes are strictly a **backup
  for the authenticator app**, never a standalone factor: the endpoint returns
  `409 { "error": "totp_not_configured" }` when the user has no TOTP credential.
  (Keycloak silently deletes the recovery-codes credential once the last code is spent
  at login, so a codes-only account would be a few logins away from having no second
  factor at all.) The endpoint also requires step-up
  (see [Step-up](#step-up-on-sensitive-mutations)).
- `deviceName` is stored as the credential's user label and is capped at 255 characters
  (Keycloak's column size); longer values return `400 { "error": "invalid_device_name" }`.

## Authorization

The model is **user self-service**, not admin-on-behalf:

1. **Bearer token required** — the caller forwards the end user's OIDC access token. No
   token → `401`.
2. **Subject-scoped** — the resource acts only on `token.sub`; there is no id to spoof, so
   a caller can never touch another user's MFA.
3. **Fail-closed client allowlist** — the token's `azp` must be in the configured
   `authorized-clients` allowlist. The allowlist is **required**: when it is empty the
   resource denies everything (`403`). This pins access to the front-end app's OIDC client
   whose user tokens are forwarded here.

Failures return `401 { "error": "not_authenticated" }` (no token / token without a user),
with a `WWW-Authenticate: Bearer` challenge, or `403 { "error": "client_not_authorized" }`
(client not allowlisted).

### Step-up on sensitive mutations

`recovery-codes/regenerate` requires the token to **prove a recent
second-factor authentication** (token-claims step-up, in the spirit of RFC 9470):

- the token's `acr` claim must equal `step-up-acr` (default `"2"`, the realm's
  second-factor level), **and**
- the token's `auth_time` claim must be no older than `step-up-max-age-seconds`.

When the check fails the endpoint returns `401 { "error": "step_up_required" }` with a
`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...",
max_age=...` challenge (RFC 9470). The consuming app should send the user through
Keycloak's login flow with `acr_values=<step-up-acr>` and `max_age=0` (forcing an
active re-authentication so `auth_time` is refreshed — otherwise a stale stepped-up
session satisfies `acr` but not the freshness check and the redirect loops), then retry
with the fresh token.

A TOTP credential always exists when the gate runs (without one, regenerate is rejected
with `409 totp_not_configured`). The gate is skipped in exactly one situation:
**immediately after TOTP enrollment**, when the user's TOTP credential was registered
within the step-up window. Registering it required presenting a valid live OTP code,
which is exactly the proof a step-up would demand, so the common
enrol-authenticator-then-save-recovery-codes flow doesn't prompt twice.

Residual risks to be aware of: a token replayed *within* `step-up-max-age-seconds` of a
genuine second-factor authentication still passes — the window is bounded but non-zero.
And first-time TOTP enrollment on an account with no MFA cannot be acr-gated (there is
no factor to challenge), so that surface is protected only by proving the new code.

Secret-bearing responses (`setup`, `recovery-codes/regenerate`) are returned with
`Cache-Control: no-store` and `Pragma: no-cache`. Credential mutations emit Keycloak
`UPDATE_CREDENTIAL` events (success and invalid-code failure) recording the user, the
acting client, and the source IP — enable realm event logging for an audit trail.

Administrative reset of *another* user's MFA is deliberately out of scope for this
resource; do that in a privileged context (e.g. an admin panel using the Keycloak Admin
API or a separate, role-gated endpoint).

## Configuration

| Option | Config key / env | Default | Purpose |
| ------ | ---------------- | ------- | ------- |
| Authorized clients | `spi-realm-restapi-extension-mfa-authorized-clients` / `KC_SPI_REALM_RESTAPI_EXTENSION_MFA_AUTHORIZED_CLIENTS` | _(unset → deny all)_ | **Required.** Comma-separated client IDs whose user tokens (matched on `azp`) may self-manage MFA — typically the front-end app's OIDC client. |
| Step-up ACR | `spi-realm-restapi-extension-mfa-step-up-acr` / `KC_SPI_REALM_RESTAPI_EXTENSION_MFA_STEP_UP_ACR` | `2` | ACR claim value a token must carry for step-up-gated mutations — the realm's second-factor level of authentication. |
| Step-up max age | `spi-realm-restapi-extension-mfa-step-up-max-age-seconds` / `KC_SPI_REALM_RESTAPI_EXTENSION_MFA_STEP_UP_MAX_AGE_SECONDS` | `600` | Maximum age (seconds) of the token's `auth_time` claim for the step-up to count as recent. Keep aligned with the consuming app's recent-auth window (thunderbird-accounts `MFA_RECENT_AUTH_SECONDS`) so the two layers expire together. |

## Building

Building happens in CI (see `.github/workflows/ci.yml`). For a local build, use a
throwaway container — only Docker is required, no JDK or Maven on your machine:

```bash
git clone https://github.com/thunderbird/keycloak-mfa-rest.git
cd keycloak-mfa-rest

docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-17 mvn -B verify
```

`mvn -B verify` compiles, runs the unit tests, and packages the module; the result is
`target/keycloak-mfa-rest.jar`. (`-B` is Maven's non-interactive batch mode.)

Notes:

- The `maven` image runs as root, so `target/` is created root-owned. Clean it with
  `mvn -B clean` in the same container, or `sudo rm -rf target`.
- Each `--rm` run re-downloads dependencies. To cache them across builds, mount a
  local repository (already gitignored as `.m2repo/`):

  ```bash
  docker run --rm -v "$PWD":/app -v "$PWD/.m2repo":/root/.m2 -w /app \
      maven:3.9-eclipse-temurin-17 mvn -B verify
  ```

## Releasing

CI runs on two triggers (see `.github/workflows/ci.yml`): pull requests to `main` run
build + test (the merge gate), and pushing a `v*` tag runs build + test and then publishes
a GitHub Release. There are no automatic releases on merge — cutting a release is an
explicit, tagged action.

To cut a release:

1. Bump `<version>` in `pom.xml` (on its own PR, or just before tagging) and merge to `main`.
2. Tag that commit and push the tag:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. CI builds the jar and publishes Release `v0.1.0` with `keycloak-mfa-rest.jar` and
   `keycloak-mfa-rest.jar.sha256` attached.
4. Point the consumer at it (see [Deploying into Keycloak](#deploying-into-keycloak)):
   set the pinned version and `sha256` from the release.

## Deploying into Keycloak

Consumers (e.g. thunderbird-accounts `Dockerfile.keycloak`) download the pinned,
checksummed jar into `/opt/keycloak/providers/` and run `kc.sh build`:

```dockerfile
ADD --checksum=sha256:<sha> \
    https://github.com/thunderbird/keycloak-mfa-rest/releases/download/v<ver>/keycloak-mfa-rest.jar \
    /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

## Realm requirements

- The recovery-codes feature must be available (supported and enabled by default in
  Keycloak 26.3+).
- Set the `authorized-clients` allowlist (see [Configuration](#configuration)) to the
  front-end app's OIDC client ID — the client whose user tokens are forwarded here. This
  is required; without it the resource denies all requests.
- The forwarded token must be a normal user access token from that client (its `azp` is the
  client ID).
- Recommended: enable realm event logging so credential-mutation events are persisted.

## Keycloak version

Targets the Keycloak version in `pom.xml` (`keycloak.version`). Keep it aligned with
the Keycloak image tag used by the consuming deployment.
