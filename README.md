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
| `POST` | `/totp/register` | `{ secret, code, deviceName?, overwrite? }` | `{ success, label }` |
| `POST` | `/recovery-codes/regenerate` | `{ deviceName? }` | `{ codes, total, remaining }` |

Notes:

- `setup` generates a secret and returns it; the caller holds it (transiently) and
  passes it back to `register` along with the user-entered `code`. The credential is
  only written after the code validates.
- `register` validates the code via `CredentialValidation.validOTP` before writing,
  and `overwrite: true` replaces any existing TOTP credential.
- `recovery-codes/regenerate` is single-step: it replaces any existing recovery-codes
  credential and returns the new plaintext codes **once**. The "this resets your old
  codes" confirmation lives in the calling UI.

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

Failures return `401` (no token / token without a user) or `403` (client not allowlisted).

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
