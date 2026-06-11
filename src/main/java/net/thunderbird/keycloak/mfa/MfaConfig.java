/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import java.util.Set;

/**
 * Immutable provider configuration, parsed once at boot by
 * {@link MfaResourceProviderFactory#init}.
 *
 * @param authorizedClients allowlist of client IDs (token {@code azp}) whose user tokens
 *                          may self-manage MFA; empty means deny all (fail-closed)
 * @param stepUpAcr         the ACR value the bearer token must carry to count as a recent
 *                          step-up (second-factor) authentication
 * @param stepUpMaxAgeSeconds how recent the token's {@code auth_time} must be for the
 *                            step-up to count
 */
public record MfaConfig(Set<String> authorizedClients, String stepUpAcr, int stepUpMaxAgeSeconds) {
}
