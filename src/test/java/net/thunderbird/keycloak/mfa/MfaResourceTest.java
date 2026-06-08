/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class MfaResourceTest {

    @Test
    void failsClosedWhenNoAuthorizedClientsConfigured() {
        assertFalse(MfaResource.isClientAuthorized(Set.of(), "tb-accounts"));
    }

    @Test
    void rejectsClientNotInAllowlist() {
        assertFalse(MfaResource.isClientAuthorized(Set.of("tb-accounts"), "some-other-client"));
    }

    @Test
    void rejectsNullAzp() {
        assertFalse(MfaResource.isClientAuthorized(Set.of("tb-accounts"), null));
    }

    @Test
    void acceptsAllowlistedClient() {
        assertTrue(MfaResource.isClientAuthorized(Set.of("tb-accounts", "other"), "tb-accounts"));
    }

    @Test
    void normalizeAlgorithmStripsHmacPrefix() {
        assertEquals("SHA1", MfaResource.normalizeAlgorithm("HmacSHA1"));
        assertEquals("SHA256", MfaResource.normalizeAlgorithm("HmacSHA256"));
    }

    @Test
    void normalizeAlgorithmPassesThroughPlainAndNull() {
        assertEquals("SHA1", MfaResource.normalizeAlgorithm("SHA1"));
        assertNull(MfaResource.normalizeAlgorithm(null));
    }
}
