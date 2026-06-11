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

    @Test
    void labelLengthAcceptsNullAndBoundary() {
        assertFalse(MfaResource.exceedsLabelLength(null));
        assertFalse(MfaResource.exceedsLabelLength("a".repeat(MfaResource.MAX_LABEL_LENGTH)));
    }

    @Test
    void labelLengthRejectsOverlongDeviceName() {
        assertTrue(MfaResource.exceedsLabelLength("a".repeat(MfaResource.MAX_LABEL_LENGTH + 1)));
    }

    // --- satisfiesStepUp: token-claims step-up (acr + auth_time freshness) ---

    private static final String REQUIRED_ACR = "2";
    private static final int MAX_AGE = 600;
    private static final long NOW_SECONDS = 1_700_000_000L;

    @Test
    void stepUpSatisfiedByMatchingAcrAndFreshAuthTime() {
        assertTrue(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, "2", NOW_SECONDS - 30, NOW_SECONDS));
    }

    @Test
    void stepUpSatisfiedExactlyAtMaxAgeBoundary() {
        assertTrue(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, "2", NOW_SECONDS - MAX_AGE, NOW_SECONDS));
    }

    @Test
    void stepUpRejectsAcrMismatch() {
        assertFalse(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, "1", NOW_SECONDS - 30, NOW_SECONDS));
    }

    @Test
    void stepUpRejectsMissingAcr() {
        assertFalse(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, null, NOW_SECONDS - 30, NOW_SECONDS));
    }

    @Test
    void stepUpRejectsStaleAuthTime() {
        assertFalse(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, "2", NOW_SECONDS - MAX_AGE - 1, NOW_SECONDS));
    }

    @Test
    void stepUpRejectsMissingAuthTime() {
        assertFalse(MfaResource.satisfiesStepUp(REQUIRED_ACR, MAX_AGE, "2", null, NOW_SECONDS));
    }

    // --- isStepUpRequiredForRegenerate: when regenerating recovery codes needs the gate.
    // A TOTP credential is guaranteed to exist by the time the gate runs — codes-only
    // (re)generation is rejected outright with totp_not_configured before this check. ---

    private static final long NOW_MILLIS = NOW_SECONDS * 1000L;

    @Test
    void regenerateIsGatedForEstablishedTotp() {
        long establishedTotpCreatedAt = NOW_MILLIS - (MAX_AGE * 1000L) - 1;
        assertTrue(MfaResource.isStepUpRequiredForRegenerate(establishedTotpCreatedAt, NOW_MILLIS, MAX_AGE));
    }

    @Test
    void regenerateIsUngatedRightAfterTotpEnrollment() {
        // Registering the TOTP just required a valid live OTP code — that is the proof a
        // step-up would demand, so the chained enrol-then-save-codes flow is not gated.
        assertFalse(MfaResource.isStepUpRequiredForRegenerate(NOW_MILLIS - 30_000L, NOW_MILLIS, MAX_AGE));
    }

    @Test
    void regenerateIsUngatedExactlyAtFreshEnrollmentBoundary() {
        assertFalse(MfaResource.isStepUpRequiredForRegenerate(NOW_MILLIS - (MAX_AGE * 1000L), NOW_MILLIS, MAX_AGE));
    }

    @Test
    void regenerateIsGatedWhenTotpHasNoCreationDate() {
        // Fail closed: a TOTP credential without a createdDate cannot prove it is fresh.
        assertTrue(MfaResource.isStepUpRequiredForRegenerate(null, NOW_MILLIS, MAX_AGE));
    }

    // --- MfaError wire codes. These strings are the JSON/audit contract; the three the
    // consumer branches on are also matched in thunderbird-accounts' mfa.py. Pin them so an
    // accidental rename fails here rather than silently breaking the integration. ---

    @Test
    void errorCodesMatchWireContract() {
        assertEquals("not_authenticated", MfaError.NOT_AUTHENTICATED.code());
        assertEquals("client_not_authorized", MfaError.CLIENT_NOT_AUTHORIZED.code());
        assertEquals("invalid_device_name", MfaError.INVALID_DEVICE_NAME.code());
        assertEquals("missing_fields", MfaError.MISSING_FIELDS.code());
        assertEquals("invalid_code", MfaError.INVALID_CODE.code());
        assertEquals("mfa_already_configured", MfaError.MFA_ALREADY_CONFIGURED.code());
        assertEquals("totp_not_configured", MfaError.TOTP_NOT_CONFIGURED.code());
        assertEquals("step_up_required", MfaError.STEP_UP_REQUIRED.code());
        assertEquals("recovery_codes_unavailable", MfaError.RECOVERY_CODES_UNAVAILABLE.code());
    }
}
