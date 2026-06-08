/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import java.util.List;

/**
 * Request/response payloads for the MFA REST resource. Field names are the JSON
 * keys the thunderbird-accounts client sends/expects.
 */
public final class MfaDtos {

    private MfaDtos() {
    }

    public record TotpSetupResponse(
            String secret,
            String encodedSecret,
            String otpAuthUri,
            String qrCode,
            int digits,
            int period,
            String algorithm) {
    }

    public record TotpRegisterRequest(
            String secret,
            String code,
            String deviceName,
            boolean overwrite) {
    }

    public record TotpRegisterResponse(
            boolean success,
            String label) {
    }

    public record RegenerateRequest(
            String deviceName) {
    }

    public record RecoveryCodesResponse(
            List<String> codes,
            int total,
            int remaining) {
    }

    public record ErrorResponse(
            String error) {
    }
}
