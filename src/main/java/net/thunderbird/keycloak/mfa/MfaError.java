/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

/**
 * Machine-readable error codes returned in {@code ErrorResponse} bodies and recorded as the
 * {@code error} detail on audit events.
 *
 * <p>Three of these are a <b>wire contract</b> with the consuming app (thunderbird-accounts'
 * {@code mfa.py}) and the cross-repo e2e suite — the consumer branches on them to choose a
 * response: {@link #MFA_ALREADY_CONFIGURED} and {@link #TOTP_NOT_CONFIGURED} (mapped to a
 * {@code 409}) and {@link #STEP_UP_REQUIRED} (drives the reauth redirect). The remainder are
 * status-driven for the consumer, so their string is informational/audit only. Renaming a
 * contract code requires the matching change in the consumer; the e2e suite is the guard.</p>
 *
 * <p>The enum exists for in-plugin call-site safety: {@code error(...)} and
 * {@code auditFailure(...)} accept an {@code MfaError} rather than a loose {@code String}, so
 * a typo or ad-hoc code cannot reach a response or an event.</p>
 */
public enum MfaError {
    NOT_AUTHENTICATED("not_authenticated"),
    CLIENT_NOT_AUTHORIZED("client_not_authorized"),
    MISSING_FIELDS("missing_fields"),
    INVALID_DEVICE_NAME("invalid_device_name"),
    INVALID_CODE("invalid_code"),
    MFA_ALREADY_CONFIGURED("mfa_already_configured"),
    TOTP_NOT_CONFIGURED("totp_not_configured"),
    STEP_UP_REQUIRED("step_up_required"),
    RECOVERY_CODES_UNAVAILABLE("recovery_codes_unavailable");

    private final String code;

    MfaError(String code) {
        this.code = code;
    }

    /** The wire/audit string: the value sent in the JSON body and recorded on events. */
    public String code() {
        return code;
    }
}
