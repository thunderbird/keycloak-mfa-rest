/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Set;

import net.thunderbird.keycloak.mfa.MfaDtos.ErrorResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.RecoveryCodesResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.RegenerateRequest;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpRegisterRequest;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpRegisterResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpSetupResponse;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProvider;
import org.keycloak.credential.RecoveryAuthnCodesCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.RecoveryAuthnCodesCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.RecoveryAuthnCodesUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

/**
 * REST resource mounted at {@code /realms/{realm}/mfa}.
 *
 * <p><b>Self-service only.</b> Every endpoint operates on the <em>subject of the bearer
 * token</em> — the authenticated end user — so a caller can only ever manage their own
 * MFA. There is no {@code userId} path parameter to spoof. Administrative reset of another
 * user's MFA is intentionally out of scope here and handled separately in a privileged
 * context.</p>
 *
 * <p>Authorization fails closed: a configured allowlist of client IDs (matched against the
 * token's {@code azp}) is <b>required</b>; when it is empty the resource denies all
 * requests. This pins access to the front-end application's OIDC client whose user tokens
 * are forwarded here.</p>
 *
 * <p>Sensitive mutations against an account that already has MFA in place additionally
 * require <b>token-claims step-up</b> (RFC 9470 style): the bearer token must carry the
 * configured ACR and a fresh {@code auth_time}, proving a recent second-factor
 * authentication. The plugin never collects an OTP code itself for this — the consuming
 * app drives the prompt through Keycloak's login flow ({@code acr_values}) and retries
 * with the fresh token.</p>
 *
 * <p>All secret generation/validation/hashing is delegated to Keycloak's own credential
 * providers. Credential mutations emit {@code UPDATE_CREDENTIAL} events (with source IP)
 * for audit, and secret-bearing responses are returned with {@code Cache-Control: no-store}.</p>
 *
 * <p>Assumes all users are local Keycloak users: credential reads and writes go through
 * Keycloak's local credential store only (no user-storage/federated credentials).</p>
 */
public class MfaResource {

    private static final String DEFAULT_TOTP_LABEL = "Authenticator app";
    private static final String DEFAULT_RECOVERY_LABEL = "Recovery codes";
    private static final int TOTP_SECRET_LENGTH = 20;
    /** Keycloak stores credential labels in CREDENTIAL.USER_LABEL, a varchar(255). */
    static final int MAX_LABEL_LENGTH = 255;
    /** RFC 6750 challenge for 401s caused by a missing/invalid bearer token. */
    private static final String BEARER_CHALLENGE = "Bearer";

    private final KeycloakSession session;
    private final MfaConfig config;

    public MfaResource(KeycloakSession session, MfaConfig config) {
        this.session = session;
        this.config = config;
    }

    @GET
    @Path("totp/setup")
    @Produces(MediaType.APPLICATION_JSON)
    public Response totpSetup() {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = authenticate().user();

        OTPPolicy policy = realm.getOTPPolicy();
        String secret = HmacOTP.generateSecret(TOTP_SECRET_LENGTH);
        String otpAuthUri = policy.getKeyURI(realm, user, secret);
        String encodedSecret = TotpUtils.encode(secret);
        String qrCode = TotpUtils.qrCode(secret, realm, user);

        return noStore(new TotpSetupResponse(
                secret,
                encodedSecret,
                otpAuthUri,
                qrCode,
                policy.getDigits(),
                policy.getPeriod(),
                normalizeAlgorithm(policy.getAlgorithm())));
    }

    @POST
    @Path("totp/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response totpRegister(TotpRegisterRequest request) {
        RealmModel realm = session.getContext().getRealm();
        Caller caller = authenticate();
        UserModel user = caller.user();

        if (request == null || isBlank(request.secret()) || isBlank(request.code())) {
            return error(Response.Status.BAD_REQUEST, MfaError.MISSING_FIELDS);
        }
        if (exceedsLabelLength(request.deviceName())) {
            return error(Response.Status.BAD_REQUEST, MfaError.INVALID_DEVICE_NAME);
        }

        // Enrollment-only: registering never replaces an existing authenticator. This keeps
        // a stolen bearer token from silently swapping the user's TOTP for an
        // attacker-controlled one. Re-enrollment is remove (admin API, step-up gated in the
        // consuming app) followed by a fresh register.
        if (hasCredentialOfType(user, OTPCredentialModel.TYPE)) {
            auditFailure(realm, user, OTPCredentialModel.TYPE, caller.clientId(), MfaError.MFA_ALREADY_CONFIGURED);
            return error(Response.Status.CONFLICT, MfaError.MFA_ALREADY_CONFIGURED);
        }

        OTPPolicy policy = realm.getOTPPolicy();
        String label = isBlank(request.deviceName()) ? DEFAULT_TOTP_LABEL : request.deviceName();
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, request.secret(), label);

        // Pre-validate before writing: CredentialHelper.createOTPCredential persists the
        // credential and only then checks the code, so without this gate an invalid code
        // would leave an orphaned credential. This mirrors Keycloak's own UpdateTotp.
        if (!CredentialValidation.validOTP(request.code(), credentialModel, policy.getLookAheadWindow())) {
            auditFailure(realm, user, OTPCredentialModel.TYPE, caller.clientId(), MfaError.INVALID_CODE);
            return error(Response.Status.BAD_REQUEST, MfaError.INVALID_CODE);
        }

        boolean created = CredentialHelper.createOTPCredential(session, realm, user, request.code(), credentialModel);
        if (!created) {
            // createOTPCredential persists the credential *before* its own validation, so a
            // code that expired between our pre-check and that validation (period boundary)
            // has already been written. Clean it up — we verified above that no TOTP existed,
            // so anything present now is the half-written orphan — otherwise the user would be
            // permanently stuck behind the enrollment-only 409 and need an admin to recover.
            removeCredentialsOfType(user, OTPCredentialModel.TYPE);
            auditFailure(realm, user, OTPCredentialModel.TYPE, caller.clientId(), MfaError.INVALID_CODE);
            return error(Response.Status.BAD_REQUEST, MfaError.INVALID_CODE);
        }

        auditChange(realm, user, OTPCredentialModel.TYPE, caller.clientId());
        return noStore(new TotpRegisterResponse(true, label));
    }

    @POST
    @Path("recovery-codes/regenerate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response recoveryCodesRegenerate(RegenerateRequest request) {
        RealmModel realm = session.getContext().getRealm();
        Caller caller = authenticate();
        UserModel user = caller.user();

        if (request != null && exceedsLabelLength(request.deviceName())) {
            return error(Response.Status.BAD_REQUEST, MfaError.INVALID_DEVICE_NAME);
        }

        // Recovery codes are strictly a backup for the authenticator app, never a
        // standalone factor: a codes-only account is a few logins away from unprotected,
        // because Keycloak deletes the credential when the last code is spent. Reject
        // any (re)generation unless a TOTP credential exists.
        if (!hasCredentialOfType(user, OTPCredentialModel.TYPE)) {
            auditFailure(realm, user, RecoveryAuthnCodesCredentialModel.TYPE, caller.clientId(),
                    MfaError.TOTP_NOT_CONFIGURED);
            return error(Response.Status.CONFLICT, MfaError.TOTP_NOT_CONFIGURED);
        }

        // Step-up gate: replacing the recovery codes requires the token to prove a recent
        // second-factor authentication (acr + auth_time). A 401 with this marker tells the
        // consuming app to drive its reauth redirect and retry.

        // When was the user's current TOTP credential registered? Drives the one exemption
        // below; null only in a race where it was removed since the check above.
        Long newestTotpCreatedAt = newestCredentialCreatedAt(user, OTPCredentialModel.TYPE);

        // Does this operation need step-up at all? Yes, except right after TOTP enrollment:
        // registering it already required a live OTP code, so re-challenging within the
        // step-up window would prompt twice for the same proof.
        boolean stepUpRequired = isStepUpRequiredForRegenerate(
                newestTotpCreatedAt, Time.currentTimeMillis(), config.stepUpMaxAgeSeconds());

        // Does the presented token already satisfy step-up? It must carry the configured
        // acr and an auth_time no older than the max age — i.e. the user recently completed
        // a second factor, not just resumed an old session.
        boolean tokenProvesStepUp = satisfiesStepUp(
                config.stepUpAcr(), config.stepUpMaxAgeSeconds(),
                caller.token().getAcr(), caller.token().getAuth_time(), Time.currentTime());

        // Gate fails closed: needs step-up but the token doesn't prove it → reject.
        if (stepUpRequired && !tokenProvesStepUp) {
            auditFailure(realm, user, RecoveryAuthnCodesCredentialModel.TYPE, caller.clientId(),
                    MfaError.STEP_UP_REQUIRED);
            // RFC 9470 challenge: tells the client which acr/max_age to request on reauth.
            return unauthorized(MfaError.STEP_UP_REQUIRED, String.format(
                    "Bearer error=\"insufficient_user_authentication\", acr_values=\"%s\", max_age=%d",
                    config.stepUpAcr(), config.stepUpMaxAgeSeconds()));
        }

        // The concrete-class cast mirrors Keycloak's own call sites and keeps the provider
        // type-checked. The guard exists because the provider is absent when the
        // recovery-codes feature is disabled.
        CredentialProvider<RecoveryAuthnCodesCredentialModel> recoveryProvider =
                (RecoveryAuthnCodesCredentialProvider) session.getProvider(
                        CredentialProvider.class, RecoveryAuthnCodesCredentialProviderFactory.PROVIDER_ID);
        if (recoveryProvider == null) {
            return error(Response.Status.SERVICE_UNAVAILABLE, MfaError.RECOVERY_CODES_UNAVAILABLE);
        }

        String label = (request != null && !isBlank(request.deviceName()))
                ? request.deviceName()
                : DEFAULT_RECOVERY_LABEL;

        // Single-step replace: the UI has already confirmed the user wants to reset
        // their existing codes, so drop the old credential and write a fresh one.
        removeCredentialsOfType(user, RecoveryAuthnCodesCredentialModel.TYPE);

        List<String> rawCodes = RecoveryAuthnCodesUtils.generateRawCodes();
        RecoveryAuthnCodesCredentialModel credentialModel =
                RecoveryAuthnCodesCredentialModel.createFromValues(rawCodes, Time.currentTimeMillis(), label);
        recoveryProvider.createCredential(realm, user, credentialModel);

        auditChange(realm, user, RecoveryAuthnCodesCredentialModel.TYPE, caller.clientId());
        return noStore(new RecoveryCodesResponse(rawCodes, rawCodes.size(), rawCodes.size()));
    }

    /**
     * Authenticate the bearer token and resolve the calling user (the token subject).
     * Authorization fails closed on the configured client allowlist (token {@code azp}).
     *
     * <p>Failure responses carry the same JSON {@code {"error": ...}} body as the endpoints:
     * {@code 401 not_authenticated} (missing or invalid bearer token, or a token without an
     * associated user) with a {@code WWW-Authenticate: Bearer} challenge, and
     * {@code 403 client_not_authorized} (client not allowlisted).</p>
     */
    private Caller authenticate() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException(unauthorized(MfaError.NOT_AUTHENTICATED, BEARER_CHALLENGE));
        }

        AccessToken token = auth.token();
        if (!isClientAuthorized(config.authorizedClients(), token.getIssuedFor())) {
            throw new ForbiddenException(error(Response.Status.FORBIDDEN, MfaError.CLIENT_NOT_AUTHORIZED));
        }

        // Operate strictly on the token subject — never a client-supplied id.
        UserModel user = auth.user();
        if (user == null) {
            throw new NotAuthorizedException(unauthorized(MfaError.NOT_AUTHENTICATED, BEARER_CHALLENGE));
        }
        return new Caller(user, token.getIssuedFor(), token);
    }

    /**
     * Fail-closed client authorization: the allowlist must be configured (non-empty) and
     * the token's authorized party ({@code azp}) must be a member. Package-private and
     * exception-free for unit testing.
     */
    static boolean isClientAuthorized(Set<String> authorizedClients, String azp) {
        return !authorizedClients.isEmpty() && azp != null && authorizedClients.contains(azp);
    }

    /**
     * Token-claims step-up check: the validated bearer token must carry the configured ACR
     * (the user's session reached the second-factor level) <em>and</em> an {@code auth_time}
     * no older than {@code maxAgeSeconds} (the authentication is recent, not a stale
     * session). Package-private and exception-free for unit testing.
     */
    static boolean satisfiesStepUp(String requiredAcr, int maxAgeSeconds,
            String tokenAcr, Long authTimeSeconds, long nowSeconds) {
        if (tokenAcr == null || !tokenAcr.equals(requiredAcr)) {
            return false;
        }
        if (authTimeSeconds == null) {
            return false;
        }
        return nowSeconds - authTimeSeconds <= maxAgeSeconds;
    }

    /**
     * Whether regenerating recovery codes must be step-up gated. A TOTP credential is
     * guaranteed to exist by the time this runs (codes-only enrollment is rejected with
     * {@link MfaError#TOTP_NOT_CONFIGURED}), so the only exemption is a TOTP created within
     * the step-up window: registering it just required presenting a valid live OTP code,
     * which is exactly the proof a step-up would demand. This keeps the
     * enrol-TOTP-then-save-codes flow from prompting twice. A missing creation date fails
     * closed (gated).
     *
     * <p>Package-private and exception-free for unit testing.</p>
     */
    static boolean isStepUpRequiredForRegenerate(Long newestTotpCreatedAtMillis, long nowMillis, int maxAgeSeconds) {
        boolean totpJustEnrolled = newestTotpCreatedAtMillis != null
                && nowMillis - newestTotpCreatedAtMillis <= maxAgeSeconds * 1000L;
        return !totpJustEnrolled;
    }

    private void auditChange(RealmModel realm, UserModel user, String credentialType, String clientId) {
        credentialEvent(realm, user, credentialType, clientId).success();
    }

    private void auditFailure(RealmModel realm, UserModel user, String credentialType, String clientId,
            MfaError error) {
        credentialEvent(realm, user, credentialType, clientId).error(error.code());
    }

    private EventBuilder credentialEvent(RealmModel realm, UserModel user, String credentialType, String clientId) {
        return new EventBuilder(realm, session, session.getContext().getConnection())
                .event(EventType.UPDATE_CREDENTIAL)
                .user(user)
                .client(clientId)
                .ipAddress(session.getContext().getConnection().getRemoteAddr())
                .detail(Details.CREDENTIAL_TYPE, credentialType);
    }

    private void removeCredentialsOfType(UserModel user, String type) {
        List<String> ids = user.credentialManager()
                .getStoredCredentialsByTypeStream(type)
                .map(CredentialModel::getId)
                .toList();
        ids.forEach(id -> user.credentialManager().removeStoredCredentialById(id));
    }

    private static boolean hasCredentialOfType(UserModel user, String type) {
        return user.credentialManager().getStoredCredentialsByTypeStream(type).findAny().isPresent();
    }

    /** Creation time (epoch millis) of the newest credential of {@code type}, or null when none has one. */
    private static Long newestCredentialCreatedAt(UserModel user, String type) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(type)
                .map(CredentialModel::getCreatedDate)
                .filter(createdDate -> createdDate != null)
                .max(Long::compareTo)
                .orElse(null);
    }

    private static Response noStore(Object entity) {
        return standardHeaders(Response.ok(entity)).build();
    }

    private static Response error(Response.Status status, MfaError error) {
        return standardHeaders(Response.status(status).entity(new ErrorResponse(error.code()))).build();
    }

    /** 401 with the JSON error body and a WWW-Authenticate challenge (RFC 7235 requires one). */
    private static Response unauthorized(MfaError error, String challenge) {
        return standardHeaders(Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
                .entity(new ErrorResponse(error.code())))
                .build();
    }

    static boolean exceedsLabelLength(String deviceName) {
        return deviceName != null && deviceName.length() > MAX_LABEL_LENGTH;
    }

    /**
     * Helper for every response this resource builds: JSON content type plus
     * no-store cache headers. Media type is required — responses thrown
     * from {@code authenticate()} (inside {@code NotAuthorizedException}/
     * {@code ForbiddenException}) bypass {@code @Produces} resolution, and Keycloak's
     * security-headers filter 500s any entity-bearing response without a resolved type.
     */
    private static Response.ResponseBuilder standardHeaders(Response.ResponseBuilder builder) {
        return builder.type(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        return algorithm.startsWith("Hmac") ? algorithm.substring(4) : algorithm;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Authenticated caller context: the subject user, acting client id (azp), and validated token. */
    private record Caller(UserModel user, String clientId, AccessToken token) {
    }
}
