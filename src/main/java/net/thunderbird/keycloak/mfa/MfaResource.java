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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import net.thunderbird.keycloak.mfa.MfaDtos.ErrorResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.RecoveryCodesResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.RegenerateRequest;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpRegisterRequest;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpRegisterResponse;
import net.thunderbird.keycloak.mfa.MfaDtos.TotpSetupResponse;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
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
 * <p>All secret generation/validation/hashing is delegated to Keycloak's own credential
 * providers. Credential mutations emit {@code UPDATE_CREDENTIAL} events (with source IP)
 * for audit, and secret-bearing responses are returned with {@code Cache-Control: no-store}.</p>
 */
public class MfaResource {

    private static final String DEFAULT_TOTP_LABEL = "Authenticator app";
    private static final String DEFAULT_RECOVERY_LABEL = "Recovery codes";
    private static final int TOTP_SECRET_LENGTH = 20;

    private final KeycloakSession session;
    /** Allowlist of client IDs (azp) whose user tokens may self-manage MFA. Required (fail-closed). */
    private final Set<String> authorizedClients;

    public MfaResource(KeycloakSession session, Set<String> authorizedClients) {
        this.session = session;
        this.authorizedClients = authorizedClients;
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
            return error(Response.Status.BAD_REQUEST, "missing_fields");
        }

        OTPPolicy policy = realm.getOTPPolicy();
        String label = isBlank(request.deviceName()) ? DEFAULT_TOTP_LABEL : request.deviceName();
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, request.secret(), label);

        // Pre-validate before writing: CredentialHelper.createOTPCredential persists the
        // credential and only then checks the code, so without this gate an invalid code
        // would leave an orphaned credential. This mirrors Keycloak's own UpdateTotp.
        if (!CredentialValidation.validOTP(request.code(), credentialModel, policy.getLookAheadWindow())) {
            auditFailure(realm, user, OTPCredentialModel.TYPE, caller.clientId(), "invalid_code");
            return error(Response.Status.BAD_REQUEST, "invalid_code");
        }

        if (request.overwrite()) {
            removeCredentialsOfType(user, OTPCredentialModel.TYPE);
        }

        boolean created = CredentialHelper.createOTPCredential(session, realm, user, request.code(), credentialModel);
        if (!created) {
            auditFailure(realm, user, OTPCredentialModel.TYPE, caller.clientId(), "invalid_code");
            return error(Response.Status.BAD_REQUEST, "invalid_code");
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

        CredentialProvider recoveryProvider = session.getProvider(
                CredentialProvider.class, RecoveryAuthnCodesCredentialProviderFactory.PROVIDER_ID);
        if (recoveryProvider == null) {
            return error(Response.Status.SERVICE_UNAVAILABLE, "recovery_codes_unavailable");
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
     */
    private Caller authenticate() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer token required");
        }

        AccessToken token = auth.getToken();
        if (!isClientAuthorized(authorizedClients, token.getIssuedFor())) {
            throw new ForbiddenException("Client not authorized to manage MFA: " + token.getIssuedFor());
        }

        // Operate strictly on the token subject — never a client-supplied id.
        UserModel user = auth.getUser();
        if (user == null) {
            throw new NotAuthorizedException("Token has no associated user");
        }
        return new Caller(user, token.getIssuedFor());
    }

    /**
     * Fail-closed client authorization: the allowlist must be configured (non-empty) and
     * the token's authorized party ({@code azp}) must be a member. Package-private and
     * exception-free for unit testing.
     */
    static boolean isClientAuthorized(Set<String> authorizedClients, String azp) {
        return !authorizedClients.isEmpty() && azp != null && authorizedClients.contains(azp);
    }

    private void auditChange(RealmModel realm, UserModel user, String credentialType, String clientId) {
        credentialEvent(realm, user, credentialType, clientId).success();
    }

    private void auditFailure(RealmModel realm, UserModel user, String credentialType, String clientId, String error) {
        credentialEvent(realm, user, credentialType, clientId).error(error);
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
                .collect(Collectors.toList());
        ids.forEach(id -> user.credentialManager().removeStoredCredentialById(id));
    }

    private static Response noStore(Object entity) {
        return cacheHeaders(Response.ok(entity)).build();
    }

    private static Response error(Response.Status status, String code) {
        return cacheHeaders(Response.status(status).entity(new ErrorResponse(code))).build();
    }

    private static Response.ResponseBuilder cacheHeaders(Response.ResponseBuilder builder) {
        return builder.header("Cache-Control", "no-store").header("Pragma", "no-cache");
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

    /** Authenticated caller context: the subject user and the acting client id (azp). */
    private record Caller(UserModel user, String clientId) {
    }
}
