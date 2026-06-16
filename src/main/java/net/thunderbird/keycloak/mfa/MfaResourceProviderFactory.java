/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers the MFA REST resource at {@code /realms/{realm}/mfa}.
 *
 * <p>Requires the {@code authorized-clients} option: a comma-separated allowlist of client
 * IDs (matched against the caller token's {@code azp}) whose user tokens may self-manage
 * MFA. Set it via {@code --spi-realm-restapi-extension-mfa-authorized-clients=...} or the
 * env var {@code KC_SPI_REALM_RESTAPI_EXTENSION_MFA_AUTHORIZED_CLIENTS}. The resource fails
 * closed: if this is empty, all requests are denied.</p>
 *
 * <p>Step-up gating of sensitive mutations is tuned with {@code step-up-acr} (the ACR value
 * a token must carry, default {@value #DEFAULT_STEP_UP_ACR}) and
 * {@code step-up-max-age-seconds} (how recent the token's {@code auth_time} must be,
 * default {@value #DEFAULT_STEP_UP_MAX_AGE_SECONDS}). Keep the max age aligned with the
 * consuming app's own recent-auth window so the two layers expire together.</p>
 */
public class MfaResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "mfa";

    static final String DEFAULT_STEP_UP_ACR = "2";
    static final int DEFAULT_STEP_UP_MAX_AGE_SECONDS = 600;

    private static final String CONFIG_AUTHORIZED_CLIENTS = "authorized-clients";
    private static final String CONFIG_STEP_UP_ACR = "step-up-acr";
    private static final String CONFIG_STEP_UP_MAX_AGE_SECONDS = "step-up-max-age-seconds";
    private static final Logger LOG = Logger.getLogger(MfaResourceProviderFactory.class);

    private MfaConfig mfaConfig =
            new MfaConfig(Set.of(), DEFAULT_STEP_UP_ACR, DEFAULT_STEP_UP_MAX_AGE_SECONDS);

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new MfaResourceProvider(session, mfaConfig);
    }

    @Override
    public void init(Config.Scope config) {
        Set<String> authorizedClients = Set.of();
        String raw = config.get(CONFIG_AUTHORIZED_CLIENTS);
        if (raw != null && !raw.isBlank()) {
            authorizedClients = Arrays.stream(raw.split(","))
                    .map(String::trim)
                    .filter(value -> !value.isEmpty())
                    .collect(Collectors.toUnmodifiableSet());
        }

        // config.get with a non-null default never returns null; only blank needs handling.
        String stepUpAcr = config.get(CONFIG_STEP_UP_ACR, DEFAULT_STEP_UP_ACR);
        if (stepUpAcr.isBlank()) {
            stepUpAcr = DEFAULT_STEP_UP_ACR;
        }
        int stepUpMaxAgeSeconds =
                config.getInt(CONFIG_STEP_UP_MAX_AGE_SECONDS, DEFAULT_STEP_UP_MAX_AGE_SECONDS);

        mfaConfig = new MfaConfig(authorizedClients, stepUpAcr.trim(), stepUpMaxAgeSeconds);

        if (authorizedClients.isEmpty()) {
            LOG.errorf("mfa: '%s' is not configured — the MFA REST endpoints will deny all "
                    + "requests (fail-closed). Set spi-realm-restapi-extension-mfa-%s to the "
                    + "front-end OIDC client id whose user tokens may self-manage MFA.",
                    CONFIG_AUTHORIZED_CLIENTS, CONFIG_AUTHORIZED_CLIENTS);
        } else {
            LOG.infof("mfa: authorized clients (token azp allowlist): %s", authorizedClients);
        }
        LOG.infof("mfa: step-up gate requires acr '%s' with auth_time no older than %d seconds",
                mfaConfig.stepUpAcr(), mfaConfig.stepUpMaxAgeSeconds());
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CONFIG_AUTHORIZED_CLIENTS)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Authorized clients")
                .helpText("Comma-separated client IDs (matched against the bearer token's azp) whose "
                        + "user tokens may self-manage MFA. Required: when empty, all requests are denied.")
                .add()
                .property()
                .name(CONFIG_STEP_UP_ACR)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Step-up ACR value")
                .helpText("ACR claim value a bearer token must carry for sensitive mutations on an "
                        + "account that already has MFA configured (the realm's second-factor level). "
                        + "Default: " + DEFAULT_STEP_UP_ACR + ".")
                .defaultValue(DEFAULT_STEP_UP_ACR)
                .add()
                .property()
                .name(CONFIG_STEP_UP_MAX_AGE_SECONDS)
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .label("Step-up max age (seconds)")
                .helpText("Maximum age of the token's auth_time claim for the step-up to count as "
                        + "recent. Keep aligned with the consuming app's recent-auth window. "
                        + "Default: " + DEFAULT_STEP_UP_MAX_AGE_SECONDS + ".")
                .defaultValue(DEFAULT_STEP_UP_MAX_AGE_SECONDS)
                .add()
                .build();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
