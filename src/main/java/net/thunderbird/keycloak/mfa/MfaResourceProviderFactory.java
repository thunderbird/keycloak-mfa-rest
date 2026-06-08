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
 */
public class MfaResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "mfa";

    private static final String CONFIG_AUTHORIZED_CLIENTS = "authorized-clients";
    private static final Logger LOG = Logger.getLogger(MfaResourceProviderFactory.class);

    private Set<String> authorizedClients = Set.of();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new MfaResourceProvider(session, authorizedClients);
    }

    @Override
    public void init(Config.Scope config) {
        String raw = config.get(CONFIG_AUTHORIZED_CLIENTS);
        if (raw != null && !raw.isBlank()) {
            authorizedClients = Arrays.stream(raw.split(","))
                    .map(String::trim)
                    .filter(value -> !value.isEmpty())
                    .collect(Collectors.toUnmodifiableSet());
        }

        if (authorizedClients.isEmpty()) {
            LOG.errorf("mfa: '%s' is not configured — the MFA REST endpoints will deny all "
                    + "requests (fail-closed). Set spi-realm-restapi-extension-mfa-%s to the "
                    + "front-end OIDC client id whose user tokens may self-manage MFA.",
                    CONFIG_AUTHORIZED_CLIENTS, CONFIG_AUTHORIZED_CLIENTS);
        } else {
            LOG.infof("mfa: authorized clients (token azp allowlist): %s", authorizedClients);
        }
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
                .build();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
