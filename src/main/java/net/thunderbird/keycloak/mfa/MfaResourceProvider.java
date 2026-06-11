/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class MfaResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final MfaConfig config;

    public MfaResourceProvider(KeycloakSession session, MfaConfig config) {
        this.session = session;
        this.config = config;
    }

    @Override
    public Object getResource() {
        return new MfaResource(session, config);
    }

    @Override
    public void close() {
    }
}
