/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package net.thunderbird.keycloak.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

class MfaResourceProviderFactoryTest {

    @Test
    void exposesStableProviderId() {
        assertEquals("mfa", new MfaResourceProviderFactory().getId());
    }

    @Test
    void serviceFileRegistersTheFactory() throws Exception {
        String resource = "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory";
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resource)) {
            assertNotNull(in, "SPI service file must be on the classpath");
            String contents = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                    .lines().collect(Collectors.joining("\n"));
            assertTrue(contents.contains(MfaResourceProviderFactory.class.getName()),
                    "service file must register MfaResourceProviderFactory");
        }
    }
}
