/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.oauth;

import org.junit.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ClientAuthEdDSASignedJWTTest extends AbstractClientAuthSignedJWTTest {

    @Test
    public void testCodeToTokenRequestSuccessEd448usingJwksUri() throws Exception {
        testCodeToTokenRequestSuccess(Algorithm.Ed448, true);
    }

    @Test
    public void testCodeToTokenRequestSuccessEd25519usingJwks() throws Exception {
        testCodeToTokenRequestSuccess(Algorithm.Ed25519, false);
    }

    @Override
    protected String getKeyAlgorithmFromJwaAlgorithm(String jwaAlgorithm) {
        String keyAlg = null;
        switch (jwaAlgorithm) {
            case Algorithm.Ed25519:
                keyAlg = Algorithm.Ed25519;
                break;
            case Algorithm.Ed448:
                keyAlg = Algorithm.Ed448;
                break;
            default :
                throw new RuntimeException("Unsupported signature algorithm");
        }
        return keyAlg;
    }
}
