/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.broker;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.broker.SocialLoginTest.Provider;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;

/**
 *
 * @author rmartinc
 */
@EnableFeature(Profile.Feature.TOKEN_EXCHANGE_EXTERNAL_INTERNAL_V2)
public class LinkedInSocialV2Test extends AbstractSocialV2Test {

    @Test
    public void linkedinLogin() {
        setTestProvider(Provider.LINKEDIN);
        addAttributeMapper("picture", "picture", "linkedin-user-attribute-mapper");
        performLogin();
        appPage.assertCurrent();
        AccessTokenResponse response = oauth.doAccessTokenRequest(oauth.parseLoginResponse().getCode());
        assertAttribute("picture", Matchers.not(Matchers.emptyOrNullString()));

        testTokenExchange(response.getAccessToken());
    }
}
