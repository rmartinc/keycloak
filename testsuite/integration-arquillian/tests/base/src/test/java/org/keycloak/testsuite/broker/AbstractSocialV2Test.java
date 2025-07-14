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

import com.google.common.collect.ImmutableMap;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.io.FileInputStream;
import java.net.URI;
import java.util.List;
import java.util.Properties;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.jboss.arquillian.graphene.Graphene;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderMapperSyncMode;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.social.AbstractSocialLoginPage;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.IdentityProviderBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.URLUtils;
import org.keycloak.testsuite.util.WaitUtils;
import org.keycloak.testsuite.util.oauth.OAuthClient;
import org.keycloak.testsuite.util.userprofile.UserProfileUtil;
import org.keycloak.util.BasicAuthHelper;
import org.openqa.selenium.By;

/**
 *
 * @author rmartinc
 */
public abstract class AbstractSocialV2Test extends AbstractKeycloakTest {

    public static final String SOCIAL_CONFIG = "social.config";
    public static final String REALM = "social";
    private static final Properties config = new Properties();

    private SocialLoginTest.Provider currentTestProvider = null;
    private AbstractSocialLoginPage currentSocialLoginPage = null;

    @Page
    protected LoginPage loginPage;

    @Page
    protected AppPage appPage;

    @BeforeClass
    public static void loadConfig() throws Exception {
        Assume.assumeTrue(System.getProperties().containsKey(SOCIAL_CONFIG));
        config.load(new FileInputStream(System.getProperty(SOCIAL_CONFIG)));
    }

    @Before
    public void beforeSocialLoginTest() {
        oauth.realm(REALM);
        createAppClientInRealm(REALM);
        UserProfileUtil.enableUnmanagedAttributes(adminClient.realm(REALM).users().userProfile());
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation rep = RealmBuilder.create().name(REALM).build();
        testRealms.add(rep);
    }

    protected String getConfig(String key) {
        return getConfig(currentTestProvider, key);
    }

    protected String getConfig(SocialLoginTest.Provider provider, String key) {
        String providerKey = provider.configId() + "." + key;
        return System.getProperty("social." + providerKey, config.getProperty(providerKey, config.getProperty("common." + key)));
    }

    protected IdentityProviderRepresentation buildIdp(SocialLoginTest.Provider provider) {
        IdentityProviderRepresentation idp = IdentityProviderBuilder.create()
                .alias(provider.id())
                .providerId(provider.id())
                .build();
        idp.setEnabled(true);
        idp.setStoreToken(true);
        idp.setAddReadTokenRoleOnCreate(true);
        idp.getConfig().put("clientId", getConfig(provider, "clientId"));
        idp.getConfig().put("clientSecret", getConfig(provider, "clientSecret"));

        return idp;
    }

    protected void setTestProvider(SocialLoginTest.Provider provider) {
        adminClient.realm(REALM).identityProviders().create(buildIdp(provider));
        log.infof("added '%s' identity provider", provider.id());
        currentTestProvider = provider;
        currentSocialLoginPage = Graphene.createPageFragment(currentTestProvider.pageObjectClazz(), driver.findElement(By.tagName("html")));
    }

    protected void addAttributeMapper(String name, String jsonField, String mapperName) {
        IdentityProviderResource identityProvider = adminClient.realm(REALM).identityProviders().get(currentTestProvider.id());
        IdentityProviderRepresentation identityProviderRepresentation = identityProvider.toRepresentation();
        //Add birthday mapper
        IdentityProviderMapperRepresentation mapperRepresentation = new IdentityProviderMapperRepresentation();
        mapperRepresentation.setName(name);
        mapperRepresentation.setIdentityProviderAlias(identityProviderRepresentation.getAlias());
        mapperRepresentation.setIdentityProviderMapper(mapperName);
        mapperRepresentation.setConfig(ImmutableMap.<String, String>builder()
                .put(IdentityProviderMapperModel.SYNC_MODE, IdentityProviderMapperSyncMode.IMPORT.toString())
                .put(AbstractJsonUserAttributeMapper.CONF_JSON_FIELD, jsonField)
                .put(AbstractJsonUserAttributeMapper.CONF_USER_ATTRIBUTE, name)
                .build());
        identityProvider.addMapper(mapperRepresentation).close();
    }

    protected void performLogin() {
        navigateToLoginPage();
        doLogin();
    }

    protected void navigateToLoginPage() {
        currentSocialLoginPage.logout(); // try to logout first to be sure we're not logged in

        driver.navigate().to(oauth.loginForm().build());
        loginPage.clickSocial(currentTestProvider.id());

        // Just to be sure there's no redirect in progress
        WaitUtils.waitForPageToLoad();
    }

    protected void doLogin() {
        // Only when there's not active session for the social provider, i.e. login is required
        if (URLUtils.currentUrlDoesntStartWith(getAuthServerRoot().toASCIIString())) {
            log.infof("current URL: %s", driver.getCurrentUrl());
            log.infof("performing log in to '%s' ...", currentTestProvider.id());
            currentSocialLoginPage.login(getConfig("username"), getConfig("password"));
        } else {
            log.infof("already logged in to '%s'; skipping the login process", currentTestProvider.id());
        }
        WaitUtils.waitForPageToLoad();
    }

    protected void assertAttribute(String attrName, Matcher<? super String> matcher) {
        List<UserRepresentation> users = adminClient.realm(REALM).users().search(null, null, null);
        Assert.assertEquals(1, users.size());
        Assert.assertNotNull(users.get(0).getAttributes());
        Assert.assertNotNull(users.get(0).getAttributes().get(attrName));
        String attrValue = users.get(0).getAttributes().get(attrName).get(0);
        MatcherAssert.assertThat(attrValue, matcher);
    }

    protected void assertAttribute(String attrName, String expectedValue) {
        assertAttribute(attrName, Matchers.is(expectedValue));
    }

    protected void testTokenExchange(String accessToken) {
        // get the external token from the token endpoint
        AccessTokenResponse tokenResponse;
        try (Client client = AdminClientUtil.createResteasyClient();
                Response response = client.target(Urls.identityProviderRetrieveToken(URI.create(OAuthClient.AUTH_SERVER_ROOT), currentTestProvider.id(), REALM))
                .request().header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken).get()) {

            Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
            tokenResponse = response.readEntity(AccessTokenResponse.class);
        }

        // with the external token perform a external to internal token exchange
        try (Client client = AdminClientUtil.createResteasyClient();
                Response response = client.target(OAuthClient.AUTH_SERVER_ROOT).path("realms").path(REALM).path("protocol/openid-connect/token")
                .request().header(HttpHeaders.AUTHORIZATION, BasicAuthHelper.createHeader("test-app", "password"))
                .post(Entity.form(new Form()
                        .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE)
                        .param(OAuth2Constants.SUBJECT_TOKEN, tokenResponse.getToken())
                        .param(OAuth2Constants.SUBJECT_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE)
                        .param(OAuth2Constants.SUBJECT_ISSUER, currentTestProvider.id())
                        .param(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID)))) {

            Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
            AccessTokenResponse externalToInternalTokenResponse = response.readEntity(AccessTokenResponse.class);
            Assert.assertNotNull(externalToInternalTokenResponse.getToken());
        }
    }
}
