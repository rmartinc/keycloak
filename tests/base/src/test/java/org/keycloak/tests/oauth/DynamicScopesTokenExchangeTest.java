package org.keycloak.tests.oauth;

import java.util.List;

import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.testframework.annotations.InjectClient;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.annotations.TestSetup;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ClientConfig;
import org.keycloak.testframework.realm.ClientScopeBuilder;
import org.keycloak.testframework.realm.ManagedClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.util.ApiUtil;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 * @author rmartinc
 */
@KeycloakIntegrationTest(config = DynamicScopesTokenExchangeTest.DynamicScopesServerConfig.class)
public class DynamicScopesTokenExchangeTest {

    private static final String DEFAULT_USERNAME = "test-user@localhost";
    private static final String DEFAULT_PASSWORD = "password";

    @InjectRealm
    ManagedRealm realm;

    @InjectUser(config = DynamicScopesUser.class)
    ManagedUser user;

    @InjectOAuthClient(config = DynamicScopesSubjectClientConfig.class)
    OAuthClient oauth;

    @InjectClient(config = DynamicScopesRequesterClientConfig.class)
    ManagedClient requester;

    @InjectEvents
    protected Events events;

    @TestSetup
    public void configureTestRealm() {
        ClientScopeRepresentation dynamicScope = ClientScopeBuilder.create()
                .name("foo-dynamic-scope")
                .protocol(OIDCLoginProtocol.LOGIN_PROTOCOL)
                .attribute(ClientScopeModel.IS_DYNAMIC_SCOPE, Boolean.TRUE.toString())
                .attribute(ClientScopeModel.DYNAMIC_SCOPE_REGEXP, "foo-dynamic-scope:*")
                .build();
        String id = ApiUtil.getCreatedId(realm.admin().clientScopes().create(dynamicScope));
        requester.admin().addOptionalClientScope(id);
    }

    @Test
    public void testTokenExchangeWithDynamicScopes() throws VerificationException {
        // login the user in the subject app to get the initial token
        String accessToken = resourceOwnerLogin().getAccessToken();

        // perform token exchange requesting an optional dynamic scope
        oauth.client(requester.getClientId(), requester.getSecret());
        oauth.scope("foo-dynamic-scope:param1");
        AccessTokenResponse response = oauth.tokenExchangeRequest(accessToken).send();
        assertSuccesfulExchange(accessToken, response, List.of("profile", "email", "foo-dynamic-scope:param1"));

        // perform token exchange with two optional dynamic scopes
        oauth.scope("foo-dynamic-scope:param1 foo-dynamic-scope:param2");
        response = oauth.tokenExchangeRequest(accessToken).send();
        assertSuccesfulExchange(accessToken, response, List.of("profile", "email", "foo-dynamic-scope:param1", "foo-dynamic-scope:param2"));

        // perform token exchange with two dynamic scopes and another common scope
        oauth.scope("microprofile-jwt foo-dynamic-scope:param1 foo-dynamic-scope:param2");
        response = oauth.tokenExchangeRequest(accessToken).send();
        assertSuccesfulExchange(accessToken, response, List.of("profile", "email", "microprofile-jwt", "foo-dynamic-scope:param1", "foo-dynamic-scope:param2"));
    }

    private AccessTokenResponse resourceOwnerLogin() throws VerificationException {
        oauth.openid(false);
        AccessTokenResponse response = oauth.doPasswordGrantRequest(user.getUsername(), user.getPassword());
        Assertions.assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(response.getAccessToken(), AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        EventAssertion.assertSuccess(events.poll()).type(EventType.LOGIN)
                .clientId(oauth.getClientId())
                .userId(token.getSubject())
                .sessionId(token.getSessionId())
                .details(Details.USERNAME, user.getUsername());
        return response;
    }

    private void assertSuccesfulExchange(String originalAccessToken, AccessTokenResponse response,
            List<String> expectedScopes) throws VerificationException {
        Assertions.assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());
        Assertions.assertEquals(OAuth2Constants.ACCESS_TOKEN_TYPE, response.getIssuedTokenType());
        String exchangedTokenString = response.getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(exchangedTokenString, AccessToken.class);
        AccessToken exchangedToken = verifier.parse().getToken();
        String sessionId = TokenVerifier.create(originalAccessToken, AccessToken.class).parse().getToken().getSessionId();
        Assertions.assertEquals(sessionId, exchangedToken.getSessionId());
        Assertions.assertEquals(requester.getClientId(), exchangedToken.getIssuedFor());
        assertScopes(exchangedToken, expectedScopes);
        EventAssertion.assertSuccess(events.poll()).type(EventType.TOKEN_EXCHANGE)
                .clientId(exchangedToken.getIssuedFor())
                .userId(user.getId())
                .sessionId(exchangedToken.getSessionId())
                .details(Details.USERNAME, user.getUsername());
    }

    private void assertScopes(AccessToken token, List<String> expectedScopes) {
        MatcherAssert.assertThat("Incorrect scopes",
                token.getScope().isEmpty() ? List.of() : List.of(token.getScope().split(" ")),
                Matchers.containsInAnyOrder(expectedScopes.toArray()));
    }

    public static class DynamicScopesUser implements UserConfig {

        @Override
        public UserBuilder configure(UserBuilder user) {
            return user.email(DEFAULT_USERNAME)
                    .name("Test", "User")
                    .emailVerified(true)
                    .password(DEFAULT_PASSWORD)
                    .enabled(true);
        }
    }

    public static class DynamicScopesSubjectClientConfig implements ClientConfig {

        @Override
        public ClientBuilder configure(ClientBuilder client) {
            // add requester client as audience for the subject client
            ProtocolMapperRepresentation audienceMapper = new ProtocolMapperRepresentation();
            audienceMapper.setName("requester-client");
            audienceMapper.setProtocol("openid-connect");
            audienceMapper.setProtocolMapper("oidc-audience-mapper");
            audienceMapper.getConfig().put("included.client.audience", "requester-client");
            audienceMapper.getConfig().put("access.token.claim", Boolean.TRUE.toString());

            return client.clientId("test-app")
                    .secret("password")
                    .serviceAccountsEnabled(true)
                    .directAccessGrantsEnabled(true)
                    .redirectUris("http://localhost:8080/test-app")
                    .protocolMappers(audienceMapper);
        }
    }

    public static class DynamicScopesRequesterClientConfig implements ClientConfig {

        @Override
        public ClientBuilder configure(ClientBuilder client) {return client.clientId("requester-client")
                    .secret("password")
                    .serviceAccountsEnabled(true)
                    .directAccessGrantsEnabled(true)
                    .attribute(OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED, Boolean.TRUE.toString());
        }
    }

    public static class DynamicScopesServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.DYNAMIC_SCOPES);
        }
    }
}
