package org.keycloak.social.twitter;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 *
 * @author rmartinc
 */
public class TwitterOAuth2IdentityProvider
        extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(TwitterIdentityProvider.class);

    public static final String AUTH_URL = "https://twitter.com/i/oauth2/authorize";
    public static final String TWITTER_API_V2_URL = "https://api.twitter.com/2";
    public static final String TOKEN_URL = TWITTER_API_V2_URL + "/oauth2/token";
    public static final String ME_URL = TWITTER_API_V2_URL + "/users/me";

    public TwitterOAuth2IdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setPkceEnabled(true);
        config.setPkceMethod(OAuth2Constants.PKCE_METHOD_S256);
        //config.setDefaultScope("tweet.read users.read");
        config.setClientAuthMethod(OIDCLoginProtocol.CLIENT_SECRET_BASIC);
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        super.authenticationFinished(authSession, context);
        AccessTokenResponse tokenResponse = (AccessTokenResponse) context.getContextData().get(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE);
        int currentTime = Time.currentTime();
        long expiration = tokenResponse.getExpiresIn() > 0 ? tokenResponse.getExpiresIn() + currentTime : 0;
        authSession.setUserSessionNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(expiration));
        authSession.setUserSessionNote(FEDERATED_ACCESS_TOKEN, tokenResponse.getToken());
        if (tokenResponse.getRefreshToken() != null) {
            authSession.setUserSessionNote(FEDERATED_REFRESH_TOKEN, tokenResponse.getRefreshToken());
        }
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext context = super.getFederatedIdentity(response);
        try {
            // add the response as in OIDC as it is very similar but with opaque tokens
            AccessTokenResponse tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            context.getContextData().put(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
            return context;
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            // obtain the information from the me endpoint
            JsonNode data = executeGet(ME_URL, accessToken).get("data");

            BrokeredIdentityContext identity = new BrokeredIdentityContext(data.get("id").textValue());
            identity.setIdp(this);

            identity.setUsername(data.get("username").textValue());
            identity.setName(data.get("name").textValue());
            //identity.setEmail(twitterUser.getEmail()); // I cannot get the email from twitter

            if (getConfig().isStoreToken()) {
                identity.setToken(accessToken);
            }

            identity.setIdpConfig(getConfig());
            identity.setBrokerUserId(getConfig().getAlias() + "." + identity.getId());

            logger.info("RIIICKY: identity=" + identity);

            return identity;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from userinfo endpoint.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "tweet.read users.read";
    }

    // TODO: exchangeStoredToken and exchangeSessionToken should be modified
    //       now there can be a refresh token and expires_in is always there
    // TODO: perform revoke of the tokens on logout

    private JsonNode executeGet(String url, String accessToken) throws IOException {
        SimpleHttp simpleHttp = SimpleHttp.doGet(url, session).header("Authorization", "Bearer " + accessToken);
        try ( SimpleHttp.Response response = simpleHttp.asResponse()) {
            if (response.getStatus() != 200) {
                String msg = "failed URL in twitter '" + url + "': ";
                try {
                    String tmp = response.asString();
                    if (tmp != null) {
                        msg += tmp;
                    }
                } catch (IOException e) {
                    // ignore
                }
                throw new IdentityBrokerException(msg);
            }
            JsonNode data = response.asJson();
            logger.info("RIIICKY: data=" + data);
            return data;
        }
    }
}
