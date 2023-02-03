package org.keycloak.social.twitter;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 *
 * @author rmartinc
 */
public class TwitterOAuth2IdentityProviderFactory
        extends AbstractIdentityProviderFactory<TwitterOAuth2IdentityProvider>
        implements SocialIdentityProviderFactory<TwitterOAuth2IdentityProvider> {

    public static final String PROVIDER_ID = "twitter-oauth";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Twitter OAuth 2.0";
    }

    @Override
    public TwitterOAuth2IdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new TwitterOAuth2IdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new OAuth2IdentityProviderConfig();
    }
}
