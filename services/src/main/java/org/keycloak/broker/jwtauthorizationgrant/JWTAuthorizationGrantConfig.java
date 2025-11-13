package org.keycloak.broker.jwtauthorizationgrant;

import java.util.Map;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.common.util.UriUtils;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

public class JWTAuthorizationGrantConfig extends IdentityProviderModel {

    public static final String JWT_AUTHORIZATION_GRANT_ENABLED = "jwtAuthorizationGrantEnabled";

    public static final String JWT_AUTHORIZATION_GRANT_ASSERTION_REUSE_ALLOWED = "jwtAuthorizationGrantAssertionReuseAllowed";

    public static final String JWT_AUTHORIZATION_GRANT_MAX_ALLOWED_ASSERTION_EXPIRATION = "jwtAuthorizationGrantMaxAllowedAssertionExpiration";

    public static final String JWT_AUTHORIZATION_GRANT_ASSERTION_SIGNATURE_ALG = "jwtAuthorizationGrantAssertionSignatureAlg";

    public static final String JWT_AUTHORIZATION_GRANT_ALLOWED_CLOCK_SKEW = "jwtAuthorizationGrantAllowedClockSkew";

    public JWTAuthorizationGrantConfig() {
        super();
    }

    public JWTAuthorizationGrantConfig(IdentityProviderModel model) {
        super(model);
    }

    public JWTAuthorizationGrantConfig(Map<String, String> config) {
        super();
        setConfig(config);
    }

    @Override
    public void validate(RealmModel realm) {
        UriUtils.checkUrl(realm.getSslRequired(), getIssuer(), ISSUER);
        UriUtils.checkUrl(realm.getSslRequired(), getJwksUrl(), OIDCIdentityProviderConfig.JWKS_URL);
    }

    public boolean getJWTAuthorizationGrantEnabled() {
        return Boolean.parseBoolean(getConfig().getOrDefault(JWT_AUTHORIZATION_GRANT_ENABLED, "false"));
    }

    public boolean getJWTAuthorizationGrantAssertionReuseAllowed() {
        return Boolean.parseBoolean(getConfig().getOrDefault(JWT_AUTHORIZATION_GRANT_ASSERTION_REUSE_ALLOWED, "false"));
    }

    public int getJWTAuthorizationGrantMaxAllowedAssertionExpiration() {
        return Integer.parseInt(getConfig().getOrDefault(JWT_AUTHORIZATION_GRANT_MAX_ALLOWED_ASSERTION_EXPIRATION, "300"));
    }

    public String getJWTAuthorizationGrantAssertionSignatureAlg() {
        String alg = getConfig().get(JWT_AUTHORIZATION_GRANT_ASSERTION_SIGNATURE_ALG);
        return StringUtil.isBlank(alg) ? null : alg;
    }

    public int getJWTAuthorizationGrantAllowedClockSkew() {
        String allowedClockSkew = getConfig().get(JWT_AUTHORIZATION_GRANT_ALLOWED_CLOCK_SKEW);
        if (allowedClockSkew == null || allowedClockSkew.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(getConfig().get(JWT_AUTHORIZATION_GRANT_ALLOWED_CLOCK_SKEW));
        } catch (NumberFormatException e) {
            // ignore it and use default
            return 0;
        }
    }

    public String getIssuer() {
        return getConfig().get(ISSUER);
    }

    public String getJwksUrl() {
        return getConfig().get(OIDCIdentityProviderConfig.JWKS_URL);
    }
}
