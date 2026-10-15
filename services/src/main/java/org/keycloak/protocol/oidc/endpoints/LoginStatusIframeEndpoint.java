/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc.endpoints;

import java.util.HashMap;
import java.util.Set;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.keycloak.common.util.UriUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.WebOriginsUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.urls.UrlType;
import org.keycloak.utils.FreemarkerUtils;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.SecureContextResolver;

import org.jboss.logging.Logger;

import static org.keycloak.services.managers.AuthenticationManager.authenticateIdentityCookie;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class LoginStatusIframeEndpoint {

    private static final Logger logger = Logger.getLogger(LoginStatusIframeEndpoint.class);

    private final KeycloakSession session;

    public LoginStatusIframeEndpoint(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Produces(MediaType.TEXT_HTML_UTF_8)
    public Response getLoginStatusIframe(@QueryParam("version") String version, @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId) {
        final var map = new HashMap<String, Object>();
        final var isSecureContext = SecureContextResolver.isSecureContext(session);
        final var serverBaseUri = session.getContext().getUri(UrlType.FRONTEND).getBaseUri();
        final var referer = session.getContext().getHttpRequest().getHttpHeaders().getHeaderString("Referer");
        map.put("isSecureContext", isSecureContext);
        map.put("resourceCommonUrl", Urls.themeRoot(serverBaseUri).getPath() + "/common/keycloak");

        // the check status iframe should be called when already logged in, check identity cookie
        RealmModel realm = session.getContext().getRealm();
        AuthenticationManager.AuthResult authResult = authenticateIdentityCookie(session, realm, false);

        if (clientId == null && referer != null && authResult != null) {
            // client_id parameter is sent by the keycloak-js, but check_session_iframe is by spec
            // and the client_id can be empty, try to guess using the referer
            UserSessionModel userSession = authResult.session();
            // TODO: just return UUIDs for clients to avoid loading all the client sessions?
            for (String clientUUID : userSession.getAuthenticatedClientSessions().keySet()) {
                ClientModel client = session.clients().getClientById(realm, clientUUID);
                if (client != null && OIDCLoginProtocol.LOGIN_PROTOCOL.equals(client.getProtocol())) {
                    Set<String> validWebOrigins = WebOriginsUtils.resolveValidWebOrigins(session, client);
                    if (validWebOrigins.contains("*") || validWebOrigins.stream().anyMatch(allowed -> UriUtils.originEquals(referer, allowed))) {
                        clientId = client.getClientId();
                    }
                }
            }
        }

        return IframeUtil.returnIframe(version, clientId, referer, session, () -> {
            try {
                return FreemarkerUtils.loadTemplateFromClasspath(map, "login-status-iframe.ftl", getClass());
            } catch (Exception e) {
                logger.error("Failure when loading login-status-iframe.ftl", e);
                return null;
            }
        });
    }

    @GET
    @Path("init")
    public Response preCheck(@QueryParam("client_id") String clientId, @QueryParam("origin") String origin) {
        try {
            UriInfo uriInfo = session.getContext().getUri();
            RealmModel realm = session.getContext().getRealm();
            ClientModel client = session.clients().getClientByClientId(realm, clientId);
            if (client != null && client.isEnabled()) {
                Set<String> validWebOrigins = WebOriginsUtils.resolveValidWebOrigins(session, client);
                String requestOrigin = UriUtils.getOrigin(uriInfo.getRequestUri());
                validWebOrigins.add(requestOrigin);
                if (validWebOrigins.contains("*")
                        || validWebOrigins.stream().anyMatch(allowed -> UriUtils.originEquals(origin, allowed))) {
                    return Response.noContent().build();
                }
                logger.debugf("client %s does not allow origin=%s for requestOrigin=%s (as determined by the proxy-header setting), init will return a 403", clientId, origin, requestOrigin);
            } else {
                logger.debugf("client %s does not exist or not enabled, init will return a 403", clientId);
            }
        } catch (Throwable t) {
            logger.debug("Exception in init, will return a 403", t);
        }
        return Response.status(Response.Status.FORBIDDEN).build();
    }

}
