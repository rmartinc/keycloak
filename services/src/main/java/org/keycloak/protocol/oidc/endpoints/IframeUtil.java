/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

import java.util.Set;
import java.util.function.Supplier;

import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.Version;
import org.keycloak.common.util.UriUtils;
import org.keycloak.headers.SecurityHeadersProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.WebOriginsUtils;
import org.keycloak.services.util.CacheControlUtil;

public class IframeUtil {

    public static Response returnIframeFromResources(String fileName, String version, String clientId, String referer, KeycloakSession session) {
        return returnIframe(version, clientId, referer, session, () -> IframeUtil.class.getResourceAsStream(fileName));
    }

    public static Response returnIframe(String version, String clientId, String referer, KeycloakSession session, Supplier<Object> responseEntityProvider) {
        CacheControl cacheControl;
        if (version != null) {
            if (!version.equals(Version.RESOURCES_VERSION)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
            cacheControl = CacheControlUtil.getDefaultCacheControl();
        } else {
            cacheControl = CacheControlUtil.noCache();
        }

        Object resource = responseEntityProvider.get();
        if (resource != null) {
            SecurityHeadersProvider securityHeaders = session.getProvider(SecurityHeadersProvider.class);
            if (clientId != null) {
                ClientModel client = session.clients().getClientByClientId(session.getContext().getRealm(), clientId);
                if (client != null) {
                    Set<String> validWebOrigins = WebOriginsUtils.resolveValidWebOrigins(session, client);
                    if (referer != null && (validWebOrigins.contains("*")
                            || validWebOrigins.stream().anyMatch(allowed -> UriUtils.originEquals(referer, allowed)))) {
                        // add the referer if valid for the client
                        securityHeaders.options().allowFrameAncestor(UriUtils.getOrigin(referer));
                    } else if (referer == null && validWebOrigins.contains("*")) {
                        // no referer but all allowed, allow any ancestor
                        securityHeaders.options().allowAnyFrameAncestor();
                    } else if (referer == null && !validWebOrigins.isEmpty()) {
                        // no referer, so add all the valid origins for the client
                        securityHeaders.options().allowFrameAncestor(String.join(" ", validWebOrigins));
                    }
                }
            } else {
                // old behavior, just allow any ancestor, remove this else when necessary or add an option somewhere
                securityHeaders.options().allowAnyFrameAncestor();
            }

            return Response.ok(resource).cacheControl(cacheControl).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }
}
