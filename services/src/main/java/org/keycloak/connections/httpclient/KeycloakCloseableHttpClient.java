/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.connections.httpclient;

import java.io.IOException;

import org.keycloak.models.KeycloakSession;

import org.apache.http.HttpHost;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;

/**
 *
 * @author rmartinc
 */
final class KeycloakCloseableHttpClient extends CloseableHttpClient {

    private final CloseableHttpClient httpClient;
    private final KeycloakSession session;

    public KeycloakCloseableHttpClient(CloseableHttpClient httpClient, KeycloakSession session) {
        this.httpClient = httpClient;
        this.session = session;
    }

    @Override
    protected CloseableHttpResponse doExecute(HttpHost hh, org.apache.http.HttpRequest hr, HttpContext hc) throws IOException, ClientProtocolException {
        hc = hc != null ? hc : new BasicHttpContext();
        hc.setAttribute(HttpClientBuilder.KEYCLOAK_SESSION_CONTEXT_ATTR, session);
        return httpClient.execute(hh, hr, hc);
    }

    @Override
    public HttpParams getParams() {
        return httpClient.getParams();
    }

    @Override
    public ClientConnectionManager getConnectionManager() {
        return httpClient.getConnectionManager();
    }

    @Override
    public void close() throws IOException {
        httpClient.close();
    }
}
