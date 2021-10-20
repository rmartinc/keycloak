/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.storage.ldap.idm.store;

import javax.naming.ldap.Control;

/**
 *
 * @author rmartinc
 */
public class LdapValidationPasswordResult {

    private final Control[] responseControls;
    private final Exception exception;

    public LdapValidationPasswordResult(Control[] responseControls) {
        this.exception = null;
        this.responseControls = responseControls;
    }

    public LdapValidationPasswordResult(Exception e) {
        this.exception = e;
        this.responseControls = null;
    }

    public LdapValidationPasswordResult(Exception e, Control[] responseControls) {
        this.exception = e;
        this.responseControls = responseControls;
    }

    public boolean isSuccess() {
        return exception == null;
    }

    public Exception getException() {
        return exception;
    }

    public Control[] getResponseControls() {
        return responseControls;
    }
}
