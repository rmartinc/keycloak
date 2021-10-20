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
package org.keycloak.storage.ldap.mappers.netscape;

import java.nio.charset.StandardCharsets;
import javax.naming.ldap.Control;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.store.LdapValidationPasswordResult;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import static org.keycloak.storage.ldap.mappers.netscape.NetscapeExpirationStorageMapperFactory.PASSWORD_EXPIRED_CONTROL_ID;
import static org.keycloak.storage.ldap.mappers.netscape.NetscapeExpirationStorageMapperFactory.PASSWORD_EXPIRING_CONTROL_ID;
import static org.keycloak.storage.ldap.mappers.netscape.NetscapeExpirationStorageMapperFactory.WARNING_SECONDS;

/**
 *
 * @author rmartinc
 */
public class NetscapeExpirationStorageMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(NetscapeExpirationStorageMapper.class);

    public NetscapeExpirationStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        return delegate;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
    }

    private long getWarningSeconds() {
        String value = mapperModel.getConfig().getFirst(WARNING_SECONDS);
        if (value != null && !value.isEmpty()) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                logger.warnf("Invalid value %s for option %s, it should be a number, using no value", value, WARNING_SECONDS);
            }
        }
        return Long.MAX_VALUE;
   }

    @Override
    public boolean onAuthenticationResult(LDAPObject ldapUser, UserModel user, LdapValidationPasswordResult result, RealmModel realm) {
        if (result.getResponseControls() != null) {
            for (int i = 0; i < result.getResponseControls().length; i++) {
                Control ctrl = result.getResponseControls()[i];
                if (PASSWORD_EXPIRED_CONTROL_ID.equals(ctrl.getID())) {
                    logger.debug("Found expired control in the user, requesting update password");
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    return true;
                } else if (PASSWORD_EXPIRING_CONTROL_ID.equals(ctrl.getID())) {
                    final String value = new String(ctrl.getEncodedValue(), StandardCharsets.UTF_8);
                    try {
                        final long expiringTime = Long.parseLong(value);
                        if (expiringTime < getWarningSeconds()) {
                            logger.debugf("Found expiring control in the user with value %d, requesting update password", expiringTime);
                            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                            return true;
                        }
                    } catch (NumberFormatException e) {
                        logger.warnf("Invalid value for expiring control %s", value);
                    }
                }
            }
        }
        return false;
    }
}
