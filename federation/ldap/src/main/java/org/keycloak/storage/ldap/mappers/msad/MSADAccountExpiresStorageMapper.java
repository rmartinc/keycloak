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
package org.keycloak.storage.ldap.mappers.msad;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Stream;
import javax.naming.AuthenticationException;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageUtil;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.TxAwareLDAPUserModelDelegate;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;

/**
 *
 * @author rmartinc
 */
public class MSADAccountExpiresStorageMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(MSADAccountExpiresStorageMapper.class);

    // offset in milliseconds from Jan 1, 1601 to Jan 1, 1970
    private static final long AD_OFFSET = 11644473600000L;

    public MSADAccountExpiresStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public Set<String> getUserAttributes() {
        final String modelAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
        return modelAttr != null
                ? Collections.singleton(modelAttr)
                : Collections.emptySet();
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        final String modelAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
        if (modelAttr != null) {
            final String ldapAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE);
            final String ldapValue = ldapUser.getAttributeAsString(ldapAttr);
            if (ldapValue != null) {
                user.setSingleAttribute(modelAttr, ldapValue);
            }
        }
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm) {
        final String modelAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
        if (modelAttr != null) {
            final String ldapAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE);
            final String modelValue = user.getFirstAttribute(modelAttr);
            if (modelValue != null) {
                ldapUser.setSingleAttribute(ldapAttr, modelValue);
            }
        }
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        final String modelAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
        final String ldapAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE);

        // Add mapped attribute to returning ldap attributes
        query.addReturningLdapAttribute(ldapAttr);
        if (modelAttr == null) {
            query.addReturningReadOnlyLdapAttribute(ldapAttr);
        } else {
            // Change conditions to use ldapAttribute instead of userModel
            for (Condition condition : query.getConditions()) {
                condition.updateParameterName(modelAttr, ldapAttr);
            }
        }
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        final String modelAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
        final String ldapAttr = mapperModel.getConfig().getFirst(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE);

        if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {

            // proxy for updates of the accountExpires attribute
            delegate = new TxAwareLDAPUserModelDelegate(delegate, ldapProvider, ldapUser) {

                @Override
                public void setSingleAttribute(String name, String value) {
                    if (name.equals(modelAttr)) {
                        if (value == null && ldapUser.getAttributeAsString(ldapAttr) != null) {
                            throw new ModelException("accountExpires attribute cannot be deleted.");
                        }
                        markUpdatedAttributeInTransaction(modelAttr);
                        ldapUser.setSingleAttribute(ldapAttr, value);
                    }
                    super.setSingleAttribute(name, value);
                }

                @Override
                public void setAttribute(String name, List<String> values) {
                    if (name.equals(modelAttr)) {
                        if (values.isEmpty() && ldapUser.getAttributeAsString(ldapAttr) != null) {
                            throw new ModelException("accountExpires attribute cannot be deleted.");
                        } else if (values.size() > 1) {
                            throw new ModelException("accountExpires attribute can only have one attribute.");
                        }
                        markUpdatedAttributeInTransaction(modelAttr);
                        ldapUser.setSingleAttribute(ldapAttr, values.iterator().next());
                    }
                    super.setAttribute(name, values);
                }

                @Override
                public void removeAttribute(String name) {
                    if (name.equals(modelAttr) && ldapUser.getAttributeAsString(ldapAttr) != null) {
                        throw new ModelException("accountExpires attribute cannot be deleted.");
                    }
                    super.removeAttribute(name);
                }

                @Override
                public void setEnabled(boolean enabled) {
                    if (logger.isDebugEnabled() && enabled && isAccountExpired(ldapUser, ldapAttr)) {
                        logger.debugf("User account '%s' is expired in AD at %s so it will remain disabled.",
                                getUsername(), toDate(ldapUser.getAttributeAsString(ldapAttr)));
                    }
                    super.setEnabled(enabled);
                }
            };
        }

        // proxy for the accountExpires reads
        delegate = new UserModelDelegate(delegate) {

            @Override
            public String getFirstAttribute(String name) {
                if (name.equals(modelAttr)) {
                    return ldapUser.getAttributeAsString(name);
                }
                return super.getFirstAttribute(name);
            }

            @Override
            public Stream<String> getAttributeStream(String name) {
                if (name.equals(modelAttr)) {
                    return Optional.ofNullable(ldapUser.getAttributeAsSet(ldapAttr)).stream().flatMap(Set::stream);
                }
                return super.getAttributeStream(name);
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                Map<String, List<String>> attrs = super.getAttributes();

                if (modelAttr != null) {
                    attrs = new HashMap<>(attrs);

                    Set<String> allLdapAttrValues = ldapUser.getAttributeAsSet(ldapAttr);
                    if (allLdapAttrValues != null) {
                        attrs.put(modelAttr, new ArrayList<>(allLdapAttrValues));
                    } else {
                        attrs.remove(modelAttr);
                    }
                }

                return attrs;
            }

            @Override
            public boolean isEnabled() {
                if (isAccountExpired(ldapUser, ldapAttr)) {
                    if (logger.isTraceEnabled()) {
                        logger.debugf("User account '%s' is expired in AD at %s",
                                getUsername(), toDate(ldapUser.getAttributeAsString(ldapAttr)));
                    }
                    return false;
                }
                return super.isEnabled();
            }

            @Override
            public long getCacheTime(long currentTime) {
                final long time1 = super.getCacheTime(currentTime);
                final Long expireTime = getExpireTime(ldapUser, ldapAttr);
                final long time2 = expireTime != null ? expireTime : -1L;
                return time1 - currentTime > 0
                        ? time2 - currentTime > 0
                                ? Math.min(time1, time2)
                                : time1
                        : time2;
            }
        };

        return delegate;
    }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException, RealmModel realm) {
        if (user instanceof UserCache) {
            String exceptionMessage = ldapException.getMessage();
            Matcher m = MSADUserAccountControlStorageMapper.AUTH_EXCEPTION_REGEX.matcher(exceptionMessage);
            if (m.matches()) {
                String errorCode = m.group(1);
                if (errorCode.equals("701") && user.isEnabled()) {
                    UserStorageUtil.userCache(session).evict(realm, user);
                }
            }
        }
        return false;
    }

    public static long toMilliSeconds(long hundredNanoSecondsInterval) {
        // convert 100-nanosecond intervals to millis (10000 = 1 000 000ns / 100) and substract offset
        return (hundredNanoSecondsInterval / 10_000L) - AD_OFFSET;
    }

    public static long fromMilliSeconds(long milliSeconds) {
        // add the offset and convert to 100-nanosecond intervals
        return (milliSeconds + AD_OFFSET) * 10_000L;
    }

    public static Date toDate(long hundredNanoSecondsInterval) {
        return new Date(toMilliSeconds(hundredNanoSecondsInterval));
    }

    public static Date toDate(String hundredNanoSecondsInterval) {
        return toDate(Long.parseLong(hundredNanoSecondsInterval));
    }

    public static long fromDate(Date date) {
        return toMilliSeconds(date.getTime());
    }

    private static Long getExpireTime(LDAPObject ldapUser, String ldapAttr) {
        String valueString = ldapUser.getAttributeAsString(ldapAttr);
        if (valueString == null) {
            return null;
        }
        long value = Long.parseLong(valueString);
        if (value == 0 || value == 0x7FFFFFFFFFFFFFFFL) {
            return null;
        }
        return toMilliSeconds(value);
    }

    private static boolean isAccountExpired(LDAPObject ldapUser, String ldapAttr) {
        final Long expireTime = getExpireTime(ldapUser, ldapAttr);
        if (expireTime == null) {
            return false;
        }
        return Time.currentTimeMillis() >= expireTime;
    }

}