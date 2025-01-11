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

import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;

/**
 * <p>Specific Active Directory mapper to manage the
 * <a href="https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires">accountExpires</a>
 * attribute.</p>
 *
 * <p>The mapper calculates the enabled attribute based on the <em>accountExpires</em>
 * value (enabled is changed to false when the account is expired in AD). The
 * <em>accountExpires</em> value can be mapped to a user attribute too.<p>
 *
 * @author rmartinc
 */
public class MSADAccountExpiresStorageMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String PROVIDER_ID = "msad-user-account-expires-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return """
               Mapper specific for MSAD. This mapper manages the accountExpires attribute in AD.
               The attribute represents the number of 100-nanosecond intervals since January 1, 1601 (UTC).
               A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires.
               When this mapper is used the expiration is managed to calculate the enabled user property too.
               """;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE)
                .label("LDAP Attribute")
                .helpText("Name of the accountExpires attribute. Required.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .required(true)
                .defaultValue("accountExpires")
                .add()
                .property()
                .name(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE)
                .label("User Model Attribute")
                .helpText("Name of the UserModel attribute you want to map the session expires value into. If not provided the value would not be added to the user model attributes. Optional.")
                .type(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE)
                .required(false)
                .add()
                .build();
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new MSADAccountExpiresStorageMapper(mapperModel, federationProvider);
    }
}
