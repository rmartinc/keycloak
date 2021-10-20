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

import java.util.ArrayList;
import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import static org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory.createConfigProperty;

/**
 *
 * @author rmartinc
 */
public class NetscapeExpirationStorageMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String NETSCAPE_EXPIRATION_MAPPER = "netscape-expiration-mapper";
    public static String PASSWORD_EXPIRED_CONTROL_ID = "2.16.840.1.113730.3.4.4";
    public static String PASSWORD_EXPIRING_CONTROL_ID = "2.16.840.1.113730.3.4.5";
    public static final String WARNING_SECONDS = "attribute.warning";

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty attrValue = createConfigProperty(WARNING_SECONDS, "Warning seconds",
                "Number of seconds in which the password is requested to be changed.",
                ProviderConfigProperty.STRING_TYPE, null);
        configProperties.add(attrValue);
    }

    @Override
    public String getHelpText() {
        return "Mapper specific for Netscape ldap derivatives that manages the password expired/expiring controls (2.16.840.1.113730.3.4.4 and 2.16.840.1.113730.3.4.5). "
                + "The mapper read the controls returned on authentication sucecs or failure and sets the corresponding password action if needed.";
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new NetscapeExpirationStorageMapper(mapperModel, federationProvider);
    }

    @Override
    public String getId() {
        return NETSCAPE_EXPIRATION_MAPPER;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
