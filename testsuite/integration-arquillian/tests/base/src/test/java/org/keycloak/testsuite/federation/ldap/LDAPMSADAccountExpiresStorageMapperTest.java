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
package org.keycloak.testsuite.federation.ldap;

import java.util.Collections;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.msad.MSADAccountExpiresStorageMapper;
import org.keycloak.storage.ldap.mappers.msad.MSADAccountExpiresStorageMapperFactory;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.util.LDAPRule;
import org.keycloak.testsuite.util.LDAPTestUtils;

/**
 *
 * @author rmartinc
 */
public class LDAPMSADAccountExpiresStorageMapperTest extends AbstractLDAPTest {

    @ClassRule
    public static LDAPRule ldapRule = new LDAPRule();

    @Override
    protected LDAPRule getLDAPRule() {
        return ldapRule;
    }

    @Override
    protected void afterImportTestRealm() {
        final String ldapAttr = LDAPConstants.VENDOR_ACTIVE_DIRECTORY.equals(ldapRule.getConfig().get(LDAPConstants.VENDOR))
                ? "accountExpires"
                : "description";

        testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();

            // create a accountExpires attribute
            ComponentModel mapperModel = KeycloakModelUtils.createComponentModel("account-expires-mapper", ctx.getLdapModel().getId(),
                    MSADAccountExpiresStorageMapperFactory.PROVIDER_ID, LDAPStorageMapper.class.getName(),
                    UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, ldapAttr,
                    UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, "accountExpires");
            appRealm.addComponentModel(mapperModel);

            // delete all users and create one for testing
            LDAPTestUtils.removeAllLDAPUsers(ctx.getLdapProvider(), appRealm);
            MultivaluedHashMap<String, String> attrs = new MultivaluedHashMap<>();
            attrs.putSingle("accountExpires", "0");
            LDAPObject john = LDAPTestUtils.addLDAPUser(ctx.getLdapProvider(), appRealm, "johnkeycloak", "John", "Doe", "john@email.org", null, attrs, "1234");
            LDAPTestUtils.updateLDAPPassword(ctx.getLdapProvider(), john, "Password1");
        });
    }

    @Test
    public void testReadOnlyExpires() throws Exception {
        final String ldapAttr = LDAPConstants.VENDOR_ACTIVE_DIRECTORY.equals(ldapRule.getConfig().get(LDAPConstants.VENDOR))
                ? "accountExpires"
                : "description";
        final RealmResource realm = testRealm();
        final ComponentRepresentation ldapComponent = getLdapComponent(realm);
        setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.READ_ONLY);

        try {
            // check the user is enabled and account expires is 0
            UserRepresentation john = ApiUtil.findUserByUsername(realm, "johnkeycloak");
            final UserResource johnRes = realm.users().get(john.getId());
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
            Assert.assertTrue(john.isEnabled());

            // modify the user with expiration in 10 min (cache time) using ldap, user is cached
            final String expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis() + 600_000L));
            testingClient.server().run(session -> {
                LDAPTestContext ctx = LDAPTestContext.init(session);
                LDAPStorageProvider ldapProvider = ctx.getLdapProvider();
                RealmModel ldapRealm = ctx.getRealm();
                LDAPObject ldapUser = ldapProvider.loadLDAPUserByUsername(ldapRealm, "johnkeycloak");
                ldapUser.setSingleAttribute(ldapAttr, expires);
                ctx.getLdapProvider().getLdapIdentityStore().update(ldapUser);
            });
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
            Assert.assertTrue(john.isEnabled());

            // assert the user is expired after the cache time
            setTimeOffset(605);
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
            Assert.assertFalse(john.isEnabled());

            // update to enable the user again
            testingClient.server().run(session -> {
                LDAPTestContext ctx = LDAPTestContext.init(session);
                LDAPStorageProvider ldapProvider = ctx.getLdapProvider();
                RealmModel ldapRealm = ctx.getRealm();
                LDAPObject ldapUser = ldapProvider.loadLDAPUserByUsername(ldapRealm, "johnkeycloak");
                ldapUser.setSingleAttribute(ldapAttr, "0");
                ctx.getLdapProvider().getLdapIdentityStore().update(ldapUser);
            });

            // wait the cache time again and the user should be enabled
            setTimeOffset(1210);
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
            Assert.assertTrue(john.isEnabled());
        } finally {
            setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.WRITABLE);
        }
    }

    @Test
    public void testReadOnlyExpiresNoModelAttr() throws Exception {
        final String ldapAttr = LDAPConstants.VENDOR_ACTIVE_DIRECTORY.equals(ldapRule.getConfig().get(LDAPConstants.VENDOR))
                ? "accountExpires"
                : "description";
        final RealmResource realm = testRealm();
        final ComponentRepresentation ldapComponent = getLdapComponent(realm);
        final ComponentRepresentation mapperComponent = getAccountExpiresMapperComponent(realm, ldapComponent);
        setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.READ_ONLY);
        updateAccountExpiresMapper(realm, mapperComponent, ldapAttr, "");

        try {
            // check the user is enabled
            UserRepresentation john = ApiUtil.findUserByUsername(realm, "johnkeycloak");
            final UserResource johnRes = realm.users().get(john.getId());
            Assert.assertTrue(john.isEnabled());

            // modify the user with expiration in 10 min (cache time) using ldap, user is cached
            final String expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis() + 600_000L));
            testingClient.server().run(session -> {
                LDAPTestContext ctx = LDAPTestContext.init(session);
                LDAPStorageProvider ldapProvider = ctx.getLdapProvider();
                RealmModel ldapRealm = ctx.getRealm();
                LDAPObject ldapUser = ldapProvider.loadLDAPUserByUsername(ldapRealm, "johnkeycloak");
                ldapUser.removeReadOnlyAttributeName(ldapAttr);
                ldapUser.setSingleAttribute(ldapAttr, expires);
                ctx.getLdapProvider().getLdapIdentityStore().update(ldapUser);
            });
            john = johnRes.toRepresentation();
            Assert.assertTrue(john.isEnabled());

            // assert the user is expired after the cache time
            setTimeOffset(605);
            john = johnRes.toRepresentation();
            Assert.assertFalse(john.isEnabled());

            // update to enable the user again
            testingClient.server().run(session -> {
                LDAPTestContext ctx = LDAPTestContext.init(session);
                LDAPStorageProvider ldapProvider = ctx.getLdapProvider();
                RealmModel ldapRealm = ctx.getRealm();
                LDAPObject ldapUser = ldapProvider.loadLDAPUserByUsername(ldapRealm, "johnkeycloak");
                ldapUser.removeReadOnlyAttributeName(ldapAttr);
                ldapUser.setSingleAttribute(ldapAttr, "0");
                ctx.getLdapProvider().getLdapIdentityStore().update(ldapUser);
            });

            // wait the cache time again and the user should be enabled
            setTimeOffset(1210);
            john = johnRes.toRepresentation();
            Assert.assertTrue(john.isEnabled());
        } finally {
            setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.WRITABLE);
            updateAccountExpiresMapper(realm, mapperComponent, ldapAttr, "accountExpires");
        }
    }

    @Test
    public void testWritableAccountExpires() throws Exception {
        // check the user is enabled and no account expires is 0
        final RealmResource realm = testRealm();
        UserRepresentation john = ApiUtil.findUserByUsername(realm, "johnkeycloak");
        final UserResource johnRes = realm.users().get(john.getId());
        Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
        Assert.assertTrue(john.isEnabled());

        // modify the user with expiration in 10 min (cache time)
        final String expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis() + 600_000L));
        john.getAttributes().put("accountExpires", Collections.singletonList(expires));
        johnRes.update(john);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
        Assert.assertTrue(john.isEnabled());

        // assert it is expired after the cache time
        setTimeOffset(605);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
        Assert.assertFalse(john.isEnabled());

        // update to enable the user again
        john.getAttributes().put("accountExpires", Collections.singletonList("0"));
        john.setEnabled(Boolean.TRUE);
        johnRes.update(john);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
        Assert.assertTrue(john.isEnabled());
    }

    @Test
    public void testAccountExpiresLogin() throws Exception {
        final RealmResource realm = testRealm();
        UserRepresentation john = ApiUtil.findUserByUsername(realm, "johnkeycloak");
        final UserResource johnRes = realm.users().get(john.getId());

        // john can login with no account expires
        login(johnRes, true);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
        Assert.assertTrue(john.isEnabled());

        // john can login setting it 10s in the future
        String expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis() + 10_000L));
        john.getAttributes().put("accountExpires", Collections.singletonList(expires));
        johnRes.update(john);
        login(johnRes, true);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
        Assert.assertTrue(john.isEnabled());

        // john cannot login seeting it to now
        expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis()));
        john.getAttributes().put("accountExpires", Collections.singletonList(expires));
        realm.users().get(john.getId()).update(john);
        login(johnRes, false);
        john = johnRes.toRepresentation();
        Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
        Assert.assertFalse(john.isEnabled());

        // reset
        john = johnRes.toRepresentation();
        john.getAttributes().put("accountExpires", Collections.singletonList("0"));
        john.setEnabled(Boolean.TRUE);
        johnRes.update(john);
    }

    @Test
    public void testAccountExpiresReadOnlyLoginFailure() throws Exception {
        Assume.assumeThat("Login failure because of accountExpires is limited to vendor AD",
                ldapRule.getConfig().get(LDAPConstants.VENDOR), Matchers.is(LDAPConstants.VENDOR_ACTIVE_DIRECTORY));

        final String ldapAttr = "accountExpires";
        final RealmResource realm = testRealm();
        final ComponentRepresentation ldapComponent = getLdapComponent(realm);
        setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.READ_ONLY);

        try {
            UserRepresentation john = ApiUtil.findUserByUsername(realm, "johnkeycloak");
            final UserResource johnRes = realm.users().get(john.getId());

            // john can login with no account expires
            login(johnRes, true);
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
            Assert.assertTrue(john.isEnabled());

            // modify the user in ldap with expiration to now but cache remains the user enabled
            final String expires = Long.toString(MSADAccountExpiresStorageMapper.fromMilliSeconds(Time.currentTimeMillis()));
            testingClient.server().run(session -> {
                LDAPTestContext ctx = LDAPTestContext.init(session);
                LDAPStorageProvider ldapProvider = ctx.getLdapProvider();
                RealmModel ldapRealm = ctx.getRealm();
                LDAPObject ldapUser = ldapProvider.loadLDAPUserByUsername(ldapRealm, "johnkeycloak");
                ldapUser.setSingleAttribute(ldapAttr, expires);
                ctx.getLdapProvider().getLdapIdentityStore().update(ldapUser);
            });
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList("0"), john.getAttributes().get("accountExpires"));
            Assert.assertTrue(john.isEnabled());

            // force a login failure in AD that should disable the user (evicted from cache)
            login(johnRes, false);
            john = johnRes.toRepresentation();
            Assert.assertEquals(Collections.singletonList(expires), john.getAttributes().get("accountExpires"));
            Assert.assertFalse(john.isEnabled());
        } finally {
            setLdapMode(realm, ldapComponent, UserStorageProvider.EditMode.WRITABLE);
        }
    }

    private void login(UserResource johnRes, boolean success) {
        loginPage.open();
        loginPage.login("johnkeycloak", "Password1");
        if (success) {
            Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        } else {
            loginPage.assertCurrent();
            // depending on cache and vendor it can be user disabled or invalid username or password
            if (loginPage.getError() != null) {
                Assert.assertEquals("Account is disabled, contact your administrator.", loginPage.getError());
            } else {
                Assert.assertEquals("Invalid username or password.", loginPage.getInputError());
            }
        }
        johnRes.logout();
    }

    private ComponentRepresentation getLdapComponent(RealmResource realm) {
        ComponentRepresentation ldapComponent = realm.components().query(
                realm.toRepresentation().getId(), UserStorageProvider.class.getName(), "test-ldap")
                .stream().findAny().orElse(null);
        Assert.assertNotNull(ldapComponent);
        return ldapComponent;
    }

    private ComponentRepresentation getAccountExpiresMapperComponent(RealmResource realm, ComponentRepresentation ldapComponent) {
        ComponentRepresentation mapperComponent = realm.components().query(
                ldapComponent.getId(), LDAPStorageMapper.class.getName(), "account-expires-mapper")
                .stream().findAny().orElse(null);
        Assert.assertNotNull(mapperComponent);
        return mapperComponent;
    }

    private void setLdapMode(RealmResource realm, ComponentRepresentation ldapComponent, UserStorageProvider.EditMode mode) {
        ldapComponent.getConfig().putSingle(LDAPConstants.EDIT_MODE, mode.toString());
        realm.components().component(ldapComponent.getId()).update(ldapComponent);
    }

    private void updateAccountExpiresMapper(RealmResource realm, ComponentRepresentation mapperComponent,
            String ldapAttr, String modelAttr) {
        mapperComponent.getConfig().putSingle(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, ldapAttr);
        mapperComponent.getConfig().putSingle(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, modelAttr);
        realm.components().component(mapperComponent.getId()).update(mapperComponent);
    }

}
