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

package org.keycloak.models;

import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.policy.PolicyError;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class PasswordPolicy implements Serializable {

    public static final String HASH_ALGORITHM_ID = "hashAlgorithm";

    public static final String HASH_ALGORITHM_DEFAULT = "pbkdf2-sha256";

    public static final String HASH_ITERATIONS_ID = "hashIterations";

    public static final int HASH_ITERATIONS_DEFAULT = 27500;

    public static final String PASSWORD_HISTORY_ID = "passwordHistory";

    public static final String FORCE_EXPIRED_ID = "forceExpiredPasswordChange";

    private Map<String, List<Object>> policyConfig;
    private Builder builder;

    public static PasswordPolicy empty() {
        return new PasswordPolicy(null, new HashMap<>());
    }

    public static Builder build() {
        return new Builder();
    }
    
    private static void addProviderIfNecessary(KeycloakSession session, PasswordPolicy result, PasswordPolicy policy) {
        for (Map.Entry<String, List<Object>> entry : policy.policyConfig.entrySet()) {
            for (Object config : entry.getValue()) {
                PasswordPolicyProvider provider = session.getProvider(PasswordPolicyProvider.class, entry.getKey());
                List<Object> values = result.policyConfig.get(entry.getKey());
                if (values == null) {
                    values = new ArrayList<>();
                    result.policyConfig.put(entry.getKey(), values);
                }
                if (provider.isMultiplSupported()) {
                    // multi provider => just add it
                    values.add(config);
                } else if (values.isEmpty()) {
                    // non-multi but it's the first one => add it
                    values.add(config);
                } else if (provider.compare(config, values.get(0)) > 0) {
                    // non-multi and more restrictive => replace
                    values.set(0, config);
                }
            }
        }
    }
    
    public static PasswordPolicy construct(KeycloakSession session, PasswordPolicy defaultPolicy, List<PasswordPolicy> otherPolicies) {
        if (otherPolicies == null || otherPolicies.isEmpty()) {
            return defaultPolicy;
        }
        // first add non-default
        PasswordPolicy result = new PasswordPolicy(new Builder(), new HashMap<>());
        for (PasswordPolicy policy: otherPolicies) {
            addProviderIfNecessary(session, result, policy);
        }
        // last the default one
        addProviderIfNecessary(session, result, defaultPolicy);
        return result;
    }

    public static PasswordPolicy parse(KeycloakSession session, String policyString) {
        return new Builder(policyString).build(session);
    }

    private PasswordPolicy(Builder builder, Map<String, List<Object>> policyConfig) {
        this.builder = builder;
        this.policyConfig = policyConfig;
    }

    public PolicyError validate(KeycloakSession session, String user, String password) {
        PolicyError result = null;
        for (Map.Entry<String, List<Object>> entry : policyConfig.entrySet()) {
            for (Object config : entry.getValue()) {
                PasswordPolicyProvider provider = session.getProvider(PasswordPolicyProvider.class, entry.getKey());
                result = provider.validate(user, password, config);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }
    
    public PolicyError validate(KeycloakSession session, RealmModel realm, UserModel user, String password) {
        PolicyError result = null;
        for (Map.Entry<String, List<Object>> entry : policyConfig.entrySet()) {
            for (Object config : entry.getValue()) {
                PasswordPolicyProvider provider = session.getProvider(PasswordPolicyProvider.class, entry.getKey());
                result = provider.validate(realm, user, password, config);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    public String getHashAlgorithm() {
        List<Object> config = policyConfig.get(HASH_ALGORITHM_ID);
        if (config != null && !config.isEmpty()) {
            return (String) config.get(0);
        } else {
            return HASH_ALGORITHM_DEFAULT;
        }
    }

    public int getHashIterations() {
        List<Object> config = policyConfig.get(HASH_ITERATIONS_ID);
        if (config != null && !config.isEmpty()) {
            return (Integer) config.get(0);
        } else {
            return -1;
        }
    }

    public int getExpiredPasswords() {
        List<Object> config = policyConfig.get(PASSWORD_HISTORY_ID);
        if (config != null && !config.isEmpty()) {
            return (Integer) config.get(0);
        } else {
            return -1;
        }
    }

    public int getDaysToExpirePassword() {
        List<Object> config = policyConfig.get(FORCE_EXPIRED_ID);
        if (config != null && !config.isEmpty()) {
            return (Integer) config.get(0);
        } else {
            return -1;
        }
    }

    @Override
    public String toString() {
        return builder.asString();
    }

    public Builder toBuilder() {
        return builder.clone();
    }

    public static class Builder {

        private LinkedHashMap<String, List<String>> map;

        private Builder() {
            this.map = new LinkedHashMap<>();
        }

        private Builder(LinkedHashMap<String, List<String>> map) {
            this.map = map;
        }

        private Builder(String policyString) {
            map = new LinkedHashMap<>();

            if (policyString != null && !policyString.trim().isEmpty()) {
                for (String policy : policyString.split(" and ")) {
                    policy = policy.trim();

                    String key;
                    String config = null;

                    int i = policy.indexOf('(');
                    if (i == -1) {
                        key = policy.trim();
                    } else {
                        key = policy.substring(0, i).trim();
                        config = policy.substring(i + 1, policy.length() - 1);
                    }

                    this.put(key, config);
                }
            }
        }

        public boolean contains(String key) {
            return map.containsKey(key);
        }

        public String getFirst(String key) {
            List<String> values = map.get(key);
            if (values == null || values.isEmpty()) {
                return null;
            } else {
                return values.get(0);
            }
        }
        
        public List<String> get(String key) {
            return map.get(key);
        }

        public Builder put(String key, String value) {
            List<String> values = map.get(key);
            if (values == null) {
                values = new ArrayList<>();
                map.put(key, values);
            }
            values.add(value);
            return this;
        }

        public Builder removeAll(String key) {
            map.remove(key);
            return this;
        }

        public PasswordPolicy build(KeycloakSession session) {
            Map<String, List<Object>> config = new HashMap<>();
            for (Map.Entry<String, List<String>> e : map.entrySet()) {
                for (String v : e.getValue()) {

                    PasswordPolicyProvider provider = session.getProvider(PasswordPolicyProvider.class, e.getKey());
                    if (provider == null) {
                        throw new PasswordPolicyConfigException("Password policy not found");
                    }

                    Object o;
                    try {
                        o = provider.parseConfig(v);
                    } catch (PasswordPolicyConfigException ex) {
                        throw new ModelException("Invalid config for " + e.getKey() + ": " + ex.getMessage());
                    }
                    List<Object> list = config.get(e.getKey());
                    if (list == null) {
                        list = new ArrayList<>();
                        config.put(e.getKey(), list);
                    } else if (!list.isEmpty() && !provider.isMultiplSupported()) {
                        throw new PasswordPolicyConfigException("Invalid multiple definition for config " + e.getKey());
                    }
                    list.add(o);
                }
            }
            return new PasswordPolicy(this, config);
        }

        public String asString() {
            if (map.isEmpty()) {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Map.Entry<String, List<String>> e : map.entrySet()) {
                for (String v : e.getValue()) {
                    if (first) {
                        first = false;
                    } else {
                        sb.append(" and ");
                    }

                    sb.append(e.getKey());

                    if (v != null && !v.trim().isEmpty()) {
                        sb.append("(");
                        sb.append(v);
                        sb.append(")");
                    }
                }
            }
            return sb.toString();
        }

        public Builder clone() {
            return new Builder((LinkedHashMap<String, List<String>>) map.clone());
        }

    }

}
