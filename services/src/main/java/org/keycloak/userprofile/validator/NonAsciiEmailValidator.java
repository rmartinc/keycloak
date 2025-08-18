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
package org.keycloak.userprofile.validator;

import java.util.List;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.validation.Validation;
import org.keycloak.validate.SimpleValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationError;
import org.keycloak.validate.ValidatorConfig;

/**
 *
 * @author rmartinc
 */
public class NonAsciiEmailValidator implements SimpleValidator {

    public static final String ID = "up-email-non-ascii";
    public static final String MESSAGE_NON_ASCII_LOCAL_PART_EMAIL = "error-non-ascii-local-part-email";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public ValidationContext validate(Object input, String inputHint, ValidationContext context, ValidatorConfig config) {
        List<String> values = (List<String>) input;

        if (values == null || values.isEmpty()) {
            return context;
        }

        String value = values.get(0);

        if (Validation.isBlank(value)) {
            return context;
        }

        final KeycloakSession session = context.getSession();
        final RealmModel realm = session.getContext().getRealm();
        if (realm == null || realm.getSmtpConfig().isEmpty() || "true".equals(realm.getSmtpConfig().get("allowutf8"))) {
            // UTF-8 non-ascii chars allowed because no smtp configuration or allowutf8 is enabled
            return context;
        }

        final int idx = value.indexOf('@');
        if (idx < 0) {
            return context;
        }

        final String local = value.substring(0, idx);
        if (!local.chars().allMatch(c -> c < 128)) {
            context.addError(new ValidationError(ID, inputHint, MESSAGE_NON_ASCII_LOCAL_PART_EMAIL, local));
        }

        return context;
    }

}
