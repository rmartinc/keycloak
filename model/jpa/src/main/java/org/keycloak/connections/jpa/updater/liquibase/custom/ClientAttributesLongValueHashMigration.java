/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.connections.jpa.updater.liquibase.custom;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import liquibase.exception.CustomChangeException;
import liquibase.statement.core.RawParameterizedSqlStatement;
import org.keycloak.storage.jpa.JpaHashUtils;

/**
 *
 * @author rmartinc
 */
public class ClientAttributesLongValueHashMigration extends CustomKeycloakTask {

    @Override
    protected void generateStatementsImpl() throws CustomChangeException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT CLIENT_ID, NAME, LONG_VALUE"
                + "  FROM " + getTableName("CLIENT_ATTRIBUTES")
                + "  WHERE LONG_VALUE is not NULL"); ResultSet resultSet = ps.executeQuery()) {
            while (resultSet.next()) {
                String clientId = resultSet.getString(1);
                String name = resultSet.getString(2);
                String value = resultSet.getString(3);
                statements.add(new RawParameterizedSqlStatement(
                        "UPDATE " + getTableName("CLIENT_ATTRIBUTES")
                        + " SET LONG_VALUE_HASH = ?"
                        + " WHERE CLIENT_ID = ? AND NAME = ?",
                        JpaHashUtils.hashForAttributeValue(value),
                        clientId,
                        name));
            }
        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when updating data from previous version", e);
        }
    }

    @Override
    protected String getTaskId() {
        return "ClientAttributesLongValueHashMigration";
    }
}
