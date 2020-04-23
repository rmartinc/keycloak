/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import liquibase.exception.CustomChangeException;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Column;
import org.jboss.logging.Logger;

/**
 * <p>Helper class to rename possible duplicated groups at top level. Previously
 * the unique key for top level groups was incorrect and groups placed at top
 * level could be duplicated (NULL parent). This class renames those groups to
 * allow the upgrade. Nevertheless if there are duplicated top level groups
 * a manual check of the duplicated list is recommended. Only one top level
 * group can exist in the realm with the same name (duplicates should be
 * examined and deleted from the realm).</p>
 *
 * <p>To obtain the top level groups that are duplicated the following query
 * can be executed at database level:</p>
 *
 * <pre>
 * SELECT REALM_ID, NAME, COUNT(*) FROM KEYCLOAK_GROUP WHERE PARENT_GROUP is NULL GROUP BY REALM_ID, NAME HAVING COUNT(*) > 1;
 * </pre>
 *
 * @author rmartinc
 */
public class RenameDuplicatedTopLevelGroups extends CustomKeycloakTask {

    private final Logger logger = Logger.getLogger(getClass());

    private static class DuplicatedGroup {
        final private String realmId;
        final private String groupName;
        final private String groupId;

        public DuplicatedGroup(String realmId, String groupName, String groupId) {
            this.realmId = realmId;
            this.groupName = groupName;
            this.groupId = groupId;
        }

        public String getRealmId() {
            return realmId;
        }

        public String getGroupName() {
            return groupName;
        }

        public String getGroupId() {
            return groupId;
        }

        @Override
        public boolean equals(Object o2) {
            if (o2 instanceof DuplicatedGroup) {
                DuplicatedGroup dg2 = (DuplicatedGroup) o2;
                return this.realmId.equals(dg2.realmId) && this.groupName.equals(dg2.groupName);
            }
            return false;
        }

        @Override
        public int hashCode() {
            int hash = 5;
            hash = 29 * hash + Objects.hashCode(this.realmId);
            hash = 29 * hash + Objects.hashCode(this.groupName);
            return hash;
        }
    }

    private boolean existsNewNameInRealm(String keycloakGroupTableName, String realmId, String newName) throws CustomChangeException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT ID FROM " + keycloakGroupTableName + " WHERE PARENT_GROUP is NULL AND REALM_ID = ? AND NAME = ?")) {
            ps.setString(1, realmId);
            ps.setString(2, newName);
            try (ResultSet rs = ps.executeQuery()) {
                // check if the new name is already taken
                return rs.next();
            }
        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when checking the new name for renaming", e);
        }
    }

    @Override
    protected void generateStatementsImpl() throws CustomChangeException {
        String keycloakGroupTableName = getTableName("KEYCLOAK_GROUP");
        List<DuplicatedGroup> duplicatedGroups = new ArrayList<>();
        // get the list of duplicated names at top level groups
        // doing a join to get the list in just one query
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT g1.REALM_ID, g1.NAME, g1.ID " +
                "FROM " + keycloakGroupTableName + " g1," +
                "     (SELECT REALM_ID, NAME FROM " + keycloakGroupTableName + " WHERE PARENT_GROUP is NULL GROUP BY REALM_ID, NAME HAVING COUNT(*) > 1) g2 " +
                "WHERE g1.PARENT_GROUP is NULL AND g1.NAME=g2.NAME AND g1.REALM_ID=g2.REALM_ID " +
                "ORDER BY g1.REALM_ID, g1.NAME")) {
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    DuplicatedGroup dg = new DuplicatedGroup(rs.getString(1), rs.getString(2), rs.getString(3));
                    duplicatedGroups.add(dg);
                }
            }
        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when renaming duplicated top level group names", e);
        }
        if (!duplicatedGroups.isEmpty()) {
            logger.warnf("Found %d duplicated top level groups. Duplicated groups will be renamed but please re-check the list.", duplicatedGroups.size());
            int suffix = 0;
            DuplicatedGroup previous = null;
            for (DuplicatedGroup current : duplicatedGroups) {
                // rename the top level groups except the first one (different to the previous one)
                if (current.equals(previous)) {
                    // previous is equals to this group => it's duplicated and should be renamed
                    String newName;
                    do {
                        suffix++;
                        newName = current.getGroupName() + "-" + suffix;
                    } while (existsNewNameInRealm(keycloakGroupTableName, current.getRealmId(), newName));
                    logger.warnf("Renaming top level group realm='%s' name='%s' id='%s' to new name '%s'", current.getRealmId(), current.getGroupName(), current.getGroupId(), newName);
                    statements.add(new UpdateStatement(null, null, "KEYCLOAK_GROUP")
                            .addNewColumnValue("NAME", newName)
                            .setWhereClause(database.escapeObjectName("ID", Column.class) + " = ?")
                            .addWhereParameters(current.getGroupId()));
                } else {
                    // new duplicated group => reset suffix to 0 again
                    suffix = 0;
                }
                previous = current;
            }
        }
    }

    @Override
    protected String getTaskId() {
        return "keycloak-9.0.1-rename-duplicated-top-level-groups";
    }

}
