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

package org.keycloak.models.cache.infinispan.events;

import java.util.Set;

import org.keycloak.models.cache.infinispan.RealmCacheManager;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import org.infinispan.commons.marshall.Externalizer;
import org.infinispan.commons.marshall.MarshallUtil;
import org.infinispan.commons.marshall.SerializeWith;
import org.keycloak.models.cache.infinispan.RealmCacheSession;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@SerializeWith(GroupUpdatedEvent.ExternalizerImpl.class)
public class GroupUpdatedEvent extends InvalidationEvent implements RealmCacheInvalidationEvent {

    private String groupId;
    private String groupName;
    private String parentId;
    private String realmId;

    public static GroupUpdatedEvent create(String groupId, String groupName, String parentId, String realmId) {
        GroupUpdatedEvent event = new GroupUpdatedEvent();
        event.groupId = groupId;
        event.groupName = groupName;
        event.parentId = parentId;
        event.realmId = realmId;
        return event;
    }

    @Override
    public String getId() {
        return groupId;
    }


    @Override
    public String toString() {
        return "GroupUpdatedEvent [ " + groupId + " ]";
    }

    @Override
    public void addInvalidations(RealmCacheManager realmCache, Set<String> invalidations) {
        invalidations.add(RealmCacheSession.getGroupByNameAndParentCacheKey(groupName, parentId, realmId));
    }

    public static class ExternalizerImpl implements Externalizer<GroupUpdatedEvent> {

        private static final int VERSION_1 = 1;
        private static final int VERSION_2 = 2;

        @Override
        public void writeObject(ObjectOutput output, GroupUpdatedEvent obj) throws IOException {
            output.writeByte(VERSION_2);

            MarshallUtil.marshallString(obj.groupId, output);
            MarshallUtil.marshallString(obj.groupName, output);
            MarshallUtil.marshallString(obj.parentId, output);
            MarshallUtil.marshallString(obj.realmId, output);
        }

        @Override
        public GroupUpdatedEvent readObject(ObjectInput input) throws IOException, ClassNotFoundException {
            switch (input.readByte()) {
                case VERSION_1:
                    return readObjectVersion1(input);
                case VERSION_2:
                    return readObjectVersion2(input);
                default:
                    throw new IOException("Unknown version");
            }
        }

        public GroupUpdatedEvent readObjectVersion1(ObjectInput input) throws IOException, ClassNotFoundException {
            GroupUpdatedEvent res = new GroupUpdatedEvent();
            res.groupId = MarshallUtil.unmarshallString(input);

            return res;
        }

        public GroupUpdatedEvent readObjectVersion2(ObjectInput input) throws IOException, ClassNotFoundException {
            GroupUpdatedEvent res = new GroupUpdatedEvent();
            res.groupId = MarshallUtil.unmarshallString(input);
            res.groupName = MarshallUtil.unmarshallString(input);
            res.parentId = MarshallUtil.unmarshallString(input);
            res.realmId = MarshallUtil.unmarshallString(input);

            return res;
        }
    }
}
