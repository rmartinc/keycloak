/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.models.jpa.entities;

import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

/**
 *
 * @author rmartinc
 */
@Table(name="REALM_PASSWORD_POLICY_GROUP")
@Entity
@IdClass(RealmPasswordPolicyGroupEntity.Key.class)
public class RealmPasswordPolicyGroupEntity {
    
    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected RealmEntity realm;
    
    @Id
    @Column(name = "NAME")
    protected String name;
    
    @Column(name = "PASSWORD_POLICY")
    protected String passwordPolicy;
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPasswordPolicy() {
        return passwordPolicy;
    }

    public void setPasswordPolicy(String passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    public RealmEntity getRealm() {
        return realm;
    }

    public void setRealm(RealmEntity realm) {
        this.realm = realm;
    }
    
    public static class Key implements Serializable {

        protected RealmEntity realm;

        protected String name;

        public Key() {
        }

        public Key(RealmEntity realm, String name) {
            this.realm = realm;
            this.name = name;
        }

        public RealmEntity getRealm() {
            return realm;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (name != null ? !name.equals(key.name) : key.name != null) return false;
            if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = realm != null ? realm.getId().hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof RealmAttributeEntity)) return false;

        RealmAttributeEntity key = (RealmAttributeEntity) o;

        if (name != null ? !name.equals(key.name) : key.name != null) return false;
        if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = realm != null ? realm.getId().hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }
}
