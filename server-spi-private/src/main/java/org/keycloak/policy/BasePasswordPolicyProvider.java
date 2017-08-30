/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.policy;

import org.keycloak.models.PasswordPolicy;

/**
 *
 * @author rmartinc
 */
public abstract class BasePasswordPolicyProvider implements PasswordPolicyProvider {
    
    protected PasswordPolicy policy;
    
    @Override
    public void setPolicy(PasswordPolicy policy) {
        this.policy = policy;
    }
    
}
