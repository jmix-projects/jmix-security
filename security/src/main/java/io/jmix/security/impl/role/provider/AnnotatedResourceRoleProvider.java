/*
 * Copyright 2020 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jmix.security.impl.role.provider;

import io.jmix.core.common.util.ReflectionHelper;
import io.jmix.core.impl.scanning.JmixModulesClasspathScanner;
import io.jmix.security.impl.role.builder.AnnotatedRoleBuilder;
import io.jmix.security.impl.role.builder.extractor.ResourcePolicyExtractor;
import io.jmix.security.impl.role.helper.RoleHelper;
import io.jmix.security.model.ResourcePolicy;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.role.ResourceRoleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Role provider that gets roles from classes annotated with
 * {@link io.jmix.security.role.annotation.ResourceRole}.
 */
@Component("sec_AnnotatedResourceRoleProvider")
public class AnnotatedResourceRoleProvider implements ResourceRoleProvider {

    protected Map<String, ResourceRole> roles;

    private final AnnotatedRoleBuilder annotatedRoleBuilder;

    private final Collection<ResourcePolicyExtractor> resourcePolicyExtractors;

    @Autowired
    public AnnotatedResourceRoleProvider(JmixModulesClasspathScanner classpathScanner,
                                         AnnotatedRoleBuilder annotatedRoleBuilder,
                                         Collection<ResourcePolicyExtractor> resourcePolicyExtractors) {
        this.annotatedRoleBuilder = annotatedRoleBuilder;
        this.resourcePolicyExtractors = resourcePolicyExtractors;

        Set<String> classNames = classpathScanner.getClassNames(ResourceRoleDetector.class);
        roles = classNames.stream()
                .map(annotatedRoleBuilder::createResourceRole)
                .collect(Collectors.toMap(ResourceRole::getCode, Function.identity()));
    }

    //refresh() - ?

    @Override
    public Collection<ResourceRole> getAllRoles() {
        Set<Map.Entry<String, ResourceRole>> entrySet = roles.entrySet();
        for (Map.Entry<String, ResourceRole> entry : entrySet) {
            String code = entry.getKey();
            roles.put(code, findRoleByCode(code));
        }
        //TODO Create method refresh() - it adds roles absent in cache
        return roles.values();
    }

    @Override
    @Nullable
    public ResourceRole findRoleByCode(String code) {
        // TODO Add new role by its code
        // if(!roles.get(code) == null) {
        //  return addRole(code);
        // }

        ResourceRole oldRole = roles.get(code);
        Collection<ResourcePolicy> oldResourcePolicies = oldRole.getAllResourcePolicies();

        String roleClassName = roles.get(code).getClass().getName();
        Class<?> roleClass = RoleHelper.loadClass(roleClassName);

        Collection<ResourcePolicy> newResourcePolicies = RoleHelper.extractResourcePolicies(roleClass, resourcePolicyExtractors);

        oldResourcePolicies = new HashSet<>(oldResourcePolicies);

        newResourcePolicies = new HashSet<>(newResourcePolicies);

        if (!oldResourcePolicies.equals(newResourcePolicies)) {
            ResourceRole newRole = annotatedRoleBuilder.createResourceRole(roleClassName);
            roles.put(code, newRole);
            return newRole;
        }

        return oldRole;
    }

    @Override
    public boolean deleteRole(ResourceRole role) {
        throw new UnsupportedOperationException("Annotated role cannot be deleted");
    }
}
