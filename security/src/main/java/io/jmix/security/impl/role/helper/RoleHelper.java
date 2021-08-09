/*
 * Copyright 2021 Haulmont.
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

package io.jmix.security.impl.role.helper;

import io.jmix.core.common.util.ReflectionHelper;
import io.jmix.security.impl.role.builder.extractor.ResourcePolicyExtractor;
import io.jmix.security.impl.role.builder.extractor.RowLevelPolicyExtractor;
import io.jmix.security.model.ResourcePolicy;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

public class RoleHelper {

    public static Class<?> loadClass(String className) {
        Class<?> clazz;
        try {
            clazz = ReflectionHelper.loadClass(className);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(String.format("Cannot find role class: %s", className));
        }
        return clazz;
    }

    public static Collection<ResourcePolicy> extractResourcePolicies(Class<?> roleClass, Collection<ResourcePolicyExtractor> resourcePolicyExtractors) {
        Collection<ResourcePolicy> policies = new ArrayList<>();
        for (Method method : roleClass.getMethods()) {
            for (ResourcePolicyExtractor policyExtractor : resourcePolicyExtractors) {
                policies.addAll(policyExtractor.extractResourcePolicies(method));
            }
        }
        return policies;
    }
}
