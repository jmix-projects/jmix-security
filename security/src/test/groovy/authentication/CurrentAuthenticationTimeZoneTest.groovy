/*
 * Copyright 2019 Haulmont.
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

package authentication

import io.jmix.core.security.CurrentAuthentication
import io.jmix.core.security.InMemoryUserRepository
import io.jmix.core.security.SecurityContextHelper
import io.jmix.core.security.SystemAuthenticationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.userdetails.UserDetails
import test_support.SecuritySpecification

class CurrentAuthenticationTimeZoneTest extends SecuritySpecification {

    @Autowired
    AuthenticationManager authenticationManager

    @Autowired
    InMemoryUserRepository userRepository

    @Autowired
    CurrentAuthentication currentAuthentication

    UserDetails userHasTimeZone

    def setup() {
        userHasTimeZone = new test_support.entity.User()
        userHasTimeZone.setUsername("timezone")
        userHasTimeZone.setPassword("{noop}timezone")
        userHasTimeZone.setTimeZone("Europe/Madrid")
        userRepository.addUser(userHasTimeZone)
    }

    def cleanup() {
        userRepository.removeUser(userHasTimeZone)
    }

    def "get user timezone via principal"() {
        when:

        def authenticate = authenticationManager.authenticate(
                new SystemAuthenticationToken(
                        userHasTimeZone.getUsername()))
        SecurityContextHelper.setAuthentication(authenticate)
        then:
        currentAuthentication.getTimeZone().getID() == "Europe/Madrid"
    }
}
