/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.auth.vhost;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.vhost.user.VHostUserContext;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

/**
 * Authentication provider that decorates another module, providing automatic
 * connection to a host through a virtual hostname.
 */
public class VHostAuthenticationProvider extends AbstractAuthenticationProvider {
    
    @Override
    public String getIdentifier() {
        return "vhost";
    }
    
    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        return new VHostUserContext(context, credentials.getRequest());
    }
    
    @Override
    public UserContext redecorate(UserContext decorated, UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        
        // Just return it, no need to redeocrate
        if (context instanceof VHostUserContext)
            return context;
        
        // If we already have a decorated instance, return that.
        else if (decorated instanceof VHostUserContext)
            return decorated;
        
        // Return a  new decorated instance.
        else
            return new VHostUserContext(context, credentials.getRequest());
    }
    
}
