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

package org.apache.guacamole.auth.vhost.user;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.vhost.connection.VHostConnection;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.Permissions;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.permission.ObjectPermission;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.apache.guacamole.net.auth.permission.SystemPermissionSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author nick_couchman
 */
public class VHostUserContext extends DelegatingUserContext {
    
    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(VHostUserContext.class);
    
    /**
     * The HTTP Request associated with this user context.
     */
    private final HttpServletRequest request;
    
    public VHostUserContext(UserContext object, HttpServletRequest request) {
        super(object);
        this.request = request;
    }
    
    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return new DecoratingDirectory<Connection>(super.getConnectionDirectory()) {
            
            @Override
            public Connection decorate(Connection object) throws GuacamoleException {

                Permissions effective = self().getEffectivePermissions();
                SystemPermissionSet sysPermissions = effective.getSystemPermissions();
                ObjectPermissionSet objPermissions = effective.getConnectionPermissions();
                Boolean isAdmin = sysPermissions.hasPermission(SystemPermission.Type.ADMINISTER);

                // Determine whether or not we have update permissions
                Boolean canUpdate = (objPermissions.hasPermission(
                                ObjectPermission.Type.UPDATE,
                                object.getIdentifier())
                        );
                
                if (isAdmin || canUpdate)
                    return new VHostConnection(object, true);

                // Get the hostname used to access Guacamole
                String vHost = URI.create(request.getRequestURL().toString()).getHost();

                // Retrieve attributes
                Map<String, String> attributes = object.getAttributes();
                if (attributes != null && vHost != null && !vHost.isEmpty()
                        && attributes.containsKey(VHostConnection.VHOST_HOSTNAME_ATTRIBUTE)
                        && vHost.equals(attributes.get(VHostConnection.VHOST_HOSTNAME_ATTRIBUTE)))
                    return new VHostConnection(object);
                
                // If not admin or updater, and no vhost, remove connection
                this.remove(object.getIdentifier());
                return null;
            }
            
            @Override
            public Connection undecorate(Connection object) throws GuacamoleException {
                assert (object instanceof VHostConnection);
                return ((VHostConnection) object).getUndecorated();
            }
            
            @Override
            public Set<String> getIdentifiers() throws GuacamoleException {
                Set<String> identifiers = new HashSet<>(super.getIdentifiers());
                Permissions effective = self().getEffectivePermissions();
                SystemPermissionSet sysPermissions = effective.getSystemPermissions();
                ObjectPermissionSet objPermissions = effective.getConnectionPermissions();
                Boolean isAdmin = sysPermissions.hasPermission(SystemPermission.Type.ADMINISTER);
                
                for (String id : identifiers) {
                    if (!isAdmin && !objPermissions.hasPermission(ObjectPermission.Type.UPDATE, id))
                        identifiers.remove(id);
                }
                
                return identifiers;
            }
            
        };
    }
    
    @Override
    public Collection<Form> getConnectionAttributes() {
        Collection<Form> attributes = new HashSet<>(super.getConnectionAttributes());
        attributes.addAll(VHostConnection.ATTRIBUTES);
        return Collections.unmodifiableCollection(attributes);
    }
    
}
