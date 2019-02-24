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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
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
                
                if (isAdmin() || canUpdate(object.getIdentifier()))
                    return new VHostConnection(object, true);

                // Retrieve attributes
                Map<String, String> attributes = object.getAttributes();
                if (hasVHostAttribute(object.getAttributes()))
                    return new VHostConnection(object);
                
                // If not admin or updater, and no vhost, remove connection
                return object;
            }
            
            @Override
            public Connection undecorate(Connection object) throws GuacamoleException {
                assert (object instanceof VHostConnection);
                return ((VHostConnection) object).getUndecorated();
            }
            
            @Override
            public Set<String> getIdentifiers() throws GuacamoleException {
                Set<String> identifiers = new HashSet<>(super.getIdentifiers());
                
                for (String id : identifiers) {
                    
                    if (isAdmin() || canUpdate(id))
                        continue;
                    
                    if (hasVHostAttribute(this.get(id).getAttributes()))
                        continue;
                    
                    logger.debug(">>>VHOST<<< Removing connection identifier {}", id);
                    identifiers.remove(id);
                }
                
                return identifiers;
            }
            
            @Override
            public Collection<Connection> getAll(Collection<String> identifiers)
                    throws GuacamoleException {
                Collection<Connection> connections = new CopyOnWriteArrayList<>(super.getAll(identifiers));
                for (Connection connection : connections) {
                    
                    if (isAdmin() || canUpdate(connection.getIdentifier()))
                        continue;
                    
                    if (hasVHostAttribute(connection.getAttributes()))
                        continue;
                    
                    logger.debug(">>>VHOST<<< Removing connection with id {}",
                            connection.getIdentifier());
                    connections.remove(connection);
                    
                }
                
                return connections;
            }
            
            private Boolean isAdmin() throws GuacamoleException {
                Permissions effective = self().getEffectivePermissions();
                return effective.getSystemPermissions().hasPermission(SystemPermission.Type.ADMINISTER);
            }
            
            private Boolean canUpdate(String identifier) throws GuacamoleException {
                Permissions effective = self().getEffectivePermissions();
                return effective.getConnectionPermissions().hasPermission(ObjectPermission.Type.UPDATE, identifier);
            }
            
            private Boolean hasVHostAttribute(Map<String, String> attributes) {
                String vHost = URI.create(request.getRequestURL().toString()).getHost();
                logger.debug(">>>VHOST<<< This VHOST: {}", vHost);
                return (attributes != null 
                        && vHost != null 
                        && !vHost.isEmpty()
                        && attributes.containsKey(VHostConnection.VHOST_HOSTNAME_ATTRIBUTE)
                        && vHost.equals(attributes.get(VHostConnection.VHOST_HOSTNAME_ATTRIBUTE)));
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
