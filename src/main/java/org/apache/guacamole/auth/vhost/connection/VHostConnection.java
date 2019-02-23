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

package org.apache.guacamole.auth.vhost.connection;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.TextField;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DelegatingConnection;

/**
 *
 * @author nick_couchman
 */
public class VHostConnection extends DelegatingConnection {
    
    public static final String VHOST_HOSTNAME_ATTRIBUTE = "vhost-hostname";
    
    public static final List<String> VHOST_ATTRIBUTES =
            Arrays.asList(VHOST_HOSTNAME_ATTRIBUTE);
    
    public static final Form VHOST_ATTRIBUTE_FORM = new Form("vhost-attributes",
            Arrays.asList(
                new TextField(VHOST_HOSTNAME_ATTRIBUTE)
            )
    );
    
    public static final Collection<Form> ATTRIBUTES =
            Collections.unmodifiableCollection(
                    Arrays.asList(VHOST_ATTRIBUTE_FORM));
    
    private final Boolean canUpdate;
    
    public VHostConnection(Connection object, Boolean canUpdate) {
        super(object);
        this.canUpdate = canUpdate;
    }
    
    @Override
    public Map<String, String> getAttributes() {
        Map<String, String> attributes = new HashMap<>(super.getAttributes());
        
        for (String attr : VHOST_ATTRIBUTES) {
            if (!attributes.containsKey(attr) && canUpdate)
                attributes.put(attr, null);
            else if (attributes.containsKey(attr) && !canUpdate)
                attributes.remove(attr);
        }
        
        return attributes;
    }
    
    @Override
    public void setAttributes(Map<String, String> attributes) {
        attributes = new HashMap<>(attributes);
        for (String attr : VHOST_ATTRIBUTES) {
            if (!canUpdate && attributes.containsKey(attr))
                attributes.remove(attr);
        }
        super.setAttributes(attributes);
    }
    
    public Connection getUndecorated() {
        return super.getDelegateConnection();
    }
    
}
