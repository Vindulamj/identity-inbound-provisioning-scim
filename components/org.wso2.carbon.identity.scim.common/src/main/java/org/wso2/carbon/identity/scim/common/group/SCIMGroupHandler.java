/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim.common.group;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.scim.common.utils.IdentitySCIMException;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;


/**
 * This is for managing SCIM specific attributes related to Group resource in Identity_SCIM_GROUP
 * Table. This should be managed per tenant.
 * TODO: Since there are only a handful of attributes in SCIM Group schema, we add them directly.
 * But need to use the same approach as for User, by going through AttributMapper to do it in a generic way.
 */
public class SCIMGroupHandler {
    private static Log logger = LogFactory.getLog(SCIMGroupHandler.class);
    private int tenantId;

    /**
     * Always use this constructor and pass tenant Id.
     *
     * @param tenantId
     */
    public SCIMGroupHandler(int tenantId) {
        this.tenantId = tenantId;
    }


    /**
     * Retrieve the group attributes by group name
     *
     * @param groupName
     * @return
     */
    public Map<String, String> getGroupAttributesByName(String groupName) {
        return null;
    }

    /**
     * Retrieve the group attributes by group id
     *
     * @param id
     * @return
     */
    public Map<String, String> getGroupAttributesById(String id) {
        return null;
    }

    /**
     * Check whether attributes related to the given group name and tenant Id exist in the identity table.
     *
     * @param groupName
     * @return
     * @throws IdentitySCIMException
     */
    public boolean isGroupExisting(String groupName) throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.isExistingGroup(groupName, tenantId);
    }

    /**
     * Delete the attributes related with the group name and the tenant Id..
     *
     * @param groupName
     * @throws IdentitySCIMException
     */
    public void deleteGroupAttributes(String groupName) throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        if (groupDAO.isExistingGroup(groupName, this.tenantId)) {
            groupDAO.removeSCIMGroup(tenantId, groupName);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Information for the group: " + groupName +
                        " doesn't contain in the identity scim table.");
            }
        }
    }

    public void updateRoleName(String oldRoleName, String newRoleName)
            throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        if (groupDAO.isExistingGroup(oldRoleName, this.tenantId)) {
            groupDAO.updateRoleName(this.tenantId, oldRoleName, newRoleName);
        } else {
            throw new IdentitySCIMException("Non-existent group: " + oldRoleName +
                    " is trying to be updated..");
        }
    }

    /**
     * Lists the Groups created from SCIM
     *
     * @return list of SCIM groups
     * @throws IdentitySCIMException
     */
    public Set<String> listSCIMRoles() throws IdentitySCIMException {
        GroupDAO groupDAO = new GroupDAO();
        return groupDAO.listSCIMGroups();
    }
}
