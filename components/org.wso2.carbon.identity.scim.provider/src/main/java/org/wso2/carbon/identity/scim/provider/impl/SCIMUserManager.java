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

package org.wso2.carbon.identity.scim.provider.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.OutboundProvisioningManager;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.listener.DefaultInboundUserProvisioningListener;
import org.wso2.carbon.identity.scim.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.charon.core.v2.schema.SCIMConstants;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.ConflictException;
import org.wso2.charon.core.v2.exceptions.NotFoundException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.objects.Group;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.utils.codeutils.Node;

import java.util.*;

public class SCIMUserManager implements UserManager {

    private static Log log = LogFactory.getLog(SCIMUserManager.class);
    private UserStoreManager carbonUM = null;
    private ClaimManager carbonClaimManager = null;
    private String consumerName;

    public SCIMUserManager(UserStoreManager carbonUserStoreManager, String userName,
                           ClaimManager claimManager) {
        carbonUM = carbonUserStoreManager;
        consumerName = userName;
        carbonClaimManager = claimManager;
    }


    @Override
    public User createUser(User user) throws CharonException, ConflictException, BadRequestException {
        try{
            Map<String, String> claimsMap = AttributeMapper.getClaimsMap(user);

            /*skip groups attribute since we map groups attribute to actual groups in ldap.
                and do not update it as an attribute in user schema*/
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.GROUP_URI)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);
            }

            if (carbonUM.isExistingUser(user.getUserName())) {
                String error = "User with the name: " + user.getUserName() + " already exists in the system.";
                throw new ConflictException(error);
            }
            if (claimsMap.containsKey(SCIMConstants.UserSchemaConstants.USER_NAME_URI)) {
                claimsMap.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
            }
            carbonUM.addUser(user.getUserName(), user.getPassword(), null, claimsMap, null);
            log.info("User: " + user.getUserName() + " is created through SCIM.");

        } catch (UserStoreException e) {
            String errMsg = "Error in adding the user: " + user.getUserName() + " to the user store. ";
            errMsg += e.getMessage();
            throw new CharonException(errMsg, e);
        }
        return user;

    }

    @Override
    public User getUser(String userId) throws CharonException {
        return  null;
    }

    @Override
    public void deleteUser(String s) throws NotFoundException, CharonException {

    }

    @Override
    public List<User> listUsers() throws CharonException {
        return null;
    }

    @Override
    public List<User> listUsersWithPagination(int i, int i1) {
        return null;
    }

    @Override
    public int getUserCount() {
        return 0;
    }

    @Override
    public User updateUser(User user) {
        return null;
    }

    @Override
    public List<User> filterUsers(Node node) {
        return null;
    }

    @Override
    public List<User> sortUsers(String s, String s1) {
        return null;
    }

    @Override
    public Group createGroup(Group group) throws CharonException, ConflictException {
        return null;
    }

    @Override
    public Group getGroup(String s) {
        return null;
    }

    @Override
    public void deleteGroup(String s) throws NotFoundException, CharonException {

    }

    @Override
    public List<Group> listGroups() throws CharonException {
        return null;
    }

    @Override
    public int getGroupCount() {
        return 0;
    }

    @Override
    public List<Group> listGroupsWithPagination(int i, int i1) {
        return null;
    }

    @Override
    public List<Group> filterGroups(Node node) {
        return null;
    }

    @Override
    public List<Group> sortGroups(String s, String s1) {
        return null;
    }

    @Override
    public Group updateGroup(Group group) {
        return null;
    }


}

