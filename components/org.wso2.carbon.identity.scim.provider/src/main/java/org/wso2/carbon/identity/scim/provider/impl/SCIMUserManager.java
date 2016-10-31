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
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.scim.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim.provider.util.SCIMProviderConstants;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.charon.core.v2.attributes.Attribute;
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
      return null;
    }

    @Override
    public void deleteUser(String userId) throws NotFoundException, CharonException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userId);
        }
        //get the user name of the user with this id
        String[] userNames = null;
        String userName = null;
        try {

            String userStoreDomainFromSP = null;
            try {
                userStoreDomainFromSP = getUserStoreDomainFromSP();
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }
            if (userNames == null || userNames.length == 0) {
                //resource with given id not found
                if (log.isDebugEnabled()) {
                    log.debug("User with id: " + userId + " not found.");
                }
                throw new NotFoundException();
            } else if (userStoreDomainFromSP != null &&
                    !(userStoreDomainFromSP
                            .equalsIgnoreCase(IdentityUtil.extractDomainFromName(userNames[0])))) {
                throw new CharonException("User :" + userNames[0] + "is not belong to user store " +
                        userStoreDomainFromSP + "Hence user updating fail");
            } else {
                //we assume (since id is unique per user) only one user exists for a given id
                userName = userNames[0];
                carbonUM.deleteUser(userName);
                log.info("User: " + userName + " is deleted through SCIM.");
            }

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in deleting user: " + userName, e);
        }

    }

    @Override
    public List<User> listUsers() throws CharonException {

        ClaimMapping[] coreClaims;
        ClaimMapping[] userClaims;
        List<User> users = new ArrayList<>();
        try {
            String[] userNames = carbonUM.getUserList(SCIMConstants.CommonSchemaConstants.ID_URI, "*", null);
            if (userNames != null && userNames.length != 0) {
                //get Claims related to SCIM claim dialect
                coreClaims = carbonClaimManager.getAllClaimMappings(SCIMProviderConstants.SCIM_CORE_CLAIM_DIALECT);
                userClaims = carbonClaimManager.getAllClaimMappings(SCIMProviderConstants.SCIM_USER_CLAIM_DIALECT);
                List<String> claimURIList = new ArrayList<>();
                for (ClaimMapping claim : coreClaims) {
                    claimURIList.add(claim.getClaim().getClaimUri());
                }
                for (ClaimMapping claim : userClaims) {
                    claimURIList.add(claim.getClaim().getClaimUri());
                }
                for (String userName : userNames) {
                    if (userName.contains(UserCoreConstants.NAME_COMBINER)) {
                        userName = userName.split("\\" + UserCoreConstants.NAME_COMBINER)[0];
                    }
                    User scimUser = this.getSCIMMetaUser(userName);
                    if (scimUser != null) {
                        Map<String, Attribute> attrMap = scimUser.getAttributeList();
                        if (attrMap != null && !attrMap.isEmpty()) {
                            users.add(scimUser);
                        }
                    }
                }
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error while retrieving users from user store..", e);
        } catch (BadRequestException e) {

        }
        return users;
    }

    private User getSCIMMetaUser(String userName) throws BadRequestException {

        List<String> claimURIList = new ArrayList<>();
        claimURIList.add(SCIMConstants.CommonSchemaConstants.ID_URI);
        claimURIList.add(SCIMConstants.CommonSchemaConstants.LOCATION_URI);
        claimURIList.add(SCIMConstants.CommonSchemaConstants.CREATED_URI);
        claimURIList.add(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI);
        claimURIList.add(SCIMConstants.CommonSchemaConstants.RESOURCE_TYPE_URI);
        claimURIList.add(SCIMConstants.CommonSchemaConstants.VERSION_URI);
        User scimUser = null;

        try {
            Map<String, String> attributes = carbonUM.getUserClaimValues(
                    userName, claimURIList.toArray(new String[claimURIList.size()]), null);
            attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);
        } catch (UserStoreException | CharonException | NotFoundException e) {
            log.error("Error in getting user information from Carbon User Store for " +
                    "user: " + userName + " ", e);
        }
        return scimUser;
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


    private String getUserStoreDomainFromSP() throws IdentityApplicationManagementException {

        ThreadLocalProvisioningServiceProvider threadLocalSP = IdentityApplicationManagementUtil
                .getThreadLocalProvisioningServiceProvider();
        ServiceProvider serviceProvider = null;
        if (threadLocalSP.getServiceProviderType() == ProvisioningServiceProviderType.OAUTH) {
            serviceProvider = ApplicationManagementService.getInstance()
                    .getServiceProviderByClientId(
                            threadLocalSP.getServiceProviderName(),
                            "oauth2", threadLocalSP.getTenantDomain());
        } else {
            serviceProvider = ApplicationManagementService.getInstance().getServiceProvider(
                    threadLocalSP.getServiceProviderName(), threadLocalSP.getTenantDomain());
        }

        if (serviceProvider != null && serviceProvider.getInboundProvisioningConfig() != null &&
                !StringUtils.isBlank(serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore())) {
            return serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore();
        }
        return null;
    }

}

