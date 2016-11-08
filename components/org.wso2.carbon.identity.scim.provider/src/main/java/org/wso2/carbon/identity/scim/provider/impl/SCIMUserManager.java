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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.scim.common.group.SCIMGroupHandler;
import org.wso2.carbon.identity.scim.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim.common.utils.IdentitySCIMException;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonConstants;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim.provider.util.SCIMProviderConstants;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.attributes.MultiValuedAttribute;
import org.wso2.charon.core.v2.attributes.SimpleAttribute;
import org.wso2.charon.core.v2.exceptions.*;
import org.wso2.charon.core.v2.schema.SCIMConstants;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.objects.Group;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.utils.AttributeUtil;
import org.wso2.charon.core.v2.utils.codeutils.ExpressionNode;
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
        String userStoreName = null;

        try {
            String userStoreDomainFromSP = getUserStoreDomainFromSP();
            if (userStoreDomainFromSP != null) {
                userStoreName = userStoreDomainFromSP;
            }
        } catch (IdentityApplicationManagementException e) {
            throw new CharonException("Error retrieving User Store name. ", e);
        }

        StringBuilder userName = new StringBuilder();

        if (StringUtils.isNotBlank(userStoreName)) {
            // if we have set a user store under provisioning configuration - we should only use that.
            String currentUserName = user.getUserName();
            currentUserName = UserCoreUtil.removeDomainFromName(currentUserName);
            user.setUserName(userName.append(userStoreName)
                    .append(CarbonConstants.DOMAIN_SEPARATOR).append(currentUserName)
                    .toString());
        }

        String userStoreDomainName = IdentityUtil.extractDomainFromName(user.getUserName());
        if(StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)){
            throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantDomain(MultitenantUtils.getTenantDomain(consumerName));
            carbonContext.getTenantId(true);
            carbonContext.setUsername(MultitenantUtils.getTenantAwareUsername(consumerName));

                //Persist in carbon user store
                if (log.isDebugEnabled()) {
                    log.debug("Creating user: " + user.getUserName());
                }
                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
                SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
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
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return user;
    }

    @Override
    public User getUser(String userId) throws CharonException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving user: " + userId);
        }
        User scimUser = null;
        try {
            ClaimMapping[] coreClaims;
            ClaimMapping[] userClaims;
            //get the user name of the user with this id
            String[] userNames = carbonUM.getUserList(SCIMConstants.CommonSchemaConstants.ID_URI, userId,
                    UserCoreConstants.DEFAULT_PROFILE);

            if (userNames == null || userNames.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("User with SCIM id: " + userId + " does not exist in the system.");
                }
                return null;
            } else if (userNames != null && userNames.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("User with SCIM id: " + userId + " does not exist in the system.");
                }
                return null;
            } else {
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
                //we assume (since id is unique per user) only one user exists for a given id
                scimUser = this.getSCIMUser(userNames[0], claimURIList);
                //set the schemas of the scim user
                scimUser.setSchemas();
                log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");
            }

        } catch (UserStoreException e) {
            throw new CharonException("Error in getting user information from Carbon User Store for" +
                    "user: " + userId, e);
        }
        return scimUser;
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
            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            userNames = carbonUM.getUserList(SCIMConstants.CommonSchemaConstants.ID_URI, userId,
                    UserCoreConstants.DEFAULT_PROFILE);
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
                    User scimUser = this.getSCIMUser(userName, claimURIList);
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
        }
        log.info("User list is retrieved through SCIM.");
        return users;
    }

    @Override
    public List<User> listUsersWithPagination(int i, int i1) throws NotImplementedException {
        String error = "Pagination is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public int getUserCount() throws NotImplementedException {
        String error = "Counting is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public User updateUser(User user) throws CharonException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Updating user: " + user.getUserName());
            }

            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            //get user claim values
            Map<String, String> claims = AttributeMapper.getClaimsMap(user);

            //check if username of the updating user existing in the userstore.
            try {
                String userStoreDomainFromSP = getUserStoreDomainFromSP();
                User oldUser = this.getUser(user.getId());
                if (userStoreDomainFromSP != null && !userStoreDomainFromSP
                        .equalsIgnoreCase(IdentityUtil.extractDomainFromName(oldUser.getUserName()))) {
                    throw new CharonException("User :" + oldUser.getUserName() + "is not belong to user store " +
                            userStoreDomainFromSP + "Hence user updating fail");
                }
                if (getUserStoreDomainFromSP() != null &&
                        !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(getUserStoreDomainFromSP())) {
                    user.setUserName(UserCoreUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(user.getUserName()),
                                    getUserStoreDomainFromSP()));
                }
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }
            if (!carbonUM.isExistingUser(user.getUserName())) {
                throw new CharonException("User name is immutable in carbon user store.");
            }

                /*skip groups attribute since we map groups attribute to actual groups in ldap.
                and do not update it as an attribute in user schema*/
            if (claims.containsKey(SCIMConstants.UserSchemaConstants.GROUP_URI)) {
                claims.remove(SCIMConstants.UserSchemaConstants.GROUP_URI);
            }

            if (claims.containsKey(SCIMConstants.UserSchemaConstants.USER_NAME_URI)) {
                claims.remove(SCIMConstants.UserSchemaConstants.USER_NAME_URI);
            }

            ClaimMapping[] coreClaimList;
            ClaimMapping[] userClaimList;
            coreClaimList = carbonClaimManager.getAllClaimMappings(SCIMProviderConstants.SCIM_CORE_CLAIM_DIALECT);
            userClaimList = carbonClaimManager.getAllClaimMappings(SCIMProviderConstants.SCIM_USER_CLAIM_DIALECT);
            List<String> claimURIList = new ArrayList<>();
            for (ClaimMapping claim : coreClaimList) {
                claimURIList.add(claim.getClaim().getClaimUri());
            }
            for (ClaimMapping claim : userClaimList) {
                claimURIList.add(claim.getClaim().getClaimUri());
            }
            Map<String, String> oldClaimList = carbonUM.getUserClaimValues(user.getUserName(), claimURIList
                    .toArray(new String[claimURIList.size()]), null);

            for (Map.Entry<String, String> entry : oldClaimList.entrySet()) {
                if (!entry.getKey().equals(SCIMConstants.CommonSchemaConstants.ID_URI) &&
                        !entry.getKey().equals(SCIMConstants.UserSchemaConstants.USER_NAME_URI) &&
                        !entry.getKey().equals(SCIMConstants.CommonSchemaConstants.CREATED_URI) &&
                        !entry.getKey().equals(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI) &&
                        !entry.getKey().equals(SCIMConstants.CommonSchemaConstants.LOCATION_URI) &&
                        !entry.getKey().equals(SCIMConstants.UserSchemaConstants.FAMILY_NAME_URI)) {
                    carbonUM.deleteUserClaimValue(user.getUserName(), entry.getKey(), null);
                }
            }
            //set user claim values
            carbonUM.setUserClaimValues(user.getUserName(), claims, null);
            //if password is updated, set it separately
            if (user.getPassword() != null) {
                carbonUM.updateCredentialByAdmin(user.getUserName(), user.getPassword());
            }
            log.info("User: " + user.getUserName() + " updated updated through SCIM.");
            return user;
        } catch (UserStoreException e) {
            throw new CharonException("Error while updating attributes of user: " + user.getUserName(), e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error occured while trying to update the user");
        }
    }

    @Override
    public List<User> filterUsers(Node node) throws NotImplementedException, CharonException {

        if(node.getLeftNode() != null || node.getRightNode() != null){
            String error = "Complex filters are not supported yet";
            throw new NotImplementedException(error);
        }

        String attributeName = ((ExpressionNode)node).getAttributeValue();
        String filterOperation = ((ExpressionNode)node).getOperation();
        String attributeValue = ((ExpressionNode)node).getValue();

        if(!filterOperation.equalsIgnoreCase(SCIMProviderConstants.EQ)){
            String error = "Filter operator "+ filterOperation +" is not implemented";
            throw new NotImplementedException(error);
        }
        if (log.isDebugEnabled()) {
            log.debug("Listing users by filter: " + attributeName + filterOperation +
                    attributeValue);
        }
        List<User> filteredUsers = new ArrayList<>();
        ClaimMapping[] userClaims;
        ClaimMapping[] coreClaims;
        User scimUser = null;
        try {
            String[] userNames = null;
            if (!SCIMConstants.UserSchemaConstants.GROUP_URI.equals(attributeName)) {
                //get the user name of the user with this id
                userNames = carbonUM.getUserList(attributeName, attributeValue, UserCoreConstants.DEFAULT_PROFILE);
            } else {
                userNames = carbonUM.getUserListOfRole(attributeValue);
            }

            if (userNames == null || userNames.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Users with filter: " + attributeName + filterOperation +
                            attributeValue + " does not exist in the system.");
                }
                return Collections.emptyList();
            } else {
                //get claims related to SCIM claim dialect
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

                    if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
                        continue;
                    }

                    scimUser = this.getSCIMUser(userName, claimURIList);
                    //if SCIM-ID is not present in the attributes, skip
                    if (scimUser != null && StringUtils.isBlank(scimUser.getId())) {
                        continue;
                    }
                    filteredUsers.add(scimUser);
                }
                log.info("Users filtered through SCIM for the filter: " + attributeName + filterOperation +
                        attributeValue);
            }
        } catch (UserStoreException | CharonException e) {
            throw new CharonException("Error in filtering users by attribute name : " + attributeName + ", " +
                            "attribute value : " + attributeValue + " and filter operation " + filterOperation, e);
        }
        return filteredUsers;
    }

    @Override
    public List<User> sortUsers(String s, String s1) throws NotImplementedException {
        String error = "Sorting is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public User getMe(String userName) throws CharonException, NotFoundException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userName);
        }
        User scimUser = null;
        ClaimMapping[] coreClaims;
        ClaimMapping[] userClaims;
        try {
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
            //we assume (since id is unique per user) only one user exists for a given id
            scimUser = this.getSCIMUser(userName, claimURIList);

            if(scimUser == null){
                log.debug("User with userName : " + userName + " does not exist in the system.");
                throw new NotFoundException();
            }else{
                //set the schemas of the scim user
                scimUser.setSchemas();
                log.info("User: " + scimUser.getUserName() + " is retrieved through SCIM.");
                return scimUser;
            }

        } catch (UserStoreException e) {
            throw new CharonException("Error from getting the authenticated user");
        } catch (NotFoundException e) {
            throw new NotFoundException("No such user exist");
        }
    }

    @Override
    public User createMe(User user) throws CharonException, ConflictException, BadRequestException {
        return createUser(user);
    }

    @Override
    public void deleteMe(String userName) throws NotFoundException, CharonException, NotImplementedException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting user: " + userName);
        }
        User scimUser = null;
        ClaimMapping[] coreClaims;
        ClaimMapping[] userClaims;
        try {
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
            //we assume (since id is unique per user) only one user exists for a given id
            scimUser = this.getSCIMUser(userName, claimURIList);

            if(scimUser == null){
                log.debug("User with userName : " + userName + " does not exist in the system.");
                throw new NotFoundException();
            }else {
            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
                SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
                //we assume (since id is unique per user) only one user exists for a given id
                carbonUM.deleteUser(userName);
                log.info("User: " + userName + " is deleted through SCIM.");
            }
        } catch (UserStoreException e) {
            throw new CharonException("Error in deleting user: " + userName, e);
        }
    }

    @Override
    public User updateMe(User user) throws NotImplementedException, CharonException {
        return updateUser(user);
    }

    @Override
    public Group createGroup(Group group) throws CharonException, ConflictException, BadRequestException {
        if (log.isDebugEnabled()) {
            log.debug("Creating group: " + group.getDisplayName());
        }
        try {
            //modify display name if no domain is specified, in order to support multiple user store feature
            String originalName = group.getDisplayName();
            String roleNameWithDomain = null;
            String domainName = "";
            try {
                if (getUserStoreDomainFromSP() != null) {
                    domainName = getUserStoreDomainFromSP();
                    roleNameWithDomain = UserCoreUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(originalName), domainName);
                } else if (originalName.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
                    domainName = IdentityUtil.extractDomainFromName(originalName);
                    roleNameWithDomain = UserCoreUtil
                            .addDomainToName(UserCoreUtil.removeDomainFromName(originalName), domainName);
                } else {
                    domainName = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                    roleNameWithDomain = SCIMCommonUtils.getGroupNameWithDomain(originalName);
                }
            } catch (IdentityApplicationManagementException e) {
                throw new CharonException("Error retrieving User Store name. ", e);
            }

            if(!isInternalOrApplicationGroup(domainName) && StringUtils.isNotBlank(domainName) && !isSCIMEnabled
                    (domainName)){
                throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                        "enabled for user store " + domainName);
            }
            group.setDisplayName(roleNameWithDomain);
            //check if the group already exists
            if (carbonUM.isExistingRole(group.getDisplayName(), false)) {
                String error = "Group with name: " + group.getDisplayName() +" already exists in the system.";
                throw new ConflictException(error);
            }

                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
                /*if members are sent when creating the group, check whether users already exist in the
                user store*/
            List<Object> userIds = group.getMembers();
            List<String> userDisplayNames = group.getMembersWithDisplayName();
            if (CollectionUtils.isNotEmpty(userIds)) {
                List<String> members = new ArrayList<>();
                for (Object userId : userIds) {
                    String[] userNames = carbonUM.getUserList(SCIMConstants.CommonSchemaConstants.ID_URI, (String) userId,
                            UserCoreConstants.DEFAULT_PROFILE);
                    if (userNames == null || userNames.length == 0) {
                        String error = "User: " + userId + " doesn't exist in the user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else if (userNames[0].indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0 &&
                            !StringUtils.containsIgnoreCase(userNames[0], domainName)) {
                        String error = "User: " + userId + " doesn't exist in the same user store. " +
                                "Hence, can not create the group: " + group.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else {
                        members.add(userNames[0]);
                        if (CollectionUtils.isNotEmpty(userDisplayNames)) {
                            boolean userContains = false;
                            for (String user : userDisplayNames) {
                                user =
                                        user.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                                ? user.split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                                : user;
                                if (user.equalsIgnoreCase(userNames[0].indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0
                                        ? userNames[0].split(UserCoreConstants.DOMAIN_SEPARATOR)[1]
                                        : userNames[0])) {
                                    userContains = true;
                                    break;
                                }
                            }
                            if (!userContains) {
                                throw new IdentitySCIMException("Given SCIM user Id and name not matching..");
                            }
                        }
                    }
                }
                //add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRole(group.getDisplayName(),
                        members.toArray(new String[members.size()]), null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            } else {
                //add other scim attributes in the identity DB since user store doesn't support some attributes.
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.createSCIMAttributes(group);
                carbonUM.addRole(group.getDisplayName(), null, null, false);
                log.info("Group: " + group.getDisplayName() + " is created through SCIM.");
            }
        } catch (UserStoreException e) {
            try {
                SCIMGroupHandler scimGroupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
                scimGroupHandler.deleteGroupAttributes(group.getDisplayName());
            } catch (UserStoreException | IdentitySCIMException ex) {
                log.error("Error occurred while doing rollback operation of the SCIM table entry for role: " + group.getDisplayName(), ex);
                throw new CharonException("Error occurred while doing rollback operation of the SCIM table entry for role: " + group.getDisplayName(), e);
            }
            throw new CharonException("Error occurred while adding role : " + group.getDisplayName(), e);
        } catch (IdentitySCIMException | BadRequestException e) {
            String error = "Member doesn't exist in the same user store. " +
                    "Hence, can not create the group: " + group.getDisplayName();
            throw new BadRequestException(error);
        }
        return group;
    }

    @Override
    public Group getGroup(String id) throws CharonException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving group with id: " + id);
        }
        Group group = null;
        try {
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            //get group name by Id
            String groupName = groupHandler.getGroupName(id);

            if (groupName != null) {
                group = getGroupWithName(groupName);
                group.setSchemas();
                return group;
            } else {
                //returning null will send a resource not found error to client by Charon.
                return null;
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in retrieving group : " + id, e);
        } catch (IdentitySCIMException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        } catch (CharonException | BadRequestException e) {
            throw new CharonException("Error in retrieving the group");
        }
    }

    @Override
    public void deleteGroup(String groupId) throws NotFoundException, CharonException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting group: " + groupId);
        }
        try {
            /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);

            //get group name by id
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            String groupName = groupHandler.getGroupName(groupId);

            if (groupName != null) {
                String userStoreDomainFromSP = null;
                try {
                    userStoreDomainFromSP = getUserStoreDomainFromSP();
                } catch (IdentityApplicationManagementException e) {
                    throw new CharonException("Error retrieving User Store name. ", e);
                }
                if (userStoreDomainFromSP != null &&
                        !(userStoreDomainFromSP.equalsIgnoreCase(IdentityUtil.extractDomainFromName(groupName)))) {
                    throw new CharonException("Group :" + groupName + "is not belong to user store " +
                            userStoreDomainFromSP + "Hence group updating fail");
                }

                String userStoreDomainName = IdentityUtil.extractDomainFromName(groupName);
                if(!isInternalOrApplicationGroup(userStoreDomainName) && StringUtils.isNotBlank(userStoreDomainName)
                        && !isSCIMEnabled
                        (userStoreDomainName)){
                    throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                            "enabled for user store " + userStoreDomainName);
                }

                //delete group in carbon UM
                carbonUM.deleteRole(groupName);

                //we do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.
                log.info("Group: " + groupName + " is deleted through SCIM.");

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Group with SCIM id: " + groupId + " doesn't exist in the system.");
                }
                throw new NotFoundException();
            }
        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException("Error occurred while deleting group " + groupId, e);
        }

    }

    @Override
    public List<Group> listGroups() throws CharonException {
        List<Group> groupList = new ArrayList<>();
        try {
            SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
            Set<String> roleNames = groupHandler.listSCIMRoles();
            for (String roleName : roleNames) {
                Group group = this.getGroupWithName(roleName);
                if (group.getId() != null) {
                    groupList.add(group);
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String errMsg = "Error in obtaining role names from user store.";
            errMsg += e.getMessage();
            throw new CharonException(errMsg, e);
        } catch (IdentitySCIMException | BadRequestException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        }
        return groupList;
    }

    @Override
    public int getGroupCount() throws NotImplementedException {
        String error = "Counting is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public List<Group> listGroupsWithPagination(int i, int i1) throws NotImplementedException {
        String error = "Pagination is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public List<Group> filterGroups(Node node) throws NotImplementedException, CharonException {

        if(node.getLeftNode() != null || node.getRightNode() != null){
            String error = "Complex filters are not supported yet";
            throw new NotImplementedException(error);
        }
        String attributeName = ((ExpressionNode)node).getAttributeValue();
        String filterOperation = ((ExpressionNode)node).getOperation();
        String attributeValue = ((ExpressionNode)node).getValue();

        if(!filterOperation.equalsIgnoreCase(SCIMProviderConstants.EQ)){
            String error = "Filter operator "+ filterOperation +" is not implemented";
            throw new NotImplementedException(error);
        }

        if (log.isDebugEnabled()) {
            log.debug("Listing groups with filter: " + attributeName + filterOperation +
                    attributeValue);
        }
        List<Group> filteredGroups = new ArrayList<>();
        Group group = null;
        try {
            if (attributeValue != null && carbonUM.isExistingRole(attributeValue, false)) {
                //skip internal roles
                if ((CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equals(attributeValue)) ||
                        UserCoreUtil.isEveryoneRole(attributeValue, carbonUM.getRealmConfiguration()) ||
                        UserCoreUtil.isPrimaryAdminRole(attributeValue, carbonUM.getRealmConfiguration())) {
                    throw new IdentitySCIMException("Internal roles do not support SCIM.");
                }
                /********we expect only one result**********/
                //construct the group name with domain -if not already provided, in order to support
                //multiple user store feature with SCIM.
                String groupNameWithDomain = null;
                if (attributeValue.indexOf(CarbonConstants.DOMAIN_SEPARATOR) > 0) {
                    groupNameWithDomain = attributeValue;
                } else {
                    groupNameWithDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME + CarbonConstants.DOMAIN_SEPARATOR
                            + attributeValue;
                }
                group = getGroupWithName(groupNameWithDomain);
                filteredGroups.add(group);
            } else {
                //returning null will send a resource not found error to client by Charon.
                return Collections.emptyList();
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new CharonException("Error in filtering groups by attribute name : " + attributeName + ", " +
                        "attribute value : " + attributeValue + " and filter operation " + filterOperation, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new CharonException("Error in filtering group with filter: "
                        + attributeName + filterOperation + attributeValue, e);
        } catch (IdentitySCIMException e) {
            throw new CharonException("Error in retrieving SCIM Group information from database.", e);
        } catch (BadRequestException e) {
            throw new CharonException("Error in retrieving SCIM Group.", e);
        }
        return filteredGroups;
    }

    @Override
    public List<Group> sortGroups(String s, String s1) throws NotImplementedException {
        String error = "Sorting is not supported";
        throw new NotImplementedException(error);
    }

    @Override
    public Group updateGroup(Group oldGroup, Group newGroup) throws CharonException {
        String displayName = null;
        try {
            String userStoreDomainFromSP = getUserStoreDomainFromSP();

            if(userStoreDomainFromSP != null && !userStoreDomainFromSP.equalsIgnoreCase(
                    IdentityUtil.extractDomainFromName(oldGroup.getDisplayName()))) {
                throw new CharonException("Group :" + oldGroup.getDisplayName() + "is not belong to user store " +
                        userStoreDomainFromSP + "Hence group updating fail");
            }
            oldGroup.setDisplayName(UserCoreUtil.addDomainToName(UserCoreUtil.removeDomainFromName(oldGroup.getDisplayName()),
                    IdentityUtil.extractDomainFromName(oldGroup.getDisplayName())));

            newGroup.setDisplayName(UserCoreUtil.addDomainToName(UserCoreUtil.removeDomainFromName(newGroup.getDisplayName()),
                    IdentityUtil.extractDomainFromName(newGroup.getDisplayName())));

            String primaryDomain = IdentityUtil.getPrimaryDomainName();
            if (IdentityUtil.extractDomainFromName(newGroup.getDisplayName()).equals(primaryDomain) && !(IdentityUtil
                    .extractDomainFromName(oldGroup.getDisplayName())
                    .equals(primaryDomain))) {
                String userStoreDomain = IdentityUtil.extractDomainFromName(oldGroup.getDisplayName());
                newGroup.setDisplayName(UserCoreUtil.addDomainToName(newGroup.getDisplayName(), userStoreDomain));

            } else if (!IdentityUtil.extractDomainFromName(oldGroup.getDisplayName())
                    .equals(IdentityUtil.extractDomainFromName(newGroup.getDisplayName()))) {
                throw new IdentitySCIMException(
                        "User store domain of the group is not matching with the given SCIM group Id.");
            }

            newGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(newGroup.getDisplayName()));
            oldGroup.setDisplayName(SCIMCommonUtils.getGroupNameWithDomain(oldGroup.getDisplayName()));

            if (log.isDebugEnabled()) {
                log.debug("Updating group: " + oldGroup.getDisplayName());
            }

            String groupName = newGroup.getDisplayName();
            String userStoreDomainForGroup = IdentityUtil.extractDomainFromName(groupName);

            if (newGroup.getMembers() != null && !(newGroup.getMembers().isEmpty()) &&
                    !isInternalOrApplicationGroup(userStoreDomainForGroup)) {
                newGroup = addDomainToUserMembers(newGroup, userStoreDomainForGroup);
            }
            boolean updated = false;
                /*set thread local property to signal the downstream SCIMUserOperationListener
                about the provisioning route.*/
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            //check if the user ids sent in updated group exist in the user store and the associated user name
            //also a matching one.
            List<Object> userIds = newGroup.getMembers();
            List<String> userDisplayNames = newGroup.getMembersWithDisplayName();

                /* compare user store domain of group and user store domain of user name , if there is a mismatch do not
                 update the group */
            if (userDisplayNames != null && userDisplayNames.size() > 0) {
                for (String userDisplayName : userDisplayNames) {
                    String userStoreDomainForUser =
                            IdentityUtil.extractDomainFromName(userDisplayName);
                    if (!isInternalOrApplicationGroup(userStoreDomainForGroup) && !userStoreDomainForGroup.equalsIgnoreCase
                            (userStoreDomainForUser)) {
                        throw new IdentitySCIMException(
                                userDisplayName + " does not " + "belongs to user store " + userStoreDomainForGroup);
                    }

                }
            }

            if (CollectionUtils.isNotEmpty(userIds)) {
                String[] userNames = null;
                for (Object userId : userIds) {
                    userNames = carbonUM.getUserList(SCIMConstants.CommonSchemaConstants.ID_URI,
                            UserCoreUtil.addDomainToName((String) userId, userStoreDomainForGroup),
                            UserCoreConstants.DEFAULT_PROFILE);
                    if (userNames == null || userNames.length == 0) {
                        String error = "User: " + userId + " doesn't exist in the user store. " +
                                "Hence, can not update the group: " + oldGroup.getDisplayName();
                        throw new IdentitySCIMException(error);
                    } else {
                        if (!UserCoreUtil.isContain(UserCoreUtil.removeDomainFromName(userNames[0]),
                                UserCoreUtil.removeDomainFromNames(userDisplayNames.toArray(
                                        new String[userDisplayNames.size()])))) {
                            throw new IdentitySCIMException("Given SCIM user Id and name not matching..");
                        }
                    }
                }
            }
            //we do not update Identity_SCIM DB here since it is updated in SCIMUserOperationListener's methods.

            //update name if it is changed
            if (!(oldGroup.getDisplayName().equalsIgnoreCase(newGroup.getDisplayName()))) {
                //update group name in carbon UM
                carbonUM.updateRoleName(oldGroup.getDisplayName(),
                        newGroup.getDisplayName());

                updated = true;
            }

            //find out added members and deleted members..
            List<String> oldMembers = oldGroup.getMembersWithDisplayName();
            List<String> newMembers = newGroup.getMembersWithDisplayName();
            if (newMembers != null) {

                List<String> addedMembers = new ArrayList<>();
                List<String> deletedMembers = new ArrayList<>();

                //check for deleted members
                if (CollectionUtils.isNotEmpty(oldMembers)) {
                    for (String oldMember : oldMembers) {
                        if (newMembers != null && newMembers.contains(oldMember)) {
                            continue;
                        }
                        deletedMembers.add(oldMember);
                    }
                }

                //check for added members
                if (CollectionUtils.isNotEmpty(newMembers)) {
                    for (String newMember : newMembers) {
                        if (oldMembers != null && oldMembers.contains(newMember)) {
                            continue;
                        }
                        addedMembers.add(newMember);
                    }
                }

                if (CollectionUtils.isNotEmpty(addedMembers) || CollectionUtils.isNotEmpty(deletedMembers)) {
                    carbonUM.updateUserListOfRole(newGroup.getDisplayName(),
                            deletedMembers.toArray(new String[deletedMembers.size()]),
                            addedMembers.toArray(new String[addedMembers.size()]));
                    updated = true;
                }
            }
            if (updated) {
                log.info("Group: " + newGroup.getDisplayName() + " is updated through SCIM.");
            } else {
                log.warn("There is no updated field in the group: " + oldGroup.getDisplayName() +
                        ". Therefore ignoring the provisioning.");
            }
            displayName = oldGroup.getDisplayName();
        } catch (UserStoreException | IdentitySCIMException e) {
            throw new CharonException("Error occurred while updating old group : " + displayName, e);
        } catch (IdentityApplicationManagementException e){
            throw new CharonException("Error retrieving User Store name. ", e);
        } catch (BadRequestException | CharonException e) {
            throw new CharonException("Error in updating the group", e);

        }

        return newGroup;
    }


    private String getUserStoreDomainFromSP() throws IdentityApplicationManagementException {
        ServiceProvider serviceProvider = null;

        if (serviceProvider != null && serviceProvider.getInboundProvisioningConfig() != null &&
                !StringUtils.isBlank(serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore())) {
            return serviceProvider.getInboundProvisioningConfig().getProvisioningUserStore();
        }
        return null;
    }

    /**
     * This method will return whether SCIM is enabled or not for a particular userStore. (from SCIMEnabled user
     * store property)
     * @param userStoreName user store name
     * @return whether scim is enabled or not for the particular user store
     */
    private boolean isSCIMEnabled(String userStoreName) {
        UserStoreManager userStoreManager = carbonUM.getSecondaryUserStoreManager(userStoreName);
        if (userStoreManager != null) {
            try {
                return userStoreManager.isSCIMEnabled();
            } catch (UserStoreException e) {
                log.error("Error while evaluating isSCIMEnalbed for user store " + userStoreName, e);
            }
        }
        return false;
    }

    /**
     * get the specfied user from the store
     * @param userName
     * @param claimURIList
     * @return
     * @throws CharonException
     */
    private User getSCIMUser(String userName, List<String> claimURIList) throws CharonException {
        User scimUser = null;

        String userStoreDomainName = IdentityUtil.extractDomainFromName(userName);
        if(StringUtils.isNotBlank(userStoreDomainName) && !isSCIMEnabled(userStoreDomainName)){
            throw new CharonException("Cannot add user through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }
        try {
            //obtain user claim values
            Map<String, String> attributes = carbonUM.getUserClaimValues(
                    userName, claimURIList.toArray(new String[claimURIList.size()]), null);

            //skip simple type addresses claim because it is complex with sub types in the schema
            if (attributes.containsKey(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
                attributes.remove(SCIMConstants.UserSchemaConstants.ADDRESSES_URI);
            }

            // Add username with domain name
            attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME_URI, userName);

            //get groups of user and add it as groups attribute
            String[] roles = carbonUM.getRoleListOfUser(userName);
            //construct the SCIM Object from the attributes
            scimUser = (User) AttributeMapper.constructSCIMObjectFromAttributes(attributes, 1);
            //add groups of user:
            for (String role : roles) {
                if (UserCoreUtil.isEveryoneRole(role, carbonUM.getRealmConfiguration())
                        || UserCoreUtil.isPrimaryAdminRole(role, carbonUM.getRealmConfiguration())
                        || CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME.equalsIgnoreCase(role)
                        || role.toLowerCase().startsWith((UserCoreConstants.INTERNAL_DOMAIN +
                        CarbonConstants.DOMAIN_SEPARATOR).toLowerCase())) {
                    // carbon specific roles do not possess SCIM info, hence
                    // skipping them.
                    // skip intenal roles
                    continue;
                }
                Group group = getGroupOnlyWithMetaAttributes(role);
                if (group != null) { // can be null for non SCIM groups
                    scimUser.setGroup(null, group.getId(), role);
                }
            }
        } catch (UserStoreException | CharonException | NotFoundException | IdentitySCIMException |BadRequestException e) {
            throw new CharonException("Error in getting user information for user: " + userName, e);
        }
        return scimUser;
    }

    /**
     * Get group with only meta attributes.
     *
     * @param groupName
     * @return
     * @throws CharonException
     * @throws IdentitySCIMException
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private Group getGroupOnlyWithMetaAttributes(String groupName) throws CharonException, IdentitySCIMException,
            org.wso2.carbon.user.core.UserStoreException, BadRequestException {
        //get other group attributes and set.
        Group group = new Group();
        group.setDisplayName(groupName);
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        return groupHandler.getGroupWithAttributes(group, groupName);
    }

    /**
     * returns whether particular user store domain is application or internal.
     * @param userstoreDomain user store domain
     * @return whether passed domain name is "internal" or "application"
     */
    private boolean isInternalOrApplicationGroup(String userstoreDomain){
        if(StringUtils.isNotBlank(userstoreDomain) &&
                (SCIMProviderConstants.APPLICATION_DOMAIN.equalsIgnoreCase(userstoreDomain) ||
                SCIMProviderConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userstoreDomain))){
            return true;
        }
        return false;
    }

    /**
     * Get the full group with all the details including users.
     *
     * @param groupName
     * @return
     * @throws CharonException
     * @throws org.wso2.carbon.user.core.UserStoreException
     * @throws IdentitySCIMException
     */
    private Group getGroupWithName(String groupName)
            throws CharonException, org.wso2.carbon.user.core.UserStoreException, IdentitySCIMException, BadRequestException {

        String userStoreDomainName = IdentityUtil.extractDomainFromName(groupName);
        if(!isInternalOrApplicationGroup(userStoreDomainName) && StringUtils.isNotBlank(userStoreDomainName) &&
                !isSCIMEnabled(userStoreDomainName)){
            throw new CharonException("Cannot retrieve group through scim to user store " + ". SCIM is not " +
                    "enabled for user store " + userStoreDomainName);
        }

        Group group = new Group();
        group.setDisplayName(groupName);
        String[] userNames = carbonUM.getUserListOfRole(groupName);

        //get the ids of the users and set them in the group with id + display name
        if (userNames != null && userNames.length != 0) {
            for (String userName : userNames) {
                String userId = carbonUM.getUserClaimValue(userName, SCIMConstants.CommonSchemaConstants.ID_URI, null);
                group.setMember(userId, userName);
            }
        }
        //get other group attributes and set.
        SCIMGroupHandler groupHandler = new SCIMGroupHandler(carbonUM.getTenantId());
        group = groupHandler.getGroupWithAttributes(group, groupName);
        return group;
    }

    /**
     * This is used to add domain name to the members of a group
     *
     * @param group
     * @param userStoreDomain
     * @return
     * @throws CharonException
     */
    private Group addDomainToUserMembers(Group group, String userStoreDomain) throws CharonException {
        List<Object> membersId = group.getMembers();

        if (StringUtils.isBlank(userStoreDomain) || membersId == null || membersId.isEmpty()) {
            return group;
        }

        if (group.isAttributeExist(SCIMConstants.GroupSchemaConstants.MEMBERS)) {
            MultiValuedAttribute members = (MultiValuedAttribute) group.getAttributeList().get(
                    SCIMConstants.GroupSchemaConstants.MEMBERS);
            List<Attribute> attributeValues = members.getAttributeValues();

            if (attributeValues != null && !attributeValues.isEmpty()) {
                for (Attribute attributeValue : attributeValues) {
                    SimpleAttribute displayNameAttribute = (SimpleAttribute) attributeValue.getSubAttribute(
                            SCIMConstants.CommonSchemaConstants.DISPLAY);
                    String displayName =
                            AttributeUtil.getStringValueOfAttribute(displayNameAttribute.getValue(),
                                    displayNameAttribute.getType());
                    displayNameAttribute.setValue(UserCoreUtil.addDomainToName(
                            UserCoreUtil.removeDomainFromName(displayName), userStoreDomain));
                }
            }
        }
        return group;
    }
}

