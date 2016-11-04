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
    public List<User> listUsersWithPagination(int i, int i1) {
        return null;
    }

    @Override
    public int getUserCount() {
        return 0;
    }

    @Override
    public User updateUser(User user) {
        try {
        if (log.isDebugEnabled()) {
            log.debug("Updating user: " + user.getUserName());
        }
            //set thread local property to signal the downstream SCIMUserOperationListener
            //about the provisioning route.
            SCIMCommonUtils.setThreadLocalIsManagedThroughSCIMEP(true);
            //get user claim values
            Map<String, String> claims = AttributeMapper.getClaimsMap(user);

            //check if username of the updating user existing in the userstore.
            //Therefore, correct way is to check the corresponding SCIM attribute for the
            //UserNameAttribute of user-mgt.xml.
            // Refer: SCIMUserOperationListener#isProvisioningActionAuthorized method.
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
                if (!entry.getKey().equals(SCIMConstants.CommonSchemaConstants.ID_URI) && !entry.getKey().equals(SCIMConstants
                        .UserSchemaConstants.USER_NAME_URI) && !entry.getKey().equals(SCIMConstants.CommonSchemaConstants.CREATED_URI) && !entry
                        .getKey().equals(SCIMConstants.CommonSchemaConstants.LAST_MODIFIED_URI) && !entry.getKey().equals
                        (SCIMConstants.CommonSchemaConstants.LOCATION_URI) && !entry.getKey().equals(SCIMConstants.UserSchemaConstants
                        .FAMILY_NAME_URI)) {
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
        } catch (UserStoreException | BadRequestException | CharonException e) {
            try {
                throw new CharonException("Error while updating attributes of user: " + user.getUserName(), e);
            } catch (CharonException e1) {
                //do nothing
            }
        }
        return user;
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


}

