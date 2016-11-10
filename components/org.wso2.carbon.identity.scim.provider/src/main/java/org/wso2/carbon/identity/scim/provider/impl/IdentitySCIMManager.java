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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.scim.common.utils.SCIMCommonUtils;
import org.wso2.carbon.identity.scim.provider.util.SCIMProviderConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.charon.core.v2.config.CharonConfiguration;
import org.wso2.charon.core.v2.encoder.JSONDecoder;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.v2.extensions.*;
import org.wso2.charon.core.v2.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon.core.v2.schema.SCIMConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class IdentitySCIMManager {
    private static Log log = LogFactory.getLog(IdentitySCIMManager.class);

    private static volatile IdentitySCIMManager identitySCIMManager;
    private JSONEncoder encoder = null;
    private static Map<String, String> endpointURLs = new HashMap<String, String>();

    private IdentitySCIMManager() throws CharonException {
        init();
    }

    /**
     * Should return the static instance of CharonManager implementation.
     * Read the config and initialize extensions as specified in the config.
     *
     * @return
     */
    public static IdentitySCIMManager getInstance() throws CharonException {
        if (identitySCIMManager == null) {
            synchronized (IdentitySCIMManager.class) {
                if (identitySCIMManager == null) {
                    identitySCIMManager = new IdentitySCIMManager();
                    return identitySCIMManager;
                } else {
                    return identitySCIMManager;
                }
            }
        } else {
            return identitySCIMManager;
        }
    }

    /**
     * Perform initialization at the deployment of the webapp.
     */
    private void init() throws CharonException {
        //this is necessary to instantiate here as we need to encode exceptions if they occur.
        encoder = new JSONEncoder();
        //register encoder,decoders in AbstractResourceEndpoint, since they are called with in the API
        registerCoders();

        //Define endpoint urls to be used in Location Header
        endpointURLs.put(SCIMConstants.USER_ENDPOINT, SCIMCommonUtils.getSCIMUserURL());
        endpointURLs.put(SCIMConstants.GROUP_ENDPOINT, SCIMCommonUtils.getSCIMGroupURL());
        endpointURLs.put(SCIMConstants.SERVICE_PROVIDER_CONFIG_ENDPOINT, SCIMCommonUtils.getSCIMServiceProviderConfigURL());
        endpointURLs.put(SCIMConstants.RESOURCE_TYPE_ENDPOINT, SCIMCommonUtils.getSCIMResourceTypeURL());
        //register endpoint URLs in AbstractResourceEndpoint since they are called with in the API
        registerEndpointURLs();
        //register the charon related configurations
        registerCharonConfig();
    }

    /**
     * return json encoder
     * @return
     */
    public JSONEncoder getEncoder() {
        return encoder;
    }


    public UserManager getUserManager(String userName) throws CharonException {
        SCIMUserManager scimUserManager = null;
        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
        String tenantLessUserName = MultitenantUtils.getTenantAwareUsername(userName);
        try {
            //get super tenant context and get realm service which is an osgi service
            RealmService realmService = (RealmService)
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(RealmService.class);
            if (realmService != null) {
                int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                //get tenant's user realm
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                ClaimManager claimManager;
                if (userRealm != null) {
                    //get claim manager for manipulating attributes
                    claimManager = (ClaimManager) userRealm.getClaimManager();
                    /*if the authenticated & authorized user is not set in the carbon context, set it,
                    coz we are going to refer it later to identify the SCIM providers registered for a particular consumer.*/
                    String authenticatedUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
                    if (authenticatedUser == null) {
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(tenantLessUserName);
                        if (log.isDebugEnabled()) {
                            log.debug("User read from carbon context is null, hence setting " +
                                    "authenticated user: " + tenantLessUserName);
                        }
                    }
                    scimUserManager = new SCIMUserManager((UserStoreManager) userRealm.getUserStoreManager(),
                            userName, claimManager);
                }
            } else {
                String error = "Can not obtain carbon realm service..";
                throw new CharonException(error);
            }
            //get user store manager
        } catch (UserStoreException e) {
            String error = "Error obtaining user realm for the user: " + userName;
            throw new CharonException(error, e);
        }
        return scimUserManager;
    }

    /**
     * Register encoders and decoders in AbstractResourceEndpoint.
     */
    private void registerCoders() throws CharonException {
        //set json encoder
        AbstractResourceManager.setEncoder();
        //set json decoder
        AbstractResourceManager.setDecoder();
    }

    /**
     * Resgister endpoint URLs in AbstractResourceEndpoint.
     */
    private void registerEndpointURLs() {
        if (MapUtils.isNotEmpty(endpointURLs)) {
            AbstractResourceManager.setEndpointURLMap(endpointURLs);
        }
    }

    /**
     * This create the basic operational configurations for charon
     */
    private void registerCharonConfig(){
        //config charon
        //this values will be used in /ServiceProviderConfigResource endpoint
        CharonConfiguration.getInstance().setDocumentationURL(SCIMProviderConstants.DOCUMENTATION_URL);
        CharonConfiguration.getInstance().setBulkSupport(false,
                                                         SCIMProviderConstants.MAX_OPERATIONS,
                                                         SCIMProviderConstants.MAX_PAYLOAD_SIZE);
        CharonConfiguration.getInstance().setSortSupport(false);
        CharonConfiguration.getInstance().setETagSupport(false);
        CharonConfiguration.getInstance().setChangePasswordSupport(true);
        CharonConfiguration.getInstance().setFilterSupport(true, SCIMProviderConstants.MAX_RESULTS);
        CharonConfiguration.getInstance().setPatchSupport(false);
        CharonConfiguration.getInstance().setCountValueForPagination(SCIMProviderConstants.COUNT_FOR_PAGINATION);

        Object [] auth1 = {SCIMProviderConstants.AUTHENTICATION_SCHEMES_NAME_1,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_DESCRIPTION_1,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_SPEC_URI_1,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_1,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_TYPE_1,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_PRIMARY_1};

        Object [] auth2 = {SCIMProviderConstants.AUTHENTICATION_SCHEMES_NAME_2,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_DESCRIPTION_2,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_SPEC_URI_2,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_2,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_TYPE_2,
                SCIMProviderConstants.AUTHENTICATION_SCHEMES_PRIMARY_2};
        ArrayList<Object[]> authList = new ArrayList<Object[]>();
        authList.add(auth1);
        authList.add(auth2);
        CharonConfiguration.getInstance().setAuthenticationSchemes(authList);
    }

}
