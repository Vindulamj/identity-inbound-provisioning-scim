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

package org.wso2.carbon.identity.scim.provider.resources;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.scim.provider.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim.provider.util.SCIMProviderConstants;
import org.wso2.carbon.identity.scim.provider.util.SupportUtils;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.protocol.ResponseCodeConstants;
import org.wso2.charon.core.v2.protocol.SCIMResponse;
import org.wso2.charon.core.v2.protocol.endpoints.AbstractResourceManager;
import org.wso2.charon.core.v2.protocol.endpoints.UserResourceManager;
import org.wso2.charon.core.v2.schema.SCIMConstants;

import javax.annotation.processing.SupportedOptions;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class UserResource extends AbstractResource {
    private static Log logger = LogFactory.getLog(UserResource.class);

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                            @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization,
                            @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            //decode the base64 encoded authorization parameter
            String userName = SupportUtils.decodeBase64(authorization);

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(userName);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = userResourceManager.get(id, userManager,attribute, excludedAttributes);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e,encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @POST
    public Response createUser(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization,
                               @QueryParam(SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam(SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String  excludedAttributes,
                               String resourceString) {

        JSONEncoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if(!isValidInputFormat(inputFormat)){
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();
            //decode the base64 encoded authorization parameter
            String userName = SupportUtils.decodeBase64(authorization);

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(userName);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse response = userResourceManager.create(resourceString, userManager,
                    attribute, excludedAttributes);

            return new SupportUtils().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMProviderConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
                               @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            //decode the base64 encoded authorization parameter
            String userName = SupportUtils.decodeBase64(authorization);

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(userName);

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = userResourceManager.delete(id, userManager);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String format,
                            @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization,
                            @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                            @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                            @QueryParam (SCIMProviderConstants.FILTER) String filter,
                            @QueryParam (SCIMProviderConstants.START_INDEX) int startIndex,
                            @QueryParam (SCIMProviderConstants.COUNT) int count,
                            @QueryParam (SCIMProviderConstants.SORT_BY) String sortBy,
                            @QueryParam (SCIMProviderConstants.SORT_ORDER) String sortOrder) {

        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // defaults to application/scim+json.
            if (format == null) {
                format = SCIMProviderConstants.APPLICATION_SCIM_JSON;
            }
            if(!isValidOutputFormat(format)){
                String error = format + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            //decode the base64 encoded authorization parameter
            String userName = SupportUtils.decodeBase64(authorization);

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(userName);

            // create charon-SCIM user resource manager and hand-over the request.
            UserResourceManager userResourceManager = new UserResourceManager();

            SCIMResponse scimResponse = null;
            if (filter != null) {
                scimResponse = userResourceManager.listByFilter(filter, userManager, attribute, excludedAttributes);
            } else if ( filter == null && startIndex == 0 && count == 0 && sortBy == null) {
                scimResponse = userResourceManager.list
                        (userManager, attribute, excludedAttributes);
            } else if (sortBy != null || sortOrder != null){
                scimResponse = userResourceManager.listBySort
                        (sortBy, sortOrder, userManager, attribute, excludedAttributes);
            } else if(startIndex != 0 || count != 0) {
                scimResponse = userResourceManager.listWithPagination
                        (startIndex, count, userManager, attribute, excludedAttributes);
            }
            return new SupportUtils().buildResponse(scimResponse);
        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
                               @HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                               @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                               @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization,
                               @QueryParam (SCIMProviderConstants.ATTRIBUTES) String attribute,
                               @QueryParam (SCIMProviderConstants.EXCLUDE_ATTRIBUTES) String excludedAttributes,
                               String resourceString) {

        JSONEncoder encoder = null;
        try {
            // obtain default charon manager
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // content-type header is compulsory in post request.
            if (inputFormat == null) {
                String error = SCIMProviderConstants.CONTENT_TYPE
                        + " not present in the request header";
                throw new FormatNotSupportedException(error);
            }

            if(!isValidInputFormat(inputFormat)){
                String error = inputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }

            if(!isValidOutputFormat(outputFormat)){
                String error = outputFormat + " is not supported.";
                throw  new FormatNotSupportedException(error);
            }
            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            //decode the base64 encoded authorization parameter
            String userName = SupportUtils.decodeBase64(authorization);

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(userName);

            // create charon-SCIM user endpoint and hand-over the request.
            UserResourceManager userResourceEndpoint = new UserResourceManager();

            SCIMResponse response = userResourceEndpoint.updateWithPUT(
                    id, resourceString, userManager, attribute, excludedAttributes);

            return new SupportUtils().buildResponse(response);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        }
    }

}