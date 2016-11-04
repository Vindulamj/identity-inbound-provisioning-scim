package org.wso2.carbon.identity.scim.provider.resources;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.charon.core.v2.protocol.endpoints.GroupResourceManager;
import org.wso2.charon.core.v2.schema.SCIMConstants;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

public class GroupResource extends AbstractResource {

    private static Log logger = LogFactory.getLog(GroupResource.class);

    @POST
    public Response createGroup(@HeaderParam(SCIMProviderConstants.CONTENT_TYPE) String inputFormat,
                                @HeaderParam(SCIMProviderConstants.ACCEPT_HEADER) String outputFormat,
                                @HeaderParam(SCIMProviderConstants.AUTHORIZATION) String authorization,
                                String resourceString) {

        Map<String, String> requestAttributes = new HashMap<>();
        requestAttributes.put(SCIMProviderConstants.CONTENT_TYPE, inputFormat);
        requestAttributes.put(SCIMProviderConstants.ACCEPT_HEADER, outputFormat);
        requestAttributes.put(SCIMProviderConstants.AUTHORIZATION, authorization);
        requestAttributes.put(SCIMProviderConstants.HTTP_VERB, POST.class.getSimpleName());
        requestAttributes.put(SCIMProviderConstants.RESOURCE_STRING, resourceString);
        return processRequest(requestAttributes);
    }

    private Response processRequest(final Map<String, String> requestAttributes) {

        String id = requestAttributes.get(SCIMProviderConstants.ID);
        String inputFormat = requestAttributes.get(SCIMProviderConstants.CONTENT_TYPE);
        String outputFormat = requestAttributes.get(SCIMProviderConstants.ACCEPT_HEADER);
        String authorization = requestAttributes.get(SCIMProviderConstants.AUTHORIZATION);
        String httpVerb = requestAttributes.get(SCIMProviderConstants.HTTP_VERB);
        String resourceString = requestAttributes.get(SCIMProviderConstants.RESOURCE_STRING);
        JSONEncoder encoder = null;
        try {
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
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();
            //obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();
            //obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(authorization);

            //create charon-SCIM group endpoint and hand-over the request.
            GroupResourceManager groupResourceManager = new GroupResourceManager();
            SCIMResponse scimResponse = null;

            if (GET.class.getSimpleName().equals(httpVerb) && id == null) {
                String filter = requestAttributes.get(SCIMProviderConstants.FILTER);
                String startIndex = requestAttributes.get(SCIMProviderConstants.START_INDEX);
                String count = requestAttributes.get(SCIMProviderConstants.COUNT);
                String sortBy = requestAttributes.get(SCIMProviderConstants.SORT_BY);
                String sortOrder = requestAttributes.get(SCIMProviderConstants.SORT_ORDER);
                if (filter != null) {
                    scimResponse = groupResourceManager.listByFilter(filter, userManager, null,null);
                } else if (startIndex != null && count != null) {
                    scimResponse = groupResourceManager.listWithPagination(Integer.valueOf(startIndex),
                            Integer.valueOf(count), userManager, null,null);
                } else if (sortBy != null) {
                    scimResponse = groupResourceManager.listBySort(sortBy, sortOrder, userManager, null, null);
                } else if (startIndex == null && count == null) {
                    scimResponse = groupResourceManager.list(userManager, null, null);
                } else {
                    String error = "Error in the request";
                    //bad request
                    throw new BadRequestException(error);
                }
            } else if (GET.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.get(id, userManager, null, null);
            } else if (POST.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.create(resourceString, userManager, null, null);
            } else if (PUT.class.getSimpleName().equals(httpVerb)) {
                scimResponse =
                        groupResourceManager.updateWithPUT(id, resourceString, userManager, null, null);
            } else if (DELETE.class.getSimpleName().equals(httpVerb)) {
                scimResponse = groupResourceManager.delete(id, userManager);
            }

            return SupportUtils.buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e, encoder);
        } catch (FormatNotSupportedException e) {
            return handleFormatNotSupportedException(e);
        } catch (BadRequestException e) {
            if (logger.isDebugEnabled()) {
                logger.debug(e.getMessage(), e);
            }
            return SupportUtils.buildResponse(AbstractResourceManager.encodeSCIMException(e));
        }
    }

}
