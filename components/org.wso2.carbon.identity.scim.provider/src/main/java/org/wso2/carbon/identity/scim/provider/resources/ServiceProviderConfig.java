package org.wso2.carbon.identity.scim.provider.resources;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.scim.provider.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim.provider.util.SupportUtils;
import org.wso2.charon.core.v2.encoder.JSONEncoder;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.extensions.UserManager;
import org.wso2.charon.core.v2.protocol.SCIMResponse;
import org.wso2.charon.core.v2.protocol.endpoints.ServiceProviderConfigResourceManager;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class ServiceProviderConfig extends AbstractResource {
    private static Log logger = LogFactory.getLog(ServiceProviderConfig.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@HeaderParam("Authorization") String authorization) {
        JSONEncoder encoder = null;
        try {
            IdentitySCIMManager identitySCIMManager = IdentitySCIMManager.getInstance();

            // obtain the encoder at this layer in case exceptions needs to be encoded.
            encoder = identitySCIMManager.getEncoder();

            // obtain the user store manager
            UserManager userManager = IdentitySCIMManager.getInstance().getUserManager(authorization);

            // create charon-SCIM service provider config endpoint and hand-over the request.
            ServiceProviderConfigResourceManager serviceProviderConfigResourceManager = new ServiceProviderConfigResourceManager();

            SCIMResponse scimResponse = serviceProviderConfigResourceManager.get(null, null, null, null);
            // needs to check the code of the response and return 200 0k or other error codes
            // appropriately.
            return new SupportUtils().buildResponse(scimResponse);

        } catch (CharonException e) {
            return handleCharonException(e,encoder);
        }
    }
}