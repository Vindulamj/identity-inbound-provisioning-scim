package org.wso2.carbon.identity.scim.provider.util;

import org.apache.commons.collections.MapUtils;
import org.wso2.charon.core.v2.protocol.SCIMResponse;

import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * This class contains the common utils used at HTTP level
 */
public class SupportUtils {

    public static Response buildResponse(SCIMResponse scimResponse) {
        //create a response builder with the status code of the response to be returned.
        Response.ResponseBuilder responseBuilder = Response.status(scimResponse.getResponseStatus());
        //set the headers on the response
        Map<String, String> httpHeaders = scimResponse.getHeaderParamMap();
        if (MapUtils.isNotEmpty(httpHeaders)) {
            for (Map.Entry<String, String> entry : httpHeaders.entrySet()) {

                responseBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        //set the payload of the response, if available.
        if (scimResponse.getResponseMessage() != null) {
            responseBuilder.entity(scimResponse.getResponseMessage());
        }
        return responseBuilder.build();
    }
}
