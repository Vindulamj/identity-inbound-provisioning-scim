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

package org.wso2.carbon.identity.scim.provider.util;

public class SCIMProviderConstants {

    public static final String AUTHORIZATION = "Authorization";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String ATTRIBUTES = "attributes";
    public static final String EXCLUDE_ATTRIBUTES = "excludedAttributes";
    public static final String FILTER = "filter";
    public static final String START_INDEX = "startIndex";
    public static final String COUNT = "count";
    public static final String SORT_BY = "sortBy";
    public static final String SORT_ORDER = "sortOder";
    public static final String APPLICATION_SCIM_JSON = "application/scim+json";
    public static final String APPLICATION__JSON = "application/json";
    public static final String ACCEPT_HEADER = "Accept";
    public static final String ID = "id";
    public static final String SCIM_CORE_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0";
    public static final String SCIM_USER_CLAIM_DIALECT = "urn:ietf:params:scim:schemas:core:2.0:User";

    public static final String RESOURCE_STRING = "RESOURCE_STRING";
    public static final String HTTP_VERB = "HTTP_VERB";
    public static final String APPLICATION_DOMAIN = "Application";
    public static final String INTERNAL_DOMAIN = "Internal";

    //ServiceProviderConfig endpoint related constants

    public static final String DOCUMENTATION_URL = "";
    public static final int MAX_OPERATIONS = 1000;
    public static final int MAX_PAYLOAD_SIZE = 1048576;
    public static final int MAX_RESULTS = 200;
    public static final int COUNT_FOR_PAGINATION = 2;

    public static final String AUTHENTICATION_SCHEMES_NAME_1 = "OAuth Bearer Token";
    public static final String AUTHENTICATION_SCHEMES_DESCRIPTION_1 =
            "Authentication scheme using the OAuth Bearer Token Standard";
    public static final String AUTHENTICATION_SCHEMES_SPEC_URI_1 = "http://www.rfc-editor.org/info/rfc6750";
    public static final String AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_1 = "http://example.com/help/oauth.html";
    public static final String AUTHENTICATION_SCHEMES_TYPE_1 = "oauthbearertoken";
    public static final Boolean AUTHENTICATION_SCHEMES_PRIMARY_1 = true;

    public static final String AUTHENTICATION_SCHEMES_NAME_2 = "HTTP Basic";
    public static final String AUTHENTICATION_SCHEMES_DESCRIPTION_2 = "Authentication scheme using the HTTP Basic Standard";
    public static final String AUTHENTICATION_SCHEMES_SPEC_URI_2 = "http://www.rfc-editor.org/info/rfc2617";
    public static final String AUTHENTICATION_SCHEMES_DOCUMENTATION_URL_2 = "http://example.com/help/httpBasic.html";
    public static final String AUTHENTICATION_SCHEMES_TYPE_2 = "httpbasic";
    public static final Boolean AUTHENTICATION_SCHEMES_PRIMARY_2 = false;







}
