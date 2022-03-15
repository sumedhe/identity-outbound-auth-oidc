/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.factory;

import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.exception.LogoutException;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.model.LogoutResponse;
import org.asgardeo.enterprise.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.exception.LogoutClientException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

/**
 * Builds a HTTP response instance based on the common IdentityRequest format used by
 * the authentication framework.
 */
public class LogoutResponseFactory extends HttpIdentityResponseFactory {

    private static final Log log = LogFactory.getLog(LogoutResponseFactory.class);

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {

        return (identityResponse instanceof LogoutResponse);

    }

    @Override
    public boolean canHandle(FrameworkException exception) {

        return (exception instanceof LogoutException);
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(httpIdentityResponseBuilder, identityResponse);
        return httpIdentityResponseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        builder.setStatusCode(((LogoutResponse) identityResponse).getStatusCode());
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        builder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN);
        builder.setBody(((LogoutResponse) identityResponse).getMessage());
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException frameworkException) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder;
        if (frameworkException instanceof LogoutClientException) {
            if (log.isDebugEnabled()) {
                log.debug("Client error when handling the request: " + frameworkException.getMessage(),
                        frameworkException);
            }
            builder = buildResponse("Invalid request.", HttpServletResponse.SC_BAD_REQUEST,
                    frameworkException.getMessage());
        } else {
            log.error(OIDCErrorConstants.ErrorMessages.LOGOUT_SERVER_EXCEPTION.getMessage(), frameworkException);
            builder = buildResponse("Internal server error.",
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR, OIDCErrorConstants.ErrorMessages.LOGOUT_SERVER_EXCEPTION.getMessage());
        }
        return builder;
    }

    /**
     * Build Identity response based on the error message and code.
     *
     * @param errorMessage
     * @param errorCode
     * @return
     */
    private HttpIdentityResponse.HttpIdentityResponseBuilder buildResponse(String errorMessage, int errorCode,
                                                                           String description) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
                new HttpIdentityResponse.HttpIdentityResponseBuilder();
        JSONObject responseBody = new JSONObject();
        responseBody.appendField("message", errorMessage);
        responseBody.appendField("code", errorCode);
        responseBody.appendField("description", description);
        responseBody.appendField("traceId", FrameworkUtils.getCorrelation());
        builder.setBody(responseBody.toJSONString());
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        builder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        return builder;
    }
}
