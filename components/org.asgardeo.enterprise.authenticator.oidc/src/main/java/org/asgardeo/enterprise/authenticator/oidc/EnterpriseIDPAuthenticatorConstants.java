/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.asgardeo.enterprise.authenticator.oidc;

import java.util.regex.Pattern;

public class EnterpriseIDPAuthenticatorConstants {

    private EnterpriseIDPAuthenticatorConstants() {

    }

    public static final String AUTHENTICATOR_NAME = "EnterpriseIDPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "enterpriseidp";
    public static final String LOGIN_TYPE = "OIDC";

    public static final String OAUTH_OIDC_SCOPE = "openid";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String OAUTH2_ERROR = "error";
    public static final String REDIRECT_URI = "redirect_uri";

    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthzEPUrl";
    public static final String OAUTH2_TOKEN_URL = "OAuth2TokenEPUrl";
    public static final String IS_BASIC_AUTH_ENABLED = "IsBasicAuthEnabled";

    public static final String OIDC_QUERY_PARAM_MAP_PROPERTY_KEY = "oidc:param.map";

    public static final String HTTP_ORIGIN_HEADER = "Origin";

    public static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    public static final String ID_TOKEN_HINT = "id_token_hint";

    public static final String AUTH_PARAM = "$authparam";
    public static final String DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX = "\\$authparam\\{(\\w+)\\}";

    public static final String LOGOUT_TOKEN = "logout_token";
    public static final Pattern OIDC_BACKCHANNEL_LOGOUT_ENDPOINT_URL_PATTERN = Pattern.compile("(.*)/identity/oidc" +
            "/slo(.*)");

    public class AuthenticatorConfParams {

        private AuthenticatorConfParams() {

        }

        public static final String DEFAULT_IDP_CONFIG = "DefaultIdPConfig";
    }

    public class IdPConfParams {

        private IdPConfParams() {

        }

        public static final String CLIENT_ID = "ClientId";
        public static final String CLIENT_SECRET = "ClientSecret";
        public static final String AUTHORIZATION_EP = "AuthorizationEndPoint";
        public static final String TOKEN_EP = "TokenEndPoint";
        public static final String OIDC_LOGOUT_URL = "OIDCLogoutEPUrl";
        public static final String USER_INFO_EP = "UserInfoEndPoint";
    }

    public class Claim {

        private Claim() {

        }

        public static final String SUB = "sub";
        public static final String NAME = "name";
        public static final String GIVEN_NAME = "given_name";
        public static final String FAMILY_NAME = "family_name";
        public static final String MIDDLE_NAME = "middle_name";
        public static final String NICK_NAME = "nickname";
        public static final String PREFERED_USERNAME = "preferred_username";
        public static final String PROFILE = "profile";
        public static final String PICTURE = "picture";
        public static final String WEBSITE = "website";
        public static final String EMAIL = "email";
        public static final String EMAIL_VERIFIED = "email_verified";
        public static final String GENDER = "gender";
        public static final String BIRTH_DATE = "birthdate";
        public static final String ZONE_INFO = "zoneinfo";
        public static final String LOCALE = "locale";
        public static final String PHONE_NUMBER = "phone_number";
        public static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
        public static final String ADDRESS = "address";
        public static final String UPDATED_AT = "updated_at";
        // Logout token claims.
        public static final String SID = "sid";
        public static final String NONCE = "nonce";
        public static final String EVENTS = "events";
        public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
        public static final String BACKCHANNEL_LOGOUT_EVENT_CLAIM = "{}";
    }

    public class BackchannelLogout {

        private BackchannelLogout() {

        }

        public static final String DEFAULT_IDP_NAME = "default";
        public static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";

        public static final String ENABLE_IAT_VALIDATION = "enableIatValidation";
        public static final String IAT_VALIDITY_PERIOD = "iatValidityPeriod";

        public static final String LOGOUT_SUCCESS = "OIDC back-channel logout success.";
        public static final String LOGOUT_FAILURE_SERVER_ERROR = "OIDC Back-channel logout failed due to an internal " +
                "server error.";

        public static final long DEFAULT_IAT_VALIDITY_PERIOD = 15000;
    }
}
