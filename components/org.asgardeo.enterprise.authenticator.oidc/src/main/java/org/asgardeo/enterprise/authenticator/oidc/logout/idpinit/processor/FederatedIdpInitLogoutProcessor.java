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

package org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.processor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asgardeo.enterprise.authenticator.oidc.EnterpriseIDPAuthenticatorConstants;
import org.asgardeo.enterprise.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.authentication.framework.ServerSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.dao.UserSessionDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.UserSessionDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementServerException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.FederatedUserSession;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.asgardeo.enterprise.authenticator.oidc.internal.EnterpriseIDPAuthenticatorDataHolder;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.exception.LogoutClientException;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.exception.LogoutException;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.exception.LogoutServerException;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.model.LogoutResponse;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;

import javax.servlet.http.HttpServletResponse;

/**
 * Processes the OIDC federated idp initiated logout requests.
 */
public class FederatedIdpInitLogoutProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(FederatedIdpInitLogoutProcessor.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Started processing OIDC federated IDP initiated logout request.");
        }
        return handleOIDCFederatedLogoutRequest(identityRequest);
    }

    /**
     * Handles the logout request according to OIDC Back-channel logout specification.
     *
     * @param logoutRequest
     * @return IdentityResponse.IdentityResponseBuilder.
     * @throws LogoutClientException Exception occurred due to error in the logout request.
     * @throws LogoutServerException Exception occurred from IS.
     */
    protected IdentityResponse.IdentityResponseBuilder handleOIDCFederatedLogoutRequest(
            IdentityRequest logoutRequest) throws LogoutException {

        try {
            String logoutToken = logoutRequest.getParameter(EnterpriseIDPAuthenticatorConstants.LOGOUT_TOKEN);
            if (StringUtils.isBlank(logoutToken)) {
                throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_EMPTY_OR_NULL);
            }

            if (log.isDebugEnabled()) {
                log.debug("Handling the OIDC federated IdP Initiated logout request for the obtained logout token: " +
                        logoutToken);
            }
            // Get the claim set from the logout token.
            SignedJWT signedJWT = SignedJWT.parse(logoutToken);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            // Check for the iss value in claim set.
            validateIssuerClaim(claimsSet);
            // Get the identity provider for the issuer of the logout token.
            String tenantDomain = logoutRequest.getTenantDomain();
            IdentityProvider identityProvider = getIdentityProvider(claimsSet.getIssuer(), tenantDomain);

            validateLogoutToken(signedJWT, identityProvider);

            if (isSidClaimExists(claimsSet)) {
                // Find the the local session corresponding to sid and terminate it.
                return logoutUsingSid((String) claimsSet.getClaim(EnterpriseIDPAuthenticatorConstants.Claim.SID));
            }

            String subClaim = claimsSet.getSubject();
            if (StringUtils.isBlank(subClaim)) {
                throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_SUB_CLAIM_NOT_FOUND);
            }

            if (log.isDebugEnabled()) {
                log.debug("No 'sid' claim present in the logout token of the federated idp initiated logout request" +
                        ". Using sub claim to terminate the sessions for user: " + subClaim +
                        " tenant domain: " + tenantDomain);
            }

            return logoutUsingSub(tenantDomain, subClaim, identityProvider);

        } catch (ParseException e) {
            throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, e);
        }
    }

    /**
     * Terminate the session related to the sid value of the logout token.
     *
     * @param sid - sid claim included in the logout token.
     * @return
     * @throws LogoutServerException
     */
    private LogoutResponse.LogoutResponseBuilder logoutUsingSid(String sid)
            throws LogoutServerException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying federated IdP initiated logout using sid: %s.", sid));
        }
        String sessionId = getSessionIdFromSid(sid);
        if (StringUtils.isBlank(sessionId)) {
            return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_OK, StringUtils.EMPTY);
        }

        ServerSessionManagementService serverSessionManagementService =
                EnterpriseIDPAuthenticatorDataHolder.getInstance().getServerSessionManagementService();
        serverSessionManagementService.removeSession(sessionId);
        if (log.isDebugEnabled()) {
            log.debug("Session terminated for session Id: " + sessionId);
        }

        return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_OK,
                EnterpriseIDPAuthenticatorConstants.BackchannelLogout.LOGOUT_SUCCESS);
    }

    private String getSessionIdFromSid(String sid) throws LogoutServerException {

        try {
            UserSessionDAO userSessionDAO = new UserSessionDAOImpl();
            FederatedUserSession federatedUserSession = userSessionDAO.getFederatedAuthSessionDetails(sid);
            if (federatedUserSession == null) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No session information found for the sid: %s. ", sid) + "Probably the " +
                            "session was cleared by another mechanism.");
                }
                return null;
            }
            return federatedUserSession.getSessionId();
        } catch (SessionManagementServerException e) {
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.RETRIEVING_SESSION_ID_MAPPING_FAILED, e, sid);
        }
    }

    /**
     * Terminate all the sessions of the user related sub claim.
     *
     * @throws LogoutServerException
     * @throws SessionManagementException
     */
    private LogoutResponse.LogoutResponseBuilder logoutUsingSub(String tenantDomain, String sub,
                                                                IdentityProvider identityProvider)
            throws LogoutServerException {

        try {
            // Retrieve the federated user id from the IDN_AUTH_USER table.
            String userId = getUserId(tenantDomain, sub, identityProvider);
            if (log.isDebugEnabled()) {
                log.debug("Trying OIDC federated identity provider initiated logout for the user: " + sub);
            }

            if (StringUtils.isBlank(userId)) {
                return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        OIDCErrorConstants.ErrorMessages.LOGOUT_SERVER_EXCEPTION.getMessage());
            }
            UserSessionManagementService userSessionManagementService =
                    EnterpriseIDPAuthenticatorDataHolder.getInstance()
                            .getUserSessionManagementService();
            userSessionManagementService.terminateSessionsByUserId(userId);
            if (log.isDebugEnabled()) {
                log.debug("Sessions terminated for user Id: " + userId);
            }
            return new LogoutResponse.LogoutResponseBuilder(HttpServletResponse.SC_OK,
                    EnterpriseIDPAuthenticatorConstants.BackchannelLogout.LOGOUT_SUCCESS);
        } catch (SessionManagementException e) {
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.USER_SESSION_TERMINATION_FAILURE, e, sub);
        }
    }

    /**
     * Validate the JWT token signature and the mandatory claim according to the OIDC specification.
     *
     * @param signedJWT
     * @param identityProvider
     * @return boolean value
     * @throws LogoutClientException
     * @throws LogoutServerException
     */
    private void validateLogoutToken(SignedJWT signedJWT, IdentityProvider identityProvider)
            throws LogoutClientException, LogoutServerException {

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (!JWTSignatureValidationUtils.validateSignature(signedJWT, identityProvider)) {
                throw new LogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getCode(),
                        OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED.getMessage());
            }
            validateAudience(claimsSet.getAudience(), identityProvider);
            validateIat(claimsSet.getIssueTime());
            validateEventClaim((JSONObject) claimsSet.getClaim(EnterpriseIDPAuthenticatorConstants.Claim.EVENTS));
            validateNonce(claimsSet);
        } catch (ParseException e) {
            throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_PARSING_FAILURE, e);
        } catch (JOSEException | IdentityOAuth2Exception e) {
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_SIGNATURE_VALIDATION_FAILED, e);
        }
    }

    /**
     * Retrieve userId of the federated user.
     *
     * @param tenantDomain     - tenant domain of the logout request.
     * @param sub              - sub claim in the logout token.
     * @param identityProvider - identity provider.
     * @return
     * @throws LogoutServerException
     */
    private String getUserId(String tenantDomain, String sub, IdentityProvider identityProvider)
            throws LogoutServerException {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            String userId = UserSessionStore.getInstance()
                    .getFederatedUserId(sub, tenantId, Integer.parseInt(identityProvider.getId()));
            if (StringUtils.isBlank(userId)) {
                throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.RETRIEVING_USER_ID_FAILED, sub);
            }
            return userId;
        } catch (UserSessionException e) {
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.RETRIEVING_USER_ID_FAILED, e, sub);
        }
    }

    /**
     * Check for iss claim in the logout token claims.
     *
     * @param claimsSet - claim set in the logout token.
     * @return boolean.
     */
    private void validateIssuerClaim(JWTClaimsSet claimsSet) throws LogoutClientException {

        if (StringUtils.isBlank(claimsSet.getIssuer())) {
            throw new LogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_ISS_CLAIM_VALIDATION_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_ISS_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    /**
     * Do the aud claim validation according to OIDC back-channel logout specification.
     *
     * @param aud - list containing audience values.
     * @param idp - identity provider.
     * @return boolean if validation is successful.
     */
    private void validateAudience(List<String> aud, IdentityProvider idp) throws LogoutClientException {

        String clientId = null;
        // Get the client id from the authenticator config.
        for (Property property : idp.getDefaultAuthenticatorConfig().getProperties()) {
            String propertyName = property.getName();
            if (propertyName.equals(EnterpriseIDPAuthenticatorConstants.IdPConfParams.CLIENT_ID)) {
                clientId = property.getValue();
                break;
            }
        }
        // Check whether the client id exist in the aud claim.
        if (StringUtils.isNotBlank(clientId)) {
            if (!aud.contains(clientId)) {
                throw new LogoutClientException(
                        String.format(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED.getCode(), clientId),
                        OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_AUD_CLAIM_VALIDATION_FAILED.getMessage());
            }
        }
    }

    /**
     * Do the iat claim validation according to OIDC back-channel logout specification
     * Read the authenticator configs to check whether the iat validation is enabled and if enabled the get the
     * validity period.
     *
     * @param iat
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private void validateIat(Date iat) throws LogoutClientException {

        if (iat == null) {
            throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED);
        }
        if (Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap()
                .get(EnterpriseIDPAuthenticatorConstants.BackchannelLogout.ENABLE_IAT_VALIDATION))) {
            // iatValidityPeriod will be in seconds.
            long iatValidityPeriod = getIatValidityPeriod();
            long issuedAtTimeMillis = iat.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            long iatValidityPeriodInMillis = iatValidityPeriod * 1000;

            if (currentTimeInMillis - issuedAtTimeMillis > iatValidityPeriodInMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Logout token is used after iat validity period." +
                            " iat validity period(m): " + iatValidityPeriod +
                            ", Current Time : " + currentTimeInMillis +
                            ". This logout token is not valid.");
                }
                throw handleLogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_IAT_VALIDATION_FAILED);
            }
            if (log.isDebugEnabled()) {
                log.debug("iat validity period of logout token was validated successfully.");
            }
        }
    }

    /**
     * Get iatValidityPeriod from configuration file.
     * Use default value if error occurs.
     *
     * @return - iatValidityPeriod.
     */
    private long getIatValidityPeriod() {

        long iatValidityPeriod = 0;
        if (StringUtils.isBlank(getAuthenticatorConfig().getParameterMap()
                .get(EnterpriseIDPAuthenticatorConstants.BackchannelLogout.IAT_VALIDITY_PERIOD))) {
            iatValidityPeriod = EnterpriseIDPAuthenticatorConstants.BackchannelLogout.DEFAULT_IAT_VALIDITY_PERIOD;
        } else {
            try {
                iatValidityPeriod =
                        Integer.parseInt(getAuthenticatorConfig().getParameterMap()
                                .get(EnterpriseIDPAuthenticatorConstants.BackchannelLogout.IAT_VALIDITY_PERIOD));
            } catch (NumberFormatException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid iatValidityPeriod is configured. Hence using default iatValidityPeriod value");
                }
            }
        }
        return iatValidityPeriod;
    }

    /**
     * Do the sid claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     */
    private boolean isSidClaimExists(JWTClaimsSet claimsSet) {

        return StringUtils.isNotBlank((String) claimsSet.getClaim(EnterpriseIDPAuthenticatorConstants.Claim.SID));
    }

    /**
     * Do the sub claim validation.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     */
    private boolean isSubClaimExists(JWTClaimsSet claimsSet) {

        return StringUtils.isNotBlank(claimsSet.getSubject());
    }

    /**
     * Do the event claim validation according to OIDC back-channel logout specification.
     *
     * @param event
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private void validateEventClaim(JSONObject event) throws LogoutClientException {

        String eventClaimValue = event.getAsString(EnterpriseIDPAuthenticatorConstants.Claim.BACKCHANNEL_LOGOUT_EVENT);
        if (event == null ||
                !StringUtils.equals(eventClaimValue, EnterpriseIDPAuthenticatorConstants.Claim.BACKCHANNEL_LOGOUT_EVENT_CLAIM)) {
            throw new LogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_EVENT_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    /**
     * Do the nonce claim validation according to OIDC back-channel logout specification.
     *
     * @param claimsSet
     * @return boolean if validation is successful.
     * @throws LogoutClientException
     */
    private void validateNonce(JWTClaimsSet claimsSet) throws LogoutClientException {

        if (StringUtils.isNotBlank((String) claimsSet.getClaim(EnterpriseIDPAuthenticatorConstants.Claim.NONCE))) {
            throw new LogoutClientException(OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.LOGOUT_TOKEN_NONCE_CLAIM_VALIDATION_FAILED.getMessage());
        }
    }

    /**
     * Get the OIDC authenticator configs from the xml file.
     *
     * @return AuthenticatorConfig.
     */
    protected AuthenticatorConfig getAuthenticatorConfig() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(EnterpriseIDPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig == null) {
            authConfig = new AuthenticatorConfig();
            authConfig.setParameterMap(new HashMap<>());
        }
        return authConfig;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return null;
    }

    @Override
    public String getRelyingPartyId() {

        return null;
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext context) {

        return null;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        boolean canHandle = false;
        if (identityRequest != null) {
            Matcher registerMatcher =
                    EnterpriseIDPAuthenticatorConstants.OIDC_BACKCHANNEL_LOGOUT_ENDPOINT_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (registerMatcher.matches()) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Can handle: " + canHandle + " by OIDC FederatedIdpInitLogoutProcessor.");
        }
        return canHandle;
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error, String data) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + "Error code:" + error.getCode());
        }
        return new LogoutServerException(error.getCode(), String.format(error.getMessage(), data));
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @param data  relevant data.
     * @param e     Throwable.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error,
                                                              Throwable e, String data) {

        if (log.isDebugEnabled()) {
            log.debug(String.format(error.getMessage(), data) + "Error code:" + error.getCode());
        }
        return new LogoutServerException(error.getCode(), String.format(error.getMessage(), data), e);
    }

    /**
     * Handle logout server exceptions.
     *
     * @param error Error description.
     * @param e     Throwable.
     * @return LogoutServerException.
     */
    private LogoutServerException handleLogoutServerException(OIDCErrorConstants.ErrorMessages error, Throwable e) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + " Error code: " + error.getCode());
        }
        return new LogoutServerException(error.getCode(), error.getMessage(), e);
    }

    /**
     * Handle logout client exceptions.
     *
     * @param error Error description.
     * @return LogoutClientException.
     */
    private LogoutClientException handleLogoutClientException(OIDCErrorConstants.ErrorMessages error) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + " Error code: " + error.getCode());
        }
        return new LogoutClientException(error.getCode(), error.getMessage());
    }

    /**
     * Handle logout client exceptions.
     *
     * @param error Error description.
     * @param e     Throwable.
     * @return LogoutClientException.
     */
    private LogoutClientException handleLogoutClientException(OIDCErrorConstants.ErrorMessages error, Throwable e) {

        if (log.isDebugEnabled()) {
            log.debug(error.getMessage() + " Error code: " + error.getCode());
        }
        return new LogoutClientException(error.getCode(), error.getMessage(), e);
    }

    /**
     * Get the identity provider from issuer and tenant domain.
     *
     * @param jwtIssuer
     * @param tenantDomain
     * @return IdentityProvider.
     * @throws LogoutServerException
     */
    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws LogoutServerException {

        IdentityProvider identityProvider = null;
        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                    IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

            if (identityProvider == null) {
                if (log.isDebugEnabled()) {
                    log.debug("IDP not found when retrieving for IDP using property: " +
                            IdentityApplicationConstants.IDP_ISSUER_NAME + " with value: " + jwtIssuer +
                            ". Attempting to retrieve IDP using IDP Name as issuer.");
                }
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            }
            if ((identityProvider != null) && (StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(),
                    EnterpriseIDPAuthenticatorConstants.BackchannelLogout.DEFAULT_IDP_NAME))) {
                // Check whether this jwt was issued by the resident identity provider.
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
                if (identityProvider == null) {
                    throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER, jwtIssuer);
                }
            }
        } catch (IdentityProviderManagementException e) {
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.RETRIEVING_IDENTITY_PROVIDER_FAILED, e);
        }
        return identityProvider;
    }

    /**
     * Get the resident identity provider from issuer and tenant domain.
     *
     * @param tenantDomain
     * @param jwtIssuer
     * @return
     * @throws IdentityOAuth2Exception
     * @throws LogoutServerException
     */
    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws LogoutServerException {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = OIDCErrorConstants.ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getCode() + " - " +
                    String.format(OIDCErrorConstants.ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getMessage(), tenantDomain);
            throw handleLogoutServerException(OIDCErrorConstants.ErrorMessages.GETTING_RESIDENT_IDP_FAILED, tenantDomain);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    EnterpriseIDPAuthenticatorConstants.BackchannelLogout.OIDC_IDP_ENTITY_ID).getValue();
        }
        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }
}
