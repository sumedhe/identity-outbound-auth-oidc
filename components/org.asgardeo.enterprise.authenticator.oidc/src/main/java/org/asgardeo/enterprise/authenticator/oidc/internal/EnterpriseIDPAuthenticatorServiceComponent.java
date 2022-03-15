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
package org.asgardeo.enterprise.authenticator.oidc.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asgardeo.enterprise.authenticator.oidc.EnterpriseIDPAuthenticator;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.processor.FederatedIdpInitLogoutProcessor;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.ServerSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.factory.LogoutRequestFactory;
import org.asgardeo.enterprise.authenticator.oidc.logout.idpinit.factory.LogoutResponseFactory;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
        name = "asgardeo.enterprise.authenticator.oidc.component",
        immediate = true
)
public class EnterpriseIDPAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(EnterpriseIDPAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            EnterpriseIDPAuthenticator openIDConnectAuthenticator = new EnterpriseIDPAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), openIDConnectAuthenticator, null);
            ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                    new LogoutRequestFactory(), null);
            ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(),
                    new FederatedIdpInitLogoutProcessor(), null);
            ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                    new LogoutResponseFactory(), null);
            if (log.isDebugEnabled()) {
                log.debug("OpenID Connect Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating oidc authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("OpenID Connect Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        EnterpriseIDPAuthenticatorDataHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        EnterpriseIDPAuthenticatorDataHolder.getInstance()
                .setClaimMetadataManagementService(null);
    }

    @Reference(
            name = "server.session.management.service",
            service = ServerSessionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerSessionManagementService"
    )
    protected void setServerSessionManagementService(ServerSessionManagementService
                                                             serverSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Server Session Management Service is set in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance()
                .setServerSessionManagementService(serverSessionManagementService);
    }

    protected void unsetServerSessionManagementService(ServerSessionManagementService
                                                               serverSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Server Session Management Service is unset in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setServerSessionManagementService(null);
    }

    @Reference(
            name = "user.session.management.service",
            service = UserSessionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserSessionManagementService"
    )
    protected void setUserSessionManagementService(UserSessionManagementService
                                                           userSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Server Session Management Service is set in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance()
                .setUserSessionManagementService(userSessionManagementService);
    }

    protected void unsetUserSessionManagementService(UserSessionManagementService
                                                             userSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Server Session Management Service is unset in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setUserSessionManagementService(null);
    }

    @Reference(
            name = "identity.application.management.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Application Management Service is set in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance()
                .setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Application Management Service is unset in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "identity.oauth.component",
            service = OAuthAdminServiceImpl.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuthAdminService"
    )
    protected void setOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth Management Service is set in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setOAuthAdminService(oAuthAdminService);
    }

    protected void unsetOAuthAdminService(OAuthAdminServiceImpl oAuthAdminService) {

        if (log.isDebugEnabled()) {
            log.debug("Application Management Service is unset in the OpenID Connect Authenticator");
        }
        EnterpriseIDPAuthenticatorDataHolder.getInstance().setOAuthAdminService(null);
    }
}
