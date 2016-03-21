/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.client.UaaContext;
import org.cloudfoundry.identity.client.UaaContextFactory;
import org.cloudfoundry.identity.client.token.GrantType;
import org.cloudfoundry.identity.client.token.TokenRequest;
import org.cloudfoundry.identity.uaa.authentication.RelayingPartyAuthenticationCodeToken;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OauthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.common.OAuthException;

import java.net.URISyntaxException;

public class RelayingPartyAuthenticationManager extends ExternalLoginAuthenticationManager {
    protected static Log logger = LogFactory.getLog(RelayingPartyAuthenticationManager.class);

    private final UaaContextFactoryProvider factoryProvider;
    private final IdentityProviderProvisioning provisioning;

    public RelayingPartyAuthenticationManager(UaaContextFactoryProvider factoryProvider, IdentityProviderProvisioning provisioning) {
        this.factoryProvider = factoryProvider;
        this.provisioning = provisioning;
    }

    ThreadLocal<String> currentOrigin = new ThreadLocal<String>() {
        @Override
        protected String initialValue() {
            return OriginKeys.UAA;
        }
    };

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {
        if (!(request instanceof RelayingPartyAuthenticationCodeToken)) {
            logger.debug("Unable to process authentication request for class:" + request);
            return null;
        }
        RelayingPartyAuthenticationCodeToken token = (RelayingPartyAuthenticationCodeToken) request;
        try {
            currentOrigin.set(token.getOrigin());
            return super.authenticate(request);
        } finally {
            currentOrigin.remove();
        }
    }

    @Override
    protected UaaUser getUser(Authentication request) {
        RelayingPartyAuthenticationCodeToken token = (RelayingPartyAuthenticationCodeToken)request;
        try {
            IdentityProvider<OauthIdentityProviderDefinition> idp = provisioning.retrieveByOrigin(token.getOrigin(), IdentityZoneHolder.get().getId());
            UaaContextFactory factory = factoryProvider.getUaaContextFactory(idp);
            TokenRequest tokenRequest = new TokenRequest(idp.getConfig().getTokenKeyUrl().toURI(), null)
                .setAuthorizationCode(token.getCode())
                .setClientId(idp.getConfig().getRelyingPartyId())
                .setClientSecret(idp.getConfig().getRelyingPartySecret())
                .setGrantType(GrantType.FETCH_TOKEN_FROM_CODE);
            UaaContext context = factory.authenticate(tokenRequest);
            if (context.hasIdToken()) {
                return getUserFromIdToken(context.getToken());
            } else if (context.hasAccessToken()) {
                return getUserFromAccessToken(context.getToken());
            } else {
                throw new OAuthException(String.format("Unable to fetch token from factoryProvider origin:%s zone:%s", getOrigin(), IdentityZoneHolder.get().getId()));
            }
        } catch (URISyntaxException x) {
            ProviderNotFoundException ex = new ProviderNotFoundException("Invalid IDP configuration");
            ex.initCause(x);
            throw ex;
        } catch (EmptyResultDataAccessException x) {
            ProviderNotFoundException ex = new ProviderNotFoundException(x.getMessage());
            ex.initCause(x);
            throw ex;
        }
    }

    protected UaaUser getUserFromIdToken(CompositeAccessToken token) {
        return null;
    }

    protected UaaUser getUserFromAccessToken(CompositeAccessToken token) {
        return null;
    }

    @Override
    public String getOrigin() {
        return currentOrigin.get();
    }

    public interface UaaContextFactoryProvider {
        UaaContextFactory getUaaContextFactory(IdentityProvider<OauthIdentityProviderDefinition> provider);
    }
}
