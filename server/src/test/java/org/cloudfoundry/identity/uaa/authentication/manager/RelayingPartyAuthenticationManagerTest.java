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

import org.cloudfoundry.identity.client.UaaContext;
import org.cloudfoundry.identity.client.UaaContextFactory;
import org.cloudfoundry.identity.client.UaaContextImpl;
import org.cloudfoundry.identity.client.token.TokenRequest;
import org.cloudfoundry.identity.uaa.authentication.RelayingPartyAuthenticationCodeToken;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OauthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import java.net.URI;
import java.net.URL;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class RelayingPartyAuthenticationManagerTest {

    IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);
    RelayingPartyAuthenticationManager manager;
    RelayingPartyAuthenticationCodeToken token;
    String origin = "test-oauth";
    UaaContextFactory factory;
    URI tokenEndpoint;
    URI authEndpoint;

    @Before
    public void setUp() throws Exception {
        token = new RelayingPartyAuthenticationCodeToken("654321", origin);
        OauthIdentityProviderDefinition definition = new OauthIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
        IdentityProvider<OauthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(origin, IdentityZone.getUaa().getId());
        identityProvider.setConfig(definition);
        when(providerProvisioning.retrieveByOrigin(eq(origin), eq(IdentityZone.getUaa().getId()))).thenReturn(identityProvider);
        tokenEndpoint = new URI("http://token.url");
        authEndpoint = new URI("http://auth.url");

        CompositeAccessToken token = new CompositeAccessToken("");

        UaaContext context = new UaaContextImpl(null,null,token);

        factory = mock(UaaContextFactory.class);
        when(factory.authenticate(anyObject())).thenReturn(context);
        when(factory.tokenRequest()).thenReturn(new TokenRequest(tokenEndpoint, authEndpoint));

        RelayingPartyAuthenticationManager.UaaContextFactoryProvider factoryProvider = provider -> factory;
        manager = new RelayingPartyAuthenticationManager(factoryProvider, providerProvisioning);
    }

    @Test
    public void testAuthenticate_wrong_class() throws Exception {
        assertNull(manager.authenticate(mock(Authentication.class)));
    }

    @Test
    public void testAuthenticate() {
        Authentication auth = manager.authenticate(token);
        verify(factory).authenticate(anyObject());
        assertNotNull(auth);
        assertTrue("Authentication should be of type UaaAuthentication", auth instanceof UaaAuthentication);
    }
}