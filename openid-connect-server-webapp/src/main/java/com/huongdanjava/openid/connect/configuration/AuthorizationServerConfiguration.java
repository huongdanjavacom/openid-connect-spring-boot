package com.huongdanjava.openid.connect.configuration;

import java.util.ArrayList;
import java.util.List;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

@SuppressWarnings("deprecation")
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

  @Autowired
  private ClientDetailsService defaultOAuth2ClientDetailsEntityService;

  @Autowired
  private OAuth2RequestFactory connectOAuth2RequestFactory;

  @Autowired
  private AuthorizationServerTokenServices defaultOAuth2ProviderTokenService;

  @Autowired
  private UserApprovalHandler tofuUserApprovalHandler;

  @Autowired
  private OAuth2RequestValidator oauthRequestValidator;

  @Autowired
  private RedirectResolver blacklistAwareRedirectResolver;

  @Autowired
  private DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService;

  @Autowired
  private TokenGranter chainedTokenGranter;

  @Autowired
  private TokenGranter jwtAssertionTokenGranter;

  @Autowired
  private TokenGranter deviceTokenGranter;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.withClientDetails(defaultOAuth2ClientDetailsEntityService);
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    // @formatter:off
    endpoints.pathMapping("/oauth/authorize", "/authorize")
        .pathMapping("/oauth/token", "/token")
        .pathMapping("/oauth/error", "/error")
        .requestFactory(connectOAuth2RequestFactory)
        .tokenServices(defaultOAuth2ProviderTokenService)
        .userApprovalHandler(tofuUserApprovalHandler)
        .requestValidator(oauthRequestValidator)
        .redirectResolver(blacklistAwareRedirectResolver)
        .tokenGranter(getTokenGranter())
        .authorizationCodeServices(defaultOAuth2AuthorizationCodeService);
    // @formatter:on
  }

  private TokenGranter getTokenGranter() {
    List<TokenGranter> tokenGranters = new ArrayList<>();

    var authorizationCodeTokenGranter = new AuthorizationCodeTokenGranter(
        defaultOAuth2ProviderTokenService, defaultOAuth2AuthorizationCodeService,
        defaultOAuth2ClientDetailsEntityService, connectOAuth2RequestFactory);
    tokenGranters.add(authorizationCodeTokenGranter);

    var implicitTokenGranter = new ImplicitTokenGranter(defaultOAuth2ProviderTokenService,
        defaultOAuth2ClientDetailsEntityService, connectOAuth2RequestFactory);
    tokenGranters.add(implicitTokenGranter);

    var refreshTokenGranter = new RefreshTokenGranter(defaultOAuth2ProviderTokenService,
        defaultOAuth2ClientDetailsEntityService, connectOAuth2RequestFactory);
    tokenGranters.add(refreshTokenGranter);

    var clientCredentialsTokenGranter =
        new ClientCredentialsTokenGranter(defaultOAuth2ProviderTokenService,
            defaultOAuth2ClientDetailsEntityService, connectOAuth2RequestFactory);
    tokenGranters.add(clientCredentialsTokenGranter);

    tokenGranters.add(chainedTokenGranter);
    tokenGranters.add(jwtAssertionTokenGranter);
    tokenGranters.add(deviceTokenGranter);

    return new CompositeTokenGranter(tokenGranters);
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    // NOP
  }
}
