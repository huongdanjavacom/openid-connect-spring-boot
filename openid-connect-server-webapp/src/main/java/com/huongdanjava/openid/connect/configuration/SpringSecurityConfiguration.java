package com.huongdanjava.openid.connect.configuration;

import javax.sql.DataSource;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.AuthorizationRequestFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SpringSecurityConfiguration {

  @Autowired
  private CorsFilter corsFilter;

  @Autowired
  private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

  @Autowired
  private JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter;

  @Configuration
  @Order(-1)
  public class TokenWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsFilter corsFilter;

    @Autowired
    private OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("authenticationTimeStamper")
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private MultiUrlRequestMatcher multiUrlRequestMatcher;

    @Autowired
    private JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider;

    @Autowired
    private OAuth2AccessDeniedHandler oauth2AccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http.antMatcher("/token")
              .authorizeRequests()
                  .antMatchers(HttpMethod.OPTIONS).permitAll()
                  .anyRequest().authenticated()
                  .and()
              .sessionManagement()
                  .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                  .and()
                  .httpBasic()
                  .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                  .and()
              .addFilterAfter(jwtBearerClientAssertionTokenEndpointFilter,
                  AbstractPreAuthenticatedProcessingFilter.class)
              .addFilterAfter(clientCredentialsTokenEndpointFilter(),
                  BasicAuthenticationFilter.class)
              .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
              .exceptionHandling()
                  .accessDeniedHandler(oauth2AccessDeniedHandler)
                  .and()
              .csrf()
                  .disable();
      // @formatter:on
    }

    @Bean
    public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter()
        throws Exception {
      var cctef = new ClientCredentialsTokenEndpointFilter();
      cctef.setAuthenticationManager(authenticationManagerBean());
      cctef.setRequiresAuthenticationRequestMatcher(multiUrlRequestMatcher);

      return cctef;
    }
  }

  @Configuration
  @Order(1)
  public class ApiWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .antMatcher("/api/**")
//              .authorizeRequests()
//                  .anyRequest().authenticated()
//                  .expressionHandler(new OAuth2WebSecurityExpressionHandler())
//                  .and()
              .csrf()
                  .disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(2)
  public class WellKnownSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .antMatcher("/.well-known/**")
              .authorizeRequests()
                  .anyRequest().permitAll()
                  .and()
              .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
              .csrf()
                  .disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(3)
  public class JwkSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .antMatcher("/jwk/**")
              .authorizeRequests()
                  .anyRequest().permitAll()
                  .and()
              .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
              .csrf()
                  .disable();
      // @formatter:on
    }
  }

  @Configuration
  @Order(4)
  public class DeviceWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .antMatcher("/devicecode/**")
              .httpBasic()
                  .authenticationEntryPoint(oauthAuthenticationEntryPoint)
                  .and()
              .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
              .addFilterAfter(jwtBearerClientAssertionTokenEndpointFilter,
                  AbstractPreAuthenticatedProcessingFilter.class)
              .addFilterAfter(clientCredentialsTokenEndpointFilter,
                  BasicAuthenticationFilter.class)
              .csrf()
                  .disable();
      // @formatter:on
    }
  }

  @Configuration
  public static class AuthorizeWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    @Qualifier("authenticationTimeStamper")
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthorizationRequestFilter authorizationRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      // @formatter:off
      auth.jdbcAuthentication()
          .passwordEncoder(new BCryptPasswordEncoder())
          .dataSource(dataSource);
      // @formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http.authorizeRequests()
              .antMatchers("/authorize").hasAnyRole("USER")
              .anyRequest().permitAll()
              .expressionHandler(new OAuth2WebSecurityExpressionHandler())
              .and()
          .formLogin()
              .loginPage("/login")
              .failureUrl("/login?error=failure")
              .successHandler(authenticationSuccessHandler)
              .permitAll()
              .and()
          .logout()
              .logoutUrl("/logout")
              .permitAll()
              .and()
          .addFilterAfter(authorizationRequestFilter, SecurityContextPersistenceFilter.class)
          .anonymous()
              .and()
          .csrf()
              .and()
          .headers()
              .frameOptions().deny();
      // @formatter:on
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
      web.ignoring().antMatchers("/resources/**");
      web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**");
    }
  }
}
