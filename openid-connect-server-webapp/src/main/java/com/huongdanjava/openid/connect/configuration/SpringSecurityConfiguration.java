package com.huongdanjava.openid.connect.configuration;

import javax.sql.DataSource;

import org.mitre.openid.connect.filter.AuthorizationRequestFilter;
import org.mitre.openid.connect.web.RootController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    @Qualifier("authenticationTimeStamper")
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private AuthorizationRequestFilter authorizationRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.jdbcAuthentication()
          .passwordEncoder(new BCryptPasswordEncoder())
          .dataSource(dataSource);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/authorize").hasRole("USER")
            .expressionHandler(new OAuth2WebSecurityExpressionHandler());

        http.formLogin()
            .loginPage("/login")
            .failureUrl("/login?error=failure")
            .successHandler(authenticationSuccessHandler);

        http.logout()
            .logoutUrl("/logout");

        http.anonymous();

        http.addFilterAfter(authorizationRequestFilter, SecurityContextPersistenceFilter.class);

        http.headers()
            .frameOptions().deny();


        http.csrf()
            .ignoringAntMatchers("/" + RootController.API_URL + "/**");
    }

}
