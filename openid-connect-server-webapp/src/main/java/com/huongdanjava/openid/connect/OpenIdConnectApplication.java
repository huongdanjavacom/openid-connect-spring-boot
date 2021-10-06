package com.huongdanjava.openid.connect;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.eclipse.persistence.config.PersistenceUnitProperties;
import org.eclipse.persistence.jpa.PersistenceProvider;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.jwt.assertion.impl.NullAssertionValidator;
import org.mitre.jwt.assertion.impl.WhitelistedIssuerAssertionValidator;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.config.UIConfiguration;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.transaction.TransactionManager;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

@SuppressWarnings("deprecation")
@SpringBootApplication(scanBasePackages = {"org.mitre", "com.huongdanjava"})
public class OpenIdConnectApplication {

  @SuppressWarnings("resource")
  public static void main(String[] args) {
    SpringApplication.run(OpenIdConnectApplication.class, args);
  }

  @Bean("entityManagerFactory")
  public LocalContainerEntityManagerFactoryBean localContainerEntityManagerFactory(
      JpaVendorAdapter jpaVendorAdapter, DataSource dataSource) {
    var factory = new LocalContainerEntityManagerFactoryBean();
    factory.setPackagesToScan("org.mitre");
    factory.setPersistenceProviderClass(PersistenceProvider.class);
    factory.setDataSource(dataSource);
    factory.setJpaVendorAdapter(jpaVendorAdapter);
    factory.setJpaPropertyMap(initJpaProperties());
    factory.setPersistenceUnitName("defaultPersistenceUnit");

    return factory;
  }

  @Bean
  public JpaVendorAdapter jpaVendorAdapter() {
    var adapter = new EclipseLinkJpaVendorAdapter();
    adapter.setDatabasePlatform("org.eclipse.persistence.platform.database.PostgreSQLPlatform");
    adapter.setShowSql(true);

    return adapter;
  }

  private static Map<String, ?> initJpaProperties() {
    final Map<String, Object> map = new HashMap<>();
    map.put(PersistenceUnitProperties.WEAVING, "false");
    map.put(PersistenceUnitProperties.LOGGING_LEVEL, "INFO");
    map.put("eclipselink.logging.level.sql", "INFO");
    map.put(PersistenceUnitProperties.CACHE_SHARED_DEFAULT, "false");

    return map;
  }

  @Bean("defaultTransactionManager")
  public TransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
    return new JpaTransactionManager(entityManagerFactory);
  }

  @Bean
  public DefaultJWTEncryptionAndDecryptionService defaultJWTEncryptionAndDecryptionService(
      JWKSetKeyStore defaultKeyStore)
      throws JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
    var defaultJWTEncryptionAndDecryptionService =
        new DefaultJWTEncryptionAndDecryptionService(defaultKeyStore);
    defaultJWTEncryptionAndDecryptionService.setDefaultAlgorithm(JWEAlgorithm.RSA1_5);
    defaultJWTEncryptionAndDecryptionService.setDefaultDecryptionKeyId(JWKSetKeyStore.KEY_ID);
    defaultJWTEncryptionAndDecryptionService.setDefaultEncryptionKeyId(JWKSetKeyStore.KEY_ID);

    return defaultJWTEncryptionAndDecryptionService;
  }

  @Bean
  public JWKSetKeyStore jwkSetKeyStore() {
    var jwkSetKeyStore = new JWKSetKeyStore();
    jwkSetKeyStore.setLocation(new ClassPathResource("keystore.jwks"));

    return jwkSetKeyStore;
  }

  @Bean
  public DefaultJWTSigningAndValidationService defaultJWTSigningAndValidationService(
      JWKSetKeyStore defaultKeyStore) throws NoSuchAlgorithmException, InvalidKeySpecException {
    var defaultJWTSigningAndValidationService =
        new DefaultJWTSigningAndValidationService(defaultKeyStore);
    defaultJWTSigningAndValidationService.setDefaultSignerKeyId(JWKSetKeyStore.KEY_ID);
    defaultJWTSigningAndValidationService
        .setDefaultSigningAlgorithmName(JWSAlgorithm.RS256.getName());

    return defaultJWTSigningAndValidationService;
  }

  @Bean
  public AssertionValidator jwtAssertionValidator() {
    return new NullAssertionValidator();
  }

  @Bean
  public AssertionValidator clientAssertionValidator() {
    return new WhitelistedIssuerAssertionValidator();
  }

  @SuppressWarnings("rawtypes")
  @Bean
  public WebResponseExceptionTranslator webResponseExceptionTranslator() {
    return new DefaultWebResponseExceptionTranslator();
  }

  @Bean
  public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
    var oauth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
    oauth2AuthenticationEntryPoint.setRealmName("openidconnect");

    return oauth2AuthenticationEntryPoint;
  }

  @Bean
  public MultiUrlRequestMatcher multiUrlRequestMatcher() {
    Set<String> filterProcessesUrls = new HashSet<>();
    filterProcessesUrls.add("/introspect");
    filterProcessesUrls.add("/revoke");
    filterProcessesUrls.add("/token");

    return new MultiUrlRequestMatcher(filterProcessesUrls);
  }

  @Bean
  public JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider() {
    return new JWTBearerAuthenticationProvider();
  }

  @Bean
  public OAuth2AccessDeniedHandler oauth2AccessDeniedHandler() {
    return new OAuth2AccessDeniedHandler();
  }

  @Bean
  public LocaleResolver localeResolver() {
    return new CookieLocaleResolver();
  }

  @Bean
  public LocaleChangeInterceptor localeChangeInterceptor() {
    LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
    lci.setParamName("lang");

    return lci;
  }

  @Bean
  public MessageSource messageSource() {
    ReloadableResourceBundleMessageSource messageSource =
        new ReloadableResourceBundleMessageSource();
    messageSource.setBasename("classpath:i18n/messages");
    messageSource.setDefaultEncoding("UTF-8");

    return messageSource;
  }

  @Bean
  public JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter(
      JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider,
      MultiUrlRequestMatcher multiUrlRequestMatcher) {
    var jwtbcatef = new JWTBearerClientAssertionTokenEndpointFilter(multiUrlRequestMatcher);
    jwtbcatef.setAuthenticationManager(
        new ProviderManager(Arrays.asList(jwtBearerAuthenticationProvider)));

    return jwtbcatef;
  }

  @Bean
  public ConfigurationPropertiesBean configurationPropertiesBean() {
    ConfigurationPropertiesBean configurationPropertiesBean = new ConfigurationPropertiesBean();
    configurationPropertiesBean.setTopbarTitle("OpenID Connect Server");

    return configurationPropertiesBean;
  }

  @Bean
  public UIConfiguration uiConfiguration() {
    UIConfiguration uiConfiguration = new UIConfiguration();

    Set<String> jsFiles = new HashSet<>();
    jsFiles.add("resources/js/client.js");
    jsFiles.add("resources/js/grant.js");
    jsFiles.add("resources/js/scope.js");
    jsFiles.add("resources/js/whitelist.js");
    jsFiles.add("resources/js/dynreg.js");
    jsFiles.add("resources/js/rsreg.js");
    jsFiles.add("resources/js/token.js");
    jsFiles.add("resources/js/blacklist.js");
    jsFiles.add("resources/js/profile.js");
    uiConfiguration.setJsFiles(jsFiles);

    return uiConfiguration;
  }
}
