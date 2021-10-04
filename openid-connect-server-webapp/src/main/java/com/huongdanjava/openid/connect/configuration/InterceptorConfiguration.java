package com.huongdanjava.openid.connect.configuration;

import java.util.ArrayList;
import java.util.List;
import org.mitre.discovery.web.DiscoveryEndpoint;
import org.mitre.oauth2.web.DeviceEndpoint;
import org.mitre.oauth2.web.IntrospectionEndpoint;
import org.mitre.oauth2.web.RevocationEndpoint;
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint;
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint;
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint;
import org.mitre.openid.connect.web.RootController;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Component
public class InterceptorConfiguration implements WebMvcConfigurer {

  @Autowired
  public UserInfoInterceptor userInfoInterceptor;

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    List<String> excludePathPatterns = new ArrayList<>();
    excludePathPatterns.add(buildPattern("resources"));
    excludePathPatterns.add(buildPattern("token"));
    excludePathPatterns.add(buildPattern(JWKSetPublishingEndpoint.URL));
    excludePathPatterns.add(buildPattern(DiscoveryEndpoint.WELL_KNOWN_URL));
    excludePathPatterns.add(buildPattern(DynamicClientRegistrationEndpoint.URL));
    excludePathPatterns.add(buildPattern(ProtectedResourceRegistrationEndpoint.URL));
    excludePathPatterns.add(buildPattern(UserInfoEndpoint.URL));
    excludePathPatterns.add(buildPattern(RootController.API_URL));
    excludePathPatterns.add(buildPattern(DeviceEndpoint.URL));
    excludePathPatterns.add(buildPattern(IntrospectionEndpoint.URL));
    excludePathPatterns.add(buildPattern(RevocationEndpoint.URL));

    // @formatter:off
    registry.addInterceptor(userInfoInterceptor)
        .addPathPatterns("/**")
        .excludePathPatterns(excludePathPatterns);
    // @formatter:on
  }

  private String buildPattern(String contextPath) {
    return "/" + contextPath + "/**";
  }
}
