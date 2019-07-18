package org.camunda.bpm.extension.keycloak.showcase.sso;

import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.camunda.bpm.engine.impl.identity.IdentityProviderException;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.web.context.request.RequestContextListener;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

/**
 * Camunda Web application SSO configuration for usage with Auth0IdentityProviderPlugin.
 */
@ConditionalOnMissingClass("org.springframework.test.context.junit4.SpringJUnit4ClassRunner")
@Configuration
@EnableOAuth2Sso
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Re using pool size config property instead of introducing new one.
     * pool size * 10 = approximate number of concurrent login attempts allowed
     */
    @Value("spring.task.execution.pool.core-size")
    Integer connectionToAuthServerSize;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf().ignoringAntMatchers("/api/**")
                .and()
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/app/**")
                .authenticated()
                .anyRequest()
                .permitAll()
        ;

    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Bean
    public FilterRegistrationBean containerBasedAuthenticationFilter() {
        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
        filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider"
                , "org.camunda.bpm.extension.keycloak.showcase.sso.KeycloakAuthenticationProvider"));
        filterRegistration.setOrder(101); // make sure the filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/app/*");
        return filterRegistration;
    }

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }


    /**
     * Oauth2RestTemplate should propagate its requestFactory, messageConverters and interceptors
     * to its accessTokenProvider
     * https://github.com/spring-projects/spring-security-oauth/issues/459
     *
     * @return UserInfoRestTemplateCustomizer with disabled SSl verification to allow self signed /custom CA certs
     */
    @Bean
    public UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer() {
        return template -> {
            AuthorizationCodeAccessTokenProvider authProvider = new AuthorizationCodeAccessTokenProvider();
            authProvider.setRequestFactory(ignoreSSLVerificationFactory());
            ImplicitAccessTokenProvider implicitProvider = new ImplicitAccessTokenProvider();
            implicitProvider.setRequestFactory(ignoreSSLVerificationFactory());
            ResourceOwnerPasswordAccessTokenProvider passwordProvider = new ResourceOwnerPasswordAccessTokenProvider();
            passwordProvider.setRequestFactory(ignoreSSLVerificationFactory());
            ClientCredentialsAccessTokenProvider credentialProvider = new ClientCredentialsAccessTokenProvider();
            credentialProvider.setRequestFactory(ignoreSSLVerificationFactory());
            AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
                    authProvider, implicitProvider, passwordProvider, credentialProvider));
            template.setAccessTokenProvider(accessTokenProvider);
            template.setRequestFactory(ignoreSSLVerificationFactory());
        };
    }

    /**
     * Enable if JWT acquisition / renewal to keycloack is failing due to SSL cert trust issues
     *
     * @Bean public JwtAccessTokenConverterRestTemplateCustomizer jwtAccessTokenConverterRestTemplateCustomizer() {
     * return template -> {
     * template.setRequestFactory(ignoreSSLVerificationFactory());
     * };
     * }
     **/

    private HttpComponentsClientHttpRequestFactory ignoreSSLVerificationFactory() {
        // Create REST template with pooling HTTP client
        final HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        HttpClientBuilder httpClient = HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy());
        try {
            Registry<ConnectionSocketFactory> socketFactory = RegistryBuilder
                    .<ConnectionSocketFactory>create().register("https", new SSLConnectionSocketFactory(
                            org.apache.http.ssl.SSLContexts.custom()
                                    .loadTrustMaterial(null,
                                            (X509Certificate[] chain, String authType) -> true).build()
                            , new NoopHostnameVerifier())).build();
            final PoolingHttpClientConnectionManager pool = new PoolingHttpClientConnectionManager(socketFactory);
            pool.setMaxTotal(connectionToAuthServerSize);
            httpClient.setConnectionManager(pool);
        } catch (GeneralSecurityException e) {
            throw new IdentityProviderException("Disabling SSL certificate validation failed", e);
        }
        factory.setHttpClient(httpClient.build());
        return factory;
    }
}