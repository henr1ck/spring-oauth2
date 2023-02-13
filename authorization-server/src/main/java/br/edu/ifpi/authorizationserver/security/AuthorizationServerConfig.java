package br.edu.ifpi.authorizationserver.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.filter.OrderedRequestContextFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final BCryptPasswordEncoder bCrypt;
    private final UserDetailsService userDetailsService;

    @Bean
    @Order(OrderedRequestContextFilter.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerFilter(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder()
                .issuer("http://auth-server:8080")
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        RegisteredClient xptoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("xpto")
                .clientSecret(bCrypt.encode("123"))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("xpto.read")
                .scope("xpto.write")
                .redirectUri("http://auth-server:8080/authorized")
                .build();

        RegisteredClient gameClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("game")
                .clientSecret(bCrypt.encode("123"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .scope("game.read")
                .scope("game.write")
                .redirectUri("http://auth-server:8080/authorized")
                .build();

        return new InMemoryRegisteredClientRepository(List.of(xptoClient, gameClient));
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException, JOSEException {
        KeyStore rsaKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        rsaKeyStore.load(new ClassPathResource("keystore/authserver.jks").getInputStream(), "123456".toCharArray());

        RSAKey rsaKey = RSAKey.load(rsaKeyStore, "game", "123456".toCharArray());
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(){
        return context -> {
            OAuth2Authorization authorization = context.getAuthorization();
            if(context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) && authorization != null){
                UserDetails userDetails = userDetailsService.loadUserByUsername(authorization.getPrincipalName());
                List<String> authorities = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());

                context.getClaims().claim("authorities", authorities);

                Set<String> scopes = context.getAuthorizedScopes();
                context.getClaims().claim("scope", scopes);
            }
        };
    }
}
