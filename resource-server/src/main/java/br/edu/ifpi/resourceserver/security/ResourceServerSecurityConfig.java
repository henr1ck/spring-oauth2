package br.edu.ifpi.resourceserver.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
public class ResourceServerSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .oauth2ResourceServer(configurer -> configurer.jwt().jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authorizeRequests(configurer -> configurer.anyRequest().authenticated());

        return http.httpBasic().and().build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(){
        var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = jwt.getClaimAsStringList("authorities");

            var simpleGrantedAuthorities = Optional.ofNullable(authorities).orElse(Collections.emptyList())
                    .stream().map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            var jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

            var scopesAsGrantedAuthorities = jwtGrantedAuthoritiesConverter.convert(jwt);
            scopesAsGrantedAuthorities.addAll(simpleGrantedAuthorities);

            return scopesAsGrantedAuthorities;
        });
        return jwtAuthenticationConverter;
    }
}
