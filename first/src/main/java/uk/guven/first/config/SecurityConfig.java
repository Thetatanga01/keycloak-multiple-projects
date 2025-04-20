package uk.guven.first.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                // Public endpoints
                .requestMatchers("/api/public/**", "/", "/error").permitAll()
                // Login related endpoints
                .requestMatchers("/login", "/oauth2/**", "/login/oauth2/code/*").permitAll()
                // Protected endpoints
                .requestMatchers("/api/admin/**").hasAnyRole("default-roles-sample_app_realm", "admin")
                .requestMatchers("/api/user/**").authenticated()
                .requestMatchers("/api/resources/**").authenticated()
                .anyRequest().authenticated()
            )
            // API için Resource Server
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            // Tarayıcı için OAuth2 Login (SSO)
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/api/user")
            );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtRoleConverter());
        return jwtAuthenticationConverter;
    }
}
