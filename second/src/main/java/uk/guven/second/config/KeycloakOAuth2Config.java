package uk.guven.second.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Configuration
public class KeycloakOAuth2Config {

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // Standart OidcUser'ı al
            OidcUser oidcUser = delegate.loadUser(userRequest);

            // Keycloak'tan gelen rolleri çıkar ve GrantedAuthority'lere dönüştür
            Collection<GrantedAuthority> mappedAuthorities = extractKeycloakAuthorities(oidcUser);

            // Orijinal yetkilere Keycloak'tan gelen rolleri ekle
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(oidcUser.getAuthorities());
            authorities.addAll(mappedAuthorities);

            // Yeni yetkilerle birlikte OidcUser oluştur
            return new DefaultOidcUser(
                authorities,
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
            );
        };
    }

    private Collection<GrantedAuthority> extractKeycloakAuthorities(OidcUser oidcUser) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        Map<String, Object> claims = oidcUser.getIdToken().getClaims();

        // Debug: Tüm claim'leri göster
        System.out.println("ID Token Claims: " + claims);

        // Realm rollerini çıkar
        Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
        if (realmAccess != null) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                System.out.println("Realm Roles: " + roles);
                roles.forEach(role ->
                    authorities.add(new SimpleGrantedAuthority(KeycloakJwtRoleConverter.APPENDIX + role))
                );
            }
        }

        // Active Directory gruplarını çıkar (groups claim'i)
        List<String> groups = (List<String>) claims.get("groups");
        if (groups != null && !groups.isEmpty()) {
            System.out.println("User Groups: " + groups);
            groups.forEach(group ->
                authorities.add(new SimpleGrantedAuthority(KeycloakJwtRoleConverter.GROUP_PREFIX + group))
            );
        }

        // Debug için yetkileri yazdır
        System.out.println("Extracted Authorities: " + authorities);

        return authorities;
    }
}
