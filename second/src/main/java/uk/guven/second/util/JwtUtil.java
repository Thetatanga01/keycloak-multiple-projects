package uk.guven.second.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtil {

    /**
     * Mevcut kimlik doğrulama bağlamından JWT nesnesini alır
     * @return JWT nesnesi veya kimlik doğrulama yoksa null
     */
    public Jwt getJwtFromContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            return (Jwt) authentication.getPrincipal();
        }
        return null;
    }

    /**
     * JWT'den kullanıcı adını alır
     * @return Kullanıcı adı veya JWT yoksa null
     */
    public String getUsername() {
        Jwt jwt = getJwtFromContext();
        if (jwt != null) {
            return jwt.getClaimAsString("preferred_username");
        }
        return null;
    }

    /**
     * JWT'den kullanıcı rollerini alır
     * @return Rol listesi veya JWT yoksa boş liste
     */
    public List<String> getRoles() {
        Jwt jwt = getJwtFromContext();
        if (jwt != null) {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return (List<String>) realmAccess.get("roles");
            }
        }
        return Collections.emptyList();
    }

    /**
     * JWT'den belirli bir claim değerini alır
     * @param claimName Claim adı
     * @return Claim değeri veya JWT yoksa null
     */
    public Object getClaim(String claimName) {
        Jwt jwt = getJwtFromContext();
        if (jwt != null) {
            return jwt.getClaim(claimName);
        }
        return null;
    }

    /**
     * JWT'den tüm claim'leri alır
     * @return Claim'ler map'i veya JWT yoksa boş map
     */
    public Map<String, Object> getAllClaims() {
        Jwt jwt = getJwtFromContext();
        if (jwt != null) {
            return jwt.getClaims();
        }
        return Collections.emptyMap();
    }

    /**
     * Kullanıcının belirli bir role sahip olup olmadığını kontrol eder
     * @param role Kontrol edilecek rol
     * @return Role sahipse true, değilse false
     */
    public boolean hasRole(String role) {
        List<String> roles = getRoles();
        return roles.contains(role);
    }
}
