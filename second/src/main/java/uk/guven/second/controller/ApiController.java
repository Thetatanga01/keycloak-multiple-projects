package uk.guven.second.controller;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")

public class ApiController {

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Bu bir halka açık endpoint'tir. Herkes erişebilir.");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    // @PreAuthorize("hasAnyRole('user')")
    public ResponseEntity<Map<String, Object>> userEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Bu bir kullanıcı endpoint'idir. Başarıyla erişildi.");
        response.put("username", authentication.getName());

        // Authentication bilgilerini ekle
        response.put("principal_type", authentication.getPrincipal().getClass().getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

        // Eğer JWT ise JWT bilgilerini ekle
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            // Debug bilgileri ekleyelim
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                response.put("realm_roles", realmAccess.get("roles"));
            }

            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                response.put("resource_access", resourceAccess);
            }

            response.put("email", jwt.getClaimAsString("email"));
        }
        // OAuth2 User ise OIDC bilgilerini ekle
        else if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            response.put("attributes", oauth2User.getAttributes());
            response.put("email", oauth2User.getAttribute("email"));
        }

        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/navigate", produces = MediaType.TEXT_HTML_VALUE)
    public String navigateEndpoint() {
        return "<html>" +
            "<head><title>API Navigation</title></head>" +
            "<body>" +
            "<a href=\"http://localhost:8080/api/user\">Go to First App's User Endpoint</a>" +
            "</body>" +
            "</html>";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> adminEndpoint(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Bu bir admin endpoint'idir. Başarıyla erişildi.");
        response.put("username", jwt.getClaimAsString("preferred_username"));
        response.put("email", jwt.getClaimAsString("email"));

        // Debug bilgileri ekleyelim
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            response.put("realm_roles", realmAccess.get("roles"));
        }

        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null) {
            response.put("resource_access", resourceAccess);
        }

        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> userInfo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("subject", jwt.getSubject());
        response.put("issuer", jwt.getIssuer().toString());
        response.put("issuedAt", jwt.getIssuedAt());
        response.put("expiresAt", jwt.getExpiresAt());
        response.put("claims", jwt.getClaims());
        return ResponseEntity.ok(response);
    }

    // Test endpoint with role-based authorization
    @GetMapping("/test/{role}")
    public ResponseEntity<Map<String, Object>> testEndpoint(@PathVariable String role, @AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();

        if ("admin".equalsIgnoreCase(role)) {
            if (jwt.getClaimAsStringList("roles").contains("admin")) {
                response.put("message", "Admin rolüne sahipsiniz");
                response.put("authorized", true);
            } else {
                response.put("message", "Admin rolüne sahip değilsiniz");
                response.put("authorized", false);
            }
        } else if ("user".equalsIgnoreCase(role)) {
            if (jwt.getClaimAsStringList("roles").contains("user")) {
                response.put("message", "User rolüne sahipsiniz");
                response.put("authorized", true);
            } else {
                response.put("message", "User rolüne sahip değilsiniz");
                response.put("authorized", false);
            }
        } else {
            response.put("message", "Geçersiz rol: " + role);
            response.put("available_roles", new String[]{"admin", "user"});
        }

        response.put("token_roles", jwt.getClaimAsStringList("roles"));
        return ResponseEntity.ok(response);
    }
}
