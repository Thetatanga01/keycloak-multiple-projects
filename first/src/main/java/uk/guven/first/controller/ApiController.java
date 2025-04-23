package uk.guven.first.controller;
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

    // ApiController içinde user endpoint'i için HTML çıktı ekleme
    @GetMapping(value = "/user", produces = MediaType.TEXT_HTML_VALUE)
    public String userEndpointHtml(Authentication authentication) {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>Kullanıcı Bilgileri</title>");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }");
        html.append("h1 { color: #2c3e50; }");
        html.append("pre { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }");
        html.append(".btn { color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; margin-top: 20px; }");
        html.append(".logout-btn { background-color: #e74c3c; }");
        html.append(".navigate-btn { background-color: #6987ff; }");
        html.append(".logout-btn:hover { background-color: #c0392b; }");
        html.append(".navigate-btn:hover { background-color: #4965d0; }");
        html.append("</style>");

        html.append("<h1>Kullanıcı Bilgileri</h1>");
        html.append("<p>Hoş geldiniz, <strong>").append(authentication.getName()).append("</strong>!</p>");

        html.append("<h2>Kimlik Doğrulama Detayları</h2>");
        html.append("<pre>");

        // Authentication bilgilerini ekle
        html.append("Principal Type: ").append(authentication.getPrincipal().getClass().getName()).append("\n");
        html.append("Authorities: ").append(authentication.getAuthorities()).append("\n");

        // Eğer JWT ise JWT bilgilerini ekle
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            html.append("\nJWT Claims:\n");
            html.append("Subject: ").append(jwt.getSubject()).append("\n");
            html.append("Issued At: ").append(jwt.getIssuedAt()).append("\n");
            html.append("Expires At: ").append(jwt.getExpiresAt()).append("\n");
            html.append("Email: ").append(jwt.getClaimAsString("email")).append("\n");
        }
        // OAuth2 User ise OIDC bilgilerini ekle
        else if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            html.append("\nOAuth2 User Attributes:\n");
            oauth2User.getAttributes().forEach((key, value) ->
                html.append(key).append(": ").append(value).append("\n")
            );
        }

        html.append("</pre>");

        //navigate butonunu ekle
        html.append("<a href=\"http://localhost:9090/api/user\"><button class=\"navigate-btn\">Second App'e git </button></a>");

        html.append("&nbsp;"); // Boşluk ekle
        // Logout butonunu ekle
        html.append("<a href=\"/api/auth/logout\"><button class=\"logout-btn\">Çıkış Yap</button></a>");

        html.append("</body></html>");
        return html.toString();
    }

    // ApiController'da navigate metoduna logout linki ekleyin
    @GetMapping(value = "/navigate", produces = MediaType.TEXT_HTML_VALUE)
    public String navigateEndpoint() {
        return "<html>" +
            "<head><title>API Navigation</title></head>" +
            "<body>" +
            "<a href=\"http://localhost:9090/api/user\">Go to Second App's User Endpoint</a><br>" +
            "<a href=\"/api/auth/logout\">Logout</a>" +
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

    // ApiController içinde
    @GetMapping("/whoami")
    public ResponseEntity<Map<String, Object>> whoAmI(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        response.put("details", authentication.getDetails());
        response.put("authenticated", authentication.isAuthenticated());

        return ResponseEntity.ok(response);
    }
}
