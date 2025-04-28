package uk.guven.second.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")

public class ApiController {

    @Value("${other.url}")
    private String otherUrl;

    @GetMapping(value = "/public", produces = MediaType.TEXT_HTML_VALUE)
    public String publicEndpointHtml() {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>Public Endpoint</title>");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }");
        html.append("h1 { color: #2c3e50; }");
        html.append("p { font-size: 16px; line-height: 1.6; }");
        html.append(".card { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-top: 20px; }");
        html.append(".btn { color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; margin-top: 20px; }");
        html.append(".login-btn { background-color: #2ecc71; }");
        html.append(".login-btn:hover { background-color: #27ae60; }");
        html.append("</style></head><body>");

        html.append("<h1>Herkese Açık Sayfa</h1>");
        html.append("<div class=\"card\">");
        html.append("<p>public sayfa, herkes erişebilir.</p>");
        html.append("</div>");

        // Login butonunu ekle
        html.append("<a href=\"/login\"><button class=\"btn login-btn\">Giriş Yap</button></a>");

        html.append("</body></html>");
        return html.toString();
    }

    // JSON isteyen client'lar için orijinal metodu da tutalım
    @GetMapping(value = "/public", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "public endpoint. Herkes erişebilir.");
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }


    @GetMapping(value = "/user", produces = MediaType.TEXT_HTML_VALUE)
    public String userEndpointHtml(Authentication authentication) {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>Kullanıcı Bilgileri</title>");
        html.append("<style>");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }");
        html.append("h1 { color: #2c3e50; }");
        html.append("h2 { color: #3498db; margin-top: 20px; }");
        html.append("pre { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }");
        html.append("ul { background-color: #f8f9fa; padding: 15px; border-radius: 5px; list-style-type: disc; margin-left: 20px; }");
        html.append("li { margin-bottom: 5px; }");
        html.append(".btn { color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; margin-top: 20px; }");
        html.append(".logout-btn { background-color: #e74c3c; }");
        html.append(".navigate-btn { background-color: #6987ff; }");
        html.append(".logout-btn:hover { background-color: #c0392b; }");
        html.append(".navigate-btn:hover { background-color: #4965d0; }");
        html.append("</style>");

        html.append("<h1>Second App > Kullanıcı Bilgileri</h1>");
        html.append("<p>Hoş geldiniz, <strong>").append(authentication.getName()).append("</strong>!</p>");

        // Kullanıcı rolleri bölümünü ekle
        html.append("<h2>Kullanıcı Rolleri</h2>");
        html.append("<ul>");

        // Tüm yetkileri ve grupları göster
        authentication.getAuthorities().forEach(authority -> {
            String authorityName = authority.getAuthority();

            // Grup mu yoksa rol mü olduğunu kontrol et ve farklı şekilde göster
            if (authorityName.startsWith("GROUP_")) {
                html.append("<li><strong>AD Grubu:</strong> ").append(authorityName.substring(6)).append("</li>");
            } else if (authorityName.startsWith("STOCK_")) {
                html.append("<li><strong>Keycloak Rolü:</strong> ").append(authorityName.substring(6)).append("</li>");
            } else {
                html.append("<li><strong>Diğer Yetki:</strong> ").append(authorityName).append("</li>");
            }
        });
        html.append("</ul>");

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

            // Realm Access bilgilerini ekle
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                html.append("\nRealm Roles: ").append(realmAccess.get("roles")).append("\n");
            }

            // Resource Access bilgilerini ekle
            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                html.append("\nResource Access: ").append(resourceAccess).append("\n");
            }
        }
        // OAuth2 User ise OIDC bilgilerini ekle
        else if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            html.append("\nOAuth2 User Attributes:\n");
            oauth2User.getAttributes().forEach((key, value) ->
                html.append(key).append(": ").append(value).append("\n")
            );

            // OidcUser ise ID Token bilgilerini göster
            if (authentication.getPrincipal() instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

                html.append("\nRaw ID Token Claims:\n");
                html.append(oidcUser.getIdToken().getClaims());

                // Realm Access'i özel olarak ekle (varsa)
                Map<String, Object> claims = oidcUser.getIdToken().getClaims();
                if (claims.containsKey("realm_access")) {
                    Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
                    if (realmAccess != null && realmAccess.containsKey("roles")) {
                        html.append("\nRealm Roles (from ID Token): ").append(realmAccess.get("roles")).append("\n");
                    }
                }
            }
        }

        html.append("</pre>");

        //navigate butonunu ekle
        html.append("<a href=\"" + otherUrl + "/api/user\">" +
                "<button class=\"btn navigate-btn\">First App'e git</button></a>");

        html.append("&nbsp;"); // Boşluk ekle
        // Logout butonunu ekle
        html.append("<a href=\"/api/auth/logout\"><button class=\"btn logout-btn\">Çıkış Yap</button></a>");

        html.append("</body></html>");
        return html.toString();
    }

    @GetMapping(value = "/user", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> userEndpoint(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();

        // Temel bilgiler
        response.put("message", "Bu bir kullanıcı endpoint'idir. Başarıyla erişildi.");
        response.put("username", authentication.getName());
        response.put("principal_type", authentication.getPrincipal().getClass().getName());

        // Yetkileri ekle
        response.put("authorities", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));

        // JWT veya OAuth2 spesifik bilgileri ekle
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            Map<String, Object> jwtInfo = new HashMap<>();
            jwtInfo.put("subject", jwt.getSubject());
            jwtInfo.put("issuer", jwt.getIssuer().toString());
            jwtInfo.put("issuedAt", jwt.getIssuedAt());
            jwtInfo.put("expiresAt", jwt.getExpiresAt());
            jwtInfo.put("email", jwt.getClaimAsString("email"));

            // JWT'den realm_access bilgilerini ekle
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                jwtInfo.put("realm_roles", realmAccess.get("roles"));
            }

            // JWT'den resource_access bilgilerini ekle
            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                jwtInfo.put("resource_access", resourceAccess);
            }

            response.put("jwt_details", jwtInfo);
        }
        // OAuth2 User bilgilerini ekle
        else if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            response.put("oauth2_attributes", oauth2User.getAttributes());
            response.put("email", oauth2User.getAttribute("email"));

            // OidcUser ise
            if (authentication.getPrincipal() instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
                Map<String, Object> idTokenClaims = new HashMap<>(oidcUser.getIdToken().getClaims());

                // Realm rolleri için özel işleme
                if (idTokenClaims.containsKey("realm_access")) {
                    Map<String, Object> realmAccess = (Map<String, Object>) idTokenClaims.get("realm_access");
                    response.put("realm_roles", realmAccess.get("roles"));
                }

                response.put("id_token_claims", idTokenClaims);
            }
        }

        // Sunucu bilgilerini ekle
        Map<String, String> links = new HashMap<>();
        links.put("second_app", "http://localhost:8080/api/user");
        links.put("logout", "/api/auth/logout");
        response.put("links", links);

        response.put("status", "success");
        return ResponseEntity.ok(response);
    }


    // ApiController'da navigate metoduna logout linki ekleyin
    @GetMapping(value = "/navigate", produces = MediaType.TEXT_HTML_VALUE)
    public String navigateEndpoint() {
        return "<html>" +
            "<head><title>API Navigation</title></head>" +
            "<body>" +
            "<a href=\"http://localhost:8080/api/user\">Go to First App's User Endpoint</a><br>" +
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
