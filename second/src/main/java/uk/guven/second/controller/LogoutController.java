package uk.guven.second.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;
import uk.guven.second.service.KeycloakService;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/api/auth")
public class LogoutController {

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret:}")
    private String clientSecret;

    @Value("${app.keycloak-logout-uri:https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/logout}")
    private String keycloakLogoutUri;

    @Value("${app.redirect-after-logout-uri:http://localhost:8080/api/public}")
    private String redirectAfterLogoutUri;

    private final KeycloakService keycloakService;

    public LogoutController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    /**
     * Hem yerel hem de Keycloak oturumunu sonlandırır
     */
    @GetMapping("/logout")
    public RedirectView logout(HttpServletRequest request, HttpServletResponse response) {
        // Yerel oturumu sonlandır
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String idToken = null;

        // ID token'ı almaya çalış
        if (auth != null) {
            // OIDC kullanıcısı için
            if (auth instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;
                if (oauthToken.getPrincipal() instanceof OidcUser) {
                    OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
                    idToken = oidcUser.getIdToken().getTokenValue();
                    System.out.println("ID Token bulundu: " + (idToken != null));
                }
            }

            // Oturumu sonlandır
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }

        // Keycloak oturumunu sonlandır
        if (idToken != null) {
            // Keycloak logout'a doğrudan yönlendir
            String logoutUrl = keycloakLogoutUri +
                "?id_token_hint=" + idToken +
                "&client_id=" + clientId +
                "&post_logout_redirect_uri=" + redirectAfterLogoutUri;

            System.out.println("Keycloak Logout URL: " + logoutUrl);
            return new RedirectView(logoutUrl);
        }

        // ID token alınamazsa doğrudan redirectAfterLogoutUri'ye yönlendir
        return new RedirectView(redirectAfterLogoutUri);
    }

    /**
     * API kullanıcıları için logout endpoint'i
     */
    @PostMapping("/logout")
    @ResponseBody
    public Map<String, Object> logoutApi(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Yerel oturumu sonlandır
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String idToken = null;

            if (auth != null) {
                // OIDC kullanıcısı için
                if (auth instanceof OAuth2AuthenticationToken) {
                    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) auth;
                    if (oauthToken.getPrincipal() instanceof OidcUser) {
                        OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
                        idToken = oidcUser.getIdToken().getTokenValue();
                    }
                }

                new SecurityContextLogoutHandler().logout(request, response, auth);
                result.put("local_logout", "success");
            } else {
                result.put("local_logout", "not_authenticated");
            }

            // Keycloak oturumunu sonlandır
            if (idToken != null) {
                Map<String, Object> keycloakResponse = keycloakService.logout(idToken, clientId, clientSecret);
                result.put("keycloak_logout", keycloakResponse);
            } else {
                result.put("keycloak_logout", "no_id_token");
            }

            result.put("status", "success");
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
            e.printStackTrace();
        }

        return result;
    }
}
