package uk.guven.second.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import uk.guven.second.service.KeycloakService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final KeycloakService keycloakService;

    public AuthController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    /**
     * Keycloak'tan token alır
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> getToken(
        @RequestParam String username,
        @RequestParam String password,
        @RequestParam String clientId,
        @RequestParam(required = false) String clientSecret) {

        Map<String, Object> tokenResponse = keycloakService.getToken(username, password, clientId, clientSecret);
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Token'ı yeniler
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
        @RequestParam String refreshToken,
        @RequestParam String clientId,
        @RequestParam(required = false) String clientSecret) {

        Map<String, Object> tokenResponse = keycloakService.refreshToken(refreshToken, clientId, clientSecret);
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * Token'ın geçerliliğini kontrol eder
     */
    @PostMapping("/introspect")
    public ResponseEntity<Map<String, Object>> introspectToken(
        @RequestParam String token,
        @RequestParam String clientId,
        @RequestParam(required = false) String clientSecret) {

        Map<String, Object> introspectionResponse = keycloakService.introspectToken(token, clientId, clientSecret);
        return ResponseEntity.ok(introspectionResponse);
    }
}
