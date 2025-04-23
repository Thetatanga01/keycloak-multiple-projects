package uk.guven.first.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class KeycloakService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String keycloakIssuerUri;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Keycloak'tan token alır
     */
    public Map<String, Object> getToken(String username, String password, String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("username", username);
        map.add("password", password);
        map.add("grant_type", "password");
        map.add("client_id", clientId);

        // Eğer client_secret gerekiyorsa
        if (clientSecret != null && !clientSecret.isEmpty()) {
            map.add("client_secret", clientSecret);
        }

        String tokenEndpoint = keycloakIssuerUri + "/protocol/openid-connect/token";

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            tokenEndpoint,
            request,
            Map.class
        );

        return response.getBody();
    }

    /**
     * Token'ı doğrular ve içeriğini alır
     */
    public Map<String, Object> introspectToken(String token, String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("token", token);
        map.add("client_id", clientId);

        // Eğer client_secret gerekiyorsa
        if (clientSecret != null && !clientSecret.isEmpty()) {
            map.add("client_secret", clientSecret);
        }

        String introspectEndpoint = keycloakIssuerUri + "/protocol/openid-connect/token/introspect";

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            introspectEndpoint,
            request,
            Map.class
        );

        return response.getBody();
    }

    /**
     * Token'ı yeniler
     */
    public Map<String, Object> refreshToken(String refreshToken, String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("refresh_token", refreshToken);
        map.add("grant_type", "refresh_token");
        map.add("client_id", clientId);

        // Eğer client_secret gerekiyorsa
        if (clientSecret != null && !clientSecret.isEmpty()) {
            map.add("client_secret", clientSecret);
        }

        String tokenEndpoint = keycloakIssuerUri + "/protocol/openid-connect/token";

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
            tokenEndpoint,
            request,
            Map.class
        );

        return response.getBody();
    }

    /**
     * Keycloak oturumunu sonlandırır
     */
    public Map<String, Object> logout(String idToken, String clientId, String clientSecret) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("id_token_hint", idToken);
            map.add("client_id", clientId);

            // Eğer client_secret gerekiyorsa
            if (clientSecret != null && !clientSecret.isEmpty()) {
                map.add("client_secret", clientSecret);
            }

            String logoutEndpoint = keycloakIssuerUri + "/protocol/openid-connect/logout";
            System.out.println("Keycloak logout endpoint: " + logoutEndpoint);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            try {
                ResponseEntity<Map> response = restTemplate.postForEntity(
                    logoutEndpoint,
                    request,
                    Map.class
                );

                Map<String, Object> result = new HashMap<>();
                result.put("status", "success");
                result.put("response_code", response.getStatusCodeValue());

                if (response.getBody() != null) {
                    result.put("body", response.getBody());
                }

                return result;
            } catch (Exception e) {
                System.err.println("Keycloak logout error: " + e.getMessage());
                e.printStackTrace();

                return Map.of(
                    "status", "error",
                    "message", "Logout request failed: " + e.getMessage()
                );
            }
        } catch (Exception e) {
            System.err.println("Genel hata: " + e.getMessage());
            e.printStackTrace();
            return Map.of(
                "status", "error",
                "message", "General error: " + e.getMessage()
            );
        }
    }
}
