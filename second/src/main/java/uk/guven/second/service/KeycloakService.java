package uk.guven.second.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class KeycloakService {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String keycloakIssuerUri;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Keycloak'tan token alır
     *
     * @param username Kullanıcı adı
     * @param password Şifre
     * @param clientId Client ID
     * @param clientSecret Client Secret
     * @return Token yanıtı
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
     *
     * @param token Doğrulanacak token
     * @return Token içeriği
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
     *
     * @param refreshToken Yenileme token'ı
     * @param clientId Client ID
     * @param clientSecret Client Secret
     * @return Yeni token yanıtı
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
}
