# OAuth 2.0 Yetkilendirme Akışları

## İçindekiler
- [Resource Owner Password Credentials Flow](#resource-owner-password-credentials-flow)
- [Client Credentials Flow](#client-credentials-flow)
- [Authorization Code Flow](#authorization-code-flow)
- [Referanslar](#referanslar)

## Resource Owner Password Credentials Flow

Resource Owner Password Credentials Flow, kullanıcının kimlik bilgilerini doğrudan uygulama ile paylaştığı bir OAuth 2.0 akışıdır.

### Kullanım Senaryoları
* Birinci taraf uygulamalar (kendi geliştirdiğiniz uygulamalar)
* Güvenilir mobil veya masaüstü uygulamalar
* Üçüncü taraf uygulamaları için ÖNERİLMEZ

### Akış Adımları
1. Kullanıcı, uygulamaya kullanıcı adı ve şifre bilgilerini girer
2. Uygulama bu bilgileri kullanarak OAuth sunucusundan token ister
3. OAuth sunucusu, kullanıcı bilgilerini doğrular ve token döndürür
4. Uygulama, alınan token ile korumalı kaynaklara erişir

### Avantajları
* Basit entegrasyon
* Daha az HTTP isteği
* Yönlendirme gerektirmez

### Dezavantajları
* Güvenlik riski: Uygulama kullanıcı şifresini görür
* Kullanıcı şifresi değiştiğinde token yenilemesi gerekir
* En düşük güvenlikli OAuth akışıdır

### Örnek Yapılandırma
```yaml
# application.properties
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://keycloak.example.com/realms/myrealm
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
```

## Client Credentials Flow

Client Credentials Flow, kullanıcı olmadan, yalnızca istemci kimlik bilgileri ile token alma akışıdır.

### Kullanım Senaryoları
* Servisler arası iletişim
* Arka plan işlemleri
* Kullanıcı bağlamı olmayan API istekleri
* Mikroservis mimarileri

### Akış Adımları
1. İstemci, client_id ve client_secret bilgilerini kullanarak OAuth sunucusundan token ister
2. OAuth sunucusu, istemci bilgilerini doğrular ve token döndürür
3. İstemci, alınan token ile korumalı kaynaklara erişir

### Avantajları
* Basit ve hızlı
* Kullanıcı etkileşimi gerektirmez
* Backend servisler için idealdir

### Dezavantajları
* Kullanıcı bağlamı yoktur
* Client secret güvenli saklanmalıdır

### Örnek Yapılandırma
```yaml
# application.properties
spring.security.oauth2.client.registration.keycloak.client-id=service-client
spring.security.oauth2.client.registration.keycloak.client-secret=service-secret
spring.security.oauth2.client.registration.keycloak.authorization-grant-type=client_credentials
spring.security.oauth2.client.registration.keycloak.scope=openid
spring.security.oauth2.client.provider.keycloak.token-uri=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
```

## Authorization Code Flow

Authorization Code Flow, en güvenli ve en yaygın kullanılan OAuth 2.0 akışıdır.

### Kullanım Senaryoları
* Web uygulamaları
* Mobil uygulamalar
* Single Page Applications (SPA)
* Üçüncü taraf uygulamalar

### Akış Adımları
1. Kullanıcı, uygulamada giriş yapmak ister
2. Uygulama, kullanıcıyı OAuth/OpenID sunucusuna yönlendirir
3. Kullanıcı, OAuth sunucusunda kimlik doğrulama yapar
4. OAuth sunucusu, kullanıcıyı bir yetkilendirme kodu ile uygulamaya geri yönlendirir
5. Uygulama, yetkilendirme kodunu kullanarak token ister
6. OAuth sunucusu, access token, refresh token ve id token (OIDC) döndürür
7. Uygulama, alınan token ile korumalı kaynaklara erişir

### Avantajları
* En güvenli OAuth akışı
* Uygulama kullanıcı kimlik bilgilerini görmez
* Kullanıcı her zaman OAuth/OIDC sunucusuna giriş yapar
* Geniş ölçekte benimsenen standart akış

### Dezavantajları
* Daha karmaşık entegrasyon
* Tarayıcı bazlı yönlendirme gerektirir

### Örnek Yapılandırma
```yaml
# application.properties
spring.security.oauth2.client.registration.keycloak.client-id=web-app
spring.security.oauth2.client.registration.keycloak.client-secret=web-app-secret
spring.security.oauth2.client.registration.keycloak.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.keycloak.scope=openid,profile,email
spring.security.oauth2.client.registration.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}
spring.security.oauth2.client.provider.keycloak.issuer-uri=https://keycloak.example.com/realms/myrealm
spring.security.oauth2.client.provider.keycloak.authorization-uri=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth
spring.security.oauth2.client.provider.keycloak.token-uri=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
spring.security.oauth2.client.provider.keycloak.jwk-set-uri=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
spring.security.oauth2.client.provider.keycloak.user-name-attribute=preferred_username
```

## Referanslar

Daha fazla bilgi için aşağıdaki kaynaklara başvurabilirsiniz:

* [OAuth 2.0 Specification](https://oauth.net/2/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Keycloak Documentation](https://www.keycloak.org/documentation)
* [OAuth 2.0 Simplified](https://www.oauth.com/)
* [OAuth 2.0 for Native and Mobile Apps](https://datatracker.ietf.org/doc/html/rfc8252)
