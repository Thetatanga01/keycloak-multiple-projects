# KeycloakService ve AuthController Sınıflarının Amaçları

## KeycloakService

Bu sınıf, uygulamanızın Keycloak kimlik sağlayıcısıyla doğrudan etkileşim kurmasını sağlayan bir servistir. Temel amaçları:

1. **Token İşlemleri**: Keycloak'ın token endpoint'ine istekler göndererek access token, refresh token ve ID token almanızı sağlar.

2. **Token Doğrulama**: Bir token'ın geçerli olup olmadığını kontrol eder ve içeriğini çözümler (introspection).

3. **Token Yenileme**: Süresi dolmak üzere olan veya dolmuş access token'ları, refresh token kullanarak yeniler.

4. **Logout İşlemi**: Keycloak'ta kullanıcının oturumunu sonlandırır. Bu, sadece yerel uygulamadaki değil, Keycloak SSO oturumunun da sonlandırılmasını sağlar.

Bu sınıf, Spring Security mekanizmasının dışında Keycloak ile doğrudan etkileşim gerektiren durumlar için kullanılır.

## AuthController

Bu controller, `KeycloakService`'i kullanarak kimlik doğrulama ve yetkilendirme ile ilgili HTTP endpoint'leri sunar. Amaçları:

1. **Token Alma Endpoint'i**: Kullanıcıların kullanıcı adı ve parola ile token alabilmelerini sağlar (Resource Owner Password Credentials Grant).

2. **Token Yenileme Endpoint'i**: Kullanıcıların refresh token ile yeni bir access token alabilmelerini sağlar.

3. **Token Doğrulama Endpoint'i**: Bir token'ın geçerli olup olmadığını kontrol etmek için kullanılır.

4. **Logout Endpoint'i**: Kullanıcı oturumunu sonlandırmak için kullanılır.

## Birlikte Faydaları

Bu iki sınıf birlikte, Spring Security'nin standart OAuth2 akışlarının yanı sıra, daha fazla esneklik ve programmatik kontrol sağlayarak:

- API istemcilerinin (mobil uygulamalar, Postman gibi) uygulama ile etkileşim kurmasını kolaylaştırır.
- Token yönetimi ve doğrulaması üzerinde daha fazla kontrol sağlar.
- Tarayıcı tabanlı akışların yanı sıra, doğrudan API tabanlı kimlik doğrulama akışlarını destekler.

Bu sınıflar, özellikle Spring Security'nin sağladığı otomatik OAuth2 entegrasyonunun yetersiz kaldığı veya daha fazla özelleştirme gerektiren durumlar için çok değerlidir.
