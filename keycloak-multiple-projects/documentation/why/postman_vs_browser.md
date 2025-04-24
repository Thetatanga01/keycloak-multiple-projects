# Browser ve Postman Arasındaki Fark

Browser ve Postman arasındaki fark, kullandıkları OAuth2/OIDC akışlarından kaynaklanıyor. Roller ve yetkilerle ilgili sorunun temelinde bu farklılık var.

## Browser ile Login (Authorization Code Flow)

Tarayıcıda login olduğunuzda:

- **Akış Türü**: Authorization Code Flow kullanılır
- **Token Türü**: ID Token ve Access Token alınır
- **Kullanıcı Bilgisi**: OAuth2User veya OidcUser nesnesi içinde tutulur
- **Roller**: Otomatik olarak rol bilgisi çıkarılmayabilir

## Postman ile Login (Resource Owner Password Flow)

Postman'de `/api/auth/token` endpoint'ini kullandığınızda:

- **Akış Türü**: Resource Owner Password Flow kullanılır
- **Token Türü**: Doğrudan JWT Access Token alınır
- **Kullanıcı Bilgisi**: JWT içinde tüm claim'ler bulunur
- **Roller**: JWT içinde `realm_access.roles` altında tam olarak bulunur
