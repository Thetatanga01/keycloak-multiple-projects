# Spring Boot Keycloak Entegrasyonu Dokümantasyonu

Bu dokümantasyon, Keycloak ile kimlik doğrulama ve yetkilendirme için entegre edilmiş bir Spring Boot uygulamasına genel bakış sağlar. Uygulama hem Tek Oturum Açma (Single Sign-On, SSO) hem de JWT tabanlı kimlik doğrulamayı göstermektedir.

## Temel Bileşenler

### 1. SecondApplication.java
- `@SpringBootApplication` anotasyonu ile ana uygulama sınıfı
- Spring Boot uygulamasını başlatmak için giriş noktası

### 2. Konfigürasyon Dosyaları

#### application.properties
- Uygulama için tüm yapılandırma ayarlarını içerir
- Keycloak bağlantı ayarları (URL'ler, realm, client ID, secret)
- CORS yapılandırması
- OAuth2/OpenID Connect ayarları
- Loglama yapılandırması
- Oturum kapatma sonrası yönlendirme URL ayarları

#### SecurityConfig.java
- Uygulama için Spring Security'yi yapılandırır
- Güvenlik filtre zinciri ve yetkilendirme kurallarını ayarlar
- JWT kimlik doğrulama ve OAuth2 girişini yapılandırır
- Çapraz kaynak istekleri için CORS yapılandırmasını ayarlar
- Korunan uç noktaları ve herkese açık uç noktaları tanımlar
- Oturum kapatma davranışını yapılandırır

#### KeycloakJwtRoleConverter.java
- Keycloak JWT rollerini Spring Security GrantedAuthority'ye dönüştürür
- Hem realm rollerini hem de istemciye özgü rolleri işler
- Standardizasyon için tüm rollere "SOT_" öneki ekler
- Atanan rolleri günlüğe kaydetmek için hata ayıklama bilgilerini içerir

#### KeycloakOAuth2Config.java
- OIDC (OpenID Connect) kullanıcı işlemeyi özelleştirir
- OIDC tokenlarından Keycloak'a özgü yetkileri çıkarır
- Keycloak rollerini Spring Security yetkilerine eşler

### 3. Yardımcı Sınıflar

#### JwtUtil.java
- JWT tokenleriyle çalışmak için yardımcı metodlar sağlar
- JWT'den kullanıcı adı, roller ve iddiaları (claims) çıkarmak için metodlar
- Rol kontrol işlevselliği sağlar
- Oturum kapatma işlemleri için ID tokenlerinin işlenmesine yardımcı olur

### 4. Servisler

#### KeycloakService.java
- REST API aracılığıyla Keycloak sunucusuyla iletişim kurar
- Token işlemlerini (alma, yenileme, introspection) yönetir
- Oturum kapatma işlemlerini yönetir
- Keycloak uç noktalarına HTTP istekleri yapmak için RestTemplate kullanır

#### ResourceService.java
- Kaynak nesnelerini yöneten basit bir servis
- Kaynaklar için CRUD operasyonları sağlar
- Test için örnek verilerle başlatılır

### 5. Kontrolörler

#### ApiController.java
- Farklı yetkilendirme seviyelerine sahip API uç noktaları içerir
- Hem HTML hem de JSON yanıtları sağlar
- `/api/public` - herkes tarafından erişilebilir
- `/api/user` - kimliği doğrulanmış kullanıcılar tarafından erişilebilir
- `/api/admin` - yalnızca yöneticiler tarafından erişilebilir
- Kullanıcı bilgilerini ve token ayrıntılarını görüntülemek için uç noktalar içerir
- Uygulamalar arasında geçiş yapmak için navigasyon metodu

#### AuthController.java
- Kimlik doğrulamayla ilgili uç noktaları yönetir
- Token alma, yenileme ve doğrulama sağlar
- KeycloakService ile arayüz oluşturur

#### ResourceController.java
- Kaynaklar için RESTful CRUD operasyonları
- `@PreAuthorize` kullanarak rol tabanlı erişim kontrolüne sahip
- Kullanıcı kimliği için JWT kullanır
- Uygun HTTP durum kodları ve yanıtları döndürür

#### LogoutController.java
- Hem yerel hem de Keycloak oturumları için oturum kapatma işlemlerini yönetir
- Tarayıcı tabanlı ve API tabanlı oturum kapatmayı işler
- Oturum kapatma sonrası uygun URL'lere yönlendirir
- Keycloak oturum kapatma için ID token kullanır

#### LoginController.java
- Keycloak giriş sayfasına yönlendiren basit bir kontrolör
- Giriş akışı için giriş noktası

#### HelloController.java
- Temel bir uç noktaya sahip basit bir örnek kontrolör

### 6. Model Sınıfları

#### Resource.java
- Bir kaynak varlığını temsil eden model sınıfı
- id, isim, açıklama, oluşturma tarihi ve oluşturucu gibi alanlar içerir

### 7. İstisna İşleme

#### GlobalExceptionHandler.java
- Uygulama için global istisna işleyici
- Güvenlik istisnalarını (AccessDenied, Authentication) yönetir
- Standartlaştırılmış hata yanıtları sağlar
- HTTP durum kodlarını ve hata mesajlarını özelleştirir

## Kimlik Doğrulama Akışı

1. **SSO Giriş Akışı**:
    - Kullanıcı korunan bir kaynağa erişir
    - Sistem Keycloak giriş sayfasına yönlendirir
    - Başarılı girişten sonra Keycloak yetkilendirme koduyla geri yönlendirir
    - Uygulama kodu tokenlarla değiştirir
    - Kullanıcı OIDC/OAuth2 ile doğrulanır

2. **JWT Kimlik Doğrulama Akışı**:
    - İstemci Keycloak'tan JWT token alır (API üzerinden `/api/auth/token`)
    - Token sonraki isteklere dahil edilir (Authorization header)
    - Spring Security token'ı doğrular ve rolleri çıkarır
    - Erişim roller ve yetkilere göre verilir

3. **Oturum Kapatma Akışı**:
    - Kullanıcı oturum kapatmayı başlatır (UI veya API aracılığıyla)
    - Uygulama yerel oturumu sonlandırır
    - Uygulama Keycloak'a oturum kapatma isteği gönderir
    - Kullanıcı yapılandırılmış oturum kapatma sonrası URL'ye yönlendirilir

## Güvenlik Özellikleri

- Rol tabanlı erişim kontrolü (RBAC)
- JWT token doğrulama
- CORS yapılandırması
- Token introspection (derinlemesine inceleme)
- Özel rol dönüştürme
- Tek Oturum Açma (SSO) desteği
- Düzgün oturum kapatma işleme (hem yerel hem de Keycloak)

## Önemli Entegrasyon Noktaları

1. **Keycloak Kimlik Doğrulama**:
    - API erişimi için kaynak sunucusu yapılandırması
    - Tarayıcı tabanlı erişim için OAuth2 istemci yapılandırması
    - Keycloak ve Spring Security arasında rol eşleme

2. **Token İşleme**:
    - JWT token doğrulama
    - Token iddialarının (claims) çıkarılması
    - Rol tabanlı yetkilendirme

3. **SSO Uygulaması**:
    - Uygulamalar arasında paylaşılan kimlik doğrulama
    - Merkezi oturum kapatma
    - Oturum yönetimi

Bu uygulama, Spring Boot ve Keycloak arasında kapsamlı bir entegrasyonu göstermekte ve hem SSO hem de JWT yaklaşımları aracılığıyla güvenli kimlik doğrulama ve yetkilendirme mekanizmaları sağlamaktadır.
