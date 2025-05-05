package uk.guven.third.auth

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import net.openid.appauth.*
import com.auth0.android.jwt.JWT
import uk.guven.third.MainActivity
import java.util.concurrent.atomic.AtomicReference

class AuthService(private val context: Context) {

    companion object {
        private const val AUTH_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/auth"
        private const val TOKEN_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/token"
        private const val LOGOUT_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/logout"
        private const val CLIENT_ID = "third_app"
        private const val REDIRECT_URI = "uk.guven.third:/oauth2callback"
        private const val SHARED_PREFERENCES_NAME = "auth_prefs"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_ID_TOKEN = "id_token"
        private const val KEY_EXPIRES_AT = "expires_at"
    }

    private val authState = AtomicReference<AuthState>()
    private val masterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val authPrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            SHARED_PREFERENCES_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    init {
        // Kayıtlı durumu yükle
        val accessToken = authPrefs.getString(KEY_ACCESS_TOKEN, null)
        val refreshToken = authPrefs.getString(KEY_REFRESH_TOKEN, null)
        val idToken = authPrefs.getString(KEY_ID_TOKEN, null)
        val expiresAt = authPrefs.getLong(KEY_EXPIRES_AT, 0)

        if (accessToken != null && refreshToken != null) {
            val restoredState = AuthState()
            try {
                // Avoid variable shadowing - removed the line that creates a new authState

                // Create tokenResponse using reflection to navigate around accessibility constraints
                try {
                    val serviceConfig = AuthorizationServiceConfiguration(
                        Uri.parse(AUTH_ENDPOINT),
                        Uri.parse(TOKEN_ENDPOINT)
                    )

                    // Create a dummy token request
                    val tokenRequest = TokenRequest.Builder(
                        serviceConfig,
                        CLIENT_ID
                    ).build()

                    // Try to use the public TokenResponse.Builder method
                    val tokenResponseBuilder = TokenResponse.Builder(tokenRequest)
                        .setAccessToken(accessToken)
                        .setRefreshToken(refreshToken)

                    if (idToken != null) {
                        tokenResponseBuilder.setIdToken(idToken)
                    }

                    if (expiresAt > 0) {
                        tokenResponseBuilder.setAccessTokenExpirationTime(expiresAt)
                    }

                    val tokenResponse = tokenResponseBuilder.build()
                    restoredState.update(tokenResponse, null)
                    this.authState.set(restoredState)  // Use 'this.authState' to refer to the class field
                } catch (e: Exception) {
                    // Approach failed, use a default AuthState
                    this.authState.set(AuthState())  // Use 'this.authState' to refer to the class field
                }
            } catch (e: Exception) {
                // Token oluşturma veya yükleme hatası, yeni bir state oluştur
                this.authState.set(AuthState())  // Use 'this.authState' to refer to the class field
            }
        } else {
            this.authState.set(AuthState())  // Use 'this.authState' to refer to the class field
        }
    }

    fun login() {
        val serviceConfig = AuthorizationServiceConfiguration(
            Uri.parse(AUTH_ENDPOINT), Uri.parse(TOKEN_ENDPOINT)
        )
        val authRequest = AuthorizationRequest.Builder(
            serviceConfig, CLIENT_ID, ResponseTypeValues.CODE, Uri.parse(REDIRECT_URI)
        )
            .setScope("openid profile email")
            .setPrompt("login")
            .build()

        val authService = AuthorizationService(context)
        val callbackIntent = Intent(context, AuthenticationActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, callbackIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        authService.performAuthorizationRequest(authRequest, pendingIntent)
    }


    /**
     * Yetkilendirme kodu yanıtını işler ve token alır
     * @param intent Callback ile alınan intent
     * @param callback Token alma işlemi tamamlandığında çağrılacak fonksiyon
     */
    fun handleAuthResponseAndGetToken(intent: Intent, callback: (Boolean) -> Unit) {
        val response = AuthorizationResponse.fromIntent(intent)
        val exception = AuthorizationException.fromIntent(intent)

        Log.d("AuthDebug", "Auth response: $response")
        Log.d("AuthDebug", "Auth exception: ${exception?.message} (${exception?.code})")

        if (response != null) {
            authState.get().update(response, exception)
            val authService = AuthorizationService(context)

            try {
                val tokenRequest = response.createTokenExchangeRequest()
                Log.d("AuthDebug", "Token request created: $tokenRequest")

                authService.performTokenRequest(tokenRequest) { tokenResponse, tokenException ->
                    Log.d("AuthDebug", "Token response: $tokenResponse")
                    Log.d("AuthDebug", "Token exception: ${tokenException?.message} (${tokenException?.code})")

                    if (tokenResponse != null) {
                        authState.get().update(tokenResponse, tokenException)
                        saveAuthState(tokenResponse)
                        callback(true)
                    } else {
                        callback(false)
                    }
                    authService.dispose()
                }
            } catch (e: Exception) {
                Log.e("AuthDebug", "Error creating token request: ${e.message}")
                callback(false)
                authService.dispose()
            }
        } else {
            Log.e("AuthDebug", "No auth response in intent")
            callback(false)
        }
    }

    /**
     * Token'ı güvenli bir şekilde kaydeder
     */
    private fun saveAuthState(tokenResponse: TokenResponse) {
        val editor = authPrefs.edit()

        tokenResponse.accessToken?.let {
            editor.putString(KEY_ACCESS_TOKEN, it)
        }

        tokenResponse.refreshToken?.let {
            editor.putString(KEY_REFRESH_TOKEN, it)
        }

        tokenResponse.idToken?.let {
            editor.putString(KEY_ID_TOKEN, it)
        }

        tokenResponse.accessTokenExpirationTime?.let {
            editor.putLong(KEY_EXPIRES_AT, it)
        }

        editor.commit()  // Changed from apply() for API compatibility
    }

    /**
     * Access token'ı getirir, gerekirse yeniler
     * @param callback Geçerli token ile çağrılacak fonksiyon
     */
    fun getValidAccessToken(callback: (String?) -> Unit) {
        val currentState = authState.get()

        if (!currentState.isAuthorized || currentState.needsTokenRefresh) {
            val refreshToken = authPrefs.getString(KEY_REFRESH_TOKEN, null)
            if (refreshToken != null) {
                val authService = AuthorizationService(context)
                currentState.refreshToken?.let { token ->
                    authService.performTokenRequest(
                        TokenRequest.Builder(
                            AuthorizationServiceConfiguration(
                                Uri.parse(AUTH_ENDPOINT),
                                Uri.parse(TOKEN_ENDPOINT)
                            ),
                            CLIENT_ID
                        )
                            .setGrantType(GrantTypeValues.REFRESH_TOKEN)
                            .setRefreshToken(token)
                            .build()
                    ) { response, ex ->
                        if (response != null) {
                            authState.get().update(response, ex)
                            saveAuthState(response)
                            callback(response.accessToken)
                        } else {
                            callback(null)
                        }
                        authService.dispose()
                    }
                } ?: callback(null)
            } else {
                callback(null)
            }
        } else {
            callback(currentState.accessToken)
        }
    }

    /**
     * Kullanıcının oturum açıp açmadığını kontrol eder
     * @return Oturum durumu
     */
    fun isLoggedIn(): Boolean {
        val currentState = authState.get()
        if (!currentState.isAuthorized) {
            return false
        }

        // Token süresi dolmuş mu kontrol et
        val accessToken = authPrefs.getString(KEY_ACCESS_TOKEN, null) ?: return false
        val expiresAt = authPrefs.getLong(KEY_EXPIRES_AT, 0)

        return expiresAt > System.currentTimeMillis()
    }

    /**
     * Token'dan kullanıcı bilgilerini çıkarır
     * @return Kullanıcı bilgileri
     */
    fun getUserInfo(): Map<String, Any> {
        val accessToken = authPrefs.getString(KEY_ACCESS_TOKEN, null) ?: return emptyMap()
        val idToken = authPrefs.getString(KEY_ID_TOKEN, null) ?: return emptyMap()

        try {
            val jwt = JWT(idToken)
            val result = mutableMapOf<String, Any>()

            jwt.claims.forEach { (key, claim) ->
                // Extract values using available methods
                claim.asString()?.let { result[key] = it }
                claim.asInt()?.let { result[key] = it }
                claim.asLong()?.let { result[key] = it }
                claim.asBoolean()?.let { result[key] = it }
                claim.asList(String::class.java)?.let { result[key] = it }

                // Handle map claims safely without isMissing and isNull properties
                try {
                    // Try to use reflection to call the 'as' method
                    val asMethod = claim.javaClass.getMethod("as", Class::class.java)
                    val mapValue = asMethod.invoke(claim, Map::class.java)
                    if (mapValue != null) {
                        result[key] = mapValue
                    }
                } catch (e: Exception) {
                    // Silently fail if method doesn't exist or can't be called
                }
            }

            return result
        } catch (e: Exception) {
            return emptyMap()
        }
    }


    fun logout(token: String?, callback: (Boolean) -> Unit) {
        // ——— 2) ServiceConfig’e logout endpoint’i ekle
        val serviceConfig = AuthorizationServiceConfiguration(
            Uri.parse(AUTH_ENDPOINT),    // authz endpoint
            Uri.parse(TOKEN_ENDPOINT),   // token endpoint
            null,                        // registration endpoint
            Uri.parse(LOGOUT_ENDPOINT)   // end-session endpoint
        )

        // ——— 3) EndSessionRequest oluştur
        val endSessionRequest = EndSessionRequest.Builder(serviceConfig)
            .setIdTokenHint(token)                                    // id_token_hint
            .setPostLogoutRedirectUri(Uri.parse(REDIRECT_URI))          // post_logout_redirect_uri
            .setAdditionalParameters(mapOf("client_id" to CLIENT_ID))    // ekstra parametre
            .build()

        // ——— 4) PendingIntent ile logout callback’ini yakala
        val intent = Intent(context, MainActivity::class.java)
            .apply { action = "LOGOUT_CALLBACK" }
        val pi = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )

        // ——— 5) AppAuth ile oturumu kapat
        AuthorizationService(context)
            .performEndSessionRequest(endSessionRequest, pi)

        // ——— 6) Şimdi lokal state’i temizle ve cookie’leri kaldır
        authPrefs.edit().clear().commit()
        authState.set(AuthState())
        android.webkit.CookieManager.getInstance().removeAllCookies(null)
        android.webkit.CookieManager.getInstance().flush()

        callback(true)
    }








}
