package uk.guven.third

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthState
import net.openid.appauth.ResponseTypeValues
import okhttp3.OkHttpClient
import okhttp3.Request
import uk.guven.third.api.ApiClient
import uk.guven.third.auth.AuthService

class MainActivity : AppCompatActivity() {

    companion object {
        private const val AUTH_REQUEST_CODE = 1001
        private const val AUTH_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/auth"
        private const val TOKEN_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/token"
        private const val CLIENT_ID = "third_app"
        private const val REDIRECT_URI = "uk.guven.third:/oauth2callback"
        private const val USERINFO_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/userinfo"
    }

    private lateinit var authService: AuthorizationService
    private lateinit var authManager: AuthService
    private var authState: AuthState = AuthState()
    private val apiClient = ApiClient()
    private val httpClient = OkHttpClient()

    private lateinit var loginButton: Button
    private lateinit var logoutButton: Button
    private lateinit var apiCallButton: Button
    private lateinit var userInfoTextView: TextView
    private lateinit var apiResponseTextView: TextView
    private lateinit var progressBar: ProgressBar

    // otomatik login denemesi için bayrak
    private var autoLoginTried = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        authService = AuthorizationService(this)
        authManager = AuthService(this)
        loginButton         = findViewById(R.id.login_button)
        logoutButton        = findViewById(R.id.logout_button)
        apiCallButton       = findViewById(R.id.api_call_button)
        userInfoTextView    = findViewById(R.id.user_info_text)
        apiResponseTextView = findViewById(R.id.api_response_text)
        progressBar         = findViewById(R.id.progress_bar)

        loginButton.setOnClickListener { launchLogin() }
        logoutButton.setOnClickListener { performLogout() }
        apiCallButton.setOnClickListener { callSecuredApi() }

        updateUIBasedOnAuthState()
    }

    override fun onResume() {
        super.onResume()
        // 1) önce UI'ı güncelle
        updateUIBasedOnAuthState()

        // 2) eğer token varsa, userinfo isteğiyle geçerliliğini kontrol et
        if (isLoggedIn()) {
            CoroutineScope(Dispatchers.IO).launch {
                val valid = isTokenStillValid()
                if (!valid) {
                    // geçersizse logout
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            this@MainActivity,
                            "Oturumunuz sona ermiş, lütfen tekrar giriş yapın",
                            Toast.LENGTH_SHORT
                        ).show()
                        performLogout()
                    }
                }
            }
            return
        }

        // 3) henüz login yoksa ve otomatik deneme yapılmadıysa login akışını başlat
        if (!autoLoginTried) {
            autoLoginTried = true
            launchLogin()
        }
    }

    private fun isLoggedIn(): Boolean {
        return authState.isAuthorized &&
            (authState.accessTokenExpirationTime ?: 0) > System.currentTimeMillis()
    }

    private fun launchLogin() {
        val serviceConfig = net.openid.appauth.AuthorizationServiceConfiguration(
            Uri.parse(AUTH_ENDPOINT),
            Uri.parse(TOKEN_ENDPOINT)
        )
        val authRequest = AuthorizationRequest.Builder(
            serviceConfig,
            CLIENT_ID,
            ResponseTypeValues.CODE,
            Uri.parse(REDIRECT_URI)
        ).setScope("openid profile email")
            .build()

        val intent = authService.getAuthorizationRequestIntent(authRequest)
        startActivityForResult(intent, AUTH_REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == AUTH_REQUEST_CODE) {
            val resp = AuthorizationResponse.fromIntent(data!!)
            val ex   = AuthorizationException.fromIntent(data)
            authState.update(resp, ex)
            if (resp != null) {
                val tokenReq = resp.createTokenExchangeRequest()
                authService.performTokenRequest(tokenReq) { tokResp, tokEx ->
                    authState.update(tokResp, tokEx)
                    runOnUiThread { updateUIBasedOnAuthState() }
                }
            } else {
                Toast.makeText(this, "Giriş başarısız", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private suspend fun isTokenStillValid(): Boolean {
        val token = authState.accessToken ?: return false
        val req = Request.Builder()
            .url(USERINFO_ENDPOINT)
            .addHeader("Authorization", "Bearer $token")
            .build()
        return try {
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

    private fun callSecuredApi() {
        progressBar.visibility = View.VISIBLE
        val token = authState.accessToken
        if (token.isNullOrEmpty()) {
            progressBar.visibility = View.GONE
            Toast.makeText(this, "Token yok, lütfen giriş yapın", Toast.LENGTH_SHORT).show()
            return
        }
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val infoMap = apiClient.callSecuredEndpoint(token)
                val sb = StringBuilder().apply {
                    infoMap.forEach { (k, v) -> append("$k: $v\n") }
                }
                withContext(Dispatchers.Main) {
                    progressBar.visibility = View.GONE
                    apiResponseTextView.text = sb.toString()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    progressBar.visibility = View.GONE
                    apiResponseTextView.text = "Hata: ${e.message}"
                }
            }
        }
    }

    private fun performLogout() {
        authManager.logout(authState.idToken) { success ->
            runOnUiThread {
                if (success) {
                    Toast.makeText(this, "Oturum sonlandi", Toast.LENGTH_SHORT).show()
                    authState = AuthState()
                    autoLoginTried = false
                    updateUIBasedOnAuthState()
                } else {
                    Toast.makeText(this, "Çıkış yapılamadı", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun updateUIBasedOnAuthState() {
        val loggedIn = isLoggedIn()
        loginButton.visibility   = if (loggedIn) View.GONE else View.VISIBLE
        logoutButton.visibility  = if (loggedIn) View.VISIBLE else View.GONE
        apiCallButton.visibility = if (loggedIn) View.VISIBLE else View.GONE
        userInfoTextView.text    = if (loggedIn) "Token alındı, API çağrısı yapabilirsiniz"
        else "Giriş yapılmadı"
        if (!loggedIn) apiResponseTextView.text = ""
    }
}
