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
import net.openid.appauth.TokenResponse
import uk.guven.third.api.ApiClient

class MainActivity : AppCompatActivity() {

    companion object {
        private const val AUTH_REQUEST_CODE = 1001
        private const val AUTH_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/auth"
        private const val TOKEN_ENDPOINT = "https://keycloak.guven.uk/realms/guven_realm/protocol/openid-connect/token"
        private const val CLIENT_ID = "third_app"
        private const val REDIRECT_URI = "uk.guven.third:/oauth2callback"
    }

    private lateinit var authService: AuthorizationService
    private var authState: AuthState = AuthState()
    private val apiClient = ApiClient()

    private lateinit var loginButton: Button
    private lateinit var logoutButton: Button
    private lateinit var apiCallButton: Button
    private lateinit var userInfoTextView: TextView
    private lateinit var apiResponseTextView: TextView
    private lateinit var progressBar: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        authService = AuthorizationService(this)

        loginButton = findViewById(R.id.login_button)
        logoutButton = findViewById(R.id.logout_button)
        apiCallButton = findViewById(R.id.api_call_button)
        userInfoTextView = findViewById(R.id.user_info_text)
        apiResponseTextView = findViewById(R.id.api_response_text)
        progressBar = findViewById(R.id.progress_bar)

        loginButton.setOnClickListener { launchLogin() }
        logoutButton.setOnClickListener { performLogout() }
        apiCallButton.setOnClickListener { callSecuredApi() }

        updateUIBasedOnAuthState()
    }

    private fun launchLogin() {
        val serviceConfig = net.openid.appauth.AuthorizationServiceConfiguration(
            Uri.parse(AUTH_ENDPOINT), Uri.parse(TOKEN_ENDPOINT)
        )
        val authRequest = AuthorizationRequest.Builder(
            serviceConfig,
            CLIENT_ID,
            ResponseTypeValues.CODE,
            Uri.parse(REDIRECT_URI)
        )
            .setScope("openid profile email")
            .build()

        val authIntent = authService.getAuthorizationRequestIntent(authRequest)
        startActivityForResult(authIntent, AUTH_REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == AUTH_REQUEST_CODE) {
            val response = AuthorizationResponse.fromIntent(data!!)
            val exception = AuthorizationException.fromIntent(data)
            authState.update(response, exception)

            if (response != null) {
                val tokenRequest = response.createTokenExchangeRequest()
                authService.performTokenRequest(tokenRequest) { tokenResponse, tokenException ->
                    authState.update(tokenResponse, tokenException)
                    runOnUiThread { updateUIBasedOnAuthState() }
                }
            } else {
                Toast.makeText(this, "Giriş başarısız", Toast.LENGTH_SHORT).show()
            }
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
                    infoMap.forEach { (k, v) ->
                        append("$k: $v\n")
                    }
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
        // SharedPreferences temizleniyorsa burada ekleyin
        authState = AuthState()
        updateUIBasedOnAuthState()
    }

    private fun updateUIBasedOnAuthState() {
        val isLoggedIn = authState.isAuthorized &&
                (authState.accessTokenExpirationTime ?: 0) > System.currentTimeMillis()

        loginButton.visibility = if (isLoggedIn) View.GONE else View.VISIBLE
        logoutButton.visibility = if (isLoggedIn) View.VISIBLE else View.GONE
        apiCallButton.visibility = if (isLoggedIn) View.VISIBLE else View.GONE

        if (isLoggedIn) {
            userInfoTextView.text = "Token alındı, API çağrısı yapabilirsiniz"
        } else {
            userInfoTextView.text = "Giriş yapılmadı"
            apiResponseTextView.text = ""
        }
    }
}