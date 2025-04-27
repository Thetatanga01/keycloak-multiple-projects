package uk.guven.third

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
import uk.guven.third.api.ApiClient
import uk.guven.third.auth.AuthService

class MainActivity : AppCompatActivity() {

    private lateinit var authService: AuthService
    private lateinit var apiClient: ApiClient

    private lateinit var loginButton: Button
    private lateinit var logoutButton: Button
    private lateinit var userInfoTextView: TextView
    private lateinit var apiCallButton: Button
    private lateinit var apiResponseTextView: TextView
    private lateinit var progressBar: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // View bileşenlerini başlat
        loginButton = findViewById(R.id.login_button)
        logoutButton = findViewById(R.id.logout_button)
        userInfoTextView = findViewById(R.id.user_info_text)
        apiCallButton = findViewById(R.id.api_call_button)
        apiResponseTextView = findViewById(R.id.api_response_text)
        progressBar = findViewById(R.id.progress_bar)

        // Servisleri başlat
        authService = AuthService(this)
        apiClient = ApiClient()

        // Buton işlevlerini ayarla
        loginButton.setOnClickListener { startLogin() }
        logoutButton.setOnClickListener { performLogout() }
        apiCallButton.setOnClickListener { callSecuredApi() }

        // Oturum durumunu kontrol et ve UI'yi güncelle
        updateUIBasedOnAuthState()
    }

    override fun onResume() {
        super.onResume()
        // Aktivite yeniden görünür olduğunda durumu güncelle
        updateUIBasedOnAuthState()
    }

    private fun updateUIBasedOnAuthState() {
        val isLoggedIn = authService.isLoggedIn()

        loginButton.visibility = if (isLoggedIn) View.GONE else View.VISIBLE
        logoutButton.visibility = if (isLoggedIn) View.VISIBLE else View.GONE
        apiCallButton.visibility = if (isLoggedIn) View.VISIBLE else View.GONE

        if (isLoggedIn) {
            // Kullanıcı bilgilerini göster
            val userInfo = authService.getUserInfo()
            val username = userInfo["preferred_username"] as? String ?: "Bilinmeyen Kullanıcı"
            val email = userInfo["email"] as? String ?: "Email bulunamadı"
            val roles = when (val realmAccess = userInfo["realm_access"]) {
                is Map<*, *> -> (realmAccess["roles"] as? List<*>)?.joinToString(", ") ?: "Rol bulunamadı"
                else -> "Rol bulunamadı"
            }

            userInfoTextView.text = """
                Hoş geldiniz, $username!
                Email: $email
                Roller: $roles
            """.trimIndent()
        } else {
            userInfoTextView.text = "Giriş yapılmadı"
            apiResponseTextView.text = ""
        }
    }

    private fun startLogin() {
        val loginIntent = authService.getLoginIntent()
        startActivity(loginIntent)
    }

    private fun performLogout() {
        progressBar.visibility = View.VISIBLE
        authService.logout { success ->
            runOnUiThread {
                progressBar.visibility = View.GONE
                if (success) {
                    Toast.makeText(this, "Çıkış başarılı", Toast.LENGTH_SHORT).show()
                    updateUIBasedOnAuthState()
                } else {
                    Toast.makeText(this, "Çıkış sırasında hata oluştu", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun callSecuredApi() {
        progressBar.visibility = View.VISIBLE

        authService.getValidAccessToken { token ->
            if (token != null) {
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val response = apiClient.callSecuredEndpoint(token)
                        withContext(Dispatchers.Main) {
                            progressBar.visibility = View.GONE
                            apiResponseTextView.text = "API Yanıtı:\n$response"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            progressBar.visibility = View.GONE
                            apiResponseTextView.text = "Hata: ${e.message}"
                        }
                    }
                }
            } else {
                runOnUiThread {
                    progressBar.visibility = View.GONE
                    Toast.makeText(this, "Geçerli token alınamadı", Toast.LENGTH_SHORT).show()
                    // Token alınamadıysa yeniden login gerekebilir
                    updateUIBasedOnAuthState()
                }
            }
        }
    }
}
