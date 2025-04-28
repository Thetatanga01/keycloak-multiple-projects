package uk.guven.third.auth

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import uk.guven.third.MainActivity

class AuthenticationActivity : AppCompatActivity() {

    private lateinit var authService: AuthService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        authService = AuthService(this)

        // Intent'ten yanıtı al ve token ile değiştir
        handleAuthResponse(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleAuthResponse(intent)
    }

    private fun handleAuthResponse(intent: Intent) {
        // Debug için
        val data = intent.data
        Log.d("AuthDebug", "Received callback: ${data?.toString()}")
        Log.d("AuthDebug", "Query params: ${data?.query}")

        authService.handleAuthResponseAndGetToken(intent) { success ->
            Log.d("AuthDebug", "Auth result: $success")
            if (success) {
                Toast.makeText(this, "Giriş başarılı", Toast.LENGTH_SHORT).show()
                finish()   // sadece bitir, MainActivity’ye dön
            } else {
                Toast.makeText(this, "Giriş başarısız", Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun startMainActivity() {
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        startActivity(intent)
        finish()
    }
}
