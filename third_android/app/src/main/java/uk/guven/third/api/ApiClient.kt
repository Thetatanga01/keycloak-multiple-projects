package uk.guven.third.api

import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Header

interface ApiService {
    @GET("https://secondbackend.guven.uk/api/user")
    suspend fun getUserInfo(@Header("Authorization") auth: String): Map<String, Any>

    @GET("/api/resources")
    suspend fun getResources(@Header("Authorization") authorization: String): List<Map<String, Any>>
}

class ApiClient {
    companion object {
        private const val BASE_URL = "https://keycloak.guven.uk/" // Spring Boot backend URL
    }

    private val retrofit: Retrofit by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    private val apiService: ApiService by lazy {
        retrofit.create(ApiService::class.java)
    }

    /**
     * Korumalı API'ye istek atar
     * @param token JWT Access token
     * @return API yanıtı
     */
    suspend fun callSecuredEndpoint(token: String): Map<String, Any> {
        return apiService.getUserInfo("Bearer $token")
    }

    /**
     * Kaynakları getiren API'ye istek atar
     * @param token JWT Access token
     * @return Kaynaklar listesi
     */
    suspend fun getResources(token: String): List<Map<String, Any>> {
        return apiService.getResources("Bearer $token")
    }
}
