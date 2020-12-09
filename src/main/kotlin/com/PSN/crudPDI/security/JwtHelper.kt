package com.PSN.crudPDI.security

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator
import com.auth0.jwt.algorithms.Algorithm
import org.springframework.stereotype.Component
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.*


@Component
class JwtHelper {

    private lateinit var privateKey: RSAPrivateKey
    private lateinit var publicKey: RSAPublicKey

    fun JwtHelper(privateKey: RSAPrivateKey, publicKey: RSAPublicKey) {
        this.privateKey = privateKey
        this.publicKey = publicKey
    }

    fun createJwtForClaims(subject: String?, claims: Map<String?, String?>): String? {
        val calendar = Calendar.getInstance()
        calendar.timeInMillis = Instant.now().toEpochMilli()
        calendar.add(Calendar.DATE, 1)
        val jwtBuilder: JWTCreator.Builder = JWT.create().withSubject(subject)

        // Add claims
        claims.forEach { (name: String?, value: String?) -> jwtBuilder.withClaim(name, value) }

        // Add expiredAt
        return jwtBuilder
                .withNotBefore(Date())
                .withExpiresAt(calendar.time)
                .sign(Algorithm.RSA256(publicKey, privateKey))
    }
}