package com.PSN.crudPDI.security

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import java.io.IOException
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.reflect.KClass
import kotlin.reflect.full.isSubclassOf

@Configuration
class JwtConfiguration {

    @Value(value = "\${spring.security.jwt.keystore-location}")
    private lateinit var keyStorePath: String

    @Value(value = "\${spring.security.jwt.keystore-password}")
    private lateinit var keyStorePassword: String

    @Value(value = "\${spring.security.jwt.key-alias}")
    private lateinit var keyAlias: String

    @Value(value = "\${spring.security.jwt.private-key-passphrase}")
    private lateinit var privateKeyPassphrase: String

    private lateinit var log: LoggerFactory

    @Bean
    fun keyStore(): KeyStore
    {
        try {
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            val resourceAsStream = Thread.currentThread().contextClassLoader.getResourceAsStream(keyStorePath)
            keyStore.load(resourceAsStream, keyStorePassword.toCharArray())
            return keyStore
        } catch (e: Exception) {
             e.multicatch(IOException::class, CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
            {
                //TODO Alterar try catch
                // log.("Unable to load keystore: {}", keyStorePath, e);
            }
        }
        throw IllegalArgumentException("Não foi possível carrega keystore ")
    }

    @Bean
    fun jwtSginingKey(keyStore: KeyStore): RSAPrivateKey
    {
        try {
            val key: Key = keyStore.getKey(keyAlias, privateKeyPassphrase.toCharArray())
            if (key is RSAPrivateKey) {
                return (key as RSAPrivateKey)
            }
        }
        catch (e: Exception) {
            e.multicatch(IOException::class, CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
            {
                //TODO Alterar try catch
                //log.("Unable to load keystore: {}", keyStorePath, e);
            }
        }
        throw IllegalArgumentException("Não foi possível carregar a private key")
    }

    @Bean
    fun jwtValidationKey(keyStore: KeyStore): RSAPublicKey
    {
        try {
            val certficate: Certificate = keyStore.getCertificate(keyAlias)
            val publicKey: PublicKey = certficate.publicKey

            if(publicKey is RSAPublicKey)
            {
                return (publicKey as RSAPublicKey)
            }
        }
        catch (e: Exception)
        {
            e.multicatch(IOException::class, CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
            {
                //TODO Alterar try catch
                //log.("Unable to load keystore: {}", keyStorePath, e);
            }
        }

        throw IllegalArgumentException("Não foi possível carregar RSA public key")
    }

    @Bean
    fun jwtDecoder(rsaPublicKey: RSAPublicKey): JwtDecoder
    {
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build()
    }

    fun <R> Throwable.multicatch(vararg classes: KClass<*>, block: () -> R): R {
        if (classes.any { this::class.isSubclassOf(it) }) {
            return block()
        } else throw this
    }

}