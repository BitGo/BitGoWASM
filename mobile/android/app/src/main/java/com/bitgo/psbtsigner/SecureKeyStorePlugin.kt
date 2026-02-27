package com.bitgo.psbtsigner

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@CapacitorPlugin(name = "SecureKeyStore")
class SecureKeyStorePlugin : Plugin() {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val PREFS_NAME = "com.bitgo.psbtsigner.secure"
        private const val AES_KEY_ALIAS = "com.bitgo.psbtsigner.aes"
        private const val GCM_TAG_LENGTH = 128
    }

    // -------------------------------------------------------------------------
    // Android approach:
    //
    // AndroidKeyStore generates an AES key that requires user authentication
    // (biometric or device credential) to use. Values are encrypted with
    // AES-GCM before being stored in SharedPreferences. On retrieval, the
    // system prompts biometric/credential auth before allowing decryption.
    //
    // This mirrors the iOS Keychain + .userPresence approach.
    // -------------------------------------------------------------------------

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        keyStore.getKey(AES_KEY_ALIAS, null)?.let {
            return it as SecretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )

        val builder = KeyGenParameterSpec.Builder(
            AES_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // API 30+: allow biometric OR device credential, with 0-second validity
            // (auth required for every cryptographic operation)
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else {
            // API 24-29: setUserAuthenticationValidityDurationSeconds(-1) means
            // every use requires auth; credential fallback is implicit
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        // Invalidate key if biometric enrollment changes
        builder.setInvalidatedByBiometricEnrollment(true)

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    private fun getPrefs() =
        context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)

    // -------------------------------------------------------------------------
    // store: encrypt value and save to SharedPreferences (no biometric prompt)
    // -------------------------------------------------------------------------

    @PluginMethod
    fun store(call: PluginCall) {
        val key = call.getString("key")
        val value = call.getString("value")
        if (key == null || value == null) {
            call.reject("Missing required parameters: key and value")
            return
        }

        try {
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val iv = cipher.iv
            val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))

            // Store as "base64(iv):base64(ciphertext)"
            val ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP)
            val encB64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
            getPrefs().edit().putString(key, "$ivB64:$encB64").apply()

            call.resolve()
        } catch (e: Exception) {
            call.reject("Failed to store key: ${e.message}", "STORE_ERROR")
        }
    }

    // -------------------------------------------------------------------------
    // retrieve: decrypt value with biometric/credential prompt
    // -------------------------------------------------------------------------

    @PluginMethod
    fun retrieve(call: PluginCall) {
        val key = call.getString("key")
        if (key == null) {
            call.reject("Missing required parameter: key")
            return
        }

        val stored = getPrefs().getString(key, null)
        if (stored == null) {
            call.reject("No key stored", "NOT_FOUND")
            return
        }

        val parts = stored.split(":")
        if (parts.size != 2) {
            call.reject("Corrupted stored data", "CORRUPTED")
            return
        }

        val iv = Base64.decode(parts[0], Base64.NO_WRAP)
        val encrypted = Base64.decode(parts[1], Base64.NO_WRAP)

        try {
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

            val prompt = call.getString("prompt") ?: "Authenticate to access key"

            val activity = activity as? FragmentActivity
            if (activity == null) {
                call.reject("Activity not available", "NO_ACTIVITY")
                return
            }

            val executor = ContextCompat.getMainExecutor(context)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val cryptoResult = result.cryptoObject?.cipher
                            ?: throw Exception("No cipher in auth result")
                        val decrypted = cryptoResult.doFinal(encrypted)
                        val value = String(decrypted, Charsets.UTF_8)
                        val ret = com.getcapacitor.JSObject()
                        ret.put("value", value)
                        call.resolve(ret)
                    } catch (e: Exception) {
                        call.reject("Decryption failed: ${e.message}", "DECRYPT_ERROR")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON ->
                            call.reject("Authentication cancelled", "USER_CANCELLED")
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
                            call.reject("Too many attempts, device locked", "LOCKOUT")
                        else ->
                            call.reject("Authentication error: $errString", "AUTH_ERROR")
                    }
                }

                override fun onAuthenticationFailed() {
                    // Called on each failed attempt; Android shows retry automatically.
                    // Don't reject here — wait for onAuthenticationError or onAuthenticationSucceeded.
                }
            }

            activity.runOnUiThread {
                val biometricPrompt = BiometricPrompt(activity, executor, callback)

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("BitGo PSBT Signer")
                    .setSubtitle(prompt)
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG
                            or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(cipher)
                )
            }
        } catch (e: Exception) {
            call.reject("Failed to initialize decryption: ${e.message}", "INIT_ERROR")
        }
    }

    // -------------------------------------------------------------------------
    // remove: delete entry from SharedPreferences (no biometric needed)
    // -------------------------------------------------------------------------

    @PluginMethod
    fun remove(call: PluginCall) {
        val key = call.getString("key")
        if (key == null) {
            call.reject("Missing required parameter: key")
            return
        }
        getPrefs().edit().remove(key).apply()
        call.resolve()
    }

    // -------------------------------------------------------------------------
    // has: check if key exists (no biometric needed)
    // -------------------------------------------------------------------------

    @PluginMethod
    fun has(call: PluginCall) {
        val key = call.getString("key")
        if (key == null) {
            call.reject("Missing required parameter: key")
            return
        }
        val exists = getPrefs().contains(key)
        val ret = com.getcapacitor.JSObject()
        ret.put("exists", exists)
        call.resolve(ret)
    }

    // -------------------------------------------------------------------------
    // isBiometricAvailable: check hardware/enrollment status
    // -------------------------------------------------------------------------

    @PluginMethod
    fun isBiometricAvailable(call: PluginCall) {
        val biometricManager = BiometricManager.from(context)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )

        val available = canAuth == BiometricManager.BIOMETRIC_SUCCESS

        val biometryType = when (canAuth) {
            BiometricManager.BIOMETRIC_SUCCESS -> "biometric"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "none"
            else -> "none"
        }

        val ret = com.getcapacitor.JSObject()
        ret.put("available", available)
        ret.put("biometryType", biometryType)
        call.resolve(ret)
    }
}
