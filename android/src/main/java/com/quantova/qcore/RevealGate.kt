// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.annotation.TargetApi
import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal class RevealGate {

    fun authorize(activity: Activity, title: String, subtitle: String, done: (Throwable?) -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            done(SeedStoreException(REVEAL_UNSUPPORTED))
            return
        }
        val settled = AtomicBoolean(false)
        val finish = { outcome: Throwable? -> if (settled.compareAndSet(false, true)) done(outcome) }
        val cipher = try {
            challenge()
        } catch (error: Throwable) {
            finish(error)
            return
        }
        activity.runOnUiThread {
            try {
                prompt(activity, cipher, title, subtitle, finish)
            } catch (error: Throwable) {
                finish(error)
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun prompt(activity: Activity, cipher: Cipher, title: String, subtitle: String, finish: (Throwable?) -> Unit) {
        val executor = activity.mainExecutor
        val builder = BiometricPrompt.Builder(activity).setTitle(title.ifEmpty { DEFAULT_TITLE })
        if (subtitle.isNotEmpty()) builder.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(AUTHENTICATORS)
        } else {
            builder.setNegativeButton(CANCEL_LABEL, executor) { _, _ ->
                finish(SeedStoreException(AUTHENTICATION_CANCELLED))
            }
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                finish(proof(cipher, result.cryptoObject?.cipher))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                finish(SeedStoreException(if (cancelled) AUTHENTICATION_CANCELLED else SeedStore.AUTHENTICATION_REQUIRED))
            }
        }
        builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), executor, callback)
    }

    private fun proof(expected: Cipher, used: Cipher?): Throwable? =
        try {
            if (used == null || used !== expected) throw SeedStoreException(SeedStore.AUTHENTICATION_REQUIRED)
            used.doFinal(ByteArray(CHALLENGE_BYTES))
            null
        } catch (error: SeedStoreException) {
            error
        } catch (error: Throwable) {
            SeedStoreException(SeedStore.AUTHENTICATION_REQUIRED)
        }

    private fun challenge(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key())
        } catch (error: KeyPermanentlyInvalidatedException) {
            discard()
            cipher.init(Cipher.ENCRYPT_MODE, key())
        }
        return cipher
    }

    private fun discard() = synchronized(KeyLock) {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
    }

    private fun key(): SecretKey = synchronized(KeyLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: run {
            try {
                generate(strongBox = true)
            } catch (error: StrongBoxUnavailableException) {
                generate(strongBox = false)
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun generate(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private object KeyLock

    companion object {
        const val AUTHENTICATION_CANCELLED = "authentication cancelled, the phrase was not revealed"
        const val REVEAL_UNSUPPORTED = "revealing the phrase needs Android 9 or later with a device lock or biometric"
        private const val DEFAULT_TITLE = "Reveal recovery phrase"
        private const val CANCEL_LABEL = "Cancel"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.quantova.qcore.reveal.key.1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val CHALLENGE_BYTES = 32
        private const val AUTHENTICATORS =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
}
