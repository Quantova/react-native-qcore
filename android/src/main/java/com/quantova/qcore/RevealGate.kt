// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.BaseActivityEventListener
import com.facebook.react.bridge.ReactContext
import java.security.KeyStore
import java.security.ProviderException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal class RevealGate(private val context: ReactContext) {

    private class Pending(val code: Int, val since: Long, val listener: BaseActivityEventListener, val abandon: () -> Unit)

    private val pending = AtomicReference<Pending?>(null)

    private val nextCode = AtomicInteger(SecureRandom().nextInt(CODE_SPAN))

    fun authorize(
        activity: Activity,
        title: String,
        subtitle: String,
        cancelled: String = AUTHENTICATION_CANCELLED,
        unsupported: String = REVEAL_UNSUPPORTED,
        done: (Throwable?) -> Unit,
    ) {
        val settled = AtomicBoolean(false)
        val finish = { outcome: Throwable? -> if (settled.compareAndSet(false, true)) done(outcome) }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            confirm(activity, title, subtitle, cancelled, unsupported, finish)
            return
        }
        val cipher = try {
            challenge()
        } catch (error: Throwable) {
            finish(error)
            return
        }
        activity.runOnUiThread {
            try {
                prompt(activity, cipher, title, subtitle, cancelled, finish)
            } catch (error: Throwable) {
                finish(error)
            }
        }
    }

    private fun confirm(
        activity: Activity,
        title: String,
        subtitle: String,
        cancelled: String,
        unsupported: String,
        finish: (Throwable?) -> Unit,
    ) {
        val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (keyguard == null || !keyguard.isDeviceSecure) {
            finish(SeedStoreException(unsupported))
            return
        }
        try {
            recentKey()
        } catch (error: Throwable) {
            finish(SeedStoreException(SeedStore.AUTHENTICATION_REQUIRED))
            return
        }
        @Suppress("DEPRECATION")
        val intent = keyguard.createConfirmDeviceCredentialIntent(title.ifEmpty { DEFAULT_TITLE }, subtitle.ifEmpty { null })
        if (intent == null) {
            finish(SeedStoreException(unsupported))
            return
        }
        val code = CODE_BASE + Math.floorMod(nextCode.getAndIncrement(), CODE_SPAN)
        val holder = AtomicReference<Pending?>(null)
        val listener = object : BaseActivityEventListener() {
            override fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?) {
                if (requestCode != code) return
                context.removeActivityEventListener(this)
                val mine = holder.get() ?: return
                if (!pending.compareAndSet(mine, null)) return
                finish(if (resultCode == Activity.RESULT_OK) recentProof() else SeedStoreException(cancelled))
            }
        }
        val mine = Pending(code, System.nanoTime(), listener) { finish(SeedStoreException(cancelled)) }
        holder.set(mine)
        while (true) {
            val current = pending.get()
            if (current != null && System.nanoTime() - current.since < STALE_NANOS) {
                finish(SeedStoreException(GATE_BUSY))
                return
            }
            if (pending.compareAndSet(current, mine)) {
                if (current != null) {
                    context.removeActivityEventListener(current.listener)
                    current.abandon()
                }
                break
            }
        }
        context.addActivityEventListener(listener)
        activity.runOnUiThread {
            try {
                activity.startActivityForResult(intent, code)
            } catch (error: Throwable) {
                context.removeActivityEventListener(listener)
                if (pending.compareAndSet(mine, null)) finish(SeedStoreException(unsupported))
            }
        }
    }

    private fun recentProof(): Throwable? =
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, recentKey())
            cipher.doFinal(ByteArray(CHALLENGE_BYTES))
            null
        } catch (error: Throwable) {
            SeedStoreException(SeedStore.AUTHENTICATION_REQUIRED)
        }

    private fun recentKey(): SecretKey = synchronized(KeyLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val found = keyStore.getKey(RECENT_ALIAS, null) as? SecretKey
        if (found != null) {
            try {
                Cipher.getInstance(TRANSFORMATION).init(Cipher.ENCRYPT_MODE, found)
                return@synchronized found
            } catch (error: KeyPermanentlyInvalidatedException) {
                keyStore.deleteEntry(RECENT_ALIAS)
            } catch (error: Throwable) {
                return@synchronized found
            }
        }
        val builder = KeyGenParameterSpec.Builder(
            RECENT_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
        @Suppress("DEPRECATION")
        builder.setUserAuthenticationValidityDurationSeconds(RECENT_SECONDS)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        generator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private fun prompt(
        activity: Activity,
        cipher: Cipher,
        title: String,
        subtitle: String,
        cancelled: String,
        finish: (Throwable?) -> Unit,
    ) {
        val executor = activity.mainExecutor
        val builder = BiometricPrompt.Builder(activity).setTitle(title.ifEmpty { DEFAULT_TITLE })
        if (subtitle.isNotEmpty()) builder.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            builder.setNegativeButton(CANCEL_LABEL, executor) { _, _ ->
                finish(SeedStoreException(cancelled))
            }
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                finish(proof(cipher, result.cryptoObject?.cipher))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val byUser = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                finish(SeedStoreException(if (byUser) cancelled else SeedStore.AUTHENTICATION_REQUIRED))
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

    @RequiresApi(Build.VERSION_CODES.P)
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

    @RequiresApi(Build.VERSION_CODES.P)
    private fun key(): SecretKey = synchronized(KeyLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: run {
            try {
                generate(strongBox = true)
            } catch (error: ProviderException) {
                if (error !is StrongBoxUnavailableException) throw error
                generate(strongBox = false)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
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
        const val REVEAL_UNSUPPORTED = "revealing the phrase needs a device lock"
        private const val DEFAULT_TITLE = "Reveal recovery phrase"
        private const val CANCEL_LABEL = "Cancel"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.quantova.qcore.reveal.key.1"
        private const val RECENT_ALIAS = "com.quantova.qcore.reveal.recent.1"
        private const val RECENT_SECONDS = 5
        private const val CODE_BASE = 0x5100
        private const val CODE_SPAN = 0x0400
        private const val STALE_NANOS = 120_000_000_000L
        const val GATE_BUSY = "another authentication is already waiting for the user, finish or cancel it first"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val CHALLENGE_BYTES = 32
    }
}
