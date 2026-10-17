// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class SeedStoreException(message: String) : Exception(message)

internal class SeedStore(context: Context) {

    private val folder = File(context.applicationContext.noBackupFilesDir, FOLDER).apply {
        if (!isDirectory && !mkdirs()) throw IllegalStateException("the seed folder could not be created")
    }

    private fun file(alias: String) = AtomicFile(File(folder, ENTRY + alias))

    fun has(alias: String): Boolean = File(folder, ENTRY + alias).isFile

    fun save(alias: String, seed: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        authenticated { cipher.init(Cipher.ENCRYPT_MODE, key()) }
        cipher.updateAAD(label(alias))
        val sealed = cipher.doFinal(seed)
        val iv = cipher.iv
        val record = ByteArray(2 + iv.size + sealed.size)
        record[0] = VERSION
        record[1] = iv.size.toByte()
        System.arraycopy(iv, 0, record, 2, iv.size)
        System.arraycopy(sealed, 0, record, 2 + iv.size, sealed.size)
        val target = file(alias)
        val out = target.startWrite()
        try {
            out.write(record)
            target.finishWrite(out)
        } catch (error: Throwable) {
            target.failWrite(out)
            throw IllegalStateException("the sealed seed could not be written")
        }
    }

    fun load(alias: String): ByteArray? {
        val record = try {
            file(alias).readFully()
        } catch (missing: FileNotFoundException) {
            return null
        }
        val ivSize = if (record.size < 2) 0 else record[1].toInt()
        if (ivSize <= 0 || record[0] != VERSION || record.size <= 2 + ivSize) {
            throw IllegalStateException("the sealed seed is damaged")
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        authenticated { cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, record, 2, ivSize)) }
        cipher.updateAAD(label(alias))
        return cipher.doFinal(record, 2 + ivSize, record.size - 2 - ivSize)
    }

    fun remove(alias: String) {
        file(alias).delete()
        if (has(alias)) throw IllegalStateException("the sealed seed could not be removed")
    }

    private inline fun authenticated(block: () -> Unit) {
        try {
            block()
        } catch (error: UserNotAuthenticatedException) {
            throw SeedStoreException(AUTHENTICATION_REQUIRED)
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw SeedStoreException(KEY_INVALIDATED)
        }
    }

    private fun label(alias: String): ByteArray = (ENTRY + alias).toByteArray(Charsets.UTF_8)

    private fun key(): SecretKey = synchronized(KeyStoreLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: run {
            try {
                generate(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            } catch (error: StrongBoxUnavailableException) {
                generate(strongBox = false)
            }
        }
    }

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                AUTH_WINDOW_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            builder.setIsStrongBoxBacked(strongBox)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private object KeyStoreLock

    companion object {
        const val AUTHENTICATION_REQUIRED = "authentication required, confirm the device lock or biometric and try again"
        const val KEY_INVALIDATED = "the device lock or biometrics changed, so the sealed seed can no longer be opened, restore it from the recovery phrase"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.quantova.qcore.seed.key.2"
        private const val FOLDER = "com.quantova.qcore.seeds"
        private const val ENTRY = "seed."
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256
        private const val AUTH_WINDOW_SECONDS = 15
        private const val VERSION: Byte = 2
    }
}
