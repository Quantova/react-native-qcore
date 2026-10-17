// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class SeedStore(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun has(alias: String): Boolean = prefs.contains(ENTRY + alias)

    fun save(alias: String, seed: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(label(alias))
        val sealed = cipher.doFinal(seed)
        val iv = cipher.iv
        val record = ByteArray(1 + iv.size + sealed.size)
        record[0] = iv.size.toByte()
        System.arraycopy(iv, 0, record, 1, iv.size)
        System.arraycopy(sealed, 0, record, 1 + iv.size, sealed.size)
        val text = Base64.encodeToString(record, Base64.NO_WRAP)
        if (!prefs.edit().putString(ENTRY + alias, text).commit()) {
            throw IllegalStateException("the sealed seed could not be written")
        }
    }

    fun load(alias: String): ByteArray? {
        val text = prefs.getString(ENTRY + alias, null) ?: return null
        val record = Base64.decode(text, Base64.NO_WRAP)
        val ivSize = if (record.isEmpty()) 0 else record[0].toInt()
        if (ivSize <= 0 || record.size <= 1 + ivSize) {
            throw IllegalStateException("the sealed seed is damaged")
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, record, 1, ivSize))
        cipher.updateAAD(label(alias))
        return cipher.doFinal(record, 1 + ivSize, record.size - 1 - ivSize)
    }

    fun remove(alias: String) {
        if (!prefs.edit().remove(ENTRY + alias).commit()) {
            throw IllegalStateException("the sealed seed could not be removed")
        }
    }

    private fun label(alias: String): ByteArray = (ENTRY + alias).toByteArray(Charsets.UTF_8)

    private fun key(): SecretKey = synchronized(KeyStoreLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: run {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(KEY_BITS)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generator.generateKey()
        }
    }

    private object KeyStoreLock

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.quantova.qcore.seed.key"
        private const val PREFS = "com.quantova.qcore.seeds"
        private const val ENTRY = "seed."
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256
    }
}
