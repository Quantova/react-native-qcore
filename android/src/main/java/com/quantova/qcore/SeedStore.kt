// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

internal class SeedStoreException(message: String) : Exception(message)

internal class SealedSeed(val alias: String, val legacy: Boolean, val iv: ByteArray, val body: ByteArray)

internal class SeedStore(context: Context) {

    private val folder = File(context.applicationContext.noBackupFilesDir, FOLDER).apply {
        if (!isDirectory && !mkdirs()) throw IllegalStateException("the seed folder could not be created")
    }

    private fun file(alias: String) = AtomicFile(File(folder, ENTRY + alias))

    private fun addressFile(alias: String) = AtomicFile(File(folder, ADDRESSES + alias))

    fun has(alias: String): Boolean = File(folder, ENTRY + alias).isFile

    fun read(alias: String): SealedSeed? {
        val record = try {
            file(alias).readFully()
        } catch (missing: FileNotFoundException) {
            return null
        }
        val ivSize = if (record.size < 2) 0 else record[1].toInt()
        val known = record.isNotEmpty() && (record[0] == VERSION || record[0] == LEGACY_VERSION)
        if (ivSize <= 0 || !known || record.size <= 2 + ivSize) {
            throw IllegalStateException("the sealed seed is damaged")
        }
        return SealedSeed(
            alias,
            record[0] == LEGACY_VERSION,
            record.copyOfRange(2, 2 + ivSize),
            record.copyOfRange(2 + ivSize, record.size),
        )
    }

    fun perUse(sealed: SealedSeed): Boolean {
        if (sealed.legacy) return false
        val key = existing(keyAlias(sealed.alias)) ?: throw SeedStoreException(KEY_INVALIDATED)
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        @Suppress("DEPRECATION")
        return info.userAuthenticationValidityDurationSeconds <= 0
    }

    fun opener(sealed: SealedSeed): Cipher {
        val key = existing(if (sealed.legacy) LEGACY_ALIAS else keyAlias(sealed.alias))
            ?: throw SeedStoreException(KEY_INVALIDATED)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        authenticated { cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed.iv)) }
        return cipher
    }

    fun open(sealed: SealedSeed, cipher: Cipher): ByteArray {
        cipher.updateAAD(label(sealed.alias))
        return authenticatedValue { cipher.doFinal(sealed.body) }
    }

    fun renew(alias: String, perUse: Boolean) = synchronized(KeyStoreLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val name = keyAlias(alias)
        if (keyStore.containsAlias(name)) keyStore.deleteEntry(name)
        try {
            generate(name, perUse, strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        } catch (error: ProviderException) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || error !is StrongBoxUnavailableException) throw error
            generate(name, perUse, strongBox = false)
        }
    }

    fun sealer(alias: String): Cipher {
        val key = existing(keyAlias(alias)) ?: throw SeedStoreException(KEY_INVALIDATED)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        authenticated { cipher.init(Cipher.ENCRYPT_MODE, key) }
        return cipher
    }

    fun seal(alias: String, cipher: Cipher, seed: ByteArray) {
        cipher.updateAAD(label(alias))
        val sealed = authenticatedValue { cipher.doFinal(seed) }
        val iv = cipher.iv
        val record = ByteArray(2 + iv.size + sealed.size)
        record[0] = VERSION
        record[1] = iv.size.toByte()
        System.arraycopy(iv, 0, record, 2, iv.size)
        System.arraycopy(sealed, 0, record, 2 + iv.size, sealed.size)
        write(file(alias), record, "the sealed seed could not be written")
    }

    fun remove(alias: String) {
        file(alias).delete()
        addressFile(alias).delete()
        if (has(alias)) throw IllegalStateException("the sealed seed could not be removed")
        synchronized(KeyStoreLock) {
            val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val name = keyAlias(alias)
            if (keyStore.containsAlias(name)) keyStore.deleteEntry(name)
            val legacyLeft = folder.listFiles().orEmpty().any { entry ->
                entry.isFile && entry.name.startsWith(ENTRY) && legacyRecord(entry)
            }
            if (!legacyLeft && keyStore.containsAlias(LEGACY_ALIAS)) keyStore.deleteEntry(LEGACY_ALIAS)
        }
    }

    fun address(alias: String, index: Long): String? = addresses(alias)[index]

    fun remember(alias: String, found: Map<Long, String>) {
        if (!has(alias)) return
        val all = addresses(alias).toMutableMap()
        if (found.all { (index, address) -> all[index] == address }) return
        all.putAll(found)
        val text = all.entries.sortedBy { it.key }.joinToString("\n") { "${it.key} ${it.value}" }
        write(addressFile(alias), text.toByteArray(Charsets.US_ASCII), "the wallet addresses could not be written")
    }

    private fun addresses(alias: String): Map<Long, String> {
        val text = try {
            String(addressFile(alias).readFully(), Charsets.US_ASCII)
        } catch (missing: FileNotFoundException) {
            return emptyMap()
        }
        return text.lineSequence().mapNotNull { line ->
            val parts = line.split(' ')
            val index = parts.getOrNull(0)?.toLongOrNull()
            val address = parts.getOrNull(1)
            if (parts.size == 2 && index != null && index >= 0 && address != null) index to address else null
        }.toMap()
    }

    fun level(): String {
        val key = synchronized(KeyStoreLock) {
            existing(LEVEL_ALIAS) ?: try {
                probe(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            } catch (error: ProviderException) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || error !is StrongBoxUnavailableException) throw error
                probe(strongBox = false)
            }
        }
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted-environment"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "unknown"
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) "secure-hardware" else "software"
    }

    private fun legacyRecord(entry: File): Boolean =
        try {
            val first = entry.inputStream().use { it.read() }
            first == LEGACY_VERSION.toInt()
        } catch (error: Throwable) {
            false
        }

    private fun write(target: AtomicFile, bytes: ByteArray, failed: String) {
        val out = target.startWrite()
        try {
            out.write(bytes)
            target.finishWrite(out)
        } catch (error: Throwable) {
            target.failWrite(out)
            throw IllegalStateException(failed)
        }
    }

    private inline fun authenticated(block: () -> Unit) {
        authenticatedValue(block)
    }

    private inline fun <T> authenticatedValue(block: () -> T): T =
        try {
            block()
        } catch (error: UserNotAuthenticatedException) {
            throw SeedStoreException(AUTHENTICATION_REQUIRED)
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw SeedStoreException(KEY_INVALIDATED)
        }

    private fun label(alias: String): ByteArray = (ENTRY + alias).toByteArray(Charsets.UTF_8)

    private fun keyAlias(alias: String) = KEY_PREFIX + alias

    private fun existing(name: String): SecretKey? = synchronized(KeyStoreLock) {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.getKey(name, null) as? SecretKey
    }

    private fun generate(name: String, perUse: Boolean, strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            name,
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
                if (perUse) 0 else WINDOW_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(if (perUse) -1 else WINDOW_SECONDS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            builder.setIsStrongBoxBacked(strongBox)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun probe(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(LEVEL_ALIAS, KeyProperties.PURPOSE_ENCRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(strongBox)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private object KeyStoreLock

    companion object {
        const val AUTHENTICATION_REQUIRED = "authentication required, confirm the device lock or biometric and try again"
        const val KEY_INVALIDATED = "the device lock or biometrics changed, so the sealed seed can no longer be opened, forget it and restore it from the recovery phrase"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_PREFIX = "com.quantova.qcore.seed.key.3."
        private const val LEGACY_ALIAS = "com.quantova.qcore.seed.key.2"
        private const val LEVEL_ALIAS = "com.quantova.qcore.seed.level.1"
        private const val FOLDER = "com.quantova.qcore.seeds"
        private const val ENTRY = "seed."
        private const val ADDRESSES = "addresses."
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256
        private const val WINDOW_SECONDS = 10
        private const val VERSION: Byte = 3
        private const val LEGACY_VERSION: Byte = 2
    }
}
