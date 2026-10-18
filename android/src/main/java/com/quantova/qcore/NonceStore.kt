// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class NonceStore(context: Context) {

    private val folder = File(context.applicationContext.noBackupFilesDir, FOLDER).apply {
        if (!isDirectory && !mkdirs()) throw IllegalStateException("the nonce state folder could not be created")
    }

    fun manifestPresent(): Boolean = File(folder, MANIFEST).exists()

    fun loadManifest(): String? = open(MANIFEST)

    fun load(account: String): String? = open(nameOf(account))

    fun unlisted(accounts: Collection<String>): List<String?> {
        val listed = accounts.mapTo(HashSet()) { nameOf(it) }
        val names = folder.list()?.filter { ENTRY_NAME.matches(it) && it !in listed }?.sorted() ?: return emptyList()
        return names.take(MAX_ACCOUNTS + 1).map { open(it) }
    }

    fun save(account: String, state: String) = write(nameOf(account), state)

    fun saveManifest(manifest: String) = write(MANIFEST, manifest)

    fun remove(account: String) {
        val file = File(folder, nameOf(account))
        AtomicFile(file).delete()
        if (file.exists()) throw IllegalStateException("the saved nonce state could not be removed")
    }

    fun clear() {
        folder.listFiles()?.forEach { it.delete() }
        if (!folder.list().isNullOrEmpty()) throw IllegalStateException("the saved nonce state could not be removed")
    }

    private fun write(name: String, state: String) {
        val plain = state.toByteArray(Charsets.UTF_8)
        if (plain.size > STATE_MAX) throw IllegalStateException(TOO_LARGE)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(label(name))
        val sealed = cipher.doFinal(plain)
        val iv = cipher.iv
        val record = ByteArray(2 + iv.size + sealed.size)
        record[0] = VERSION
        record[1] = iv.size.toByte()
        System.arraycopy(iv, 0, record, 2, iv.size)
        System.arraycopy(sealed, 0, record, 2 + iv.size, sealed.size)
        val target = AtomicFile(File(folder, name))
        val out = try {
            target.startWrite()
        } catch (error: IOException) {
            throw IllegalStateException(WRITE_FAILED)
        }
        try {
            out.write(record)
            target.finishWrite(out)
        } catch (error: Throwable) {
            target.failWrite(out)
            throw IllegalStateException(WRITE_FAILED)
        }
    }

    private fun open(name: String): String? {
        val file = File(folder, name)
        if (!file.isFile || file.length() > RECORD_MAX) return null
        val record = try {
            AtomicFile(file).readFully()
        } catch (error: IOException) {
            return null
        }
        val ivSize = if (record.size < 2) 0 else record[1].toInt()
        if (ivSize <= 0 || record[0] != VERSION || record.size <= 2 + ivSize) return null
        val plain = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, record, 2, ivSize))
            cipher.updateAAD(label(name))
            cipher.doFinal(record, 2 + ivSize, record.size - 2 - ivSize)
        } catch (error: GeneralSecurityException) {
            return null
        }
        return String(plain, Charsets.UTF_8)
    }

    private fun nameOf(account: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(account.toByteArray(Charsets.UTF_8))
        return ENTRY + digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun label(name: String): ByteArray = (LABEL + name).toByteArray(Charsets.UTF_8)

    private fun key(): SecretKey = synchronized(KeyStoreLock) {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: generate()
    }

    private fun generate(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    private object KeyStoreLock

    companion object {
        const val TOO_LARGE = "the saved nonce state of an account may take at most 1 MiB, so nothing was signed"
        const val WRITE_FAILED = "the nonce state could not be written, so nothing was signed"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.quantova.qcore.nonces.key.1"
        private const val FOLDER = "com.quantova.qcore.nonces"
        private const val ENTRY = "account."
        private const val MANIFEST = "manifest"
        private const val LABEL = "com.quantova.qcore.nonces.2/"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256
        private const val MAX_ACCOUNTS = 4096
        private const val STATE_MAX = 1 shl 20
        private const val RECORD_MAX = STATE_MAX + 64L
        private const val VERSION: Byte = 2
        private val ENTRY_NAME = Regex("^account\\.[0-9a-f]{64}$")
    }
}
