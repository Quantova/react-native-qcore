// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.quantova_qcore.NonceBatch
import uniffi.quantova_qcore.NonceStored

internal class NonceStore(context: Context) {

    private val folder = File(context.applicationContext.noBackupFilesDir, FOLDER).apply {
        if (!isDirectory && !mkdirs()) throw IllegalStateException("the nonce state folder could not be created")
    }

    private val lockPath = File(folder, LOCK).path

    private class Held(val file: RandomAccessFile, val dev: Long, val ino: Long)

    private class Header(val tag: String, val alias: String, val next: String?, val end: Int)

    private val held = ThreadLocal<Held?>()

    fun <T> locked(block: () -> T): T {
        repeat(LOCK_ATTEMPTS) {
            val file = try {
                RandomAccessFile(lockPath, "rw")
            } catch (error: IOException) {
                throw IllegalStateException(LOCK_FAILED)
            }
            try {
                val lock = try {
                    file.channel.lock()
                } catch (error: IOException) {
                    throw IllegalStateException(LOCK_FAILED)
                }
                try {
                    val opened = try {
                        Os.fstat(file.fd)
                    } catch (error: ErrnoException) {
                        throw IllegalStateException(LOCK_FAILED)
                    }
                    val named = named()
                    if (named != null && OsConstants.S_ISLNK(named.st_mode)) throw IllegalStateException(LOCK_FAILED)
                    if (named != null && named.st_dev == opened.st_dev && named.st_ino == opened.st_ino) {
                        held.set(Held(file, opened.st_dev, opened.st_ino))
                        try {
                            return block()
                        } finally {
                            held.set(null)
                        }
                    }
                } finally {
                    lock.release()
                }
            } finally {
                file.close()
            }
        }
        throw IllegalStateException(LOCK_FAILED)
    }

    private fun named(): StructStat? =
        try {
            Os.lstat(lockPath)
        } catch (error: ErrnoException) {
            null
        }

    private fun guard() {
        val current = held.get() ?: throw IllegalStateException(LOCK_FAILED)
        val named = named() ?: throw IllegalStateException(LOCK_FAILED)
        if (OsConstants.S_ISLNK(named.st_mode) || named.st_dev != current.dev || named.st_ino != current.ino) {
            throw IllegalStateException(LOCK_FAILED)
        }
    }

    fun stored(account: String?, known: String?, boot: String?, uptimeMs: Long): NonceStored {
        val manifestFile = File(folder, MANIFEST)
        val aliases = NonceKeys.manifestAliases()
        val present = manifestFile.exists() || aliases.isNotEmpty()
        var tag: String? = null
        var manifest: String? = null
        if (manifestFile.exists()) {
            val record = read(MANIFEST, MANIFEST_FILE_MAX)
            val header = record?.let { header(it) }
            if (record != null && header != null) {
                tag = header.tag
                val others = aliases.filter { it != header.alias }
                val counter = counterOf(header.alias) ?: -1L
                val unexplained = others.any { other ->
                    val newer = (counterOf(other) ?: -1L) > counter
                    newer && other != header.next
                }
                if (unexplained) {
                    tag = null
                } else if (others.isNotEmpty() || tag != known) {
                    manifest = openManifest(record, header)
                    if (manifest == null) {
                        tag = null
                    } else if (others.isNotEmpty()) {
                        guard()
                        deleteKeys(others)
                    }
                }
            }
        }
        val records = !present && (folder.list()?.any { ENTRY_NAME.matches(it) } ?: false)
        val name = account?.let { nameOf(it) }
        val recordPresent = name != null && File(folder, name).exists()
        val record = if (name != null && recordPresent) open(name, NonceKeys.recordKey(), label(name), RECORD_FILE_MAX) else null
        return NonceStored(present, manifest, tag, records, account, recordPresent, record, boot, uptimeMs.coerceAtLeast(0L).toULong())
    }

    fun commit(batch: NonceBatch): String {
        guard()
        val plain = batch.manifest.toByteArray(Charsets.UTF_8)
        if (plain.size > MANIFEST_MAX) throw IllegalStateException(MANIFEST_TOO_LARGE)
        for (record in batch.records) {
            if (record.state.toByteArray(Charsets.UTF_8).size > STATE_MAX) throw IllegalStateException(TOO_LARGE)
        }
        val aliases = NonceKeys.manifestAliases()
        val current = read(MANIFEST, MANIFEST_FILE_MAX)?.let { header(it) }?.alias?.takeIf { it in aliases }
        val tag = if (!batch.rotate && current != null) {
            val key = NonceKeys.manifestKey(current) ?: throw IllegalStateException(WRITE_FAILED)
            writeManifest(plain, current, null, key)
        } else {
            val counter = (aliases.mapNotNull { counterOf(it) }.maxOrNull() ?: 0L) + 1L
            val next = aliasOf(counter)
            if (current != null) {
                val key = NonceKeys.manifestKey(current) ?: throw IllegalStateException(WRITE_FAILED)
                writeManifest(plain, current, next, key)
            }
            val key = try {
                NonceKeys.newManifestKey(next)
            } catch (error: Throwable) {
                throw IllegalStateException(WRITE_FAILED)
            }
            writeManifest(plain, next, null, key)
        }
        for (record in batch.records) save(record.account, record.state)
        val written = tag.substringBeforeLast('.')
        deleteKeys(NonceKeys.manifestAliases().filter { it != written })
        return tag
    }

    private fun save(account: String, state: String) {
        val name = nameOf(account)
        val plain = state.toByteArray(Charsets.UTF_8)
        if (plain.size > STATE_MAX) throw IllegalStateException(TOO_LARGE)
        write(name, seal(plain, NonceKeys.recordKey(), label(name), ByteArray(0)))
    }

    private fun writeManifest(plain: ByteArray, alias: String, next: String?, key: SecretKey): String {
        val tag = alias + "." + randomHex(WRITE_ID_BYTES)
        val tagBytes = tag.toByteArray(Charsets.US_ASCII)
        val nextBytes = (next ?: "").toByteArray(Charsets.US_ASCII)
        val header = ByteArray(2 + tagBytes.size + nextBytes.size)
        header[0] = tagBytes.size.toByte()
        System.arraycopy(tagBytes, 0, header, 1, tagBytes.size)
        header[1 + tagBytes.size] = nextBytes.size.toByte()
        System.arraycopy(nextBytes, 0, header, 2 + tagBytes.size, nextBytes.size)
        val aad = manifestLabel(byteArrayOf(VERSION) + header)
        val sealed = try {
            seal(plain, key, aad, header)
        } catch (error: GeneralSecurityException) {
            throw IllegalStateException(WRITE_FAILED)
        }
        write(MANIFEST, sealed)
        return tag
    }

    private fun deleteKeys(aliases: List<String>) {
        for (alias in aliases) {
            try {
                NonceKeys.delete(alias)
            } catch (error: Throwable) {
                throw IllegalStateException(KEY_DELETE_FAILED)
            }
        }
        if (NonceKeys.manifestAliases().any { it in aliases }) throw IllegalStateException(KEY_DELETE_FAILED)
    }

    fun remove(account: String) {
        guard()
        val file = File(folder, nameOf(account))
        AtomicFile(file).delete()
        if (file.exists()) throw IllegalStateException("the saved nonce state could not be removed")
    }

    fun clearRecords() {
        guard()
        folder.listFiles()?.filter { it.name != LOCK && it.name != MANIFEST }?.forEach { it.delete() }
        if (folder.list()?.any { it != LOCK && it != MANIFEST } == true) throw IllegalStateException("the saved nonce state could not be removed")
    }

    private fun seal(plain: ByteArray, key: SecretKey, aad: ByteArray, header: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plain)
        val iv = cipher.iv
        val record = ByteArray(1 + header.size + 1 + iv.size + sealed.size)
        record[0] = VERSION
        System.arraycopy(header, 0, record, 1, header.size)
        record[1 + header.size] = iv.size.toByte()
        System.arraycopy(iv, 0, record, 2 + header.size, iv.size)
        System.arraycopy(sealed, 0, record, 2 + header.size + iv.size, sealed.size)
        return record
    }

    private fun write(name: String, record: ByteArray) {
        guard()
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

    private fun read(name: String, limit: Long): ByteArray? {
        val file = File(folder, name)
        if (!file.isFile || file.length() > limit) return null
        return try {
            AtomicFile(file).readFully()
        } catch (error: IOException) {
            null
        }
    }

    private fun open(name: String, key: SecretKey, aad: ByteArray, limit: Long): String? {
        val record = read(name, limit) ?: return null
        return unseal(record, 1, key, aad)
    }

    private fun header(record: ByteArray): Header? {
        if (record.size < 3 || record[0] != VERSION) return null
        val tagSize = record[1].toInt() and 0xff
        if (record.size < 3 + tagSize) return null
        val tag = String(record, 2, tagSize, Charsets.US_ASCII)
        val nextSize = record[2 + tagSize].toInt() and 0xff
        val end = 3 + tagSize + nextSize
        if (record.size <= end) return null
        val next = if (nextSize == 0) null else String(record, 3 + tagSize, nextSize, Charsets.US_ASCII)
        if (!TAG_NAME.matches(tag)) return null
        if (next != null && !ALIAS_NAME.matches(next)) return null
        return Header(tag, tag.substringBeforeLast('.'), next, end)
    }

    private fun openManifest(record: ByteArray, header: Header): String? {
        val key = try {
            NonceKeys.manifestKey(header.alias)
        } catch (error: Throwable) {
            null
        } ?: return null
        return unseal(record, header.end, key, manifestLabel(record.copyOfRange(0, header.end)))
    }

    private fun unseal(record: ByteArray, at: Int, key: SecretKey, aad: ByteArray): String? {
        if (record.size < at + 1 || record[0] != VERSION) return null
        val ivSize = record[at].toInt() and 0xff
        val body = at + 1 + ivSize
        if (ivSize == 0 || record.size <= body) return null
        val plain = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, record, at + 1, ivSize))
            cipher.updateAAD(aad)
            cipher.doFinal(record, body, record.size - body)
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

    private fun manifestLabel(header: ByteArray): ByteArray = (LABEL + MANIFEST + "/").toByteArray(Charsets.UTF_8) + header

    private fun randomHex(size: Int): String {
        val bytes = ByteArray(size)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    companion object {
        const val TOO_LARGE = "the saved nonce state of an account may take at most 1 MiB, so nothing was signed"
        const val MANIFEST_TOO_LARGE = "the saved nonce manifest may take at most 1.5 MiB, so nothing was signed"
        const val WRITE_FAILED = "the nonce state could not be written, so nothing was signed"
        const val KEY_DELETE_FAILED = "an earlier device key of the nonce manifest could not be deleted, so nothing was signed, try again"
        const val LOCK_FAILED = "the nonce state could not be locked against the other processes of this app, so nothing was signed"
        const val MANIFEST_ALIAS = "com.quantova.qcore.nonces.manifest."
        private const val FOLDER = "com.quantova.qcore.nonces"
        private const val ENTRY = "account."
        private const val MANIFEST = "manifest"
        private const val LOCK = "lock"
        private const val LABEL = "com.quantova.qcore.nonces.4/"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val STATE_MAX = 1 shl 20
        private const val MANIFEST_MAX = 3 shl 19
        private const val RECORD_FILE_MAX = STATE_MAX + 64L
        private const val MANIFEST_FILE_MAX = MANIFEST_MAX + 320L
        private const val LOCK_ATTEMPTS = 8
        private const val WRITE_ID_BYTES = 8
        private const val VERSION: Byte = 4
        private val ENTRY_NAME = Regex("^account\\.[0-9a-f]{64}$")
        private val ALIAS_NAME = Regex("^com\\.quantova\\.qcore\\.nonces\\.manifest\\.[0-9a-f]{16}$")
        private val TAG_NAME = Regex("^com\\.quantova\\.qcore\\.nonces\\.manifest\\.[0-9a-f]{16}\\.[0-9a-f]{16}$")

        fun aliasOf(counter: Long): String = MANIFEST_ALIAS + "%016x".format(counter)

        fun counterOf(alias: String): Long? =
            if (ALIAS_NAME.matches(alias)) alias.substring(MANIFEST_ALIAS.length).toLongOrNull(16) else null
    }
}

private object NonceKeys {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val RECORD_ALIAS = "com.quantova.qcore.nonces.key.1"
    private const val KEY_BITS = 256

    fun recordKey(): SecretKey = synchronized(this) {
        (keyStore().getKey(RECORD_ALIAS, null) as? SecretKey) ?: generate(RECORD_ALIAS)
    }

    fun manifestKey(alias: String): SecretKey? = synchronized(this) {
        keyStore().getKey(alias, null) as? SecretKey
    }

    fun newManifestKey(alias: String): SecretKey = synchronized(this) {
        generate(alias)
    }

    fun manifestAliases(): List<String> = synchronized(this) {
        keyStore().aliases().toList().filter { it.startsWith(NonceStore.MANIFEST_ALIAS) }
    }

    fun delete(alias: String) = synchronized(this) {
        keyStore().deleteEntry(alias)
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun generate(alias: String): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
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
}
