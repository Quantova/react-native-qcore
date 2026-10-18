// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.os.SystemClock
import android.util.Base64
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import uniffi.quantova_qcore.SeedHandle
import uniffi.quantova_qcore.SigningSession

class QcoreModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext),
    LifecycleEventListener {

    override fun getName(): String = NAME

    private class BridgeException(message: String) : Exception(message)

    private val store by lazy { SeedStore(reactApplicationContext) }

    private val nonces by lazy { NonceStore(reactApplicationContext) }

    private val lock = Any()

    private val held = HashMap<String, SeedHandle>()

    private val heldAt = HashMap<String, Long>()

    private val worker = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "qcore-vault").apply { isDaemon = true }
    }

    private var idleTimer: ScheduledFuture<*>? = null

    private val revealGate by lazy { RevealGate() }

    init {
        reactContext.addLifecycleEventListener(this)
    }

    private fun expireIdle() {
        val now = SystemClock.elapsedRealtime()
        val stale = heldAt.filterValues { now - it >= IDLE_MILLIS }.keys.toList()
        for (alias in stale) {
            held.remove(alias)?.let { release(it) }
            heldAt.remove(alias)
        }
        armIdleTimer(now)
    }

    private fun armIdleTimer(now: Long) {
        idleTimer?.cancel(false)
        idleTimer = null
        val oldest = heldAt.values.minOrNull() ?: return
        val delay = (oldest + IDLE_MILLIS - now).coerceAtLeast(0L)
        idleTimer = worker.schedule({ synchronized(lock) { expireIdle() } }, delay, TimeUnit.MILLISECONDS)
    }

    private fun touch(alias: String) {
        val now = SystemClock.elapsedRealtime()
        heldAt[alias] = now
        armIdleTimer(now)
    }

    private fun drop(alias: String) {
        held.remove(alias)?.let { release(it) }
        heldAt.remove(alias)
        armIdleTimer(SystemClock.elapsedRealtime())
    }

    private fun forgetHeld() {
        idleTimer?.cancel(false)
        idleTimer = null
        held.values.forEach { release(it) }
        held.clear()
        heldAt.clear()
    }

    private val sessions = HashMap<String, SigningSession>()

    private fun u64(value: String, label: String): ULong =
        value.takeIf { v -> v.isNotEmpty() && v.all { it in '0'..'9' } }?.toULongOrNull()
            ?: throw BridgeException("the $label is not a whole number")

    private fun optionalU64(value: String, label: String): ULong? =
        if (value.isEmpty()) null else u64(value, label)

    private fun failure(error: Throwable): String {
        val message = when (error) {
            is uniffi.quantova_qcore.QcoreException.Invalid -> error.v1
            is BridgeException -> error.message ?: ""
            else -> error.message ?: error.toString()
        }
        return FAILURE_PREFIX + message
    }

    private inline fun guarded(block: () -> String): String =
        try {
            block()
        } catch (error: Throwable) {
            failure(error)
        }

    private fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    private fun hexBytes(hex: String, label: String): ByteArray {
        var start = 0
        var end = hex.length
        while (start < end && hex[start].isWhitespace()) start++
        while (end > start && hex[end - 1].isWhitespace()) end--
        if ((end - start) % 2 != 0) throw BridgeException("the $label is not hex")
        val out = ByteArray((end - start) / 2)
        for (i in out.indices) {
            val hi = nibble(hex[start + 2 * i])
            val lo = nibble(hex[start + 2 * i + 1])
            if (hi < 0 || lo < 0) {
                out.fill(0)
                throw BridgeException("the $label is not hex")
            }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun hexOf(bytes: ByteArray): String {
        val chars = CharArray(bytes.size * 2)
        try {
            for (i in bytes.indices) {
                val b = bytes[i].toInt() and 0xff
                chars[2 * i] = HEX[b ushr 4]
                chars[2 * i + 1] = HEX[b and 0x0f]
            }
            return String(chars)
        } finally {
            chars.fill('\u0000')
        }
    }

    private fun base64Bytes(text: String, label: String): ByteArray {
        val ascii = text.toByteArray(Charsets.US_ASCII)
        try {
            return Base64.decode(ascii, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw BridgeException("the $label is not base64")
        } finally {
            ascii.fill(0)
        }
    }

    private fun base64Of(bytes: ByteArray): String {
        val encoded = Base64.encode(bytes, Base64.NO_WRAP)
        try {
            return String(encoded, Charsets.US_ASCII)
        } finally {
            encoded.fill(0)
        }
    }

    private inline fun <T> withSeedHex(seedHex: String, use: (ByteArray) -> T): T {
        val seed = hexBytes(seedHex, "seed")
        try {
            return use(seed)
        } finally {
            seed.fill(0)
        }
    }

    private fun checkedAlias(alias: String): String {
        uniffi.quantova_qcore.checkSeedAlias(alias)
        return alias
    }

    private fun release(handle: SeedHandle) {
        handle.forget()
        handle.destroy()
    }

    private fun handleFor(alias: String): SeedHandle = synchronized(lock) {
        checkedAlias(alias)
        expireIdle()
        val handle = held[alias] ?: run {
            val seed = store.load(alias) ?: throw BridgeException("no seed is stored under this alias")
            try {
                SeedHandle.fromSeedBytes(seed)
            } finally {
                seed.fill(0)
            }
        }.also { held[alias] = it }
        touch(alias)
        handle
    }

    private fun keep(alias: String, make: () -> SeedHandle) {
        synchronized(lock) {
            if (store.has(checkedAlias(alias))) {
                throw BridgeException("a seed is already stored under this alias, forget it first")
            }
            val handle = make()
            try {
                val seed = handle.seedBytes()
                try {
                    store.save(alias, seed)
                } finally {
                    seed.fill(0)
                }
            } catch (error: Throwable) {
                release(handle)
                throw error
            }
            held.put(alias, handle)?.let { release(it) }
            touch(alias)
        }
    }

    private fun session(id: String): SigningSession =
        synchronized(lock) { sessions[id] } ?: throw BridgeException("no signing session is open under this id")

    private fun persist(session: SigningSession) {
        synchronized(lock) {
            for (account in session.savedAccounts()) nonces.save(account.key, account.state)
        }
    }

    private inline fun <T> recorded(session: SigningSession, change: () -> T): T {
        val out = change()
        persist(session)
        return out
    }

    override fun onHostResume() {}

    override fun onHostPause() {
        synchronized(lock) { forgetHeld() }
    }

    override fun onHostDestroy() {
        synchronized(lock) { forgetHeld() }
    }

    override fun invalidate() {
        reactApplicationContext.removeLifecycleEventListener(this)
        synchronized(lock) {
            forgetHeld()
            sessions.values.forEach { it.destroy() }
            sessions.clear()
        }
        worker.shutdownNow()
        super.invalidate()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun generateSeed(): String = guarded {
        val seed = uniffi.quantova_qcore.generateSeed()
        try {
            hexOf(seed)
        } finally {
            seed.fill(0)
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vmCallFee(transferFee: String, meterLimit: String): String = guarded {
        uniffi.quantova_qcore.vmCallFee(transferFee, u64(meterLimit, "meter limit"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun mnemonicFromSeed(seedHex: String): String = guarded {
        withSeedHex(seedHex) { seed ->
            val phrase = uniffi.quantova_qcore.mnemonicFromSeed(seed)
            try {
                String(phrase, Charsets.UTF_8)
            } finally {
                phrase.fill(0)
            }
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun seedFromMnemonic(phrase: String): String = guarded {
        val bytes = phrase.toByteArray(Charsets.UTF_8)
        try {
            val seed = uniffi.quantova_qcore.seedFromMnemonic(bytes)
            try {
                hexOf(seed)
            } finally {
                seed.fill(0)
            }
        } finally {
            bytes.fill(0)
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun address(seedHex: String, index: String): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.address(seed, u64(index, "index"))
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun validAddress(address: String): Boolean =
        try {
            uniffi.quantova_qcore.validAddress(address)
        } catch (error: Throwable) {
            false
        }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sameAddress(a: String, b: String): Boolean =
        try {
            uniffi.quantova_qcore.sameAddress(a, b)
        } catch (error: Throwable) {
            false
        }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun lookalikeOf(candidate: String, known: String): String =
        try {
            uniffi.quantova_qcore.lookalikeOf(candidate, known.split(",").filter { it.isNotEmpty() }) ?: ""
        } catch (error: Throwable) {
            ""
        }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signTransfer(
        seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
    ): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.signTransfer(
                seed,
                u64(index, "index"),
                to,
                amount,
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signCall(
        seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.signCall(
                seed,
                u64(index, "index"),
                target,
                argsHex,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signRegister(
        seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
    ): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.signRegister(
                seed,
                u64(index, "index"),
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun chainIdFromName(name: String): String = guarded {
        uniffi.quantova_qcore.chainIdFromName(name).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signPayableCall(
        seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        value: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.signPayableCall(
                seed,
                u64(index, "index"),
                target,
                argsHex,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                value,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signAssetCall(
        seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        assetIssuer: String,
        amount: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        withSeedHex(seedHex) { seed ->
            uniffi.quantova_qcore.signAssetCall(
                seed,
                u64(index, "index"),
                target,
                argsHex,
                assetIssuer,
                amount,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun nameKey(label: String): String = guarded {
        uniffi.quantova_qcore.nameKey(label)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun mapSlotKey(mapDomainTag: String, keyAddressHex: String): String = guarded {
        uniffi.quantova_qcore.mapSlotKey(u64(mapDomainTag, "map domain tag"), keyAddressHex)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun mapAddrWordKey(mapDomainTag: String, key32Hex: String, word: String): String = guarded {
        uniffi.quantova_qcore.mapAddrWordKey(u64(mapDomainTag, "map domain tag"), key32Hex, u64(word, "word"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun scalarSlotKey(slot: String): String = guarded {
        uniffi.quantova_qcore.scalarSlotKey(u64(slot, "slot"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultCreate(alias: String): String = guarded {
        keep(alias) { SeedHandle.generate() }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultImportPhrase(alias: String, phraseBase64: String): String = guarded {
        keep(alias) {
            val phrase = base64Bytes(phraseBase64, "phrase")
            try {
                SeedHandle.fromPhraseBytes(phrase)
            } finally {
                phrase.fill(0)
            }
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultImportSeed(alias: String, seedBase64: String): String = guarded {
        keep(alias) {
            val seed = base64Bytes(seedBase64, "seed")
            try {
                SeedHandle.fromSeedBytes(seed)
            } finally {
                seed.fill(0)
            }
        }
        ""
    }

    @ReactMethod
    fun vaultRevealPhrase(alias: String, title: String, subtitle: String, promise: Promise) {
        val activity = try {
            synchronized(lock) {
                if (!store.has(checkedAlias(alias))) throw BridgeException("no seed is stored under this alias")
            }
            reactApplicationContext.currentActivity
                ?: throw BridgeException("the phrase can be revealed only while the app is in the foreground")
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        revealGate.authorize(activity, title, subtitle) { refused ->
            try {
                worker.execute { promise.resolve(if (refused != null) failure(refused) else guarded { revealNow(alias) }) }
            } catch (error: Throwable) {
                promise.resolve(failure(error))
            }
        }
    }

    private fun revealNow(alias: String): String {
        val handle = synchronized(lock) {
            val seed = store.load(checkedAlias(alias)) ?: throw BridgeException("no seed is stored under this alias")
            try {
                SeedHandle.fromSeedBytes(seed)
            } finally {
                seed.fill(0)
            }
        }
        try {
            val phrase = handle.phraseBytes()
            try {
                return base64Of(phrase)
            } finally {
                phrase.fill(0)
            }
        } finally {
            release(handle)
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultHas(alias: String): String = guarded {
        synchronized(lock) {
            (held.containsKey(checkedAlias(alias)) || store.has(alias)).toString()
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultClose(alias: String): String = guarded {
        synchronized(lock) { drop(checkedAlias(alias)) }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultCloseAll(): String = guarded {
        synchronized(lock) { forgetHeld() }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultForget(alias: String): String = guarded {
        synchronized(lock) {
            drop(checkedAlias(alias))
            store.remove(alias)
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultAddress(alias: String, index: String): String = guarded {
        handleFor(alias).address(u64(index, "index"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultSignTransfer(
        alias: String,
        sessionId: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
    ): String = guarded {
        val session = session(sessionId)
        recorded(session) {
            handleFor(alias).signTransfer(
                session,
                u64(index, "index"),
                to,
                amount,
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultSignCall(
        alias: String,
        sessionId: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        val session = session(sessionId)
        recorded(session) {
            handleFor(alias).signCall(
                session,
                u64(index, "index"),
                target,
                argsHex,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultSignRegister(
        alias: String,
        sessionId: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
    ): String = guarded {
        val session = session(sessionId)
        recorded(session) {
            handleFor(alias).signRegister(
                session,
                u64(index, "index"),
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultSignPayableCall(
        alias: String,
        sessionId: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        value: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        val session = session(sessionId)
        recorded(session) {
            handleFor(alias).signPayableCall(
                session,
                u64(index, "index"),
                target,
                argsHex,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                value,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultSignAssetCall(
        alias: String,
        sessionId: String,
        index: String,
        target: String,
        argsHex: String,
        assetIssuer: String,
        amount: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String,
        validUntil: String,
        transferFee: String,
        head: String,
    ): String = guarded {
        val session = session(sessionId)
        recorded(session) {
            handleFor(alias).signAssetCall(
                session,
                u64(index, "index"),
                target,
                argsHex,
                assetIssuer,
                amount,
                u64(nonce, "nonce"),
                u64(meterLimit, "meter limit"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                transferFee,
                u64(head, "head"),
            )
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun checkValidUntil(validUntil: String, head: String): String = guarded {
        uniffi.quantova_qcore.checkValidUntil(u64(validUntil, "valid until"), u64(head, "head"))
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun boundedValidUntil(
        chainName: String,
        head: String,
        wallSecs: String,
        floor: String,
        floorAgeSecs: String,
    ): String = guarded {
        uniffi.quantova_qcore.boundedValidUntil(
            chainName,
            u64(head, "head"),
            u64(wallSecs, "wall clock"),
            optionalU64(floor, "floor"),
            u64(floorAgeSecs, "floor age"),
        ).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun headCeiling(chainName: String, wallSecs: String): String = guarded {
        uniffi.quantova_qcore.headCeiling(chainName, u64(wallSecs, "wall clock")).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun genesisSecs(chainName: String): String = guarded {
        uniffi.quantova_qcore.genesisSecs(chainName).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun maxValidityBlocks(): String = guarded {
        uniffi.quantova_qcore.maxValidityBlocks().toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun defaultValidityBlocks(): String = guarded {
        uniffi.quantova_qcore.defaultValidityBlocks().toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun checkOrderExpiry(expiry: String, nowSecs: String): String = guarded {
        uniffi.quantova_qcore.checkOrderExpiry(u64(expiry, "order expiry"), u64(nowSecs, "wall clock"))
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun maxOrderLifetimeSecs(): String = guarded {
        uniffi.quantova_qcore.maxOrderLifetimeSecs().toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun verifyFinality(chainId: String, headerHex: String, certificateHex: String, rosterJson: String): String = guarded {
        uniffi.quantova_qcore.verifyFinality(u64(chainId, "chain id"), headerHex, certificateHex, rosterJson)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun verifyEvent(eventRootHex: String, leafHex: String, stepsJson: String): String = guarded {
        uniffi.quantova_qcore.verifyEvent(eventRootHex, leafHex, stepsJson).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun verifyTransaction(transactionRootHex: String, txId: String, leafHex: String, stepsJson: String): String = guarded {
        uniffi.quantova_qcore.verifyTransaction(transactionRootHex, txId, leafHex, stepsJson).toString()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun confirmTransaction(
        chainId: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String,
    ): String = guarded {
        uniffi.quantova_qcore.confirmTransaction(u64(chainId, "chain id"), txId, proofJson, finalityJson, rosterJson)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun decodeEvent(leafHex: String): String = guarded {
        uniffi.quantova_qcore.decodeEvent(leafHex)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionOpen(addressBook: String): String = guarded {
        val book = addressBook.split(",").filter { it.isNotEmpty() }
        synchronized(lock) {
            if (sessions.size >= MAX_SESSIONS) throw BridgeException(TOO_MANY_SESSIONS)
        }
        val opened = if (book.isEmpty()) SigningSession() else SigningSession.withAddressBook(book)
        try {
            synchronized(lock) { nonces.loadAll().forEach { opened.restore(it) } }
        } catch (error: Throwable) {
            opened.destroy()
            throw error
        }
        val id = UUID.randomUUID().toString()
        val admitted = synchronized(lock) {
            (sessions.size < MAX_SESSIONS).also { if (it) sessions[id] = opened }
        }
        if (!admitted) {
            opened.destroy()
            throw BridgeException(TOO_MANY_SESSIONS)
        }
        id
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionClose(id: String): String = guarded {
        synchronized(lock) { sessions.remove(id) }?.destroy()
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionKnown(id: String): String = guarded {
        session(id).known().joinToString(",")
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionRememberAddress(id: String, address: String): String = guarded {
        session(id).rememberAddress(address)
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionCheckTarget(id: String, address: String): String = guarded {
        session(id).checkTarget(address)
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionSlot(id: String, key: String, reported: String, expected: String, order: Boolean): String = guarded {
        val session = session(id)
        recorded(session) {
            session.slot(
                key,
                u64(reported, "reported nonce"),
                optionalU64(expected, "expected nonce"),
                order,
            ).toString()
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionSigned(id: String, key: String, slot: String): String = guarded {
        val session = session(id)
        recorded(session) { session.signed(key, u64(slot, "slot")) }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionRelease(id: String, key: String, slot: String): String = guarded {
        val session = session(id)
        recorded(session) { session.release(key, u64(slot, "slot")) }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionReleasePending(id: String, key: String): String = guarded {
        val session = session(id)
        recorded(session) { session.releasePending(key) }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionOutcome(id: String, key: String, slot: String, accepted: Boolean): String = guarded {
        val session = session(id)
        recorded(session) { session.outcome(key, u64(slot, "slot"), accepted) }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionNextNonce(id: String, key: String): String = guarded {
        session(id).nextNonce(key)?.toString() ?: ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionIsHeld(id: String, key: String, slot: String): String = guarded {
        session(id).isHeld(key, u64(slot, "slot")).toString()
    }

    companion object {
        const val NAME = "Qcore"
        const val FAILURE_PREFIX = "\u0000QCORE_ERROR:"
        private const val IDLE_MILLIS = 120_000L
        private const val MAX_SESSIONS = 64
        private const val TOO_MANY_SESSIONS = "too many signing sessions are open, close one first"
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
