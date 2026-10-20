// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.app.ActivityManager
import android.os.SystemClock
import android.provider.Settings
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

    private val nonceWorker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "qcore-nonces").apply { isDaemon = true }
    }

    private var idleTimer: ScheduledFuture<*>? = null

    @Volatile
    private var closed = false

    private val revealGate by lazy { RevealGate(reactApplicationContext) }

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

    private fun answer(promise: Promise, work: () -> String) {
        try {
            nonceWorker.execute { promise.resolve(guarded(work)) }
        } catch (error: Throwable) {
            promise.resolve(failure(BridgeException(CLOSED)))
        }
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

    private fun ensureOpen() {
        if (closed) throw BridgeException(CLOSED)
    }

    private fun hold(alias: String, handle: SeedHandle) {
        try {
            touch(alias)
        } catch (error: Throwable) {
            heldAt.remove(alias)
            release(handle)
            throw error
        }
        held.put(alias, handle)?.let { if (it !== handle) release(it) }
    }

    private fun ensureForeground() {
        val state = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(state)
        if (state.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
            forgetHeld()
            throw BridgeException(BACKGROUND)
        }
    }

    private fun handleFor(alias: String): SeedHandle = synchronized(lock) {
        ensureOpen()
        checkedAlias(alias)
        ensureForeground()
        expireIdle()
        held[alias]?.let { found ->
            touch(alias)
            return@synchronized found
        }
        val seed = store.load(alias) ?: throw BridgeException("no seed is stored under this alias")
        val handle = try {
            SeedHandle.fromSeedBytes(seed)
        } finally {
            seed.fill(0)
        }
        hold(alias, handle)
        handle
    }

    private fun keep(alias: String, make: () -> SeedHandle) {
        synchronized(lock) {
            ensureOpen()
            ensureForeground()
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
            hold(alias, handle)
        }
    }

    private fun session(id: String): SigningSession =
        synchronized(lock) {
            ensureOpen()
            sessions[id]
        } ?: throw BridgeException("no signing session is open under this id")

    private fun persistNonces() {
        val batch = uniffi.quantova_qcore.nonceBatch() ?: return
        val tag = nonces.commit(batch)
        uniffi.quantova_qcore.nonceCommitted(tag)
    }

    private fun bootId(): String? =
        try {
            val count = Settings.Global.getInt(reactApplicationContext.contentResolver, Settings.Global.BOOT_COUNT, -1)
            if (count >= 0) "android-boot-$count" else null
        } catch (error: Throwable) {
            null
        }

    private fun <T> synced(account: String?, change: () -> T): T = synchronized(NONCE_LOCK) {
        ensureOpen()
        nonces.locked {
            val stored = nonces.stored(account, uniffi.quantova_qcore.nonceManifestTag(), bootId(), SystemClock.elapsedRealtime())
            uniffi.quantova_qcore.nonceSync(stored)
            change()
        }
    }

    private fun <T> recorded(account: String, change: () -> T): T = synced(account) {
        val out = try {
            change()
        } catch (error: Throwable) {
            try {
                persistNonces()
            } catch (ignored: Throwable) {
            }
            throw error
        }
        persistNonces()
        out
    }

    private fun account(chainId: String, genesisHex: String, key: String): String =
        uniffi.quantova_qcore.nonceAccount(u64(chainId, "chain id"), genesisHex, key)

    private fun signer(alias: String, index: String, chainId: String, genesisHex: String): Pair<SeedHandle, String> {
        val handle = handleFor(alias)
        return handle to uniffi.quantova_qcore.nonceAccount(u64(chainId, "chain id"), genesisHex, handle.address(u64(index, "index")))
    }

    private class ResetTarget(val chainId: ULong, val genesisHex: String, val key: String)

    private fun resetTarget(chainId: String, genesisHex: String, key: String): ResetTarget? = when {
        chainId.isEmpty() && genesisHex.isEmpty() && key.isEmpty() -> null
        chainId.isNotEmpty() && genesisHex.isNotEmpty() && key.isNotEmpty() -> ResetTarget(u64(chainId, "chain id"), genesisHex, key)
        else -> throw BridgeException("name the chain id, the genesis hash and the key to reset one account, or none of them to reset every account")
    }

    private fun resetNow(chainId: String, genesisHex: String, key: String) {
        val target = resetTarget(chainId, genesisHex, key)
        val account = target?.let { uniffi.quantova_qcore.nonceAccount(it.chainId, it.genesisHex, it.key) }
        synced(account) {
            val reset = uniffi.quantova_qcore.resetNonceState(target?.chainId, target?.genesisHex, target?.key)
            val tag = nonces.commit(uniffi.quantova_qcore.NonceBatch(reset.manifest, emptyList(), true))
            if (target == null) {
                nonces.clearRecords()
            } else {
                reset.removed.forEach { nonces.remove(it) }
            }
            uniffi.quantova_qcore.nonceCommitted(tag)
        }
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
            closed = true
            forgetHeld()
            sessions.values.forEach { it.destroy() }
            sessions.clear()
        }
        worker.shutdownNow()
        nonceWorker.shutdown()
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
        genesisHex: String,
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
                genesisHex,
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
        genesisHex: String,
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
                genesisHex,
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
        genesisHex: String,
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
                genesisHex,
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
        genesisHex: String,
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
                genesisHex,
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
        genesisHex: String,
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
                genesisHex,
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
                ensureOpen()
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

    @ReactMethod
    fun vaultResetNonceState(alias: String, chainId: String, genesisHex: String, key: String, title: String, subtitle: String, promise: Promise) {
        val activity = try {
            resetTarget(chainId, genesisHex, key)
            synchronized(lock) {
                ensureOpen()
                if (!store.has(checkedAlias(alias))) throw BridgeException("no seed is stored under this alias")
            }
            reactApplicationContext.currentActivity
                ?: throw BridgeException("the nonce state can be reset only while the app is in the foreground")
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        revealGate.authorize(
            activity,
            title.ifEmpty { RESET_TITLE },
            subtitle,
            RESET_CANCELLED,
            RESET_UNSUPPORTED,
        ) { refused ->
            try {
                worker.execute {
                    promise.resolve(
                        if (refused != null) {
                            failure(refused)
                        } else {
                            guarded {
                                resetNow(chainId, genesisHex, key)
                                ""
                            }
                        },
                    )
                }
            } catch (error: Throwable) {
                promise.resolve(failure(error))
            }
        }
    }

    @ReactMethod
    fun vaultAcknowledgeImportedHistory(alias: String, chainId: String, genesisHex: String, key: String, title: String, subtitle: String, promise: Promise) {
        val activity = try {
            if (chainId.isEmpty() || genesisHex.isEmpty() || key.isEmpty()) throw BridgeException(ACKNOWLEDGE_NEEDS_ACCOUNT)
            account(chainId, genesisHex, key)
            synchronized(lock) {
                ensureOpen()
                if (!store.has(checkedAlias(alias))) throw BridgeException("no seed is stored under this alias")
            }
            reactApplicationContext.currentActivity
                ?: throw BridgeException("the imported history can be acknowledged only while the app is in the foreground")
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        revealGate.authorize(
            activity,
            title.ifEmpty { ACKNOWLEDGE_TITLE },
            subtitle,
            ACKNOWLEDGE_CANCELLED,
            ACKNOWLEDGE_UNSUPPORTED,
        ) { refused ->
            try {
                worker.execute {
                    promise.resolve(
                        if (refused != null) {
                            failure(refused)
                        } else {
                            guarded {
                                recorded(account(chainId, genesisHex, key)) {
                                    uniffi.quantova_qcore.acknowledgeImportedHistory(u64(chainId, "chain id"), genesisHex, key)
                                }
                                ""
                            }
                        },
                    )
                }
            } catch (error: Throwable) {
                promise.resolve(failure(error))
            }
        }
    }

    private fun revealNow(alias: String): String {
        val handle = synchronized(lock) {
            ensureOpen()
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
    fun vaultStorageLevel(): String = guarded {
        synchronized(lock) {
            ensureOpen()
            store.level()
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultHas(alias: String): String = guarded {
        synchronized(lock) {
            ensureOpen()
            (held.containsKey(checkedAlias(alias)) || store.has(alias)).toString()
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultClose(alias: String): String = guarded {
        synchronized(lock) {
            ensureOpen()
            drop(checkedAlias(alias))
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultCloseAll(): String = guarded {
        synchronized(lock) {
            ensureOpen()
            forgetHeld()
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultForget(alias: String): String = guarded {
        synchronized(lock) {
            ensureOpen()
            drop(checkedAlias(alias))
            store.remove(alias)
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultAddress(alias: String, index: String): String = guarded {
        handleFor(alias).address(u64(index, "index"))
    }

    @ReactMethod
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
        genesisHex: String,
        promise: Promise,
    ) = answer(promise) {
        val session = session(sessionId)
        val (handle, account) = signer(alias, index, chainId, genesisHex)
        recorded(account) {
            handle.signTransfer(
                session,
                u64(index, "index"),
                to,
                amount,
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
                genesisHex,
            )
        }
    }

    @ReactMethod
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
        genesisHex: String,
        promise: Promise,
    ) = answer(promise) {
        val session = session(sessionId)
        val (handle, account) = signer(alias, index, chainId, genesisHex)
        recorded(account) {
            handle.signCall(
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
                genesisHex,
            )
        }
    }

    @ReactMethod
    fun vaultSignRegister(
        alias: String,
        sessionId: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String,
        promise: Promise,
    ) = answer(promise) {
        val session = session(sessionId)
        val (handle, account) = signer(alias, index, chainId, genesisHex)
        recorded(account) {
            handle.signRegister(
                session,
                u64(index, "index"),
                u64(nonce, "nonce"),
                fee,
                u64(chainId, "chain id"),
                u64(validUntil, "valid until"),
                u64(head, "head"),
                genesisHex,
            )
        }
    }

    @ReactMethod
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
        genesisHex: String,
        promise: Promise,
    ) = answer(promise) {
        val session = session(sessionId)
        val (handle, account) = signer(alias, index, chainId, genesisHex)
        recorded(account) {
            handle.signPayableCall(
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
                genesisHex,
            )
        }
    }

    @ReactMethod
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
        genesisHex: String,
        promise: Promise,
    ) = answer(promise) {
        val session = session(sessionId)
        val (handle, account) = signer(alias, index, chainId, genesisHex)
        recorded(account) {
            handle.signAssetCall(
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
                genesisHex,
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
    fun verifyFinality(chainId: String, genesisHex: String, headerHex: String, certificateHex: String, rosterJson: String): String = guarded {
        uniffi.quantova_qcore.verifyFinality(u64(chainId, "chain id"), genesisHex, headerHex, certificateHex, rosterJson)
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
        genesisHex: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String,
    ): String = guarded {
        uniffi.quantova_qcore.confirmTransaction(u64(chainId, "chain id"), genesisHex, txId, proofJson, finalityJson, rosterJson)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun decodeEvent(leafHex: String): String = guarded {
        uniffi.quantova_qcore.decodeEvent(leafHex)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun sessionOpen(addressBook: String): String = guarded {
        val book = addressBook.split(",").filter { it.isNotEmpty() }
        synchronized(lock) {
            ensureOpen()
            if (sessions.size >= MAX_SESSIONS) throw BridgeException(TOO_MANY_SESSIONS)
        }
        val opened = if (book.isEmpty()) SigningSession() else SigningSession.withAddressBook(book)
        val id = UUID.randomUUID().toString()
        val admitted = synchronized(lock) {
            (!closed && sessions.size < MAX_SESSIONS).also { if (it) sessions[id] = opened }
        }
        if (!admitted) {
            opened.destroy()
            throw BridgeException(if (closed) CLOSED else TOO_MANY_SESSIONS)
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

    @ReactMethod
    fun sessionSlot(id: String, chainId: String, genesisHex: String, key: String, reported: String, expected: String, order: Boolean, promise: Promise) = answer(promise) {
        val session = session(id)
        recorded(account(chainId, genesisHex, key)) {
            session.slot(
                u64(chainId, "chain id"),
                genesisHex,
                key,
                u64(reported, "reported nonce"),
                optionalU64(expected, "expected nonce"),
                order,
            ).toString()
        }
    }

    @ReactMethod
    fun sessionSigned(id: String, chainId: String, genesisHex: String, key: String, slot: String, promise: Promise) = answer(promise) {
        val session = session(id)
        recorded(account(chainId, genesisHex, key)) { session.signed(u64(chainId, "chain id"), genesisHex, key, u64(slot, "slot")) }
        ""
    }

    @ReactMethod
    fun sessionRelease(id: String, chainId: String, genesisHex: String, key: String, slot: String, promise: Promise) = answer(promise) {
        val session = session(id)
        recorded(account(chainId, genesisHex, key)) { session.release(u64(chainId, "chain id"), genesisHex, key, u64(slot, "slot")) }
        ""
    }

    @ReactMethod
    fun sessionReleasePending(id: String, chainId: String, genesisHex: String, key: String, promise: Promise) = answer(promise) {
        val session = session(id)
        recorded(account(chainId, genesisHex, key)) { session.releasePending(u64(chainId, "chain id"), genesisHex, key) }
        ""
    }

    @ReactMethod
    fun sessionOutcome(id: String, chainId: String, genesisHex: String, key: String, slot: String, accepted: Boolean, promise: Promise) = answer(promise) {
        val session = session(id)
        recorded(account(chainId, genesisHex, key)) { session.outcome(u64(chainId, "chain id"), genesisHex, key, u64(slot, "slot"), accepted) }
        ""
    }

    @ReactMethod
    fun sessionNextNonce(id: String, chainId: String, genesisHex: String, key: String, promise: Promise) = answer(promise) {
        val session = session(id)
        synced(account(chainId, genesisHex, key)) { session.nextNonce(u64(chainId, "chain id"), genesisHex, key)?.toString() ?: "" }
    }

    @ReactMethod
    fun sessionIsHeld(id: String, chainId: String, genesisHex: String, key: String, slot: String, promise: Promise) = answer(promise) {
        val session = session(id)
        synced(account(chainId, genesisHex, key)) { session.isHeld(u64(chainId, "chain id"), genesisHex, key, u64(slot, "slot")).toString() }
    }

    @ReactMethod
    fun vaultSettleHistory(
        chainId: String,
        genesisHex: String,
        key: String,
        headerHex: String,
        certificateHex: String,
        rosterJson: String,
        promise: Promise,
    ) = answer(promise) {
        val settled = recorded(account(chainId, genesisHex, key)) {
            uniffi.quantova_qcore.settleHistory(u64(chainId, "chain id"), genesisHex, key, headerHex, certificateHex, rosterJson)
        }
        "{\"settled\":${settled.settled},\"blocks_left\":\"${settled.blocksLeft}\",\"secs_left\":\"${settled.secsLeft}\"}"
    }

    companion object {
        const val NAME = "Qcore"
        const val FAILURE_PREFIX = "\u0000QCORE_ERROR:"
        private const val IDLE_MILLIS = 120_000L
        private const val MAX_SESSIONS = 64
        private const val TOO_MANY_SESSIONS = "too many signing sessions are open, close one first"
        private const val CLOSED = "the vault module was shut down, so it serves no further vault call"
        private const val BACKGROUND = "the vault is used only while the app is in the foreground, nothing was signed"
        private const val RESET_TITLE = "Reset nonce state"
        private const val RESET_CANCELLED = "authentication cancelled, the nonce state was not reset"
        private const val RESET_UNSUPPORTED = "resetting the nonce state needs a device lock"
        private const val ACKNOWLEDGE_TITLE = "Acknowledge imported history"
        private const val ACKNOWLEDGE_CANCELLED = "authentication cancelled, the imported history was not acknowledged"
        private const val ACKNOWLEDGE_UNSUPPORTED = "acknowledging imported history needs a device lock"
        private const val ACKNOWLEDGE_NEEDS_ACCOUNT = "name the chain id, the genesis hash and the key of the account whose imported history is acknowledged"
        private val NONCE_LOCK = Any()
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
