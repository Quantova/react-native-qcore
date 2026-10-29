// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import android.app.Activity
import android.app.ActivityManager
import android.os.SystemClock
import android.provider.Settings
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableType
import java.util.UUID
import java.util.concurrent.Executors
import javax.crypto.Cipher
import uniffi.quantova_qcore.SeedHandle
import uniffi.quantova_qcore.SigningSession

class QcoreModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = NAME

    private class BridgeException(message: String) : Exception(message)

    private val store by lazy { SeedStore(reactApplicationContext) }

    private val nonces by lazy { NonceStore(reactApplicationContext) }

    private val lock = Any()

    private val nonceWorker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "qcore-nonces").apply { isDaemon = true }
    }

    @Volatile
    private var closed = false

    private val revealGate by lazy { RevealGate(reactApplicationContext) }

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

    private fun arrayBytes(values: ReadableArray, label: String): ByteArray {
        if (values.size() > MAX_SECRET_BYTES) throw BridgeException("the $label is too long")
        val out = ByteArray(values.size())
        for (i in 0 until values.size()) {
            val value = if (values.getType(i) == ReadableType.Number) values.getDouble(i) else -1.0
            if (value < 0 || value > 255 || value != Math.floor(value)) {
                out.fill(0)
                throw BridgeException("the $label is not a list of byte values")
            }
            out[i] = value.toInt().toByte()
        }
        return out
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

    private fun ensureForeground() {
        val state = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(state)
        if (state.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
            throw BridgeException(BACKGROUND)
        }
    }

    private fun foregroundActivity(alias: String, needSeed: Boolean): Activity {
        synchronized(lock) {
            ensureOpen()
            checkedAlias(alias)
            ensureForeground()
            if (needSeed && !store.has(alias)) throw BridgeException(NO_SEED)
        }
        return reactApplicationContext.currentActivity ?: throw BridgeException(BACKGROUND)
    }

    private fun resolveLater(promise: Promise, refused: Throwable?, work: () -> Any) {
        try {
            nonceWorker.execute {
                promise.resolve(
                    if (refused != null) {
                        failure(refused)
                    } else {
                        try {
                            work()
                        } catch (error: Throwable) {
                            failure(error)
                        }
                    },
                )
            }
        } catch (error: Throwable) {
            promise.resolve(failure(BridgeException(CLOSED)))
        }
    }

    private fun authorized(promise: Promise, alias: String, gate: Gate, summary: String, extra: String, needSeed: Boolean, prepare: () -> Unit, work: () -> Any) {
        val activity = try {
            prepare()
            foregroundActivity(alias, needSeed)
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        revealGate.authorize(activity, gate, summary, extra) { refused -> resolveLater(promise, refused, work) }
    }

    private fun withSeed(promise: Promise, alias: String, gate: Gate, summary: String, extra: String, prepare: () -> Unit, use: (SeedHandle) -> Any) {
        val activity: Activity
        val sealed: SealedSeed
        val cipher: Cipher?
        try {
            prepare()
            activity = foregroundActivity(alias, true)
            sealed = store.read(alias) ?: throw BridgeException(NO_SEED)
            cipher = if (store.perUse(sealed)) store.opener(sealed) else null
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        val opened = { refused: Throwable? ->
            resolveLater(promise, refused) {
                synchronized(lock) { ensureOpen() }
                val seed = store.open(sealed, cipher ?: store.opener(sealed))
                val handle = try {
                    SeedHandle.fromSeedBytes(seed)
                } finally {
                    seed.fill(0)
                }
                try {
                    use(handle)
                } finally {
                    release(handle)
                }
            }
        }
        if (cipher != null) {
            revealGate.unlock(activity, cipher, gate, summary, extra, opened)
        } else {
            revealGate.authorize(activity, gate, summary, extra, opened)
        }
    }

    private fun protect(promise: Promise, alias: String, make: () -> SeedHandle) {
        val activity: Activity
        val handle: SeedHandle
        try {
            activity = foregroundActivity(alias, false)
            if (store.has(alias)) throw BridgeException(SEED_EXISTS)
            handle = make()
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        val cipher = try {
            val perUse = revealGate.path(activity) == GatePath.PROMPT
            store.renew(alias, perUse)
            if (perUse) store.sealer(alias) else null
        } catch (error: Throwable) {
            release(handle)
            promise.resolve(failure(error))
            return
        }
        val sealed = { refused: Throwable? ->
            if (refused != null) release(handle)
            resolveLater(promise, refused) {
                try {
                    synchronized(lock) {
                        ensureOpen()
                        if (store.has(alias)) throw BridgeException(SEED_EXISTS)
                        val seed = handle.seedBytes()
                        try {
                            store.seal(alias, cipher ?: store.sealer(alias), seed)
                        } finally {
                            seed.fill(0)
                        }
                    }
                    learn(alias, handle, 0L, PRELOADED_ADDRESSES)
                    ""
                } finally {
                    release(handle)
                }
            }
        }
        val summary = "Seal this seed with the device lock so only you can sign with it"
        if (cipher != null) {
            revealGate.unlock(activity, cipher, Gate.PROTECT, summary, "", sealed)
        } else {
            revealGate.authorize(activity, Gate.PROTECT, summary, "", sealed)
        }
    }

    private fun learn(alias: String, handle: SeedHandle, from: Long, count: Long) {
        val found = HashMap<Long, String>()
        for (index in from until from + count) found[index] = handle.address(index.toULong())
        synchronized(lock) { store.remember(alias, found) }
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

    override fun invalidate() {
        synchronized(lock) {
            closed = true
            sessions.values.forEach { it.destroy() }
            sessions.clear()
        }
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
    fun gatewayProtocol(): Double = uniffi.quantova_qcore.gatewayProtocol().toDouble()

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun checkEndpoint(base: String): String = guarded {
        uniffi.quantova_qcore.checkEndpoint(base)
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun testnetRpcUrl(): String = uniffi.quantova_qcore.testnetRpcUrl()

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun testnetChainName(): String = uniffi.quantova_qcore.testnetChainName()

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun testnetGenesisHash(): String = uniffi.quantova_qcore.testnetGenesisHash() ?: ""

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

    @ReactMethod
    fun vaultCreate(alias: String, promise: Promise) {
        protect(promise, alias) { SeedHandle.generate() }
    }

    @ReactMethod
    fun vaultImportPhrase(alias: String, phrase: ReadableArray, promise: Promise) {
        protect(promise, alias) {
            val bytes = arrayBytes(phrase, "phrase")
            try {
                SeedHandle.fromPhraseBytes(bytes)
            } finally {
                bytes.fill(0)
            }
        }
    }

    @ReactMethod
    fun vaultImportSeed(alias: String, seed: ReadableArray, promise: Promise) {
        protect(promise, alias) {
            val bytes = arrayBytes(seed, "seed")
            try {
                SeedHandle.fromSeedBytes(bytes)
            } finally {
                bytes.fill(0)
            }
        }
    }

    @ReactMethod
    fun vaultRevealPhrase(alias: String, title: String, subtitle: String, promise: Promise) {
        withSeed(promise, alias, Gate.REVEAL, "Show the recovery phrase of this wallet on screen", gateText(title, subtitle), {}) { handle ->
            val phrase = handle.phraseBytes()
            try {
                val out = Arguments.createArray()
                phrase.forEach { out.pushInt(it.toInt() and 0xff) }
                out
            } finally {
                phrase.fill(0)
            }
        }
    }

    @ReactMethod
    fun vaultLearnAddresses(alias: String, count: String, promise: Promise) {
        var wanted = 0L
        withSeed(
            promise,
            alias,
            Gate.ADDRESSES,
            "Derive the first account addresses of this wallet",
            "",
            {
                wanted = u64(count, "address count").toLong()
                if (wanted < 1 || wanted > MAX_LEARNED_ADDRESSES) throw BridgeException(ADDRESS_COUNT)
            },
        ) { handle ->
            learn(alias, handle, 0L, wanted)
            ""
        }
    }

    @ReactMethod
    fun vaultResetNonceState(alias: String, chainId: String, genesisHex: String, key: String, title: String, subtitle: String, promise: Promise) {
        authorized(
            promise,
            alias,
            Gate.RESET,
            "Clear the saved nonce state so this wallet signs again",
            gateText(title, subtitle),
            true,
            { resetTarget(chainId, genesisHex, key) },
        ) {
            resetNow(chainId, genesisHex, key)
            ""
        }
    }

    @ReactMethod
    fun vaultAcknowledgeImportedHistory(alias: String, chainId: String, genesisHex: String, key: String, title: String, subtitle: String, promise: Promise) {
        authorized(
            promise,
            alias,
            Gate.ACKNOWLEDGE,
            "Accept that this account signed elsewhere before this device kept its nonces",
            gateText(title, subtitle),
            true,
            {
                if (chainId.isEmpty() || genesisHex.isEmpty() || key.isEmpty()) throw BridgeException(ACKNOWLEDGE_NEEDS_ACCOUNT)
                account(chainId, genesisHex, key)
            },
        ) {
            recorded(account(chainId, genesisHex, key)) {
                uniffi.quantova_qcore.acknowledgeImportedHistory(u64(chainId, "chain id"), genesisHex, key)
            }
            ""
        }
    }

    @ReactMethod
    fun vaultAcknowledgeMainnet(alias: String, chainId: String, genesisHex: String, key: String, title: String, subtitle: String, promise: Promise) {
        authorized(
            promise,
            alias,
            Gate.MAINNET,
            "Let this wallet sign on mainnet, where a transaction moves real value",
            gateText(title, subtitle),
            true,
            {
                if (chainId.isEmpty() || genesisHex.isEmpty() || key.isEmpty()) throw BridgeException(ACKNOWLEDGE_NEEDS_ACCOUNT)
                account(chainId, genesisHex, key)
            },
        ) {
            recorded(account(chainId, genesisHex, key)) {
                uniffi.quantova_qcore.acknowledgeMainnet(u64(chainId, "chain id"), genesisHex, key)
            }
            ""
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
            store.has(checkedAlias(alias)).toString()
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultClose(alias: String): String = guarded {
        synchronized(lock) {
            ensureOpen()
            checkedAlias(alias)
        }
        ""
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultCloseAll(): String = guarded {
        synchronized(lock) { ensureOpen() }
        ""
    }

    @ReactMethod
    fun vaultForget(alias: String, title: String, subtitle: String, promise: Promise) {
        authorized(
            promise,
            alias,
            Gate.FORGET,
            "Delete the sealed seed of this wallet from this device",
            gateText(title, subtitle),
            true,
            {},
        ) {
            synchronized(lock) {
                ensureOpen()
                store.remove(alias)
            }
            ""
        }
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vaultAddress(alias: String, index: String): String = guarded {
        val at = u64(index, "index")
        synchronized(lock) {
            ensureOpen()
            ensureForeground()
            if (!store.has(checkedAlias(alias))) throw BridgeException(NO_SEED)
            store.address(alias, at.toLong())
        } ?: throw BridgeException("authentication required, the address at index $at of this seed is not known on this device yet, learn it with learnAddresses after authenticating")
    }

    private fun vaultSign(
        promise: Promise,
        alias: String,
        sessionId: String,
        index: String,
        chainId: String,
        genesisHex: String,
        shown: () -> String,
        sign: (SeedHandle, SigningSession) -> String,
    ) {
        val summary = try {
            session(sessionId)
            u64(index, "index")
            uniffi.quantova_qcore.nonceAccount(u64(chainId, "chain id"), genesisHex, PROBE_KEY)
            shown()
        } catch (error: Throwable) {
            promise.resolve(failure(error))
            return
        }
        withSeed(promise, alias, Gate.SIGN, summary, "", {}) { handle ->
            val session = session(sessionId)
            val at = u64(index, "index")
            val address = handle.address(at)
            learn(alias, handle, at.toLong(), 1L)
            recorded(account(chainId, genesisHex, address)) { sign(handle, session) }
        }
    }

    private fun summaryOf(kind: String, chainId: String, target: String, amount: String, fee: String, assetIssuer: String, alias: String, index: String, argsHex: String, meterLimit: String): String {
        val at = u64(index, "index")
        val signer = synchronized(lock) { store.address(checkedAlias(alias), at.toLong()) } ?: ""
        return uniffi.quantova_qcore.signingSummary(kind, u64(chainId, "chain id"), target, amount, fee, assetIssuer, at, signer, argsHex, meterLimit)
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
    ) = vaultSign(promise, alias, sessionId, index, chainId, genesisHex, { summaryOf("transfer", chainId, to, amount, fee, "", alias, index, "", "0") }) { handle, session ->
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
    ) = vaultSign(promise, alias, sessionId, index, chainId, genesisHex, { summaryOf("call", chainId, target, "0", fee, "", alias, index, argsHex, meterLimit) }) { handle, session ->
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
    ) = vaultSign(promise, alias, sessionId, index, chainId, genesisHex, { summaryOf("register", chainId, "", "0", fee, "", alias, index, "", "0") }) { handle, session ->
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
    ) = vaultSign(promise, alias, sessionId, index, chainId, genesisHex, { summaryOf("payable", chainId, target, value, fee, "", alias, index, argsHex, meterLimit) }) { handle, session ->
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
    ) = vaultSign(promise, alias, sessionId, index, chainId, genesisHex, { summaryOf("asset", chainId, target, amount, fee, assetIssuer, alias, index, argsHex, meterLimit) }) { handle, session ->
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
    fun verifyFinality(chainId: String, genesisHex: String, epochLength: String, rosterEpoch: String, headerHex: String, certificateHex: String, rosterJson: String): String = guarded {
        uniffi.quantova_qcore.verifyFinality(
            u64(chainId, "chain id"),
            genesisHex,
            optionalU64(epochLength, "epoch length"),
            u64(rosterEpoch, "roster epoch"),
            headerHex,
            certificateHex,
            rosterJson,
        )
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
        epochLength: String,
        rosterEpoch: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String,
    ): String = guarded {
        uniffi.quantova_qcore.confirmTransaction(
            u64(chainId, "chain id"),
            genesisHex,
            optionalU64(epochLength, "epoch length"),
            u64(rosterEpoch, "roster epoch"),
            txId,
            proofJson,
            finalityJson,
            rosterJson,
        )
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun confirmInclusion(
        chainId: String,
        genesisHex: String,
        epochLength: String,
        rosterEpoch: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String,
    ): String = guarded {
        uniffi.quantova_qcore.confirmInclusion(
            u64(chainId, "chain id"),
            genesisHex,
            optionalU64(epochLength, "epoch length"),
            u64(rosterEpoch, "roster epoch"),
            txId,
            proofJson,
            finalityJson,
            rosterJson,
        )
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
        private const val MAX_SESSIONS = 64
        private const val MAX_SECRET_BYTES = 4096
        private const val MAX_LEARNED_ADDRESSES = 64L
        private const val PRELOADED_ADDRESSES = 8L
        private const val PROBE_KEY = "vault"
        private const val TOO_MANY_SESSIONS = "too many signing sessions are open, close one first"
        private const val CLOSED = "the vault module was shut down, so it serves no further vault call"
        private const val BACKGROUND = "the vault is used only while the app is in the foreground, nothing was signed"
        private const val NO_SEED = "no seed is stored under this alias"
        private const val SEED_EXISTS = "a seed is already stored under this alias, forget it first"
        private const val ADDRESS_COUNT = "learn between one and sixty four addresses at a time"
        private const val ACKNOWLEDGE_NEEDS_ACCOUNT = "name the chain id, the genesis hash and the key of the account this acknowledgement is for"
        private val NONCE_LOCK = Any()
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
