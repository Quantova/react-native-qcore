// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

class QcoreModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = NAME

    private class BridgeException(message: String) : Exception(message)

    private fun u64(value: String, label: String): ULong =
        value.toULongOrNull() ?: throw BridgeException("the $label is not a whole number")

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

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun generateSeed(): String = guarded {
        uniffi.quantova_qcore.generateSeed()
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun vmCallFee(transferFee: String, meterLimit: String): String = guarded {
        uniffi.quantova_qcore.vmCallFee(transferFee, u64(meterLimit, "meter limit"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun mnemonicFromSeed(seedHex: String): String = guarded {
        uniffi.quantova_qcore.mnemonicFromSeed(seedHex)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun seedFromMnemonic(phrase: String): String = guarded {
        uniffi.quantova_qcore.seedFromMnemonic(phrase)
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun address(seedHex: String, index: String): String = guarded {
        uniffi.quantova_qcore.address(seedHex, u64(index, "index"))
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun validAddress(address: String): Boolean =
        try {
            uniffi.quantova_qcore.validAddress(address)
        } catch (error: Throwable) {
            false
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
    ): String = guarded {
        uniffi.quantova_qcore.signTransfer(
            seedHex,
            u64(index, "index"),
            to,
            amount,
            u64(nonce, "nonce"),
            fee,
            u64(chainId, "chain id"),
            u64(validUntil, "valid until"),
        )
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
    ): String = guarded {
        uniffi.quantova_qcore.signCall(
            seedHex,
            u64(index, "index"),
            target,
            argsHex,
            u64(nonce, "nonce"),
            u64(meterLimit, "meter limit"),
            fee,
            u64(chainId, "chain id"),
            u64(validUntil, "valid until"),
            transferFee,
        )
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signRegister(
        seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
    ): String = guarded {
        uniffi.quantova_qcore.signRegister(
            seedHex,
            u64(index, "index"),
            u64(nonce, "nonce"),
            fee,
            u64(chainId, "chain id"),
            u64(validUntil, "valid until"),
        )
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
    ): String = guarded {
        uniffi.quantova_qcore.signPayableCall(
            seedHex,
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
        )
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
    ): String = guarded {
        uniffi.quantova_qcore.signAssetCall(
            seedHex,
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
        )
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

    companion object {
        const val NAME = "Qcore"
        const val FAILURE_PREFIX = "\u0000QCORE_ERROR:"
    }
}
