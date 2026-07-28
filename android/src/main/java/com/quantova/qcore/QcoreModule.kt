// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

package com.quantova.qcore

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

class QcoreModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = NAME

    private fun u64(value: String, label: String): ULong =
        value.toULongOrNull() ?: throw IllegalArgumentException("the $label is not a whole number")

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun mnemonicFromSeed(seedHex: String): String =
        uniffi.quantova_qcore.mnemonicFromSeed(seedHex)

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun seedFromMnemonic(phrase: String): String =
        uniffi.quantova_qcore.seedFromMnemonic(phrase)

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun address(seedHex: String, index: String): String =
        uniffi.quantova_qcore.address(seedHex, u64(index, "index"))

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun validAddress(address: String): Boolean =
        uniffi.quantova_qcore.validAddress(address)

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signTransfer(
        seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
    ): String =
        uniffi.quantova_qcore.signTransfer(
            seedHex,
            u64(index, "index"),
            to,
            amount,
            u64(nonce, "nonce"),
            fee,
            u64(chainId, "chain id"),
        )

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
    ): String =
        uniffi.quantova_qcore.signCall(
            seedHex,
            u64(index, "index"),
            target,
            argsHex,
            u64(nonce, "nonce"),
            u64(meterLimit, "meter limit"),
            fee,
            u64(chainId, "chain id"),
        )

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun signRegister(
        seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
    ): String =
        uniffi.quantova_qcore.signRegister(
            seedHex,
            u64(index, "index"),
            u64(nonce, "nonce"),
            fee,
            u64(chainId, "chain id"),
        )

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun chainIdFromName(name: String): String =
        uniffi.quantova_qcore.chainIdFromName(name).toString()

    companion object {
        const val NAME = "Qcore"
    }
}
