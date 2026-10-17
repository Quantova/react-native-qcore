// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation

@objc(Qcore)
class Qcore: NSObject {

    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }

    static let failurePrefix = "\u{0}QCORE_ERROR:"

    private struct BridgeError: Error {
        let message: String
    }

    private func failure(_ error: Error) -> NSString {
        let message: String
        if let bridge = error as? BridgeError {
            message = bridge.message
        } else if let core = error as? QcoreError, case let .Invalid(reason) = core {
            message = reason
        } else {
            message = "\(error)"
        }
        return (Qcore.failurePrefix + message) as NSString
    }

    private func u64(_ value: String, _ label: String) throws -> UInt64 {
        guard !value.isEmpty, value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let parsed = UInt64(value) else {
            throw BridgeError(message: "the \(label) is not a whole number")
        }
        return parsed
    }

    @objc(generateSeed)
    func rnGenerateSeed() -> NSString {
        do { return try generateSeed() as NSString } catch { return failure(error) }
    }

    @objc(vmCallFee:meterLimit:)
    func rnVmCallFee(_ transferFee: String, meterLimit: String) -> NSString {
        do {
            return try vmCallFee(
                transferFee: transferFee,
                meterLimit: try u64(meterLimit, "meter limit")
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(mnemonicFromSeed:)
    func rnMnemonicFromSeed(_ seedHex: String) -> NSString {
        do { return try mnemonicFromSeed(seedHex: seedHex) as NSString } catch { return failure(error) }
    }

    @objc(seedFromMnemonic:)
    func rnSeedFromMnemonic(_ phrase: String) -> NSString {
        do { return try seedFromMnemonic(phrase: phrase) as NSString } catch { return failure(error) }
    }

    @objc(address:index:)
    func rnAddress(_ seedHex: String, index: String) -> NSString {
        do { return try address(seedHex: seedHex, index: try u64(index, "index")) as NSString } catch { return failure(error) }
    }

    @objc(validAddress:)
    func rnValidAddress(_ address: String) -> NSNumber {
        return NSNumber(value: validAddress(address: address))
    }

    @objc(sameAddress:b:)
    func rnSameAddress(_ a: String, b: String) -> NSNumber {
        return NSNumber(value: sameAddress(a: a, b: b))
    }

    @objc(lookalikeOf:known:)
    func rnLookalikeOf(_ candidate: String, known: String) -> NSString {
        let list = known.split(separator: ",").map(String.init)
        return (lookalikeOf(candidate: candidate, known: list) ?? "") as NSString
    }

    @objc(signTransfer:index:to:amount:nonce:fee:chainId:validUntil:)
    func rnSignTransfer(
        _ seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String
    ) -> NSString {
        do {
            return try signTransfer(
                seedHex: seedHex,
                index: try u64(index, "index"),
                to: to,
                amount: amount,
                nonce: try u64(nonce, "nonce"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until")
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(signCall:index:target:argsHex:nonce:meterLimit:fee:chainId:validUntil:transferFee:)
    func rnSignCall(
        _ seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String,
        validUntil: String,
        transferFee: String
    ) -> NSString {
        do {
            return try signCall(
                seedHex: seedHex,
                index: try u64(index, "index"),
                target: target,
                argsHex: argsHex,
                nonce: try u64(nonce, "nonce"),
                meterLimit: try u64(meterLimit, "meter limit"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until"),
                transferFee: transferFee
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(signRegister:index:nonce:fee:chainId:validUntil:)
    func rnSignRegister(
        _ seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String
    ) -> NSString {
        do {
            return try signRegister(
                seedHex: seedHex,
                index: try u64(index, "index"),
                nonce: try u64(nonce, "nonce"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until")
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(signPayableCall:index:target:argsHex:nonce:meterLimit:fee:value:chainId:validUntil:transferFee:)
    func rnSignPayableCall(
        _ seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        value: String,
        chainId: String,
        validUntil: String,
        transferFee: String
    ) -> NSString {
        do {
            return try signPayableCall(
                seedHex: seedHex,
                index: try u64(index, "index"),
                target: target,
                argsHex: argsHex,
                nonce: try u64(nonce, "nonce"),
                meterLimit: try u64(meterLimit, "meter limit"),
                fee: fee,
                value: value,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until"),
                transferFee: transferFee
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(signAssetCall:index:target:argsHex:assetIssuer:amount:nonce:meterLimit:fee:chainId:validUntil:transferFee:)
    func rnSignAssetCall(
        _ seedHex: String,
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
        transferFee: String
    ) -> NSString {
        do {
            return try signAssetCall(
                seedHex: seedHex,
                index: try u64(index, "index"),
                target: target,
                argsHex: argsHex,
                assetIssuer: assetIssuer,
                amount: amount,
                nonce: try u64(nonce, "nonce"),
                meterLimit: try u64(meterLimit, "meter limit"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until"),
                transferFee: transferFee
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(chainIdFromName:)
    func rnChainIdFromName(_ name: String) -> NSString {
        return String(chainIdFromName(name: name)) as NSString
    }

    @objc(nameKey:)
    func rnNameKey(_ label: String) -> NSString {
        return nameKey(label: label) as NSString
    }

    @objc(mapSlotKey:keyAddressHex:)
    func rnMapSlotKey(_ mapDomainTag: String, keyAddressHex: String) -> NSString {
        do {
            return try mapSlotKey(
                mapDomainTag: try u64(mapDomainTag, "map domain tag"),
                keyAddressHex: keyAddressHex
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(mapAddrWordKey:key32Hex:word:)
    func rnMapAddrWordKey(_ mapDomainTag: String, key32Hex: String, word: String) -> NSString {
        do {
            return try mapAddrWordKey(
                mapDomainTag: try u64(mapDomainTag, "map domain tag"),
                keyAddressHex: key32Hex,
                word: try u64(word, "word")
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(scalarSlotKey:)
    func rnScalarSlotKey(_ slot: String) -> NSString {
        do {
            return scalarSlotKey(slot: try u64(slot, "slot")) as NSString
        } catch { return failure(error) }
    }
}
