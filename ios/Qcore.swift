// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation

@objc(Qcore)
class Qcore: NSObject {

    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }

    private func abort(_ reason: String) -> Never {
        NSException(name: NSExceptionName(rawValue: "QcoreError"), reason: reason, userInfo: nil).raise()
        fatalError(reason)
    }

    private func u64(_ value: String, _ label: String) -> UInt64 {
        guard let parsed = UInt64(value) else { abort("the \(label) is not a whole number") }
        return parsed
    }

    @objc(mnemonicFromSeed:)
    func rnMnemonicFromSeed(_ seedHex: String) -> NSString {
        do { return try mnemonicFromSeed(seedHex: seedHex) as NSString } catch { abort("\(error)") }
    }

    @objc(seedFromMnemonic:)
    func rnSeedFromMnemonic(_ phrase: String) -> NSString {
        do { return try seedFromMnemonic(phrase: phrase) as NSString } catch { abort("\(error)") }
    }

    @objc(address:index:)
    func rnAddress(_ seedHex: String, index: String) -> NSString {
        do { return try address(seedHex: seedHex, index: u64(index, "index")) as NSString } catch { abort("\(error)") }
    }

    @objc(validAddress:)
    func rnValidAddress(_ address: String) -> NSNumber {
        return NSNumber(value: validAddress(address: address))
    }

    @objc(signTransfer:index:to:amount:nonce:fee:chainId:)
    func rnSignTransfer(
        _ seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String
    ) -> NSString {
        do {
            return try signTransfer(
                seedHex: seedHex,
                index: u64(index, "index"),
                to: to,
                amount: amount,
                nonce: u64(nonce, "nonce"),
                fee: fee,
                chainId: u64(chainId, "chain id")
            ) as NSString
        } catch { abort("\(error)") }
    }

    @objc(signCall:index:target:argsHex:nonce:meterLimit:fee:chainId:)
    func rnSignCall(
        _ seedHex: String,
        index: String,
        target: String,
        argsHex: String,
        nonce: String,
        meterLimit: String,
        fee: String,
        chainId: String
    ) -> NSString {
        do {
            return try signCall(
                seedHex: seedHex,
                index: u64(index, "index"),
                target: target,
                argsHex: argsHex,
                nonce: u64(nonce, "nonce"),
                meterLimit: u64(meterLimit, "meter limit"),
                fee: fee,
                chainId: u64(chainId, "chain id")
            ) as NSString
        } catch { abort("\(error)") }
    }

    @objc(signRegister:index:nonce:fee:chainId:)
    func rnSignRegister(
        _ seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String
    ) -> NSString {
        do {
            return try signRegister(
                seedHex: seedHex,
                index: u64(index, "index"),
                nonce: u64(nonce, "nonce"),
                fee: fee,
                chainId: u64(chainId, "chain id")
            ) as NSString
        } catch { abort("\(error)") }
    }

    @objc(chainIdFromName:)
    func rnChainIdFromName(_ name: String) -> NSString {
        return String(chainIdFromName(name: name)) as NSString
    }
}
