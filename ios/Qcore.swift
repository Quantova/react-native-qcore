// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import Foundation
import LocalAuthentication
import Security
import UIKit

@objc(Qcore)
class Qcore: NSObject {

    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }

    static let failurePrefix = "\u{0}QCORE_ERROR:"

    private struct BridgeError: Error {
        let message: String
    }

    private let lock = NSLock()

    private var held: [String: SeedHandle] = [:]

    private var heldAt: [String: TimeInterval] = [:]

    private static let idleSeconds: TimeInterval = 120

    private static let maxSessions = 64

    private static let tooManySessions = "too many signing sessions are open, close one first"

    private let idleQueue = DispatchQueue(label: "com.quantova.qcore.idle")

    private var idleTimer: DispatchSourceTimer?

    override init() {
        super.init()
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(hostLeftForeground), name: UIApplication.didEnterBackgroundNotification, object: nil)
        center.addObserver(self, selector: #selector(hostLeftForeground), name: UIApplication.willResignActiveNotification, object: nil)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        idleTimer?.cancel()
    }

    @objc private func hostLeftForeground() {
        locked { forgetHeld() }
    }

    private func expireIdle() {
        let now = ProcessInfo.processInfo.systemUptime
        for (alias, at) in heldAt where now - at >= Self.idleSeconds {
            held.removeValue(forKey: alias)?.forget()
            heldAt.removeValue(forKey: alias)
        }
        armIdleTimer(now)
    }

    private func armIdleTimer(_ now: TimeInterval) {
        idleTimer?.cancel()
        idleTimer = nil
        guard let oldest = heldAt.values.min() else { return }
        let timer = DispatchSource.makeTimerSource(queue: idleQueue)
        timer.schedule(deadline: .now() + max(0, oldest + Self.idleSeconds - now))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.locked { self.expireIdle() }
        }
        idleTimer = timer
        timer.resume()
    }

    private func touch(_ alias: String) {
        let now = ProcessInfo.processInfo.systemUptime
        heldAt[alias] = now
        armIdleTimer(now)
    }

    private func drop(_ alias: String) {
        held.removeValue(forKey: alias)?.forget()
        heldAt.removeValue(forKey: alias)
        armIdleTimer(ProcessInfo.processInfo.systemUptime)
    }

    private func forgetHeld() {
        idleTimer?.cancel()
        idleTimer = nil
        for handle in held.values {
            handle.forget()
        }
        held.removeAll()
        heldAt.removeAll()
    }

    private var sessions: [String: SigningSession] = [:]

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

    private func optionalU64(_ value: String, _ label: String) throws -> UInt64? {
        return value.isEmpty ? nil : try u64(value, label)
    }

    private func wipe(_ data: inout Data) {
        let count = data.count
        guard count > 0 else { return }
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                _ = memset_s(base, count, 0, count)
            }
        }
    }

    private func wipe(_ bytes: inout [UInt8]) {
        let count = bytes.count
        guard count > 0 else { return }
        bytes.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress {
                _ = memset_s(base, count, 0, count)
            }
        }
    }

    private func nibble(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar.value {
        case 0x30...0x39: return UInt8(scalar.value - 0x30)
        case 0x61...0x66: return UInt8(scalar.value - 0x61 + 10)
        case 0x41...0x46: return UInt8(scalar.value - 0x41 + 10)
        default: return nil
        }
    }

    private func hexData(_ hex: String, _ label: String) throws -> Data {
        let scalars = hex.unicodeScalars
        let space = CharacterSet.whitespacesAndNewlines
        var start = scalars.startIndex
        var end = scalars.endIndex
        while start < end && space.contains(scalars[start]) {
            start = scalars.index(after: start)
        }
        while end > start && space.contains(scalars[scalars.index(before: end)]) {
            end = scalars.index(before: end)
        }
        let count = scalars.distance(from: start, to: end)
        guard count % 2 == 0 else {
            throw BridgeError(message: "the \(label) is not hex")
        }
        var out = Data(count: count / 2)
        var at = start
        var n = 0
        while at < end {
            let next = scalars.index(after: at)
            guard let hi = nibble(scalars[at]), let lo = nibble(scalars[next]) else {
                wipe(&out)
                throw BridgeError(message: "the \(label) is not hex")
            }
            out[n] = (hi << 4) | lo
            n += 1
            at = scalars.index(after: next)
        }
        return out
    }

    private func hexString(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var chars = [UInt8](repeating: 0, count: data.count * 2)
        defer { wipe(&chars) }
        for (i, byte) in data.enumerated() {
            chars[2 * i] = digits[Int(byte >> 4)]
            chars[2 * i + 1] = digits[Int(byte & 0x0f)]
        }
        return String(decoding: chars, as: UTF8.self)
    }

    private func base64Data(_ text: String, _ label: String) throws -> Data {
        guard let decoded = Data(base64Encoded: text) else {
            throw BridgeError(message: "the \(label) is not base64")
        }
        return decoded
    }

    private func withSeedHex<T>(_ seedHex: String, _ body: (Data) throws -> T) throws -> T {
        var seed = try hexData(seedHex, "seed")
        defer { wipe(&seed) }
        return try body(seed)
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func checkedAlias(_ alias: String) throws -> String {
        try checkSeedAlias(alias: alias)
        return alias
    }

    private enum Keychain {
        static let service = "com.quantova.qcore.seed.2"

        static func query(_ alias: String) -> [String: Any] {
            return [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: alias,
            ]
        }

        static func has(_ alias: String) throws -> Bool {
            var search = query(alias)
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            let status = SecItemCopyMatching(search as CFDictionary, nil)
            switch status {
            case errSecSuccess, errSecInteractionNotAllowed:
                return true
            case errSecItemNotFound:
                return false
            default:
                throw BridgeError(message: "the keychain refused the lookup with status \(status)")
            }
        }

        static func save(_ alias: String, _ seed: Data) throws {
            let box = NSMutableData(data: seed)
            defer { box.resetBytes(in: NSRange(location: 0, length: box.length)) }
            var failed: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &failed) else {
                failed?.release()
                throw BridgeError(message: "a seed needs a device passcode, set one and try again")
            }
            var item = query(alias)
            item[kSecAttrAccessControl as String] = access
            item[kSecValueData as String] = box
            let status = SecItemAdd(item as CFDictionary, nil)
            if status == errSecDuplicateItem {
                throw BridgeError(message: "a seed is already stored under this alias, forget it first")
            }
            if status == errSecAuthFailed || status == errSecNotAvailable {
                throw BridgeError(message: "a seed needs a device passcode, set one and try again")
            }
            guard status == errSecSuccess else {
                throw BridgeError(message: "the keychain refused to store the seed with status \(status)")
            }
        }

        static func load(_ alias: String, context: LAContext? = nil) throws -> Data {
            var search = query(alias)
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            if let context = context {
                search[kSecUseAuthenticationContext as String] = context
            }
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                throw BridgeError(message: "no seed is stored under this alias")
            }
            if status == errSecUserCanceled || status == errSecAuthFailed || status == errSecInteractionNotAllowed {
                throw BridgeError(message: "authentication required, confirm the device passcode or biometric and try again")
            }
            guard status == errSecSuccess, let stored = found as? Data else {
                throw BridgeError(message: "the keychain refused to read the seed with status \(status)")
            }
            return stored
        }

        static func remove(_ alias: String) throws {
            let status = SecItemDelete(query(alias) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw BridgeError(message: "the keychain refused to remove the seed with status \(status)")
            }
        }
    }

    private enum NonceKeychain {
        static let service = "com.quantova.qcore.nonces.1"
        static let maxAccounts = 4096

        static func query(_ account: String) -> [String: Any] {
            return [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
        }

        static func loadAll() throws -> [String] {
            let search: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                return []
            }
            guard status == errSecSuccess, let items = found as? [Data], items.count <= maxAccounts else {
                throw BridgeError(message: "the saved nonce state could not be opened, so no signing session is opened")
            }
            return try items.map { item in
                guard let text = String(data: item, encoding: .utf8) else {
                    throw BridgeError(message: "the saved nonce state could not be opened, so no signing session is opened")
                }
                return text
            }
        }

        static func save(_ account: String, _ state: String) throws {
            let data = Data(state.utf8)
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            var status = SecItemUpdate(query(account) as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound {
                var item = query(account)
                item[kSecValueData as String] = data
                item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                status = SecItemAdd(item as CFDictionary, nil)
            }
            guard status == errSecSuccess else {
                throw BridgeError(message: "the nonce state could not be written, so nothing was signed")
            }
        }
    }

    private func persist(_ session: SigningSession) throws {
        try locked {
            for account in try session.savedAccounts() {
                try NonceKeychain.save(account.key, account.state)
            }
        }
    }

    private func recorded<T>(_ session: SigningSession, _ change: () throws -> T) throws -> T {
        let out = try change()
        try persist(session)
        return out
    }

    private func handleFor(_ alias: String) throws -> SeedHandle {
        let alias = try checkedAlias(alias)
        let found: SeedHandle? = locked {
            expireIdle()
            guard let found = held[alias] else { return nil }
            touch(alias)
            return found
        }
        if let found = found {
            return found
        }
        var seed = try Keychain.load(alias)
        defer { wipe(&seed) }
        let handle = try SeedHandle.fromSeedBytes(seed: seed)
        return locked {
            if let raced = held[alias] {
                handle.forget()
                touch(alias)
                return raced
            }
            held[alias] = handle
            touch(alias)
            return handle
        }
    }

    private func keep(_ alias: String, _ make: () throws -> SeedHandle) throws {
        try locked {
            let alias = try checkedAlias(alias)
            if try Keychain.has(alias) {
                throw BridgeError(message: "a seed is already stored under this alias, forget it first")
            }
            let handle = try make()
            do {
                var seed = try handle.seedBytes()
                defer { wipe(&seed) }
                try Keychain.save(alias, seed)
            } catch {
                handle.forget()
                throw error
            }
            held[alias]?.forget()
            held[alias] = handle
            touch(alias)
        }
    }

    private func session(_ id: String) throws -> SigningSession {
        guard let found = locked({ sessions[id] }) else {
            throw BridgeError(message: "no signing session is open under this id")
        }
        return found
    }

    @objc func invalidate() {
        NotificationCenter.default.removeObserver(self)
        locked {
            forgetHeld()
            sessions.removeAll()
        }
    }

    @objc(generateSeed)
    func rnGenerateSeed() -> NSString {
        do {
            var seed = try generateSeed()
            defer { wipe(&seed) }
            return hexString(seed) as NSString
        } catch { return failure(error) }
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
        do {
            return try withSeedHex(seedHex) { seed in
                var phrase = try mnemonicFromSeed(seed: seed)
                defer { wipe(&phrase) }
                return String(decoding: phrase, as: UTF8.self) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(seedFromMnemonic:)
    func rnSeedFromMnemonic(_ phrase: String) -> NSString {
        do {
            var bytes = Data(phrase.utf8)
            defer { wipe(&bytes) }
            var seed = try seedFromMnemonic(phrase: bytes)
            defer { wipe(&seed) }
            return hexString(seed) as NSString
        } catch { return failure(error) }
    }

    @objc(address:index:)
    func rnAddress(_ seedHex: String, index: String) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try address(seed: seed, index: try u64(index, "index")) as NSString
            }
        } catch { return failure(error) }
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

    @objc(signTransfer:index:to:amount:nonce:fee:chainId:validUntil:head:)
    func rnSignTransfer(
        _ seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String
    ) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try signTransfer(
                    seed: seed,
                    index: try u64(index, "index"),
                    to: to,
                    amount: amount,
                    nonce: try u64(nonce, "nonce"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signCall:index:target:argsHex:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:)
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
        transferFee: String,
        head: String
    ) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try signCall(
                    seed: seed,
                    index: try u64(index, "index"),
                    target: target,
                    argsHex: argsHex,
                    nonce: try u64(nonce, "nonce"),
                    meterLimit: try u64(meterLimit, "meter limit"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signRegister:index:nonce:fee:chainId:validUntil:head:)
    func rnSignRegister(
        _ seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String
    ) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try signRegister(
                    seed: seed,
                    index: try u64(index, "index"),
                    nonce: try u64(nonce, "nonce"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signPayableCall:index:target:argsHex:nonce:meterLimit:fee:value:chainId:validUntil:transferFee:head:)
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
        transferFee: String,
        head: String
    ) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try signPayableCall(
                    seed: seed,
                    index: try u64(index, "index"),
                    target: target,
                    argsHex: argsHex,
                    nonce: try u64(nonce, "nonce"),
                    meterLimit: try u64(meterLimit, "meter limit"),
                    fee: fee,
                    value: value,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signAssetCall:index:target:argsHex:assetIssuer:amount:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:)
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
        transferFee: String,
        head: String
    ) -> NSString {
        do {
            return try withSeedHex(seedHex) { seed in
                try signAssetCall(
                    seed: seed,
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
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(chainIdFromName:)
    func rnChainIdFromName(_ name: String) -> NSString {
        do {
            return String(try chainIdFromName(name: name)) as NSString
        } catch { return failure(error) }
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

    @objc(vaultCreate:)
    func rnVaultCreate(_ alias: String) -> NSString {
        do {
            try keep(alias) { try SeedHandle.generate() }
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultImportPhrase:phraseBase64:)
    func rnVaultImportPhrase(_ alias: String, phraseBase64: String) -> NSString {
        do {
            try keep(alias) {
                var phrase = try base64Data(phraseBase64, "phrase")
                defer { wipe(&phrase) }
                return try SeedHandle.fromPhraseBytes(phrase: phrase)
            }
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultImportSeed:seedBase64:)
    func rnVaultImportSeed(_ alias: String, seedBase64: String) -> NSString {
        do {
            try keep(alias) {
                var seed = try base64Data(seedBase64, "seed")
                defer { wipe(&seed) }
                return try SeedHandle.fromSeedBytes(seed: seed)
            }
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultRevealPhrase:title:subtitle:resolver:rejecter:)
    func rnVaultRevealPhrase(
        _ alias: String,
        title: String,
        subtitle: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            resolve(self.revealNow(alias, title: title, subtitle: subtitle))
        }
    }

    private func revealNow(_ alias: String, title: String, subtitle: String) -> NSString {
        do {
            let alias = try checkedAlias(alias)
            let context = LAContext()
            context.touchIDAuthenticationAllowableReuseDuration = 0
            let reason = [title, subtitle].filter { !$0.isEmpty }.joined(separator: ". ")
            context.localizedReason = reason.isEmpty ? "Reveal recovery phrase" : reason
            defer { context.invalidate() }
            var seed = try Keychain.load(alias, context: context)
            defer { wipe(&seed) }
            let handle = try SeedHandle.fromSeedBytes(seed: seed)
            defer { handle.forget() }
            var phrase = try handle.phraseBytes()
            defer { wipe(&phrase) }
            return phrase.base64EncodedString() as NSString
        } catch { return failure(error) }
    }

    @objc(vaultHas:)
    func rnVaultHas(_ alias: String) -> NSString {
        do {
            return try locked {
                let alias = try checkedAlias(alias)
                let present = try held[alias] != nil || Keychain.has(alias)
                return (present ? "true" : "false") as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultClose:)
    func rnVaultClose(_ alias: String) -> NSString {
        do {
            try locked {
                let alias = try checkedAlias(alias)
                drop(alias)
            }
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultCloseAll)
    func rnVaultCloseAll() -> NSString {
        locked { forgetHeld() }
        return ""
    }

    @objc(vaultForget:)
    func rnVaultForget(_ alias: String) -> NSString {
        do {
            try locked {
                let alias = try checkedAlias(alias)
                drop(alias)
                try Keychain.remove(alias)
            }
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultAddress:index:)
    func rnVaultAddress(_ alias: String, index: String) -> NSString {
        do {
            return try handleFor(alias).address(index: try u64(index, "index")) as NSString
        } catch { return failure(error) }
    }

    @objc(vaultSignTransfer:sessionId:index:to:amount:nonce:fee:chainId:validUntil:head:)
    func rnVaultSignTransfer(
        _ alias: String,
        sessionId: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            return try recorded(session) {
                try handleFor(alias).signTransfer(
                    session: session,
                    index: try u64(index, "index"),
                    to: to,
                    amount: amount,
                    nonce: try u64(nonce, "nonce"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultSignCall:sessionId:index:target:argsHex:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:)
    func rnVaultSignCall(
        _ alias: String,
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
        head: String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            return try recorded(session) {
                try handleFor(alias).signCall(
                    session: session,
                    index: try u64(index, "index"),
                    target: target,
                    argsHex: argsHex,
                    nonce: try u64(nonce, "nonce"),
                    meterLimit: try u64(meterLimit, "meter limit"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultSignRegister:sessionId:index:nonce:fee:chainId:validUntil:head:)
    func rnVaultSignRegister(
        _ alias: String,
        sessionId: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            return try recorded(session) {
                try handleFor(alias).signRegister(
                    session: session,
                    index: try u64(index, "index"),
                    nonce: try u64(nonce, "nonce"),
                    fee: fee,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultSignPayableCall:sessionId:index:target:argsHex:nonce:meterLimit:fee:value:chainId:validUntil:transferFee:head:)
    func rnVaultSignPayableCall(
        _ alias: String,
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
        head: String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            return try recorded(session) {
                try handleFor(alias).signPayableCall(
                    session: session,
                    index: try u64(index, "index"),
                    target: target,
                    argsHex: argsHex,
                    nonce: try u64(nonce, "nonce"),
                    meterLimit: try u64(meterLimit, "meter limit"),
                    fee: fee,
                    value: value,
                    chainId: try u64(chainId, "chain id"),
                    validUntil: try u64(validUntil, "valid until"),
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultSignAssetCall:sessionId:index:target:argsHex:assetIssuer:amount:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:)
    func rnVaultSignAssetCall(
        _ alias: String,
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
        head: String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            return try recorded(session) {
                try handleFor(alias).signAssetCall(
                    session: session,
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
                    transferFee: transferFee,
                    head: try u64(head, "head")
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(checkValidUntil:head:)
    func rnCheckValidUntil(_ validUntil: String, head: String) -> NSString {
        do {
            try checkValidUntil(validUntil: try u64(validUntil, "valid until"), head: try u64(head, "head"))
            return ""
        } catch { return failure(error) }
    }

    @objc(boundedValidUntil:head:wallSecs:floor:floorAgeSecs:)
    func rnBoundedValidUntil(
        _ chainName: String,
        head: String,
        wallSecs: String,
        floor: String,
        floorAgeSecs: String
    ) -> NSString {
        do {
            return String(try boundedValidUntil(
                chainName: chainName,
                head: try u64(head, "head"),
                wallSecs: try u64(wallSecs, "wall clock"),
                floor: try optionalU64(floor, "floor"),
                floorAgeSecs: try u64(floorAgeSecs, "floor age")
            )) as NSString
        } catch { return failure(error) }
    }

    @objc(headCeiling:wallSecs:)
    func rnHeadCeiling(_ chainName: String, wallSecs: String) -> NSString {
        do {
            return String(headCeiling(chainName: chainName, wallSecs: try u64(wallSecs, "wall clock"))) as NSString
        } catch { return failure(error) }
    }

    @objc(genesisSecs:)
    func rnGenesisSecs(_ chainName: String) -> NSString {
        return String(genesisSecs(chainName: chainName)) as NSString
    }

    @objc(maxValidityBlocks)
    func rnMaxValidityBlocks() -> NSString {
        return String(maxValidityBlocks()) as NSString
    }

    @objc(defaultValidityBlocks)
    func rnDefaultValidityBlocks() -> NSString {
        return String(defaultValidityBlocks()) as NSString
    }

    @objc(checkOrderExpiry:nowSecs:)
    func rnCheckOrderExpiry(_ expiry: String, nowSecs: String) -> NSString {
        do {
            try checkOrderExpiry(expiry: try u64(expiry, "order expiry"), nowSecs: try u64(nowSecs, "wall clock"))
            return ""
        } catch { return failure(error) }
    }

    @objc(maxOrderLifetimeSecs)
    func rnMaxOrderLifetimeSecs() -> NSString {
        return String(maxOrderLifetimeSecs()) as NSString
    }

    @objc(verifyFinality:headerHex:certificateHex:rosterJson:)
    func rnVerifyFinality(_ chainId: String, headerHex: String, certificateHex: String, rosterJson: String) -> NSString {
        do {
            return try verifyFinality(
                chainId: try u64(chainId, "chain id"),
                headerHex: headerHex,
                certificateHex: certificateHex,
                rosterJson: rosterJson
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(verifyEvent:leafHex:stepsJson:)
    func rnVerifyEvent(_ eventRootHex: String, leafHex: String, stepsJson: String) -> NSString {
        do {
            return String(try verifyEvent(eventRootHex: eventRootHex, leafHex: leafHex, stepsJson: stepsJson)) as NSString
        } catch { return failure(error) }
    }

    @objc(verifyTransaction:txId:leafHex:stepsJson:)
    func rnVerifyTransaction(_ transactionRootHex: String, txId: String, leafHex: String, stepsJson: String) -> NSString {
        do {
            return String(try verifyTransaction(
                transactionRootHex: transactionRootHex,
                txId: txId,
                leafHex: leafHex,
                stepsJson: stepsJson
            )) as NSString
        } catch { return failure(error) }
    }

    @objc(confirmTransaction:txId:proofJson:finalityJson:rosterJson:)
    func rnConfirmTransaction(
        _ chainId: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String
    ) -> NSString {
        do {
            return try confirmTransaction(
                chainId: try u64(chainId, "chain id"),
                txId: txId,
                proofJson: proofJson,
                finalityJson: finalityJson,
                rosterJson: rosterJson
            ) as NSString
        } catch { return failure(error) }
    }

    @objc(decodeEvent:)
    func rnDecodeEvent(_ leafHex: String) -> NSString {
        do {
            return try decodeEvent(leafHex: leafHex) as NSString
        } catch { return failure(error) }
    }

    @objc(sessionOpen:)
    func rnSessionOpen(_ addressBook: String) -> NSString {
        do {
            let book = addressBook.split(separator: ",").map(String.init)
            if locked({ sessions.count >= Self.maxSessions }) {
                throw BridgeError(message: Self.tooManySessions)
            }
            let opened = book.isEmpty ? SigningSession() : try SigningSession.withAddressBook(book: book)
            try locked {
                for state in try NonceKeychain.loadAll() {
                    try opened.restore(state: state)
                }
            }
            let id = UUID().uuidString
            let admitted: Bool = locked {
                guard sessions.count < Self.maxSessions else { return false }
                sessions[id] = opened
                return true
            }
            guard admitted else {
                throw BridgeError(message: Self.tooManySessions)
            }
            return id as NSString
        } catch { return failure(error) }
    }

    @objc(sessionClose:)
    func rnSessionClose(_ id: String) -> NSString {
        locked { _ = sessions.removeValue(forKey: id) }
        return ""
    }

    @objc(sessionKnown:)
    func rnSessionKnown(_ id: String) -> NSString {
        do {
            return try session(id).known().joined(separator: ",") as NSString
        } catch { return failure(error) }
    }

    @objc(sessionRememberAddress:address:)
    func rnSessionRememberAddress(_ id: String, address: String) -> NSString {
        do {
            try session(id).rememberAddress(address: address)
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionCheckTarget:address:)
    func rnSessionCheckTarget(_ id: String, address: String) -> NSString {
        do {
            try session(id).checkTarget(address: address)
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionSlot:key:reported:expected:order:)
    func rnSessionSlot(_ id: String, key: String, reported: String, expected: String, order: Bool) -> NSString {
        do {
            let session = try session(id)
            return String(try recorded(session) {
                try session.slot(
                    key: key,
                    reported: try u64(reported, "reported nonce"),
                    expected: try optionalU64(expected, "expected nonce"),
                    order: order
                )
            }) as NSString
        } catch { return failure(error) }
    }

    @objc(sessionSigned:key:slot:)
    func rnSessionSigned(_ id: String, key: String, slot: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(session) { session.signed(key: key, slot: try u64(slot, "slot")) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionRelease:key:slot:)
    func rnSessionRelease(_ id: String, key: String, slot: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(session) { session.release(key: key, slot: try u64(slot, "slot")) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionReleasePending:key:)
    func rnSessionReleasePending(_ id: String, key: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(session) { session.releasePending(key: key) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionOutcome:key:slot:accepted:)
    func rnSessionOutcome(_ id: String, key: String, slot: String, accepted: Bool) -> NSString {
        do {
            let session = try session(id)
            try recorded(session) { session.outcome(key: key, slot: try u64(slot, "slot"), accepted: accepted) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionNextNonce:key:)
    func rnSessionNextNonce(_ id: String, key: String) -> NSString {
        do {
            return try session(id).nextNonce(key: key).map { String($0) }.map { $0 as NSString } ?? ""
        } catch { return failure(error) }
    }

    @objc(sessionIsHeld:key:slot:)
    func rnSessionIsHeld(_ id: String, key: String, slot: String) -> NSString {
        do {
            return (try session(id).isHeld(key: key, slot: try u64(slot, "slot")) ? "true" : "false") as NSString
        } catch { return failure(error) }
    }
}
