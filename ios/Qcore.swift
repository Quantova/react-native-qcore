// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import CryptoKit
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

    private static let maxSessions = 64

    private static let maxLearnedAddresses: UInt64 = 64

    private static let preloadedAddresses: UInt64 = 8

    private static let maxSecretBytes = 4096

    private static let tooManySessions = "too many signing sessions are open, close one first"

    private static let closedMessage = "the vault module was shut down, so it serves no further vault call"

    private static let backgroundMessage = "the vault is used only while the app is in the foreground, nothing was signed"

    private static let declinedMessage = "authentication cancelled, nothing was signed"

    private static let nonceLock = NSLock()

    private var closed = false

    private var active = false

    override init() {
        super.init()
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(hostBecameActive), name: UIApplication.didBecomeActiveNotification, object: nil)
        center.addObserver(self, selector: #selector(hostLeftForeground), name: UIApplication.didEnterBackgroundNotification, object: nil)
        center.addObserver(self, selector: #selector(hostLeftForeground), name: UIApplication.willResignActiveNotification, object: nil)
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let state = UIApplication.shared.applicationState == .active
            self.locked { self.active = state }
        }
        Keychain.removeSeedsFromEarlierInstall()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func hostBecameActive() {
        locked { active = true }
    }

    @objc private func hostLeftForeground() {
        locked { active = false }
    }

    private func ensureForeground() throws {
        if !locked({ active }) {
            throw BridgeError(message: Self.backgroundMessage)
        }
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

    private func byteData(_ values: [NSNumber], _ label: String) throws -> Data {
        guard values.count <= Self.maxSecretBytes else {
            throw BridgeError(message: "the \(label) is too long")
        }
        var out = Data(count: values.count)
        for (i, value) in values.enumerated() {
            let number = value.doubleValue
            guard number >= 0, number <= 255, number == number.rounded() else {
                wipe(&out)
                throw BridgeError(message: "the \(label) is not a list of byte values")
            }
            out[i] = UInt8(number)
        }
        return out
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
        static let installMarker = "com.quantova.qcore.install.1"

        static func earlierInstall(created: Date, installed: Date) -> Bool {
            return created < installed
        }

        static func removeSeedsFromEarlierInstall() {
            let defaults = UserDefaults.standard
            if defaults.bool(forKey: installMarker) { return }
            guard let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first,
                  let installed = (try? library.resourceValues(forKeys: [.creationDateKey]))?.creationDate else { return }
            let context = LAContext()
            context.interactionNotAllowed = true
            defer { context.invalidate() }
            let search: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
                kSecUseAuthenticationContext as String: context,
            ]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                defaults.set(true, forKey: installMarker)
                return
            }
            guard status == errSecSuccess, let items = found as? [[String: Any]] else { return }
            var cleared = true
            for item in items {
                guard let account = item[kSecAttrAccount as String] as? String,
                      let created = item[kSecAttrCreationDate as String] as? Date else {
                    cleared = false
                    continue
                }
                if earlierInstall(created: created, installed: installed) {
                    let removed = SecItemDelete(query(account) as CFDictionary)
                    if removed != errSecSuccess && removed != errSecItemNotFound { cleared = false }
                }
            }
            if cleared { defaults.set(true, forKey: installMarker) }
        }


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

    private enum AddressBook {
        static let service = "com.quantova.qcore.addresses.1"

        static func query(_ alias: String) -> [String: Any] {
            return [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: alias,
            ]
        }

        static func read(_ alias: String) throws -> [UInt64: String] {
            var search = query(alias)
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound { return [:] }
            guard status == errSecSuccess, let data = found as? Data else {
                throw BridgeError(message: "the keychain refused to read the wallet addresses with status \(status)")
            }
            var out: [UInt64: String] = [:]
            for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
                let parts = line.split(separator: " ")
                if parts.count == 2, let index = UInt64(parts[0]) {
                    out[index] = String(parts[1])
                }
            }
            return out
        }

        static func remember(_ alias: String, _ found: [UInt64: String]) throws {
            var all = try read(alias)
            if found.allSatisfy({ all[$0.key] == $0.value }) { return }
            all.merge(found) { _, new in new }
            let text = all.keys.sorted().map { "\($0) \(all[$0] ?? "")" }.joined(separator: "\n")
            let data = Data(text.utf8)
            let status = SecItemUpdate(query(alias) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status == errSecItemNotFound {
                var item = query(alias)
                item[kSecValueData as String] = data
                item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                let added = SecItemAdd(item as CFDictionary, nil)
                guard added == errSecSuccess else {
                    throw BridgeError(message: "the keychain refused to store the wallet addresses with status \(added)")
                }
            } else if status != errSecSuccess {
                throw BridgeError(message: "the keychain refused to store the wallet addresses with status \(status)")
            }
        }

        static func remove(_ alias: String) throws {
            let status = SecItemDelete(query(alias) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw BridgeError(message: "the keychain refused to remove the wallet addresses with status \(status)")
            }
        }
    }

    private enum NonceKeychain {
        static let service = "com.quantova.qcore.nonces.1"
        static let manifestAccount = "manifest"
        static let stateMax = 1 << 20
        static let manifestMax = 3 << 19
        static let lockName = "com.quantova.qcore.nonces.lock"
        static let keyLabel = "com.quantova.qcore.nonces.manifest"
        static let recordKeyTag = Data("com.quantova.qcore.nonces.record".utf8)
        static let recordKeyLabel = "com.quantova.qcore.nonces.record"
        static let readyTag = Data("com.quantova.qcore.nonces.ready.1".utf8)
        static let readyLabel = "com.quantova.qcore.nonces.ready"
        static let macLabel = "com.quantova.qcore.nonces.4/"
        static let sealVersion: UInt8 = 4
        static let macBytes = 32
        static let lockAttempts = 8
        static let writeFailed = "the nonce state could not be written, so nothing was signed"
        static let lockFailed = "the nonce state could not be locked against the other processes of this app, so nothing was signed"
        static let keyDeleteFailed = "an earlier device key of the nonce manifest could not be deleted, so nothing was signed, try again"
        static let noEnclave = "this device offers no Secure Enclave, so the nonce state cannot be protected against being put back and the vault does not sign"

        struct Header {
            let tag: String
            let alias: String
            let next: String?
            let end: Int
        }

        static var heldLock: (fd: Int32, dev: dev_t, ino: ino_t)?

        static var macKeys: [Data: SymmetricKey] = [:]

        static func lockPath() throws -> String {
            guard let folder = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true) else {
                throw BridgeError(message: lockFailed)
            }
            return folder.appendingPathComponent(lockName).path
        }

        static func named(_ path: String) -> stat? {
            var info = stat()
            return lstat(path, &info) == 0 ? info : nil
        }

        static func locked<T>(_ body: () throws -> T) throws -> T {
            let path = try lockPath()
            for _ in 0..<lockAttempts {
                let fd = Darwin.open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)
                guard fd >= 0 else {
                    throw BridgeError(message: lockFailed)
                }
                defer { _ = Darwin.close(fd) }
                while flock(fd, LOCK_EX) != 0 {
                    guard errno == EINTR else {
                        throw BridgeError(message: lockFailed)
                    }
                }
                defer { _ = flock(fd, LOCK_UN) }
                var opened = stat()
                guard fstat(fd, &opened) == 0 else {
                    throw BridgeError(message: lockFailed)
                }
                guard let current = named(path) else { continue }
                if (current.st_mode & S_IFMT) == S_IFLNK {
                    throw BridgeError(message: lockFailed)
                }
                if current.st_dev == opened.st_dev && current.st_ino == opened.st_ino {
                    heldLock = (fd, opened.st_dev, opened.st_ino)
                    defer { heldLock = nil }
                    return try body()
                }
            }
            throw BridgeError(message: lockFailed)
        }

        static func guardLock() throws {
            guard let held = heldLock, let current = named(try lockPath()) else {
                throw BridgeError(message: lockFailed)
            }
            if (current.st_mode & S_IFMT) == S_IFLNK || current.st_dev != held.dev || current.st_ino != held.ino {
                throw BridgeError(message: lockFailed)
            }
        }

        static func query(_ account: String) -> [String: Any] {
            return [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
        }

        static func read(_ account: String, _ limit: Int) throws -> (present: Bool, data: Data?) {
            var search = query(account)
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                return (false, nil)
            }
            guard status == errSecSuccess else {
                throw BridgeError(message: "the saved nonce state could not be read from the keychain with status \(status)")
            }
            guard let data = found as? Data, data.count <= limit else {
                return (true, nil)
            }
            return (true, data)
        }

        static func anyRecord() throws -> Bool {
            let search: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                return false
            }
            guard status == errSecSuccess, let items = found as? [[String: Any]] else {
                throw BridgeError(message: "the saved nonce state could not be read from the keychain with status \(status)")
            }
            return items.contains { ($0[kSecAttrAccount as String] as? String) != manifestAccount }
        }

        static func counter(_ alias: String) -> UInt64? {
            let prefix = keyLabel + "."
            guard alias.hasPrefix(prefix) else { return nil }
            let digits = alias.dropFirst(prefix.count)
            guard digits.count == 16, digits.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else {
                return nil
            }
            return UInt64(digits, radix: 16)
        }

        static func alias(_ counter: UInt64) -> String {
            let digits = String(counter, radix: 16)
            return keyLabel + "." + String(repeating: "0", count: max(0, 16 - digits.count)) + digits
        }

        static func header(_ box: Data) -> Header? {
            let bytes = [UInt8](box.prefix(2 + 255 + 1 + 255))
            guard bytes.count > 2, bytes[0] == sealVersion else { return nil }
            let tagCount = Int(bytes[1])
            guard bytes.count > 2 + tagCount else { return nil }
            let nextCount = Int(bytes[2 + tagCount])
            let end = 3 + tagCount + nextCount
            guard box.count >= end + macBytes, bytes.count >= end else { return nil }
            guard let tag = String(data: Data(bytes[2..<(2 + tagCount)]), encoding: .utf8) else { return nil }
            let parts = tag.split(separator: ".", omittingEmptySubsequences: false)
            guard let writeId = parts.last, writeId.count == 16, writeId.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else {
                return nil
            }
            let aliasName = String(tag.dropLast(17))
            guard counter(aliasName) != nil else { return nil }
            var next: String?
            if nextCount > 0 {
                guard let text = String(data: Data(bytes[(3 + tagCount)..<end]), encoding: .utf8), counter(text) != nil else {
                    return nil
                }
                next = text
            }
            return Header(tag: tag, alias: aliasName, next: next, end: end)
        }

        static func markReady() throws {
            if key(readyTag) == nil {
                _ = try newKey(readyTag, label: readyLabel)
            }
        }

        static func stored(_ account: String?, _ known: String?, boot: String?, uptimeMs: UInt64) throws -> NonceStored {
            let first = try read(manifestAccount, manifestMax + 1024)
            if !first.present, key(readyTag) == nil, try !anyRecord() {
                let orphans = try keyTags()
                if !orphans.isEmpty {
                    try guardLock()
                    try deleteKeys(orphans)
                }
            }
            let item = try read(manifestAccount, manifestMax + 1024)
            let tags = try keyTags()
            let aliases = tags.compactMap { String(data: $0, encoding: .utf8) }
            let present = item.present || !tags.isEmpty
            var tag: String?
            var manifest: String?
            if let box = item.data, let header = header(box) {
                if key(readyTag) == nil {
                    try guardLock()
                    try markReady()
                }
                tag = header.tag
                let others = tags.filter { String(data: $0, encoding: .utf8) != header.alias }
                let mine = counter(header.alias) ?? 0
                let unexplained = aliases.contains { other in
                    other != header.alias && (counter(other) ?? 0) > mine && other != header.next
                }
                if unexplained {
                    tag = nil
                } else if !others.isEmpty || tag != known {
                    manifest = openManifest(box, header)
                    if manifest == nil {
                        tag = nil
                    } else if !others.isEmpty {
                        try guardLock()
                        try deleteKeys(others)
                    }
                }
            }
            let records = present ? false : try anyRecord()
            var recordPresent = false
            var record: String?
            if let account = account {
                let found = try read(account, stateMax + 64)
                recordPresent = found.present
                record = found.data.flatMap { openRecord(account, $0) }
            }
            return NonceStored(manifestPresent: present, manifest: manifest, manifestTag: tag, recordsPresent: records, account: account, recordPresent: recordPresent, record: record, boot: boot, uptimeMs: uptimeMs)
        }

        static func put(_ account: String, _ data: Data) throws {
            try guardLock()
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
                throw BridgeError(message: writeFailed)
            }
        }

        static func recordMessage(_ account: String, _ plain: Data) -> Data {
            var message = Data((macLabel + account).utf8)
            message.append(0)
            message.append(plain)
            return message
        }

        static func save(_ account: String, _ state: String) throws {
            let plain = Data(state.utf8)
            guard plain.count <= stateMax else {
                throw BridgeError(message: "the saved nonce state of an account may take at most 1 MiB, so nothing was signed")
            }
            let key = try macKey(recordKeyTag, label: recordKeyLabel, create: true)
            var box = Data([sealVersion])
            box.append(Data(HMAC<SHA256>.authenticationCode(for: recordMessage(account, plain), using: key)))
            box.append(plain)
            try put(account, box)
        }

        static func openRecord(_ account: String, _ box: Data) -> String? {
            let bytes = [UInt8](box)
            guard bytes.count > 1 + macBytes, bytes[0] == sealVersion else { return nil }
            guard let key = try? macKey(recordKeyTag, label: recordKeyLabel, create: false) else { return nil }
            let mac = Data(bytes[1..<(1 + macBytes)])
            let plain = Data(bytes[(1 + macBytes)...])
            guard same(mac, Data(HMAC<SHA256>.authenticationCode(for: recordMessage(account, plain), using: key))) else {
                return nil
            }
            return String(data: plain, encoding: .utf8)
        }

        static func same(_ a: Data, _ b: Data) -> Bool {
            guard a.count == b.count else { return false }
            var diff: UInt8 = 0
            for (x, y) in zip(a, b) {
                diff |= x ^ y
            }
            return diff == 0
        }

        static func manifestMessage(_ header: Data, _ plain: Data) -> Data {
            var message = Data((macLabel + manifestAccount + "/").utf8)
            message.append(header)
            message.append(plain)
            return message
        }

        static func writeManifest(_ plain: Data, alias: String, next: String?) throws -> String {
            var random = [UInt8](repeating: 0, count: 8)
            guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
                throw BridgeError(message: writeFailed)
            }
            let tag = alias + "." + random.map { String(format: "%02x", $0) }.joined()
            let tagBytes = Data(tag.utf8)
            let nextBytes = Data((next ?? "").utf8)
            var header = Data([sealVersion, UInt8(tagBytes.count)])
            header.append(tagBytes)
            header.append(UInt8(nextBytes.count))
            header.append(nextBytes)
            let key = try macKey(Data(alias.utf8), label: keyLabel, create: false)
            var box = header
            box.append(Data(HMAC<SHA256>.authenticationCode(for: manifestMessage(header, plain), using: key)))
            box.append(plain)
            try put(manifestAccount, box)
            return tag
        }

        static func commit(_ batch: NonceBatch) throws -> String {
            try guardLock()
            let plain = Data(batch.manifest.utf8)
            guard plain.count <= manifestMax else {
                throw BridgeError(message: "the saved nonce manifest may take at most 1.5 MiB, so nothing was signed")
            }
            let aliases = try keyTags().compactMap { String(data: $0, encoding: .utf8) }
            let current = (try read(manifestAccount, manifestMax + 1024)).data.flatMap(header)?.alias
            let usable = current.flatMap { aliases.contains($0) ? $0 : nil }
            let tag: String
            if !batch.rotate, let usable = usable {
                tag = try writeManifest(plain, alias: usable, next: nil)
            } else {
                let next = alias((aliases.compactMap(counter).max() ?? 0) + 1)
                if let usable = usable {
                    _ = try writeManifest(plain, alias: usable, next: next)
                }
                _ = try newKey(Data(next.utf8), label: keyLabel)
                tag = try writeManifest(plain, alias: next, next: nil)
            }
            for record in batch.records {
                try save(record.account, record.state)
            }
            try markReady()
            let written = String(tag.dropLast(17))
            try deleteKeys(try keyTags().filter { String(data: $0, encoding: .utf8) != written })
            return tag
        }

        static func openManifest(_ box: Data, _ header: Header) -> String? {
            let bytes = [UInt8](box)
            guard let key = try? macKey(Data(header.alias.utf8), label: keyLabel, create: false) else {
                return nil
            }
            let mac = Data(bytes[header.end..<(header.end + macBytes)])
            let plain = Data(bytes[(header.end + macBytes)...])
            guard same(mac, Data(HMAC<SHA256>.authenticationCode(for: manifestMessage(Data(bytes[0..<header.end]), plain), using: key))) else {
                return nil
            }
            return String(data: plain, encoding: .utf8)
        }

        static func remove(_ account: String) throws {
            try guardLock()
            let status = SecItemDelete(query(account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw BridgeError(message: "the saved nonce state could not be removed with status \(status)")
            }
        }

        static func removeRecords() throws {
            try guardLock()
            let search: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                return
            }
            guard status == errSecSuccess, let items = found as? [[String: Any]] else {
                throw BridgeError(message: "the saved nonce state could not be removed with status \(status)")
            }
            for account in items.compactMap({ $0[kSecAttrAccount as String] as? String }) where account != manifestAccount {
                try remove(account)
            }
        }

        static func enclaveSearch(_ search: inout [String: Any]) {
            #if !targetEnvironment(simulator)
            search[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            #endif
        }

        static func keyTags() throws -> [Data] {
            var search: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: keyLabel,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            enclaveSearch(&search)
            var found: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &found)
            if status == errSecItemNotFound {
                return []
            }
            guard status == errSecSuccess, let items = found as? [[String: Any]] else {
                throw BridgeError(message: "the key that seals the nonce manifest could not be read with status \(status)")
            }
            return items.compactMap { $0[kSecAttrApplicationTag as String] as? Data }
        }

        static func key(_ tag: Data) -> SecKey? {
            var search: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            enclaveSearch(&search)
            var found: CFTypeRef?
            guard SecItemCopyMatching(search as CFDictionary, &found) == errSecSuccess, let item = found, CFGetTypeID(item) == SecKeyGetTypeID() else {
                return nil
            }
            return (item as! SecKey)
        }

        static func macKey(_ tag: Data, label: String, create: Bool) throws -> SymmetricKey {
            if let cached = macKeys[tag] {
                return cached
            }
            let found: SecKey
            if let existing = key(tag) {
                found = existing
            } else if create {
                found = try newKey(tag, label: label)
            } else {
                throw BridgeError(message: writeFailed)
            }
            guard let shared = SecKeyCopyPublicKey(found) else {
                throw BridgeError(message: writeFailed)
            }
            let parameters: [String: Any] = [
                SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 32,
                SecKeyKeyExchangeParameter.sharedInfo.rawValue as String: Data((macLabel + "mac/").utf8) + tag,
            ]
            var failed: Unmanaged<CFError>?
            guard let secret = SecKeyCopyKeyExchangeResult(found, .ecdhKeyExchangeStandardX963SHA256, shared, parameters as CFDictionary, &failed) as Data? else {
                failed?.release()
                throw BridgeError(message: writeFailed)
            }
            let derived = SymmetricKey(data: secret)
            macKeys[tag] = derived
            return derived
        }

        static func newKey(_ tag: Data, label: String) throws -> SecKey {
            var failed: Unmanaged<CFError>?
            var privateAttributes: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrLabel as String: label,
            ]
            var attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
            ]
            #if targetEnvironment(simulator)
            privateAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            #else
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &failed) else {
                failed?.release()
                throw BridgeError(message: noEnclave)
            }
            privateAttributes[kSecAttrAccessControl as String] = access
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            #endif
            attributes[kSecPrivateKeyAttrs as String] = privateAttributes
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &failed) else {
                failed?.release()
                #if targetEnvironment(simulator)
                throw BridgeError(message: writeFailed)
                #else
                throw BridgeError(message: noEnclave)
                #endif
            }
            return key
        }

        static func deleteKeys(_ tags: [Data]) throws {
            for tag in tags {
                let search: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                ]
                let status = SecItemDelete(search as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else {
                    throw BridgeError(message: keyDeleteFailed)
                }
                macKeys.removeValue(forKey: tag)
            }
            let left = try keyTags()
            if left.contains(where: { tags.contains($0) }) {
                throw BridgeError(message: keyDeleteFailed)
            }
        }
    }

    private static func bootSession() -> String? {
        var size = 0
        if sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 {
            var buffer = [CChar](repeating: 0, count: size)
            if sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 {
                let text = String(cString: buffer)
                if !text.isEmpty {
                    return "ios-boot-" + text
                }
            }
        }
        var boot = timeval()
        var length = MemoryLayout<timeval>.stride
        if sysctlbyname("kern.boottime", &boot, &length, nil, 0) == 0 {
            return "ios-boottime-\(boot.tv_sec).\(boot.tv_usec)"
        }
        return nil
    }

    private static func uptimeMs() -> UInt64 {
        var base = mach_timebase_info_data_t()
        guard mach_timebase_info(&base) == KERN_SUCCESS, base.denom != 0 else { return 0 }
        return mach_continuous_time() / UInt64(base.denom) * UInt64(base.numer) / 1_000_000
    }

    private func persist() throws {
        guard let batch = try nonceBatch() else { return }
        let tag = try NonceKeychain.commit(batch)
        nonceCommitted(manifestTag: tag)
    }

    private static let nonceQueue = DispatchQueue(label: "com.quantova.qcore.nonces")

    private func answer(_ resolve: @escaping (Any?) -> Void, _ work: @escaping () -> NSString) {
        Self.nonceQueue.async {
            resolve(work())
        }
    }

    private func ensureOpen() throws {
        if locked({ closed }) {
            throw BridgeError(message: Self.closedMessage)
        }
    }

    private func withNonceLock<T>(_ body: () throws -> T) rethrows -> T {
        Self.nonceLock.lock()
        defer { Self.nonceLock.unlock() }
        return try body()
    }

    private func synced<T>(_ account: String?, _ body: () throws -> T) throws -> T {
        return try withNonceLock {
            try ensureOpen()
            return try NonceKeychain.locked {
                try nonceSync(stored: try NonceKeychain.stored(account, nonceManifestTag(), boot: Self.bootSession(), uptimeMs: Self.uptimeMs()))
                return try body()
            }
        }
    }

    private func recorded<T>(_ account: String, _ change: () throws -> T) throws -> T {
        return try synced(account) {
            let out: T
            do {
                out = try change()
            } catch {
                try? persist()
                throw error
            }
            try persist()
            return out
        }
    }

    private func nonceAccountOf(_ chainId: String, _ genesisHex: String, _ key: String) throws -> String {
        return try nonceAccount(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key)
    }

    private func resetTarget(_ chainId: String, _ genesisHex: String, _ key: String) throws -> (UInt64, String, String)? {
        if chainId.isEmpty && genesisHex.isEmpty && key.isEmpty {
            return nil
        }
        guard !chainId.isEmpty, !genesisHex.isEmpty, !key.isEmpty else {
            throw BridgeError(message: "name the chain id, the genesis hash and the key to reset one account, or none of them to reset every account")
        }
        return (try u64(chainId, "chain id"), genesisHex, key)
    }

    private func resetNow(_ chainId: String, _ genesisHex: String, _ key: String) throws {
        let target = try resetTarget(chainId, genesisHex, key)
        let account = try target.map { try nonceAccount(chainId: $0.0, genesisHex: $0.1, key: $0.2) }
        try synced(account) {
            let reset = try resetNonceState(chainId: target?.0, genesisHex: target?.1, key: target?.2)
            let tag = try NonceKeychain.commit(NonceBatch(manifest: reset.manifest, records: [], rotate: true))
            if target == nil {
                try NonceKeychain.removeRecords()
            } else {
                for removed in reset.removed {
                    try NonceKeychain.remove(removed)
                }
            }
            nonceCommitted(manifestTag: tag)
        }
    }

    private final class Decision {
        var approved = false
    }

    private static func topController() -> UIViewController? {
        let windows = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
        var top = (windows.first { $0.isKeyWindow } ?? windows.first)?.rootViewController
        while let presented = top?.presentedViewController {
            top = presented
        }
        return top
    }

    private func confirmNatively(_ title: String, _ message: String) throws {
        if Thread.isMainThread {
            throw BridgeError(message: "the vault asks the user from a background thread only, nothing was signed")
        }
        let decided = DispatchSemaphore(value: 0)
        let decision = Decision()
        DispatchQueue.main.async {
            guard let top = Self.topController() else {
                decided.signal()
                return
            }
            let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                decided.signal()
            })
            alert.addAction(UIAlertAction(title: "Approve", style: .default) { _ in
                decision.approved = true
                decided.signal()
            })
            top.present(alert, animated: true)
        }
        decided.wait()
        if !decision.approved {
            throw BridgeError(message: Self.declinedMessage)
        }
    }

    private func gateReason(_ title: String, _ summary: String, _ extra: String) -> String {
        return [title, summary, extra].filter { !$0.isEmpty }.joined(separator: "\n")
    }

    private func unlocked<T>(_ alias: String, title: String, summary: String, extra: String, confirm: Bool, _ body: (SeedHandle) throws -> T) throws -> T {
        try ensureOpen()
        let alias = try checkedAlias(alias)
        try ensureForeground()
        if confirm {
            try confirmNatively(title, [summary, extra].filter { !$0.isEmpty }.joined(separator: "\n"))
        }
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = gateReason(title, summary, extra)
        defer { context.invalidate() }
        var seed = try Keychain.load(alias, context: context)
        defer { wipe(&seed) }
        let handle = try SeedHandle.fromSeedBytes(seed: seed)
        defer { handle.forget() }
        try ensureOpen()
        return try body(handle)
    }

    private func learn(_ alias: String, _ handle: SeedHandle, from: UInt64, count: UInt64) throws {
        var found: [UInt64: String] = [:]
        for index in from..<(from + count) {
            found[index] = try handle.address(index: index)
        }
        try locked { try AddressBook.remember(alias, found) }
    }

    private func keep(_ alias: String, _ make: () throws -> SeedHandle) throws {
        try ensureOpen()
        let alias = try checkedAlias(alias)
        try ensureForeground()
        let handle = try make()
        defer { handle.forget() }
        var seed = try handle.seedBytes()
        defer { wipe(&seed) }
        try Keychain.save(alias, seed)
        try learn(alias, handle, from: 0, count: Self.preloadedAddresses)
    }

    private func vaultSigned(
        _ alias: String,
        sessionId: String,
        index: String,
        chainId: String,
        genesisHex: String,
        summary: () throws -> String,
        _ sign: (SeedHandle, SigningSession) throws -> String
    ) -> NSString {
        do {
            let session = try session(sessionId)
            let at = try u64(index, "index")
            let chain = try u64(chainId, "chain id")
            _ = try nonceAccount(chainId: chain, genesisHex: genesisHex, key: "vault")
            let shown = try summary()
            return try unlocked(alias, title: "Approve transaction", summary: shown, extra: "", confirm: true) { handle in
                let address = try handle.address(index: at)
                try learn(alias, handle, from: at, count: 1)
                return try recorded(try nonceAccount(chainId: chain, genesisHex: genesisHex, key: address)) {
                    try sign(handle, session)
                } as NSString
            }
        } catch { return failure(error) }
    }

    private func session(_ id: String) throws -> SigningSession {
        try ensureOpen()
        guard let found = locked({ sessions[id] }) else {
            throw BridgeError(message: "no signing session is open under this id")
        }
        return found
    }

    @objc func invalidate() {
        NotificationCenter.default.removeObserver(self)
        locked {
            closed = true
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

    @objc(signTransfer:index:to:amount:nonce:fee:chainId:validUntil:head:genesisHex:)
    func rnSignTransfer(
        _ seedHex: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String
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
                    head: try u64(head, "head"),
                    genesisHex: genesisHex
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signCall:index:target:argsHex:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:genesisHex:)
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
        head: String,
        genesisHex: String
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
                    head: try u64(head, "head"),
                    genesisHex: genesisHex
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signRegister:index:nonce:fee:chainId:validUntil:head:genesisHex:)
    func rnSignRegister(
        _ seedHex: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String
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
                    head: try u64(head, "head"),
                    genesisHex: genesisHex
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signPayableCall:index:target:argsHex:nonce:meterLimit:fee:value:chainId:validUntil:transferFee:head:genesisHex:)
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
        head: String,
        genesisHex: String
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
                    head: try u64(head, "head"),
                    genesisHex: genesisHex
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(signAssetCall:index:target:argsHex:assetIssuer:amount:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:genesisHex:)
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
        head: String,
        genesisHex: String
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
                    head: try u64(head, "head"),
                    genesisHex: genesisHex
                ) as NSString
            }
        } catch { return failure(error) }
    }

    @objc(gatewayProtocol)
    func rnGatewayProtocol() -> NSNumber {
        return NSNumber(value: gatewayProtocol())
    }

    @objc(checkEndpoint:)
    func rnCheckEndpoint(_ base: String) -> NSString {
        do {
            try checkEndpoint(base: base)
            return ""
        } catch { return failure(error) }
    }

    @objc(testnetRpcUrl)
    func rnTestnetRpcUrl() -> NSString {
        return testnetRpcUrl() as NSString
    }

    @objc(testnetChainName)
    func rnTestnetChainName() -> NSString {
        return testnetChainName() as NSString
    }

    @objc(testnetGenesisHash)
    func rnTestnetGenesisHash() -> NSString {
        return (testnetGenesisHash() ?? "") as NSString
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

    @objc(vaultCreate:resolver:rejecter:)
    func rnVaultCreate(
        _ alias: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.keep(alias) { try SeedHandle.generate() }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultImportPhrase:phrase:resolver:rejecter:)
    func rnVaultImportPhrase(
        _ alias: String,
        phrase: [NSNumber],
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.keep(alias) {
                    var bytes = try self.byteData(phrase, "phrase")
                    defer { self.wipe(&bytes) }
                    return try SeedHandle.fromPhraseBytes(phrase: bytes)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultImportSeed:seed:resolver:rejecter:)
    func rnVaultImportSeed(
        _ alias: String,
        seed: [NSNumber],
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.keep(alias) {
                    var bytes = try self.byteData(seed, "seed")
                    defer { self.wipe(&bytes) }
                    return try SeedHandle.fromSeedBytes(seed: bytes)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
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
            do {
                let extra = [title, subtitle].filter { !$0.isEmpty }.joined(separator: "\n")
                let phrase: [NSNumber] = try self.unlocked(alias, title: "Reveal recovery phrase", summary: "Show the recovery phrase of this wallet on screen", extra: extra, confirm: false) { handle in
                    var bytes = try handle.phraseBytes()
                    defer { self.wipe(&bytes) }
                    return bytes.map { NSNumber(value: $0) }
                }
                resolve(phrase)
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultLearnAddresses:count:resolver:rejecter:)
    func rnVaultLearnAddresses(
        _ alias: String,
        count: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let wanted = try self.u64(count, "address count")
                guard wanted >= 1, wanted <= Self.maxLearnedAddresses else {
                    throw BridgeError(message: "learn between one and sixty four addresses at a time")
                }
                try self.unlocked(alias, title: "Show wallet addresses", summary: "Derive the first account addresses of this wallet", extra: "", confirm: false) { handle in
                    try self.learn(alias, handle, from: 0, count: wanted)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultResetNonceState:chainId:genesisHex:key:title:subtitle:resolver:rejecter:)
    func rnVaultResetNonceState(
        _ alias: String,
        chainId: String,
        genesisHex: String,
        key: String,
        title: String,
        subtitle: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try self.resetTarget(chainId, genesisHex, key)
                try self.authenticateAgain(alias, title: "Reset nonce state", summary: "Clear the saved nonce state so this wallet signs again", title, subtitle)
                try self.resetNow(chainId, genesisHex, key)
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultAcknowledgeImportedHistory:chainId:genesisHex:key:title:subtitle:resolver:rejecter:)
    func rnVaultAcknowledgeImportedHistory(
        _ alias: String,
        chainId: String,
        genesisHex: String,
        key: String,
        title: String,
        subtitle: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let account = try self.namedAccount(chainId, genesisHex, key)
                try self.authenticateAgain(alias, title: "Acknowledge imported history", summary: "Accept that this account signed elsewhere before this device kept its nonces", title, subtitle)
                try self.recorded(account) {
                    try acknowledgeImportedHistory(chainId: try self.u64(chainId, "chain id"), genesisHex: genesisHex, key: key)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultAcknowledgeMainnet:chainId:genesisHex:key:title:subtitle:resolver:rejecter:)
    func rnVaultAcknowledgeMainnet(
        _ alias: String,
        chainId: String,
        genesisHex: String,
        key: String,
        title: String,
        subtitle: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let account = try self.namedAccount(chainId, genesisHex, key)
                try self.authenticateAgain(alias, title: "Allow mainnet signing", summary: "Let this wallet sign on mainnet, where a transaction moves real value", title, subtitle)
                try self.recorded(account) {
                    try acknowledgeMainnet(chainId: try self.u64(chainId, "chain id"), genesisHex: genesisHex, key: key)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    private func namedAccount(_ chainId: String, _ genesisHex: String, _ key: String) throws -> String {
        guard !chainId.isEmpty, !genesisHex.isEmpty, !key.isEmpty else {
            throw BridgeError(message: "name the chain id, the genesis hash and the key of the account this acknowledgement is for")
        }
        return try nonceAccountOf(chainId, genesisHex, key)
    }

    private func authenticateAgain(_ alias: String, title: String, summary: String, _ jsTitle: String, _ jsSubtitle: String) throws {
        let extra = [jsTitle, jsSubtitle].filter { !$0.isEmpty }.joined(separator: "\n")
        try unlocked(alias, title: title, summary: summary, extra: extra, confirm: false) { _ in }
    }

    @objc(vaultStorageLevel)
    func rnVaultStorageLevel() -> NSString {
        do {
            try ensureOpen()
            return "keychain"
        } catch { return failure(error) }
    }

    @objc(vaultHas:)
    func rnVaultHas(_ alias: String) -> NSString {
        do {
            try ensureOpen()
            let alias = try checkedAlias(alias)
            return (try Keychain.has(alias) ? "true" : "false") as NSString
        } catch { return failure(error) }
    }

    @objc(vaultClose:)
    func rnVaultClose(_ alias: String) -> NSString {
        do {
            try ensureOpen()
            _ = try checkedAlias(alias)
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultCloseAll)
    func rnVaultCloseAll() -> NSString {
        do {
            try ensureOpen()
            return ""
        } catch { return failure(error) }
    }

    @objc(vaultForget:title:subtitle:resolver:rejecter:)
    func rnVaultForget(
        _ alias: String,
        title: String,
        subtitle: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.authenticateAgain(alias, title: "Delete wallet from this device", summary: "Delete the sealed seed of this wallet from this device", title, subtitle)
                try self.locked {
                    try Keychain.remove(alias)
                    try AddressBook.remove(alias)
                }
                resolve("")
            } catch { resolve(self.failure(error)) }
        }
    }

    @objc(vaultAddress:index:)
    func rnVaultAddress(_ alias: String, index: String) -> NSString {
        do {
            try ensureOpen()
            let alias = try checkedAlias(alias)
            let at = try u64(index, "index")
            try ensureForeground()
            guard try Keychain.has(alias) else {
                throw BridgeError(message: "no seed is stored under this alias")
            }
            guard let found = try locked({ try AddressBook.read(alias) })[at] else {
                throw BridgeError(message: "authentication required, the address at index \(at) of this seed is not known on this device yet, learn it with learnAddresses after authenticating")
            }
            return found as NSString
        } catch { return failure(error) }
    }

    @objc(vaultSignTransfer:sessionId:index:to:amount:nonce:fee:chainId:validUntil:head:genesisHex:resolver:rejecter:)
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
        head: String,
        genesisHex: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.vaultSignTransferNow(alias, sessionId: sessionId, index: index, to: to, amount: amount, nonce: nonce, fee: fee, chainId: chainId, validUntil: validUntil, head: head, genesisHex: genesisHex) }
    }

    private func vaultSignTransferNow(
        _ alias: String,
        sessionId: String,
        index: String,
        to: String,
        amount: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String
    ) -> NSString {
        return vaultSigned(alias, sessionId: sessionId, index: index, chainId: chainId, genesisHex: genesisHex, summary: { try signingSummary(kind: "transfer", chainId: try u64(chainId, "chain id"), target: to, amount: amount, fee: fee, assetIssuer: "") }) { handle, session in
            try handle.signTransfer(
                session: session,
                index: try u64(index, "index"),
                to: to,
                amount: amount,
                nonce: try u64(nonce, "nonce"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until"),
                head: try u64(head, "head"),
                genesisHex: genesisHex
            )
        }
    }

    @objc(vaultSignCall:sessionId:index:target:argsHex:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:genesisHex:resolver:rejecter:)
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
        head: String,
        genesisHex: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.vaultSignCallNow(alias, sessionId: sessionId, index: index, target: target, argsHex: argsHex, nonce: nonce, meterLimit: meterLimit, fee: fee, chainId: chainId, validUntil: validUntil, transferFee: transferFee, head: head, genesisHex: genesisHex) }
    }

    private func vaultSignCallNow(
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
        head: String,
        genesisHex: String
    ) -> NSString {
        return vaultSigned(alias, sessionId: sessionId, index: index, chainId: chainId, genesisHex: genesisHex, summary: { try signingSummary(kind: "call", chainId: try u64(chainId, "chain id"), target: target, amount: "0", fee: fee, assetIssuer: "") }) { handle, session in
            try handle.signCall(
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
                head: try u64(head, "head"),
                genesisHex: genesisHex
            )
        }
    }

    @objc(vaultSignRegister:sessionId:index:nonce:fee:chainId:validUntil:head:genesisHex:resolver:rejecter:)
    func rnVaultSignRegister(
        _ alias: String,
        sessionId: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.vaultSignRegisterNow(alias, sessionId: sessionId, index: index, nonce: nonce, fee: fee, chainId: chainId, validUntil: validUntil, head: head, genesisHex: genesisHex) }
    }

    private func vaultSignRegisterNow(
        _ alias: String,
        sessionId: String,
        index: String,
        nonce: String,
        fee: String,
        chainId: String,
        validUntil: String,
        head: String,
        genesisHex: String
    ) -> NSString {
        return vaultSigned(alias, sessionId: sessionId, index: index, chainId: chainId, genesisHex: genesisHex, summary: { try signingSummary(kind: "register", chainId: try u64(chainId, "chain id"), target: "", amount: "0", fee: fee, assetIssuer: "") }) { handle, session in
            try handle.signRegister(
                session: session,
                index: try u64(index, "index"),
                nonce: try u64(nonce, "nonce"),
                fee: fee,
                chainId: try u64(chainId, "chain id"),
                validUntil: try u64(validUntil, "valid until"),
                head: try u64(head, "head"),
                genesisHex: genesisHex
            )
        }
    }

    @objc(vaultSignPayableCall:sessionId:index:target:argsHex:nonce:meterLimit:fee:value:chainId:validUntil:transferFee:head:genesisHex:resolver:rejecter:)
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
        head: String,
        genesisHex: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.vaultSignPayableCallNow(alias, sessionId: sessionId, index: index, target: target, argsHex: argsHex, nonce: nonce, meterLimit: meterLimit, fee: fee, value: value, chainId: chainId, validUntil: validUntil, transferFee: transferFee, head: head, genesisHex: genesisHex) }
    }

    private func vaultSignPayableCallNow(
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
        head: String,
        genesisHex: String
    ) -> NSString {
        return vaultSigned(alias, sessionId: sessionId, index: index, chainId: chainId, genesisHex: genesisHex, summary: { try signingSummary(kind: "payable", chainId: try u64(chainId, "chain id"), target: target, amount: value, fee: fee, assetIssuer: "") }) { handle, session in
            try handle.signPayableCall(
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
                head: try u64(head, "head"),
                genesisHex: genesisHex
            )
        }
    }

    @objc(vaultSignAssetCall:sessionId:index:target:argsHex:assetIssuer:amount:nonce:meterLimit:fee:chainId:validUntil:transferFee:head:genesisHex:resolver:rejecter:)
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
        head: String,
        genesisHex: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.vaultSignAssetCallNow(alias, sessionId: sessionId, index: index, target: target, argsHex: argsHex, assetIssuer: assetIssuer, amount: amount, nonce: nonce, meterLimit: meterLimit, fee: fee, chainId: chainId, validUntil: validUntil, transferFee: transferFee, head: head, genesisHex: genesisHex) }
    }

    private func vaultSignAssetCallNow(
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
        head: String,
        genesisHex: String
    ) -> NSString {
        return vaultSigned(alias, sessionId: sessionId, index: index, chainId: chainId, genesisHex: genesisHex, summary: { try signingSummary(kind: "asset", chainId: try u64(chainId, "chain id"), target: target, amount: amount, fee: fee, assetIssuer: assetIssuer) }) { handle, session in
            try handle.signAssetCall(
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
                head: try u64(head, "head"),
                genesisHex: genesisHex
            )
        }
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

    @objc(verifyFinality:genesisHex:headerHex:certificateHex:rosterJson:)
    func rnVerifyFinality(_ chainId: String, genesisHex: String, headerHex: String, certificateHex: String, rosterJson: String) -> NSString {
        do {
            return try verifyFinality(
                chainId: try u64(chainId, "chain id"),
                genesisHex: genesisHex,
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

    @objc(confirmTransaction:genesisHex:txId:proofJson:finalityJson:rosterJson:)
    func rnConfirmTransaction(
        _ chainId: String,
        genesisHex: String,
        txId: String,
        proofJson: String,
        finalityJson: String,
        rosterJson: String
    ) -> NSString {
        do {
            return try confirmTransaction(
                chainId: try u64(chainId, "chain id"),
                genesisHex: genesisHex,
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
            try ensureOpen()
            let book = addressBook.split(separator: ",").map(String.init)
            if locked({ sessions.count >= Self.maxSessions }) {
                throw BridgeError(message: Self.tooManySessions)
            }
            let opened = book.isEmpty ? SigningSession() : try SigningSession.withAddressBook(book: book)
            let id = UUID().uuidString
            let admitted: Bool = locked {
                guard !closed, sessions.count < Self.maxSessions else { return false }
                sessions[id] = opened
                return true
            }
            guard admitted else {
                throw BridgeError(message: locked({ closed }) ? Self.closedMessage : Self.tooManySessions)
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

    @objc(sessionSlot:chainId:genesisHex:key:reported:expected:order:resolver:rejecter:)
    func rnSessionSlot(
        _ id: String,
        chainId: String,
        genesisHex: String,
        key: String,
        reported: String,
        expected: String,
        order: Bool,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.sessionSlotNow(id, chainId: chainId, genesisHex: genesisHex, key: key, reported: reported, expected: expected, order: order) }
    }

    private func sessionSlotNow(_ id: String, chainId: String, genesisHex: String, key: String, reported: String, expected: String, order: Bool) -> NSString {
        do {
            let session = try session(id)
            return String(try recorded(try nonceAccountOf(chainId, genesisHex, key)) {
                try session.slot(
                    chainId: try u64(chainId, "chain id"),
                    genesisHex: genesisHex,
                    key: key,
                    reported: try u64(reported, "reported nonce"),
                    expected: try optionalU64(expected, "expected nonce"),
                    order: order
                )
            }) as NSString
        } catch { return failure(error) }
    }

    @objc(sessionSigned:chainId:genesisHex:key:slot:resolver:rejecter:)
    func rnSessionSigned(_ id: String, chainId: String, genesisHex: String, key: String, slot: String, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionSignedNow(id, chainId: chainId, genesisHex: genesisHex, key: key, slot: slot) }
    }

    private func sessionSignedNow(_ id: String, chainId: String, genesisHex: String, key: String, slot: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(try nonceAccountOf(chainId, genesisHex, key)) { try session.signed(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key, slot: try u64(slot, "slot")) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionRelease:chainId:genesisHex:key:slot:resolver:rejecter:)
    func rnSessionRelease(_ id: String, chainId: String, genesisHex: String, key: String, slot: String, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionReleaseNow(id, chainId: chainId, genesisHex: genesisHex, key: key, slot: slot) }
    }

    private func sessionReleaseNow(_ id: String, chainId: String, genesisHex: String, key: String, slot: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(try nonceAccountOf(chainId, genesisHex, key)) { try session.release(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key, slot: try u64(slot, "slot")) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionReleasePending:chainId:genesisHex:key:resolver:rejecter:)
    func rnSessionReleasePending(_ id: String, chainId: String, genesisHex: String, key: String, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionReleasePendingNow(id, chainId: chainId, genesisHex: genesisHex, key: key) }
    }

    private func sessionReleasePendingNow(_ id: String, chainId: String, genesisHex: String, key: String) -> NSString {
        do {
            let session = try session(id)
            try recorded(try nonceAccountOf(chainId, genesisHex, key)) { try session.releasePending(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key) }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionOutcome:chainId:genesisHex:key:slot:accepted:resolver:rejecter:)
    func rnSessionOutcome(_ id: String, chainId: String, genesisHex: String, key: String, slot: String, accepted: Bool, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionOutcomeNow(id, chainId: chainId, genesisHex: genesisHex, key: key, slot: slot, accepted: accepted) }
    }

    private func sessionOutcomeNow(_ id: String, chainId: String, genesisHex: String, key: String, slot: String, accepted: Bool) -> NSString {
        do {
            let session = try session(id)
            try recorded(try nonceAccountOf(chainId, genesisHex, key)) {
                try session.outcome(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key, slot: try u64(slot, "slot"), accepted: accepted)
            }
            return ""
        } catch { return failure(error) }
    }

    @objc(sessionNextNonce:chainId:genesisHex:key:resolver:rejecter:)
    func rnSessionNextNonce(_ id: String, chainId: String, genesisHex: String, key: String, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionNextNonceNow(id, chainId: chainId, genesisHex: genesisHex, key: key) }
    }

    private func sessionNextNonceNow(_ id: String, chainId: String, genesisHex: String, key: String) -> NSString {
        do {
            let session = try session(id)
            return try synced(try nonceAccountOf(chainId, genesisHex, key)) {
                try session.nextNonce(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key).map { String($0) }.map { $0 as NSString } ?? ""
            }
        } catch { return failure(error) }
    }

    @objc(sessionIsHeld:chainId:genesisHex:key:slot:resolver:rejecter:)
    func rnSessionIsHeld(_ id: String, chainId: String, genesisHex: String, key: String, slot: String, resolver resolve: @escaping (Any?) -> Void, rejecter reject: @escaping (String?, String?, Error?) -> Void) {
        answer(resolve) { self.sessionIsHeldNow(id, chainId: chainId, genesisHex: genesisHex, key: key, slot: slot) }
    }

    private func sessionIsHeldNow(_ id: String, chainId: String, genesisHex: String, key: String, slot: String) -> NSString {
        do {
            let session = try session(id)
            return try synced(try nonceAccountOf(chainId, genesisHex, key)) {
                (try session.isHeld(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key, slot: try u64(slot, "slot")) ? "true" : "false") as NSString
            }
        } catch { return failure(error) }
    }

    @objc(vaultSettleHistory:genesisHex:key:headerHex:certificateHex:rosterJson:resolver:rejecter:)
    func rnVaultSettleHistory(
        _ chainId: String,
        genesisHex: String,
        key: String,
        headerHex: String,
        certificateHex: String,
        rosterJson: String,
        resolver resolve: @escaping (Any?) -> Void,
        rejecter reject: @escaping (String?, String?, Error?) -> Void
    ) {
        answer(resolve) { self.settleHistoryNow(chainId, genesisHex: genesisHex, key: key, headerHex: headerHex, certificateHex: certificateHex, rosterJson: rosterJson) }
    }

    private func settleHistoryNow(_ chainId: String, genesisHex: String, key: String, headerHex: String, certificateHex: String, rosterJson: String) -> NSString {
        do {
            let settled = try recorded(try nonceAccountOf(chainId, genesisHex, key)) {
                try settleHistory(chainId: try u64(chainId, "chain id"), genesisHex: genesisHex, key: key, headerHex: headerHex, certificateHex: certificateHex, rosterJson: rosterJson)
            }
            return "{\"settled\":\(settled.settled),\"blocks_left\":\"\(settled.blocksLeft)\",\"secs_left\":\"\(settled.secsLeft)\"}" as NSString
        } catch { return failure(error) }
    }
}
