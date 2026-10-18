# react-native-qcore

Post quantum client core for React Native apps on the Quantova network. Keys are derived and transactions are signed with ML-DSA-65 on the device through the Rust core [QCore.rs](https://github.com/Quantova/QCore.rs), linked as native code on Android and iOS with no wasm and no JavaScript cryptography.

## Install

```sh
npm install @quantovainc/react-native-qcore
cd ios && pod install
```

Android needs minSdk 24 or later and iOS needs 13.0 or later. The prebuilt native libraries ship with the package and their hashes are listed in `SHA256SUMS`, which `npm run verify:binaries` checks.

## The vault

Apps that hold user funds should sign through `secureQCore`. The seed is kept in the Android Keystore or the iOS Keychain, bound to this device and never backed up. Once stored it is never handed to JavaScript again, apart from the recovery phrase that `revealPhrase` returns after a fresh unlock.

```ts
import { secureQCore, SigningSession } from '@quantovainc/react-native-qcore';

secureQCore.createSeed('main');
const from = secureQCore.address('main', 0n);

const session = SigningSession.open([knownPayee]);
session.checkTarget(to);
const nonce = session.slot(from, reportedNonce, null, false);
const signed = secureQCore.signTransfer('main', session, 0n, to, '5', nonce, '1', chainId, validUntil, head);
session.signed(from, nonce);
```

1. On Android the key that wraps the seed requires user authentication within the last 15 seconds and is held in StrongBox where the device has it. On iOS the seed is a Keychain item that requires user presence and is readable only while a passcode is set.
2. A seed held in memory is wiped after two minutes of no use and whenever the app goes to the background.
3. `revealPhrase` asks the user to authenticate again every time and returns the 25 word recovery phrase as bytes, which the app should clear with `wipeBytes` once shown.
4. The vault signs only at a nonce slot reserved from a `SigningSession` opened by this module. The session state is kept encrypted on the device per account, so a nonce that was signed once is never handed out again after a crash or a restart.
5. Every signer takes the current chain `head` and refuses a `validUntil` that has already passed or lies more than `maxValidityBlocks()` blocks past it. `boundedValidUntil` gives a deadline inside that window.
6. Signing for a retired network name is refused.

## Low level functions

`nativeQCore` exposes the same derivation and signing functions over a seed given as hexadecimal, together with the proof checks `verifyFinality`, `verifyEvent`, `verifyTransaction`, `confirmTransaction` and `decodeEvent`. The seed functions take a raw nonce and keep no session, so they are meant for tooling and tests and not for wallets.

## Releases

Each release is built from a tag on `main` by the release workflow, and the attestation of every published file names that tag and its commit.

## License

Licensed under either of Apache License 2.0 or MIT license at your option. See `LICENSE-APACHE`, `LICENSE-MIT` and `NOTICE`.
