// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { NativeModules, TurboModuleRegistry } from 'react-native';

export interface QCore {
  generateSeed(): string;
  vmCallFee(transferFee: string, meterLimit: bigint): bigint;
  mnemonicFromSeed(seedHex: string): string;
  seedFromMnemonic(phrase: string): string;
  address(seedHex: string, index: bigint): string;
  valid_address(address: string): boolean;
  sign_transfer(
    seedHex: string,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
  ): string;
  sign_call(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string;
  signRegister(
    seedHex: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
  ): string;
  chainIdFromName(name: string): bigint;
  signPayableCall(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    value: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string;
  signAssetCall(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    assetIssuer: string,
    amount: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string;
  nameKey(label: string): string;
  mapSlotKey(mapDomainTag: bigint, keyAddressHex: string): string;
  mapAddrWordKey(mapDomainTag: bigint, key32Hex: string, word: bigint): string;
  scalarSlotKey(slot: bigint): string;
}

interface QcoreNative {
  generateSeed(): string;
  vmCallFee(transferFee: string, meterLimit: string): string;
  mnemonicFromSeed(seedHex: string): string;
  seedFromMnemonic(phrase: string): string;
  address(seedHex: string, index: string): string;
  validAddress(address: string): boolean;
  signTransfer(
    seedHex: string,
    index: string,
    to: string,
    amount: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
  ): string;
  signCall(
    seedHex: string,
    index: string,
    target: string,
    argsHex: string,
    nonce: string,
    meterLimit: string,
    fee: string,
    chainId: string,
    validUntil: string,
    transferFee: string,
  ): string;
  signRegister(
    seedHex: string,
    index: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
  ): string;
  chainIdFromName(name: string): string;
  signPayableCall(
    seedHex: string,
    index: string,
    target: string,
    argsHex: string,
    nonce: string,
    meterLimit: string,
    fee: string,
    value: string,
    chainId: string,
    validUntil: string,
    transferFee: string,
  ): string;
  signAssetCall(
    seedHex: string,
    index: string,
    target: string,
    argsHex: string,
    assetIssuer: string,
    amount: string,
    nonce: string,
    meterLimit: string,
    fee: string,
    chainId: string,
    validUntil: string,
    transferFee: string,
  ): string;
  nameKey(label: string): string;
  mapSlotKey(mapDomainTag: string, keyAddressHex: string): string;
  mapAddrWordKey(mapDomainTag: string, key32Hex: string, word: string): string;
  scalarSlotKey(slot: string): string;
}

const LINKING_ERROR =
  "The '@quantovainc/react-native-qcore' native module is not available. Rebuild the app after " +
  'adding the package so the Quantova client core is linked on device.';

const FAILURE_PREFIX = '\u0000QCORE_ERROR:';

function throwingOnFailure(module: QcoreNative): QcoreNative {
  return new Proxy(module, {
    get(target, property, receiver) {
      const member = Reflect.get(target, property, receiver);
      if (typeof member !== 'function') return member;
      return (...args: unknown[]) => {
        const result = (member as (...a: unknown[]) => unknown).apply(target, args);
        if (typeof result === 'string' && result.startsWith(FAILURE_PREFIX)) {
          throw new Error(result.slice(FAILURE_PREFIX.length));
        }
        return result;
      };
    },
  }) as QcoreNative;
}

function resolveNative(): QcoreNative {
  const turbo =
    typeof TurboModuleRegistry !== 'undefined' && TurboModuleRegistry
      ? (TurboModuleRegistry.get('Qcore') as unknown as QcoreNative | null)
      : null;
  const legacy = (NativeModules && (NativeModules.Qcore as unknown as QcoreNative)) || null;
  const found = turbo || legacy;
  if (found) return throwingOnFailure(found);
  return new Proxy({} as QcoreNative, {
    get() {
      throw new Error(LINKING_ERROR);
    },
  });
}

const native = resolveNative();

const u64 = (value: bigint): string => value.toString(10);

export const nativeQCore: QCore = {
  generateSeed(): string {
    return native.generateSeed();
  },
  vmCallFee(transferFee: string, meterLimit: bigint): bigint {
    return BigInt(native.vmCallFee(transferFee, u64(meterLimit)));
  },
  mnemonicFromSeed(seedHex: string): string {
    return native.mnemonicFromSeed(seedHex);
  },
  seedFromMnemonic(phrase: string): string {
    return native.seedFromMnemonic(phrase);
  },
  address(seedHex: string, index: bigint): string {
    return native.address(seedHex, u64(index));
  },
  valid_address(address: string): boolean {
    return native.validAddress(address);
  },
  sign_transfer(
    seedHex: string,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
  ): string {
    return native.signTransfer(
      seedHex,
      u64(index),
      to,
      amount,
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
    );
  },
  sign_call(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string {
    return native.signCall(
      seedHex,
      u64(index),
      target,
      argsHex,
      u64(nonce),
      u64(meterLimit),
      fee,
      u64(chainId),
      u64(validUntil),
      transferFee,
    );
  },
  signRegister(
    seedHex: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
  ): string {
    return native.signRegister(seedHex, u64(index), u64(nonce), fee, u64(chainId), u64(validUntil));
  },
  chainIdFromName(name: string): bigint {
    return BigInt(native.chainIdFromName(name));
  },
  signPayableCall(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    value: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string {
    return native.signPayableCall(
      seedHex,
      u64(index),
      target,
      argsHex,
      u64(nonce),
      u64(meterLimit),
      fee,
      value,
      u64(chainId),
      u64(validUntil),
      transferFee,
    );
  },
  signAssetCall(
    seedHex: string,
    index: bigint,
    target: string,
    argsHex: string,
    assetIssuer: string,
    amount: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
  ): string {
    return native.signAssetCall(
      seedHex,
      u64(index),
      target,
      argsHex,
      assetIssuer,
      amount,
      u64(nonce),
      u64(meterLimit),
      fee,
      u64(chainId),
      u64(validUntil),
      transferFee,
    );
  },
  nameKey(label: string): string {
    return native.nameKey(label);
  },
  mapSlotKey(mapDomainTag: bigint, keyAddressHex: string): string {
    return native.mapSlotKey(u64(mapDomainTag), keyAddressHex);
  },
  mapAddrWordKey(mapDomainTag: bigint, key32Hex: string, word: bigint): string {
    return native.mapAddrWordKey(u64(mapDomainTag), key32Hex, u64(word));
  },
  scalarSlotKey(slot: bigint): string {
    return native.scalarSlotKey(u64(slot));
  },
};

export function registerQCore(setQCore: (instance: QCore) => void): void {
  setQCore(nativeQCore);
}

export default nativeQCore;
