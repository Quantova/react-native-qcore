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
  sameAddress(a: string, b: string): boolean;
  lookalikeOf(candidate: string, known: string[]): string | null;
  sign_transfer(
    seedHex: string,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
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
    head: bigint,
    genesisHash: string,
  ): string;
  signRegister(
    seedHex: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): string;
  chainIdFromName(name: string): bigint;
  gatewayProtocol(): number;
  /** Refuses an endpoint the network has retired (throws). */
  checkEndpoint(base: string): void;
  testnetRpcUrl(): string;
  testnetChainName(): string;
  /** The genesis hash this core pins for the testnet, or null when it pins none. */
  testnetGenesisHash(): string | null;
  boundedValidUntil(
    chainName: string,
    head: bigint,
    wallSecs: bigint,
    floor: bigint | null | undefined,
    floorAgeSecs: bigint,
  ): bigint;
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
    head: bigint,
    genesisHash: string,
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
    head: bigint,
    genesisHash: string,
  ): string;
  nameKey(label: string): string;
  mapSlotKey(mapDomainTag: bigint, keyAddressHex: string): string;
  mapAddrWordKey(mapDomainTag: bigint, key32Hex: string, word: bigint): string;
  scalarSlotKey(slot: bigint): string;
  checkOrderExpiry(expiry: bigint, nowSecs: bigint): void;
  verifyFinality(chainId: bigint, genesisHash: string, headerHex: string, certificateHex: string, rosterJson: string): string;
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): boolean;
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): boolean;
  confirmTransaction(chainId: bigint, genesisHash: string, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string;
  decodeEvent(leafHex: string): string;
}

interface QcoreNative {
  generateSeed(): string;
  vmCallFee(transferFee: string, meterLimit: string): string;
  mnemonicFromSeed(seedHex: string): string;
  seedFromMnemonic(phrase: string): string;
  address(seedHex: string, index: string): string;
  validAddress(address: string): boolean;
  sameAddress(a: string, b: string): boolean;
  lookalikeOf(candidate: string, known: string): string;
  signTransfer(
    seedHex: string,
    index: string,
    to: string,
    amount: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
    genesisHex: string,
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
    head: string,
    genesisHex: string,
  ): string;
  signRegister(
    seedHex: string,
    index: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
    genesisHex: string,
  ): string;
  chainIdFromName(name: string): string;
  gatewayProtocol(): number;
  checkEndpoint(base: string): string;
  testnetRpcUrl(): string;
  testnetChainName(): string;
  testnetGenesisHash(): string;
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
    head: string,
    genesisHex: string,
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
    head: string,
    genesisHex: string,
  ): string;
  nameKey(label: string): string;
  mapSlotKey(mapDomainTag: string, keyAddressHex: string): string;
  mapAddrWordKey(mapDomainTag: string, key32Hex: string, word: string): string;
  scalarSlotKey(slot: string): string;
  vaultCreate(alias: string): Promise<string>;
  vaultImportPhrase(alias: string, phrase: number[]): Promise<string>;
  vaultImportSeed(alias: string, seed: number[]): Promise<string>;
  vaultRevealPhrase(alias: string, title: string, subtitle: string): Promise<string | number[]>;
  vaultLearnAddresses(alias: string, count: string): Promise<string>;
  vaultResetNonceState(alias: string, chainId: string, genesisHex: string, key: string, title: string, subtitle: string): Promise<string>;
  vaultAcknowledgeImportedHistory(alias: string, chainId: string, genesisHex: string, key: string, title: string, subtitle: string): Promise<string>;
  vaultAcknowledgeMainnet(alias: string, chainId: string, genesisHex: string, key: string, title: string, subtitle: string): Promise<string>;
  vaultStorageLevel(): string;
  vaultHas(alias: string): string;
  vaultClose(alias: string): string;
  vaultCloseAll(): string;
  vaultForget(alias: string, title: string, subtitle: string): Promise<string>;
  vaultAddress(alias: string, index: string): string;
  vaultSignTransfer(
    alias: string,
    sessionId: string,
    index: string,
    to: string,
    amount: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
    genesisHex: string,
  ): Promise<string>;
  vaultSignCall(
    alias: string,
    sessionId: string,
    index: string,
    target: string,
    argsHex: string,
    nonce: string,
    meterLimit: string,
    fee: string,
    chainId: string,
    validUntil: string,
    transferFee: string,
    head: string,
    genesisHex: string,
  ): Promise<string>;
  vaultSignRegister(
    alias: string,
    sessionId: string,
    index: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
    genesisHex: string,
  ): Promise<string>;
  vaultSignPayableCall(
    alias: string,
    sessionId: string,
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
    head: string,
    genesisHex: string,
  ): Promise<string>;
  vaultSignAssetCall(
    alias: string,
    sessionId: string,
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
    head: string,
    genesisHex: string,
  ): Promise<string>;
  checkValidUntil(validUntil: string, head: string): string;
  boundedValidUntil(
    chainName: string,
    head: string,
    wallSecs: string,
    floor: string,
    floorAgeSecs: string,
  ): string;
  headCeiling(chainName: string, wallSecs: string): string;
  genesisSecs(chainName: string): string;
  maxValidityBlocks(): string;
  defaultValidityBlocks(): string;
  checkOrderExpiry(expiry: string, nowSecs: string): string;
  maxOrderLifetimeSecs(): string;
  verifyFinality(chainId: string, genesisHex: string, headerHex: string, certificateHex: string, rosterJson: string): string;
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): string;
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): string;
  confirmTransaction(chainId: string, genesisHex: string, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string;
  decodeEvent(leafHex: string): string;
  sessionOpen(addressBook: string): string;
  sessionClose(id: string): string;
  sessionKnown(id: string): string;
  sessionRememberAddress(id: string, address: string): string;
  sessionCheckTarget(id: string, address: string): string;
  sessionSlot(id: string, chainId: string, genesisHex: string, key: string, reported: string, expected: string, order: boolean): Promise<string>;
  sessionSigned(id: string, chainId: string, genesisHex: string, key: string, slot: string): Promise<string>;
  sessionRelease(id: string, chainId: string, genesisHex: string, key: string, slot: string): Promise<string>;
  sessionReleasePending(id: string, chainId: string, genesisHex: string, key: string): Promise<string>;
  sessionOutcome(id: string, chainId: string, genesisHex: string, key: string, slot: string, accepted: boolean): Promise<string>;
  sessionNextNonce(id: string, chainId: string, genesisHex: string, key: string): Promise<string>;
  sessionIsHeld(id: string, chainId: string, genesisHex: string, key: string, slot: string): Promise<string>;
  vaultSettleHistory(
    chainId: string,
    genesisHex: string,
    key: string,
    headerHex: string,
    certificateHex: string,
    rosterJson: string,
  ): Promise<string>;
}

const LINKING_ERROR =
  "The '@quantovainc/react-native-qcore' native module is not available. Rebuild the app after " +
  'adding the package so the Quantova client core is linked on device.';

const FAILURE_PREFIX = '\u0000QCORE_ERROR:';

export class QCoreAuthenticationRequired extends Error {
  readonly code = 'QCORE_AUTHENTICATION_REQUIRED';
}

export class QCoreAuthenticationCancelled extends Error {
  readonly code = 'QCORE_AUTHENTICATION_CANCELLED';
}

function nativeError(message: string): Error {
  if (message.startsWith('authentication required')) return new QCoreAuthenticationRequired(message);
  if (message.startsWith('authentication cancelled')) return new QCoreAuthenticationCancelled(message);
  return new Error(message);
}

function checked(result: unknown): unknown {
  if (typeof result === 'string' && result.startsWith(FAILURE_PREFIX)) {
    throw nativeError(result.slice(FAILURE_PREFIX.length));
  }
  return result;
}

function throwingOnFailure(module: QcoreNative): QcoreNative {
  return new Proxy(module, {
    get(target, property, receiver) {
      const member = Reflect.get(target, property, receiver);
      if (typeof member !== 'function') return member;
      return (...args: unknown[]) => {
        const result = (member as (...a: unknown[]) => unknown).apply(target, args);
        if (result !== null && typeof result === 'object' && typeof (result as Promise<unknown>).then === 'function') {
          return (result as Promise<unknown>).then(checked);
        }
        return checked(result);
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

const genesis = (hash: string): string => {
  if (typeof hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error('the genesis hash is 64 hex characters, the 32 byte genesis of the network this app pins');
  }
  if (/^0{64}$/.test(hash)) {
    throw new Error('a genesis hash of zeros names no network, pass the genesis of the network this app pins');
  }
  return hash;
};

function verdict(value: string): boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('the native layer returned a malformed verdict');
}

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
  sameAddress(a: string, b: string): boolean {
    return native.sameAddress(a, b);
  },
  lookalikeOf(candidate: string, known: string[]): string | null {
    return native.lookalikeOf(candidate, known.join(',')) || null;
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
    head: bigint,
    genesisHash: string,
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
      u64(head),
      genesis(genesisHash),
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
    head: bigint,
    genesisHash: string,
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
      u64(head),
      genesis(genesisHash),
    );
  },
  signRegister(
    seedHex: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): string {
    return native.signRegister(
      seedHex,
      u64(index),
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
      u64(head),
      genesis(genesisHash),
    );
  },
  chainIdFromName(name: string): bigint {
    return BigInt(native.chainIdFromName(name));
  },
  gatewayProtocol(): number {
    return Number(native.gatewayProtocol());
  },
  checkEndpoint(base: string): void {
    native.checkEndpoint(base);
  },
  testnetRpcUrl(): string {
    return native.testnetRpcUrl();
  },
  testnetChainName(): string {
    return native.testnetChainName();
  },
  testnetGenesisHash(): string | null {
    return native.testnetGenesisHash() || null;
  },
  boundedValidUntil(
    chainName: string,
    head: bigint,
    wallSecs: bigint,
    floor: bigint | null | undefined,
    floorAgeSecs: bigint,
  ): bigint {
    return boundedValidUntil(chainName, head, wallSecs, floor ?? null, floorAgeSecs);
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
    head: bigint,
    genesisHash: string,
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
      u64(head),
      genesis(genesisHash),
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
    head: bigint,
    genesisHash: string,
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
      u64(head),
      genesis(genesisHash),
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
  checkOrderExpiry(expiry: bigint, nowSecs: bigint): void {
    native.checkOrderExpiry(u64(expiry), u64(nowSecs));
  },
  verifyFinality(chainId: bigint, genesisHash: string, headerHex: string, certificateHex: string, rosterJson: string): string {
    return native.verifyFinality(u64(chainId), genesis(genesisHash), headerHex, certificateHex, rosterJson);
  },
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): boolean {
    return verdict(native.verifyEvent(eventRootHex, leafHex, stepsJson));
  },
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): boolean {
    return verdict(native.verifyTransaction(transactionRootHex, txId, leafHex, stepsJson));
  },
  confirmTransaction(chainId: bigint, genesisHash: string, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string {
    return native.confirmTransaction(u64(chainId), genesis(genesisHash), txId, proofJson, finalityJson, rosterJson);
  },
  decodeEvent(leafHex: string): string {
    return native.decodeEvent(leafHex);
  },
};

export interface RevealPrompt {
  title?: string;
  subtitle?: string;
}

export interface NonceAccount {
  chainId: bigint;
  genesisHash: string;
  key: string;
}

export interface SettleProgress {
  settled: boolean;
  blocksLeft: bigint;
  secondsLeft: bigint;
}

export interface SecureQCore {
  createSeed(alias: string): Promise<void>;
  importPhrase(alias: string, phrase: Uint8Array): Promise<void>;
  importSeed(alias: string, seed: Uint8Array): Promise<void>;
  revealPhrase(alias: string, prompt?: RevealPrompt): Promise<Uint8Array>;
  learnAddresses(alias: string, count: bigint): Promise<void>;
  resetNonceState(alias: string, account: NonceAccount | null, prompt?: RevealPrompt): Promise<void>;
  acknowledgeImportedHistory(alias: string, account: NonceAccount, prompt?: RevealPrompt): Promise<void>;
  acknowledgeMainnet(alias: string, account: NonceAccount, prompt?: RevealPrompt): Promise<void>;
  settleHistory(
    account: NonceAccount,
    headerHex: string,
    certificateHex: string,
    roster: readonly RosterMember[],
  ): Promise<SettleProgress>;
  storageLevel(): StorageLevel;
  hasSeed(alias: string): boolean;
  closeSeed(alias: string): void;
  closeAll(): void;
  forgetSeed(alias: string, prompt?: RevealPrompt): Promise<void>;
  address(alias: string, index: bigint): string;
  signTransfer(
    alias: string,
    session: SigningSession,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): Promise<string>;
  signCall(
    alias: string,
    session: SigningSession,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
    head: bigint,
    genesisHash: string,
  ): Promise<string>;
  signRegister(
    alias: string,
    session: SigningSession,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): Promise<string>;
  signPayableCall(
    alias: string,
    session: SigningSession,
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
    head: bigint,
    genesisHash: string,
  ): Promise<string>;
  signAssetCall(
    alias: string,
    session: SigningSession,
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
    head: bigint,
    genesisHash: string,
  ): Promise<string>;
}

const STORAGE_LEVELS = ['strongbox', 'trusted-environment', 'secure-hardware', 'software', 'keychain', 'unknown'] as const;

export type StorageLevel = (typeof STORAGE_LEVELS)[number];

function plainBytes(value: unknown, what: string): Uint8Array {
  if (!(ArrayBuffer.isView(value) && value instanceof Uint8Array)) throw new Error(what + ' must be a Uint8Array');
  return value;
}

function byteList(input: Uint8Array, what: string): number[] {
  return Array.from(plainBytes(input, what));
}

function fromByteList(list: unknown): Uint8Array {
  if (!Array.isArray(list)) throw new Error('the native layer returned no phrase');
  const out = new Uint8Array(list.length);
  for (let i = 0; i < list.length; i += 1) {
    const value = list[i];
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 255) {
      out.fill(0);
      list.fill(0);
      throw new Error('the native layer returned a malformed phrase');
    }
    out[i] = value;
  }
  list.fill(0);
  return out;
}

async function settled(call: Promise<unknown>): Promise<void> {
  const text = await call;
  if (typeof text !== 'string') throw new Error('the native layer returned no answer');
  if (text.startsWith(FAILURE_PREFIX)) throw nativeError(text.slice(FAILURE_PREFIX.length));
}

function account(given: NonceAccount, what: string): [string, string, string] {
  if (given === null || typeof given !== 'object') throw new Error(what);
  if (typeof given.key !== 'string' || given.key.length === 0) throw new Error('a nonce account names a key');
  return [u64(given.chainId), genesis(given.genesisHash), given.key];
}

export function wipeBytes(bytes: Uint8Array): void {
  plainBytes(bytes, 'the bytes to wipe').fill(0);
}

export const secureQCore: SecureQCore = {
  async createSeed(alias: string): Promise<void> {
    await settled(native.vaultCreate(alias));
  },
  async importPhrase(alias: string, phrase: Uint8Array): Promise<void> {
    const list = byteList(phrase, 'the recovery phrase');
    try {
      await settled(native.vaultImportPhrase(alias, list));
    } finally {
      list.fill(0);
    }
  },
  async importSeed(alias: string, seed: Uint8Array): Promise<void> {
    const list = byteList(seed, 'the seed');
    try {
      await settled(native.vaultImportSeed(alias, list));
    } finally {
      list.fill(0);
    }
  },
  async revealPhrase(alias: string, prompt: RevealPrompt = {}): Promise<Uint8Array> {
    const answer = await native.vaultRevealPhrase(alias, prompt.title ?? '', prompt.subtitle ?? '');
    if (typeof answer === 'string') {
      if (answer.startsWith(FAILURE_PREFIX)) throw nativeError(answer.slice(FAILURE_PREFIX.length));
      throw new Error('the native layer returned no phrase');
    }
    return fromByteList(answer);
  },
  async learnAddresses(alias: string, count: bigint): Promise<void> {
    await settled(native.vaultLearnAddresses(alias, u64(count)));
  },
  async resetNonceState(alias: string, account: NonceAccount | null, prompt: RevealPrompt = {}): Promise<void> {
    const chainId = account === null ? '' : u64(account.chainId);
    const pinned = account === null ? '' : genesis(account.genesisHash);
    const key = account === null ? '' : account.key;
    if (account !== null && key.length === 0) throw new Error('a nonce account names a key');
    const text = await native.vaultResetNonceState(alias, chainId, pinned, key, prompt.title ?? '', prompt.subtitle ?? '');
    if (typeof text !== 'string') throw new Error('the native layer returned no answer');
    if (text.startsWith(FAILURE_PREFIX)) throw nativeError(text.slice(FAILURE_PREFIX.length));
  },
  async acknowledgeImportedHistory(alias: string, given: NonceAccount, prompt: RevealPrompt = {}): Promise<void> {
    const [chainId, pinned, key] = account(given, 'name the account whose imported history is acknowledged');
    await settled(native.vaultAcknowledgeImportedHistory(alias, chainId, pinned, key, prompt.title ?? '', prompt.subtitle ?? ''));
  },
  async acknowledgeMainnet(alias: string, given: NonceAccount, prompt: RevealPrompt = {}): Promise<void> {
    const [chainId, pinned, key] = account(given, 'name the mainnet account to acknowledge');
    await settled(native.vaultAcknowledgeMainnet(alias, chainId, pinned, key, prompt.title ?? '', prompt.subtitle ?? ''));
  },
  async settleHistory(
    account: NonceAccount,
    headerHex: string,
    certificateHex: string,
    roster: readonly RosterMember[],
  ): Promise<SettleProgress> {
    if (account === null || typeof account !== 'object') throw new Error('name the account whose history settles');
    if (typeof account.key !== 'string' || account.key.length === 0) throw new Error('a nonce account names a key');
    const members = roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots }));
    const text = await native.vaultSettleHistory(
      u64(account.chainId),
      genesis(account.genesisHash),
      account.key,
      headerHex,
      certificateHex,
      JSON.stringify(members),
    );
    const progress = JSON.parse(text) as { settled: boolean; blocks_left: string; secs_left: string };
    return { settled: progress.settled === true, blocksLeft: BigInt(progress.blocks_left), secondsLeft: BigInt(progress.secs_left) };
  },
  storageLevel(): StorageLevel {
    const level = native.vaultStorageLevel();
    if (!(STORAGE_LEVELS as readonly string[]).includes(level)) throw new Error('the native layer returned an unknown storage level');
    return level as StorageLevel;
  },
  hasSeed(alias: string): boolean {
    return native.vaultHas(alias) === 'true';
  },
  closeSeed(alias: string): void {
    native.vaultClose(alias);
  },
  closeAll(): void {
    native.vaultCloseAll();
  },
  async forgetSeed(alias: string, prompt: RevealPrompt = {}): Promise<void> {
    await settled(native.vaultForget(alias, prompt.title ?? '', prompt.subtitle ?? ''));
  },
  address(alias: string, index: bigint): string {
    return native.vaultAddress(alias, u64(index));
  },
  async signTransfer(
    alias: string,
    session: SigningSession,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): Promise<string> {
    return native.vaultSignTransfer(
      alias,
      sessionIdOf(session),
      u64(index),
      to,
      amount,
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
      u64(head),
      genesis(genesisHash),
    );
  },
  async signCall(
    alias: string,
    session: SigningSession,
    index: bigint,
    target: string,
    argsHex: string,
    nonce: bigint,
    meterLimit: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    transferFee: string,
    head: bigint,
    genesisHash: string,
  ): Promise<string> {
    return native.vaultSignCall(
      alias,
      sessionIdOf(session),
      u64(index),
      target,
      argsHex,
      u64(nonce),
      u64(meterLimit),
      fee,
      u64(chainId),
      u64(validUntil),
      transferFee,
      u64(head),
      genesis(genesisHash),
    );
  },
  async signRegister(
    alias: string,
    session: SigningSession,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
    genesisHash: string,
  ): Promise<string> {
    return native.vaultSignRegister(
      alias,
      sessionIdOf(session),
      u64(index),
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
      u64(head),
      genesis(genesisHash),
    );
  },
  async signPayableCall(
    alias: string,
    session: SigningSession,
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
    head: bigint,
    genesisHash: string,
  ): Promise<string> {
    return native.vaultSignPayableCall(
      alias,
      sessionIdOf(session),
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
      u64(head),
      genesis(genesisHash),
    );
  },
  async signAssetCall(
    alias: string,
    session: SigningSession,
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
    head: bigint,
    genesisHash: string,
  ): Promise<string> {
    return native.vaultSignAssetCall(
      alias,
      sessionIdOf(session),
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
      u64(head),
      genesis(genesisHash),
    );
  },
};

export function checkValidUntil(validUntil: bigint, head: bigint): void {
  native.checkValidUntil(u64(validUntil), u64(head));
}

export function boundedValidUntil(
  chainName: string,
  head: bigint,
  wallSecs: bigint,
  floor: bigint | null,
  floorAgeSecs: bigint,
): bigint {
  return BigInt(
    native.boundedValidUntil(
      chainName,
      u64(head),
      u64(wallSecs),
      floor === null ? '' : u64(floor),
      u64(floorAgeSecs),
    ),
  );
}

export function headCeiling(chainName: string, wallSecs: bigint): bigint {
  return BigInt(native.headCeiling(chainName, u64(wallSecs)));
}

export function genesisSecs(chainName: string): bigint {
  return BigInt(native.genesisSecs(chainName));
}

export function maxValidityBlocks(): bigint {
  return BigInt(native.maxValidityBlocks());
}

export function defaultValidityBlocks(): bigint {
  return BigInt(native.defaultValidityBlocks());
}

export function checkOrderExpiry(expiry: bigint, nowSecs: bigint): void {
  native.checkOrderExpiry(u64(expiry), u64(nowSecs));
}

export function maxOrderLifetimeSecs(): bigint {
  return BigInt(native.maxOrderLifetimeSecs());
}

export interface RosterMember {
  id: number;
  stake: string;
  attest_pk: string;
  root: string;
  root_slots: string;
}

export interface ProofStep {
  sibling: string;
  left: boolean;
}

export interface FinalizedHeader {
  height: string;
  hash: string;
  parent_hash: string;
  q_root: string;
  transaction_root: string;
  event_root: string;
  time: string;
  signed_stake: string;
  total_stake: string;
}

export interface ChainEvent {
  contract: string;
  selector: string;
  data: string;
}

export function verifyFinality(
  chainId: bigint,
  genesisHash: string,
  headerHex: string,
  certificateHex: string,
  roster: readonly RosterMember[],
): FinalizedHeader {
  const pinned = genesis(genesisHash);
  const members = roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots }));
  return JSON.parse(native.verifyFinality(u64(chainId), pinned, headerHex, certificateHex, JSON.stringify(members))) as FinalizedHeader;
}

export function verifyEvent(eventRootHex: string, leafHex: string, steps: readonly ProofStep[]): boolean {
  const path = steps.map((s) => ({ sibling: s.sibling, left: s.left }));
  return verdict(native.verifyEvent(eventRootHex, leafHex, JSON.stringify(path)));
}

export function verifyTransaction(
  transactionRootHex: string,
  txId: string,
  leafHex: string,
  steps: readonly ProofStep[],
): boolean {
  const path = steps.map((s) => ({ sibling: s.sibling, left: s.left }));
  return verdict(native.verifyTransaction(transactionRootHex, txId, leafHex, JSON.stringify(path)));
}

export interface TransactionProof {
  height: number;
  index: number;
  leaf: string;
  steps: readonly ProofStep[];
}

export interface FinalityAnswer {
  header_bytes: string;
  certificate: string;
}

export interface ConfirmedTransaction {
  txId: string;
  height: bigint;
  index: bigint;
  header: FinalizedHeader;
}

export function confirmTransaction(
  chainId: bigint,
  genesisHash: string,
  txId: string,
  proof: TransactionProof | string,
  finality: FinalityAnswer | string,
  roster: readonly RosterMember[] | string,
): ConfirmedTransaction {
  const pinned = genesis(genesisHash);
  if (typeof txId !== 'string') throw new Error('the transaction id must be a string');
  const proofJson =
    typeof proof === 'string'
      ? proof
      : JSON.stringify({
          height: proof.height,
          index: proof.index,
          leaf: proof.leaf,
          steps: proof.steps.map((s) => ({ sibling: s.sibling, left: s.left })),
        });
  const finalityJson =
    typeof finality === 'string'
      ? finality
      : JSON.stringify({ header_bytes: finality.header_bytes, certificate: finality.certificate });
  const rosterJson =
    typeof roster === 'string'
      ? roster
      : JSON.stringify(roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots })));
  const confirmed = JSON.parse(
    native.confirmTransaction(u64(chainId), pinned, txId, proofJson, finalityJson, rosterJson),
  ) as { tx_id: string; height: string; index: string; header: FinalizedHeader };
  if (confirmed.tx_id !== txId) throw new Error('the native layer confirmed a different transaction');
  return { txId: confirmed.tx_id, height: BigInt(confirmed.height), index: BigInt(confirmed.index), header: confirmed.header };
}

export function decodeEvent(leafHex: string): ChainEvent {
  return JSON.parse(native.decodeEvent(leafHex)) as ChainEvent;
}

const sessionIds = new WeakMap<SigningSession, () => string>();

function sessionIdOf(session: SigningSession): string {
  const live = sessionIds.get(session);
  if (!live) throw new Error('the vault signs only with a signing session opened by this module');
  return live();
}

export class SigningSession {
  private id: string | null;

  private constructor(id: string) {
    this.id = id;
    sessionIds.set(this, () => this.live());
  }

  static open(addressBook: readonly string[] = []): SigningSession {
    return new SigningSession(native.sessionOpen(addressBook.join(',')));
  }

  private live(): string {
    if (this.id === null) throw new Error('this signing session is closed');
    return this.id;
  }

  known(): string[] {
    return native
      .sessionKnown(this.live())
      .split(',')
      .filter((entry) => entry.length > 0);
  }

  rememberAddress(address: string): void {
    native.sessionRememberAddress(this.live(), address);
  }

  checkTarget(address: string): void {
    native.sessionCheckTarget(this.live(), address);
  }

  async slot(chainId: bigint, genesisHash: string, key: string, reported: bigint, expected: bigint | null, order: boolean): Promise<bigint> {
    return BigInt(
      await native.sessionSlot(
        this.live(),
        u64(chainId),
        genesis(genesisHash),
        key,
        u64(reported),
        expected === null ? '' : u64(expected),
        order,
      ),
    );
  }

  async signed(chainId: bigint, genesisHash: string, key: string, slot: bigint): Promise<void> {
    await native.sessionSigned(this.live(), u64(chainId), genesis(genesisHash), key, u64(slot));
  }

  async release(chainId: bigint, genesisHash: string, key: string, slot: bigint): Promise<void> {
    await native.sessionRelease(this.live(), u64(chainId), genesis(genesisHash), key, u64(slot));
  }

  async releasePending(chainId: bigint, genesisHash: string, key: string): Promise<void> {
    await native.sessionReleasePending(this.live(), u64(chainId), genesis(genesisHash), key);
  }

  async outcome(chainId: bigint, genesisHash: string, key: string, slot: bigint, accepted: boolean): Promise<void> {
    await native.sessionOutcome(this.live(), u64(chainId), genesis(genesisHash), key, u64(slot), accepted);
  }

  async nextNonce(chainId: bigint, genesisHash: string, key: string): Promise<bigint | null> {
    const next = await native.sessionNextNonce(this.live(), u64(chainId), genesis(genesisHash), key);
    return next === '' ? null : BigInt(next);
  }

  async isHeld(chainId: bigint, genesisHash: string, key: string, slot: bigint): Promise<boolean> {
    return (await native.sessionIsHeld(this.live(), u64(chainId), genesis(genesisHash), key, u64(slot))) === 'true';
  }

  close(): void {
    if (this.id === null) return;
    native.sessionClose(this.id);
    this.id = null;
  }
}

export function registerQCore(setQCore: (instance: QCore) => void): void {
  setQCore(nativeQCore);
}

export default secureQCore;
