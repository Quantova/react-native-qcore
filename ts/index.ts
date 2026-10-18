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
  checkOrderExpiry(expiry: bigint, nowSecs: bigint): void;
  verifyFinality(chainId: bigint, headerHex: string, certificateHex: string, rosterJson: string): string;
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): boolean;
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): boolean;
  confirmTransaction(chainId: bigint, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string;
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
  vaultCreate(alias: string): string;
  vaultImportPhrase(alias: string, phraseBase64: string): string;
  vaultImportSeed(alias: string, seedBase64: string): string;
  vaultRevealPhrase(alias: string, title: string, subtitle: string): Promise<string>;
  vaultHas(alias: string): string;
  vaultClose(alias: string): string;
  vaultCloseAll(): string;
  vaultForget(alias: string): string;
  vaultAddress(alias: string, index: string): string;
  vaultSignTransfer(
    alias: string,
    index: string,
    to: string,
    amount: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
  ): string;
  vaultSignCall(
    alias: string,
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
  ): string;
  vaultSignRegister(
    alias: string,
    index: string,
    nonce: string,
    fee: string,
    chainId: string,
    validUntil: string,
    head: string,
  ): string;
  vaultSignPayableCall(
    alias: string,
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
  ): string;
  vaultSignAssetCall(
    alias: string,
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
  ): string;
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
  verifyFinality(chainId: string, headerHex: string, certificateHex: string, rosterJson: string): string;
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): string;
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): string;
  confirmTransaction(chainId: string, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string;
  decodeEvent(leafHex: string): string;
  sessionOpen(addressBook: string): string;
  sessionClose(id: string): string;
  sessionKnown(id: string): string;
  sessionRememberAddress(id: string, address: string): string;
  sessionCheckTarget(id: string, address: string): string;
  sessionSlot(id: string, key: string, reported: string, expected: string, order: boolean): string;
  sessionSigned(id: string, key: string, slot: string): string;
  sessionRelease(id: string, key: string, slot: string): string;
  sessionReleasePending(id: string, key: string): string;
  sessionOutcome(id: string, key: string, slot: string, accepted: boolean): string;
  sessionNextNonce(id: string, key: string): string;
  sessionIsHeld(id: string, key: string, slot: string): string;
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

function throwingOnFailure(module: QcoreNative): QcoreNative {
  return new Proxy(module, {
    get(target, property, receiver) {
      const member = Reflect.get(target, property, receiver);
      if (typeof member !== 'function') return member;
      return (...args: unknown[]) => {
        const result = (member as (...a: unknown[]) => unknown).apply(target, args);
        if (typeof result === 'string' && result.startsWith(FAILURE_PREFIX)) {
          throw nativeError(result.slice(FAILURE_PREFIX.length));
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
  checkOrderExpiry(expiry: bigint, nowSecs: bigint): void {
    native.checkOrderExpiry(u64(expiry), u64(nowSecs));
  },
  verifyFinality(chainId: bigint, headerHex: string, certificateHex: string, rosterJson: string): string {
    return native.verifyFinality(u64(chainId), headerHex, certificateHex, rosterJson);
  },
  verifyEvent(eventRootHex: string, leafHex: string, stepsJson: string): boolean {
    return verdict(native.verifyEvent(eventRootHex, leafHex, stepsJson));
  },
  verifyTransaction(transactionRootHex: string, txId: string, leafHex: string, stepsJson: string): boolean {
    return verdict(native.verifyTransaction(transactionRootHex, txId, leafHex, stepsJson));
  },
  confirmTransaction(chainId: bigint, txId: string, proofJson: string, finalityJson: string, rosterJson: string): string {
    return native.confirmTransaction(u64(chainId), txId, proofJson, finalityJson, rosterJson);
  },
  decodeEvent(leafHex: string): string {
    return native.decodeEvent(leafHex);
  },
};

export interface RevealPrompt {
  title?: string;
  subtitle?: string;
}

export interface SecureQCore {
  createSeed(alias: string): void;
  importPhrase(alias: string, phrase: Uint8Array): void;
  importSeed(alias: string, seed: Uint8Array): void;
  revealPhrase(alias: string, prompt?: RevealPrompt): Promise<Uint8Array>;
  hasSeed(alias: string): boolean;
  closeSeed(alias: string): void;
  closeAll(): void;
  forgetSeed(alias: string): void;
  address(alias: string, index: bigint): string;
  signTransfer(
    alias: string,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
  ): string;
  signCall(
    alias: string,
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
  ): string;
  signRegister(
    alias: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
  ): string;
  signPayableCall(
    alias: string,
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
  ): string;
  signAssetCall(
    alias: string,
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
  ): string;
}

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function sextet(code: number): number {
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 71;
  if (code >= 48 && code <= 57) return code + 4;
  if (code === 43) return 62;
  if (code === 47) return 63;
  return -1;
}

function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const left = bytes.length - i;
    const triple = (bytes[i] << 16) | ((left > 1 ? bytes[i + 1] : 0) << 8) | (left > 2 ? bytes[i + 2] : 0);
    out += BASE64_ALPHABET[(triple >> 18) & 63];
    out += BASE64_ALPHABET[(triple >> 12) & 63];
    out += left > 1 ? BASE64_ALPHABET[(triple >> 6) & 63] : '=';
    out += left > 2 ? BASE64_ALPHABET[triple & 63] : '=';
  }
  return out;
}

function fromBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0) throw new Error('the native layer returned malformed base64');
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let at = 0;
  for (let i = 0; i < text.length; i += 4) {
    let triple = 0;
    for (let j = 0; j < 4; j += 1) {
      const code = text.charCodeAt(i + j);
      const value = code === 61 && i + j >= text.length - padding ? 0 : sextet(code);
      if (value < 0) {
        out.fill(0);
        throw new Error('the native layer returned malformed base64');
      }
      triple = (triple << 6) | value;
    }
    if (at < out.length) out[at++] = (triple >> 16) & 255;
    if (at < out.length) out[at++] = (triple >> 8) & 255;
    if (at < out.length) out[at++] = triple & 255;
  }
  return out;
}

export function wipeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

export const secureQCore: SecureQCore = {
  createSeed(alias: string): void {
    native.vaultCreate(alias);
  },
  importPhrase(alias: string, phrase: Uint8Array): void {
    native.vaultImportPhrase(alias, toBase64(phrase));
  },
  importSeed(alias: string, seed: Uint8Array): void {
    native.vaultImportSeed(alias, toBase64(seed));
  },
  async revealPhrase(alias: string, prompt: RevealPrompt = {}): Promise<Uint8Array> {
    const text = await native.vaultRevealPhrase(alias, prompt.title ?? '', prompt.subtitle ?? '');
    if (typeof text !== 'string') throw new Error('the native layer returned no phrase');
    if (text.startsWith(FAILURE_PREFIX)) throw nativeError(text.slice(FAILURE_PREFIX.length));
    return fromBase64(text);
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
  forgetSeed(alias: string): void {
    native.vaultForget(alias);
  },
  address(alias: string, index: bigint): string {
    return native.vaultAddress(alias, u64(index));
  },
  signTransfer(
    alias: string,
    index: bigint,
    to: string,
    amount: string,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
  ): string {
    return native.vaultSignTransfer(
      alias,
      u64(index),
      to,
      amount,
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
      u64(head),
    );
  },
  signCall(
    alias: string,
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
  ): string {
    return native.vaultSignCall(
      alias,
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
    );
  },
  signRegister(
    alias: string,
    index: bigint,
    nonce: bigint,
    fee: string,
    chainId: bigint,
    validUntil: bigint,
    head: bigint,
  ): string {
    return native.vaultSignRegister(
      alias,
      u64(index),
      u64(nonce),
      fee,
      u64(chainId),
      u64(validUntil),
      u64(head),
    );
  },
  signPayableCall(
    alias: string,
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
  ): string {
    return native.vaultSignPayableCall(
      alias,
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
    );
  },
  signAssetCall(
    alias: string,
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
  ): string {
    return native.vaultSignAssetCall(
      alias,
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
  headerHex: string,
  certificateHex: string,
  roster: readonly RosterMember[],
): FinalizedHeader {
  const members = roster.map((m) => ({ id: m.id, stake: m.stake, attest_pk: m.attest_pk, root: m.root, root_slots: m.root_slots }));
  return JSON.parse(native.verifyFinality(u64(chainId), headerHex, certificateHex, JSON.stringify(members))) as FinalizedHeader;
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
  txId: string,
  proof: TransactionProof | string,
  finality: FinalityAnswer | string,
  roster: readonly RosterMember[] | string,
): ConfirmedTransaction {
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
    native.confirmTransaction(u64(chainId), txId, proofJson, finalityJson, rosterJson),
  ) as { tx_id: string; height: string; index: string; header: FinalizedHeader };
  if (confirmed.tx_id !== txId) throw new Error('the native layer confirmed a different transaction');
  return { txId: confirmed.tx_id, height: BigInt(confirmed.height), index: BigInt(confirmed.index), header: confirmed.header };
}

export function decodeEvent(leafHex: string): ChainEvent {
  return JSON.parse(native.decodeEvent(leafHex)) as ChainEvent;
}

export class SigningSession {
  private id: string | null;

  private constructor(id: string) {
    this.id = id;
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

  slot(key: string, reported: bigint, expected: bigint | null, order: boolean): bigint {
    return BigInt(
      native.sessionSlot(this.live(), key, u64(reported), expected === null ? '' : u64(expected), order),
    );
  }

  signed(key: string, slot: bigint): void {
    native.sessionSigned(this.live(), key, u64(slot));
  }

  release(key: string, slot: bigint): void {
    native.sessionRelease(this.live(), key, u64(slot));
  }

  releasePending(key: string): void {
    native.sessionReleasePending(this.live(), key);
  }

  outcome(key: string, slot: bigint, accepted: boolean): void {
    native.sessionOutcome(this.live(), key, u64(slot), accepted);
  }

  nextNonce(key: string): bigint | null {
    const next = native.sessionNextNonce(this.live(), key);
    return next === '' ? null : BigInt(next);
  }

  isHeld(key: string, slot: bigint): boolean {
    return native.sessionIsHeld(this.live(), key, u64(slot)) === 'true';
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

export default nativeQCore;
