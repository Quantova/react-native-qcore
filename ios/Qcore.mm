// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#import <React/RCTBridgeModule.h>
#import <React/RCTInvalidating.h>

@interface RCT_EXTERN_MODULE(Qcore, NSObject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(generateSeed)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vmCallFee:(NSString *)transferFee
                                        meterLimit:(NSString *)meterLimit)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mnemonicFromSeed:(NSString *)seedHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(seedFromMnemonic:(NSString *)phrase)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(address:(NSString *)seedHex index:(NSString *)index)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(validAddress:(NSString *)address)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sameAddress:(NSString *)a b:(NSString *)b)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(lookalikeOf:(NSString *)candidate known:(NSString *)known)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signTransfer:(NSString *)seedHex
                                        index:(NSString *)index
                                        to:(NSString *)to
                                        amount:(NSString *)amount
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        head:(NSString *)head
                                        genesisHex:(NSString *)genesisHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signCall:(NSString *)seedHex
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        transferFee:(NSString *)transferFee
                                        head:(NSString *)head
                                        genesisHex:(NSString *)genesisHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signRegister:(NSString *)seedHex
                                        index:(NSString *)index
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        head:(NSString *)head
                                        genesisHex:(NSString *)genesisHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signPayableCall:(NSString *)seedHex
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        value:(NSString *)value
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        transferFee:(NSString *)transferFee
                                        head:(NSString *)head
                                        genesisHex:(NSString *)genesisHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signAssetCall:(NSString *)seedHex
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        assetIssuer:(NSString *)assetIssuer
                                        amount:(NSString *)amount
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        transferFee:(NSString *)transferFee
                                        head:(NSString *)head
                                        genesisHex:(NSString *)genesisHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(gatewayProtocol)
RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(checkEndpoint:(NSString *)base)
RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(testnetRpcUrl)
RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(testnetChainName)
RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(testnetGenesisHash)
RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(chainIdFromName:(NSString *)name)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(nameKey:(NSString *)label)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mapSlotKey:(NSString *)mapDomainTag
                                        keyAddressHex:(NSString *)keyAddressHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mapAddrWordKey:(NSString *)mapDomainTag
                                        key32Hex:(NSString *)key32Hex
                                        word:(NSString *)word)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(scalarSlotKey:(NSString *)slot)

RCT_EXTERN_METHOD(vaultCreate:(NSString *)alias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultImportPhrase:(NSString *)alias
                  phrase:(NSArray<NSNumber *> *)phrase
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultImportSeed:(NSString *)alias
                  seed:(NSArray<NSNumber *> *)seed
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultRevealPhrase:(NSString *)alias
                  title:(NSString *)title
                  subtitle:(NSString *)subtitle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultResetNonceState:(NSString *)alias
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  title:(NSString *)title
                  subtitle:(NSString *)subtitle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultAcknowledgeImportedHistory:(NSString *)alias
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  title:(NSString *)title
                  subtitle:(NSString *)subtitle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultAcknowledgeMainnet:(NSString *)alias
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  title:(NSString *)title
                  subtitle:(NSString *)subtitle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultLearnAddresses:(NSString *)alias
                  count:(NSString *)count
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultStorageLevel)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultHas:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultClose:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultCloseAll)

RCT_EXTERN_METHOD(vaultForget:(NSString *)alias
                  title:(NSString *)title
                  subtitle:(NSString *)subtitle
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultAddress:(NSString *)alias index:(NSString *)index)

RCT_EXTERN_METHOD(vaultSignTransfer:(NSString *)alias
                  sessionId:(NSString *)sessionId
                  index:(NSString *)index
                  to:(NSString *)to
                  amount:(NSString *)amount
                  nonce:(NSString *)nonce
                  fee:(NSString *)fee
                  chainId:(NSString *)chainId
                  validUntil:(NSString *)validUntil
                  head:(NSString *)head
                  genesisHex:(NSString *)genesisHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultSignCall:(NSString *)alias
                  sessionId:(NSString *)sessionId
                  index:(NSString *)index
                  target:(NSString *)target
                  argsHex:(NSString *)argsHex
                  nonce:(NSString *)nonce
                  meterLimit:(NSString *)meterLimit
                  fee:(NSString *)fee
                  chainId:(NSString *)chainId
                  validUntil:(NSString *)validUntil
                  transferFee:(NSString *)transferFee
                  head:(NSString *)head
                  genesisHex:(NSString *)genesisHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultSignRegister:(NSString *)alias
                  sessionId:(NSString *)sessionId
                  index:(NSString *)index
                  nonce:(NSString *)nonce
                  fee:(NSString *)fee
                  chainId:(NSString *)chainId
                  validUntil:(NSString *)validUntil
                  head:(NSString *)head
                  genesisHex:(NSString *)genesisHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultSignPayableCall:(NSString *)alias
                  sessionId:(NSString *)sessionId
                  index:(NSString *)index
                  target:(NSString *)target
                  argsHex:(NSString *)argsHex
                  nonce:(NSString *)nonce
                  meterLimit:(NSString *)meterLimit
                  fee:(NSString *)fee
                  value:(NSString *)value
                  chainId:(NSString *)chainId
                  validUntil:(NSString *)validUntil
                  transferFee:(NSString *)transferFee
                  head:(NSString *)head
                  genesisHex:(NSString *)genesisHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(vaultSignAssetCall:(NSString *)alias
                  sessionId:(NSString *)sessionId
                  index:(NSString *)index
                  target:(NSString *)target
                  argsHex:(NSString *)argsHex
                  assetIssuer:(NSString *)assetIssuer
                  amount:(NSString *)amount
                  nonce:(NSString *)nonce
                  meterLimit:(NSString *)meterLimit
                  fee:(NSString *)fee
                  chainId:(NSString *)chainId
                  validUntil:(NSString *)validUntil
                  transferFee:(NSString *)transferFee
                  head:(NSString *)head
                  genesisHex:(NSString *)genesisHex
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(checkValidUntil:(NSString *)validUntil head:(NSString *)head)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(boundedValidUntil:(NSString *)chainName
                                        head:(NSString *)head
                                        wallSecs:(NSString *)wallSecs
                                        floor:(NSString *)floor
                                        floorAgeSecs:(NSString *)floorAgeSecs)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(headCeiling:(NSString *)chainName wallSecs:(NSString *)wallSecs)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(genesisSecs:(NSString *)chainName)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(maxValidityBlocks)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(defaultValidityBlocks)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(checkOrderExpiry:(NSString *)expiry nowSecs:(NSString *)nowSecs)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(maxOrderLifetimeSecs)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(verifyFinality:(NSString *)chainId
                                        genesisHex:(NSString *)genesisHex
                                        epochLength:(NSString *)epochLength
                                        rosterEpoch:(NSString *)rosterEpoch
                                        headerHex:(NSString *)headerHex
                                        certificateHex:(NSString *)certificateHex
                                        rosterJson:(NSString *)rosterJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(verifyEvent:(NSString *)eventRootHex
                                        leafHex:(NSString *)leafHex
                                        stepsJson:(NSString *)stepsJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(verifyTransaction:(NSString *)transactionRootHex
                                        txId:(NSString *)txId
                                        leafHex:(NSString *)leafHex
                                        stepsJson:(NSString *)stepsJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(confirmTransaction:(NSString *)chainId
                                        genesisHex:(NSString *)genesisHex
                                        epochLength:(NSString *)epochLength
                                        rosterEpoch:(NSString *)rosterEpoch
                                        txId:(NSString *)txId
                                        proofJson:(NSString *)proofJson
                                        finalityJson:(NSString *)finalityJson
                                        rosterJson:(NSString *)rosterJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(confirmInclusion:(NSString *)chainId
                                        genesisHex:(NSString *)genesisHex
                                        epochLength:(NSString *)epochLength
                                        rosterEpoch:(NSString *)rosterEpoch
                                        txId:(NSString *)txId
                                        proofJson:(NSString *)proofJson
                                        finalityJson:(NSString *)finalityJson
                                        rosterJson:(NSString *)rosterJson)rosterJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(decodeEvent:(NSString *)leafHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionOpen:(NSString *)addressBook)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionClose:(NSString *)id)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionKnown:(NSString *)id)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionRememberAddress:(NSString *)id address:(NSString *)address)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionCheckTarget:(NSString *)id address:(NSString *)address)

RCT_EXTERN_METHOD(sessionSlot:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  reported:(NSString *)reported
                  expected:(NSString *)expected
                  order:(BOOL)order
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionSigned:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  slot:(NSString *)slot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionRelease:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  slot:(NSString *)slot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionReleasePending:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionOutcome:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  slot:(NSString *)slot
                  accepted:(BOOL)accepted
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionNextNonce:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sessionIsHeld:(NSString *)id
                  chainId:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  slot:(NSString *)slot
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

@end

@interface Qcore (QcoreInvalidating) <RCTInvalidating>
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wprotocol"
@implementation Qcore (QcoreInvalidating)
RCT_EXTERN_METHOD(vaultSettleHistory:(NSString *)chainId
                  genesisHex:(NSString *)genesisHex
                  key:(NSString *)key
                  headerHex:(NSString *)headerHex
                  certificateHex:(NSString *)certificateHex
                  rosterJson:(NSString *)rosterJson
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
#pragma clang diagnostic pop
