// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#import <React/RCTBridgeModule.h>

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
                                        validUntil:(NSString *)validUntil)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signCall:(NSString *)seedHex
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        transferFee:(NSString *)transferFee)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signRegister:(NSString *)seedHex
                                        index:(NSString *)index
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil)

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
                                        transferFee:(NSString *)transferFee)

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
                                        transferFee:(NSString *)transferFee)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(chainIdFromName:(NSString *)name)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(nameKey:(NSString *)label)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mapSlotKey:(NSString *)mapDomainTag
                                        keyAddressHex:(NSString *)keyAddressHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mapAddrWordKey:(NSString *)mapDomainTag
                                        key32Hex:(NSString *)key32Hex
                                        word:(NSString *)word)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(scalarSlotKey:(NSString *)slot)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultCreate:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultImportPhrase:(NSString *)alias
                                        phraseBase64:(NSString *)phraseBase64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultImportSeed:(NSString *)alias
                                        seedBase64:(NSString *)seedBase64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultRevealPhrase:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultHas:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultClose:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultForget:(NSString *)alias)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultAddress:(NSString *)alias index:(NSString *)index)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultSignTransfer:(NSString *)alias
                                        index:(NSString *)index
                                        to:(NSString *)to
                                        amount:(NSString *)amount
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        head:(NSString *)head)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultSignCall:(NSString *)alias
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        transferFee:(NSString *)transferFee
                                        head:(NSString *)head)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultSignRegister:(NSString *)alias
                                        index:(NSString *)index
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId
                                        validUntil:(NSString *)validUntil
                                        head:(NSString *)head)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultSignPayableCall:(NSString *)alias
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
                                        head:(NSString *)head)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(vaultSignAssetCall:(NSString *)alias
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
                                        head:(NSString *)head)

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
                                        headerHex:(NSString *)headerHex
                                        certificateHex:(NSString *)certificateHex
                                        rosterJson:(NSString *)rosterJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(verifyEvent:(NSString *)eventRootHex
                                        leafHex:(NSString *)leafHex
                                        stepsJson:(NSString *)stepsJson)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(decodeEvent:(NSString *)leafHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionOpen:(NSString *)addressBook)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionClose:(NSString *)id)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionKnown:(NSString *)id)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionRememberAddress:(NSString *)id address:(NSString *)address)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionCheckTarget:(NSString *)id address:(NSString *)address)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionSlot:(NSString *)id
                                        key:(NSString *)key
                                        reported:(NSString *)reported
                                        expected:(NSString *)expected
                                        order:(BOOL)order)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionSigned:(NSString *)id key:(NSString *)key slot:(NSString *)slot)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionOutcome:(NSString *)id
                                        key:(NSString *)key
                                        slot:(NSString *)slot
                                        accepted:(BOOL)accepted)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionNextNonce:(NSString *)id key:(NSString *)key)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sessionIsHeld:(NSString *)id key:(NSString *)key slot:(NSString *)slot)

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

@end
