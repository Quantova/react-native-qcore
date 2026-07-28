// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Qcore, NSObject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(mnemonicFromSeed:(NSString *)seedHex)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(seedFromMnemonic:(NSString *)phrase)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(address:(NSString *)seedHex index:(NSString *)index)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(validAddress:(NSString *)address)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signTransfer:(NSString *)seedHex
                                        index:(NSString *)index
                                        to:(NSString *)to
                                        amount:(NSString *)amount
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signCall:(NSString *)seedHex
                                        index:(NSString *)index
                                        target:(NSString *)target
                                        argsHex:(NSString *)argsHex
                                        nonce:(NSString *)nonce
                                        meterLimit:(NSString *)meterLimit
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signRegister:(NSString *)seedHex
                                        index:(NSString *)index
                                        nonce:(NSString *)nonce
                                        fee:(NSString *)fee
                                        chainId:(NSString *)chainId)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(chainIdFromName:(NSString *)name)

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

@end
