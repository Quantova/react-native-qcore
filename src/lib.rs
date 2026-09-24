// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::json::{from_hex, object, to_hex, Json};
use qcore::SEED_LEN;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!("quantova_qcore");

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum QcoreError {
    #[error("{0}")]
    Invalid(String),
}

fn err(message: impl Into<String>) -> QcoreError {
    QcoreError::Invalid(message.into())
}

fn parse_seed(seed_hex: &str) -> Result<Zeroizing<[u8; SEED_LEN]>, QcoreError> {
    let bytes = Zeroizing::new(from_hex(seed_hex).map_err(err)?);
    if bytes.len() != SEED_LEN {
        return Err(err("a seed is thirty two bytes of hex"));
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn parse_amount(value: &str) -> Result<u64, QcoreError> {
    value
        .parse::<u64>()
        .map_err(|_| err("the amount is not a whole number of Quon"))
}

fn parse_fee(value: &str) -> Result<u128, QcoreError> {
    value
        .parse::<u128>()
        .map_err(|_| err("the fee is not a whole number of Quon"))
}

fn signed_json(signed: qcore::SignedTransfer) -> String {
    object(vec![
        ("from", Json::str(signed.from)),
        ("tx_id", Json::str(signed.tx_id)),
        ("tx_hex", Json::str(to_hex(&signed.tx_bytes))),
    ])
    .render()
}

#[uniffi::export]
pub fn mnemonic_from_seed(seed_hex: String) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    Ok(qcore::mnemonic_from_seed(&seed).to_string())
}

#[uniffi::export]
pub fn seed_from_mnemonic(phrase: String) -> Result<String, QcoreError> {
    let phrase = Zeroizing::new(phrase);
    let seed = qcore::seed_from_mnemonic(&phrase).map_err(err)?;
    Ok(to_hex(&seed[..]))
}

#[uniffi::export]
pub fn address(seed_hex: String, index: u64) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    Ok(qcore::account_address(&seed, index))
}

#[uniffi::export]
pub fn valid_address(address: String) -> bool {
    qcore::valid_address(&address)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_transfer(
    seed_hex: String,
    index: u64,
    to: String,
    amount: String,
    nonce: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    let signed = qcore::sign_transfer(
        &seed,
        index,
        &to,
        parse_amount(&amount)?,
        nonce,
        parse_fee(&fee)?,
        chain_id,
        valid_until,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_call(
    seed_hex: String,
    index: u64,
    target: String,
    args_hex: String,
    nonce: u64,
    meter_limit: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    let args = from_hex(&args_hex).map_err(err)?;
    let signed = qcore::sign_call(
        &seed,
        index,
        &target,
        args,
        nonce,
        meter_limit,
        parse_fee(&fee)?,
        chain_id,
        valid_until,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
pub fn sign_register(
    seed_hex: String,
    index: u64,
    nonce: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    let signed = qcore::sign_register(&seed, index, nonce, parse_fee(&fee)?, chain_id, valid_until)
        .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
pub fn chain_id_from_name(name: String) -> u64 {
    qcore::chain_id_from_name(&name)
}

fn parse_key32(hex: &str) -> Result<[u8; 32], QcoreError> {
    let bytes = from_hex(hex).map_err(err)?;
    if bytes.len() != 32 {
        return Err(err("a storage key is thirty two bytes of hex"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_payable_call(
    seed_hex: String,
    index: u64,
    target: String,
    args_hex: String,
    nonce: u64,
    meter_limit: u64,
    fee: String,
    value: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    let args = from_hex(&args_hex).map_err(err)?;
    let signed = qcore::sign_payable_call(
        &seed,
        index,
        &target,
        args,
        parse_amount(&value)?,
        nonce,
        meter_limit,
        parse_fee(&fee)?,
        chain_id,
        valid_until,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_asset_call(
    seed_hex: String,
    index: u64,
    target: String,
    args_hex: String,
    asset_issuer: String,
    amount: String,
    nonce: u64,
    meter_limit: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed_hex = Zeroizing::new(seed_hex);
    let seed = parse_seed(&seed_hex)?;
    let args = from_hex(&args_hex).map_err(err)?;
    let signed = qcore::sign_asset_call(
        &seed,
        index,
        &target,
        args,
        &asset_issuer,
        parse_amount(&amount)?,
        nonce,
        meter_limit,
        parse_fee(&fee)?,
        chain_id,
        valid_until,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
pub fn name_key(label: String) -> String {
    to_hex(&qcore::contract::name_key(&label))
}

#[uniffi::export]
pub fn scalar_slot_key(slot: u64) -> String {
    to_hex(&qcore::contract::scalar_slot_key(slot))
}

#[uniffi::export]
pub fn map_slot_key(map_domain_tag: u64, key_address_hex: String) -> Result<String, QcoreError> {
    let key = parse_key32(&key_address_hex)?;
    Ok(to_hex(&qcore::contract::map_slot_key(map_domain_tag, &key)))
}

#[uniffi::export]
pub fn map_addr_word_key(
    map_domain_tag: u64,
    key_address_hex: String,
    word: u64,
) -> Result<String, QcoreError> {
    let key = parse_key32(&key_address_hex)?;
    Ok(to_hex(&qcore::contract::map_addr_word_key(
        map_domain_tag,
        &key,
        word,
    )))
}
