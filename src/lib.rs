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

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn a_malformed_address_is_an_error_and_not_a_panic() {
        for bad in ["not an address", "", "Q1zzzz"] {
            assert!(
                sign_transfer(
                    SEED.to_string(),
                    0,
                    bad.to_string(),
                    "5".to_string(),
                    0,
                    "1".to_string(),
                    1,
                    0,
                )
                .is_err(),
                "a transfer to {bad:?} must return an error, not sign and not panic"
            );
        }
    }

    #[test]
    fn a_malformed_seed_is_an_error_and_not_a_panic() {
        let to = address(SEED.to_string(), 0).expect("a good seed derives an address");
        for bad in ["", "00", "zz", &"00".repeat(31)] {
            assert!(
                address(bad.to_string(), 0).is_err(),
                "the seed {bad:?} must be refused"
            );
            assert!(
                sign_transfer(
                    bad.to_string(),
                    0,
                    to.clone(),
                    "5".to_string(),
                    0,
                    "1".to_string(),
                    1,
                    0,
                )
                .is_err(),
                "signing under the seed {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn an_index_selects_the_key_it_names() {
        let zero = address(SEED.to_string(), 0).expect("index zero derives");
        let one = address(SEED.to_string(), 1).expect("index one derives");
        let last = address(SEED.to_string(), u64::MAX).expect("the last index derives");
        assert_ne!(zero, one, "two indices must not share an address");
        assert_ne!(one, last, "the far end of the range is its own address");
        assert_eq!(
            zero,
            address(SEED.to_string(), 0).expect("deriving twice agrees"),
            "an index gives the same address every time"
        );
        assert!(valid_address(zero), "a derived address must parse");
    }

    #[test]
    fn a_full_width_amount_survives_the_boundary() {
        let to = address(SEED.to_string(), 3).expect("derives");
        let sign = |amount: &str| {
            sign_transfer(
                SEED.to_string(),
                0,
                to.clone(),
                amount.to_string(),
                0,
                "1".to_string(),
                1,
                0,
            )
            .expect("a good transfer signs")
        };
        assert_ne!(
            sign("9007199254740992"),
            sign("9007199254740993"),
            "two amounts one apart must not sign alike"
        );
        assert!(!sign("18446744073709551615").is_empty());
    }

    #[test]
    fn a_phrase_carries_the_seed_it_was_made_from() {
        let phrase = mnemonic_from_seed(SEED.to_string()).expect("a seed makes a phrase");
        let back = seed_from_mnemonic(phrase).expect("the phrase gives the seed back");
        assert_eq!(back, SEED, "a phrase must round trip to its own seed");
        assert!(
            seed_from_mnemonic("word ".repeat(24).trim().to_string()).is_err(),
            "a phrase that is not one of ours is refused, not guessed at"
        );
    }
}
