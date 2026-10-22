// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use qcore::json::{from_hex, object, to_hex, Json};
use qcore::SEED_LEN;
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!("quantova_qcore");

struct WipingAllocator;

unsafe impl GlobalAlloc for WipingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static WIPING_ALLOCATOR: WipingAllocator = WipingAllocator;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum QcoreError {
    #[error("{0}")]
    Invalid(String),
}

fn err(message: impl Into<String>) -> QcoreError {
    QcoreError::Invalid(message.into())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn strong(seed: &[u8]) -> Result<(), QcoreError> {
    let mut seen = [false; 256];
    let mut different = 0usize;
    for b in seed {
        if !seen[usize::from(*b)] {
            seen[usize::from(*b)] = true;
            different += 1;
        }
    }
    if different < 13 {
        return Err(err(
            "a seed made of too few different byte values is refused, create a new wallet",
        ));
    }
    Ok(())
}

fn parse_seed(seed: Vec<u8>) -> Result<Zeroizing<[u8; SEED_LEN]>, QcoreError> {
    let bytes = Zeroizing::new(seed);
    if bytes.len() != SEED_LEN {
        return Err(err("a seed is thirty two bytes"));
    }
    strong(&bytes)?;
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn held(seed: &[u8; SEED_LEN]) -> Zeroizing<[u8; SEED_LEN]> {
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    out.copy_from_slice(seed);
    out
}

fn fresh_seed() -> Result<Zeroizing<[u8; SEED_LEN]>, QcoreError> {
    let seed = qcore::generate_seed().map_err(err)?;
    Ok(held(&seed))
}

fn seed_from_phrase(phrase: Vec<u8>) -> Result<Zeroizing<[u8; SEED_LEN]>, QcoreError> {
    let phrase = Zeroizing::new(phrase);
    let seed = qcore::seed_from_mnemonic_bytes(&phrase).map_err(err)?;
    strong(&seed[..])?;
    Ok(held(&seed))
}

fn phrase_from(seed: &[u8; SEED_LEN]) -> Vec<u8> {
    let mut phrase = qcore::mnemonic_bytes_from_seed(seed);
    std::mem::take(&mut *phrase)
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn parse_amount(value: &str) -> Result<u64, QcoreError> {
    if !digits(value) {
        return Err(err("the amount is not a whole number of Quon"));
    }
    value
        .parse::<u64>()
        .map_err(|_| err("the amount is not a whole number of Quon"))
}

fn parse_fee(value: &str) -> Result<u128, QcoreError> {
    if !digits(value) {
        return Err(err("the fee is not a whole number of Quon"));
    }
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

#[allow(clippy::too_many_arguments)]
fn transfer_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    to: &str,
    amount: &str,
    nonce: u64,
    fee: &str,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis: &[u8; 32],
) -> Result<String, QcoreError> {
    let signed = qcore::sign_transfer(
        seed,
        index,
        to,
        parse_amount(amount)?,
        nonce,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        head,
        genesis,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[allow(clippy::too_many_arguments)]
fn call_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: &str,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: &str,
    head: u64,
    genesis: &[u8; 32],
) -> Result<String, QcoreError> {
    let args = from_hex(args_hex).map_err(err)?;
    let signed = qcore::sign_call(
        seed,
        index,
        target,
        args,
        nonce,
        meter_limit,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        parse_fee(transfer_fee)?,
        head,
        genesis,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[allow(clippy::too_many_arguments)]
fn register_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    nonce: u64,
    fee: &str,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis: &[u8; 32],
) -> Result<String, QcoreError> {
    let signed = qcore::sign_register(
        seed,
        index,
        nonce,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        head,
        genesis,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[allow(clippy::too_many_arguments)]
fn payable_call_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: &str,
    value: &str,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: &str,
    head: u64,
    genesis: &[u8; 32],
) -> Result<String, QcoreError> {
    let args = from_hex(args_hex).map_err(err)?;
    let signed = qcore::sign_payable_call(
        seed,
        index,
        target,
        args,
        parse_amount(value)?,
        nonce,
        meter_limit,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        parse_fee(transfer_fee)?,
        head,
        genesis,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[allow(clippy::too_many_arguments)]
fn asset_call_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args_hex: &str,
    asset_issuer: &str,
    amount: &str,
    nonce: u64,
    meter_limit: u64,
    fee: &str,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: &str,
    head: u64,
    genesis: &[u8; 32],
) -> Result<String, QcoreError> {
    let args = from_hex(args_hex).map_err(err)?;
    let signed = qcore::sign_asset_call(
        seed,
        index,
        target,
        args,
        asset_issuer,
        parse_amount(amount)?,
        nonce,
        meter_limit,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        parse_fee(transfer_fee)?,
        head,
        genesis,
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

#[uniffi::export]
pub fn generate_seed() -> Result<Vec<u8>, QcoreError> {
    let seed = fresh_seed()?;
    Ok(seed.to_vec())
}

#[uniffi::export]
pub fn vm_call_fee(transfer_fee: String, meter_limit: u64) -> Result<String, QcoreError> {
    Ok(qcore::vm_call_fee(parse_fee(&transfer_fee)?, meter_limit).to_string())
}

#[uniffi::export]
pub fn mnemonic_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, QcoreError> {
    let seed = parse_seed(seed)?;
    Ok(phrase_from(&seed))
}

#[uniffi::export]
pub fn seed_from_mnemonic(phrase: Vec<u8>) -> Result<Vec<u8>, QcoreError> {
    let seed = seed_from_phrase(phrase)?;
    Ok(seed.to_vec())
}

#[uniffi::export]
pub fn address(seed: Vec<u8>, index: u64) -> Result<String, QcoreError> {
    let seed = parse_seed(seed)?;
    Ok(qcore::account_address(&seed, index))
}

#[uniffi::export]
pub fn valid_address(address: String) -> bool {
    qcore::valid_address(&address)
}

#[uniffi::export]
pub fn same_address(a: String, b: String) -> bool {
    qcore::same_address(&a, &b)
}

#[uniffi::export]
pub fn lookalike_of(candidate: String, known: Vec<String>) -> Option<String> {
    qcore::lookalike_of(&candidate, &known)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_transfer(
    seed: Vec<u8>,
    index: u64,
    to: String,
    amount: String,
    nonce: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis_hex: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let seed = parse_seed(seed)?;
    transfer_with(
        &seed,
        index,
        &to,
        &amount,
        nonce,
        &fee,
        chain_id,
        valid_until,
        head,
        &genesis,
    )
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_call(
    seed: Vec<u8>,
    index: u64,
    target: String,
    args_hex: String,
    nonce: u64,
    meter_limit: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: String,
    head: u64,
    genesis_hex: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let seed = parse_seed(seed)?;
    call_with(
        &seed,
        index,
        &target,
        &args_hex,
        nonce,
        meter_limit,
        &fee,
        chain_id,
        valid_until,
        &transfer_fee,
        head,
        &genesis,
    )
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_register(
    seed: Vec<u8>,
    index: u64,
    nonce: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis_hex: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let seed = parse_seed(seed)?;
    register_with(
        &seed,
        index,
        nonce,
        &fee,
        chain_id,
        valid_until,
        head,
        &genesis,
    )
}

#[uniffi::export]
pub fn chain_id_from_name(name: String) -> Result<u64, QcoreError> {
    qcore::checked_chain_id(&name).map_err(err)
}

#[uniffi::export]
pub fn gateway_protocol() -> u32 {
    qcore::GATEWAY_PROTOCOL
}

#[uniffi::export]
pub fn check_endpoint(base: String) -> Result<(), QcoreError> {
    qcore::check_endpoint(&base).map_err(err)
}

#[uniffi::export]
pub fn testnet_rpc_url() -> String {
    qcore::TESTNET_RPC_URL.to_string()
}

#[uniffi::export]
pub fn testnet_chain_name() -> String {
    qcore::TESTNET_CHAIN_NAME.to_string()
}

#[uniffi::export]
pub fn testnet_genesis_hash() -> Option<String> {
    qcore::TESTNET_GENESIS_HASH.map(|h| to_hex(&h))
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
    seed: Vec<u8>,
    index: u64,
    target: String,
    args_hex: String,
    nonce: u64,
    meter_limit: u64,
    fee: String,
    value: String,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: String,
    head: u64,
    genesis_hex: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let seed = parse_seed(seed)?;
    payable_call_with(
        &seed,
        index,
        &target,
        &args_hex,
        nonce,
        meter_limit,
        &fee,
        &value,
        chain_id,
        valid_until,
        &transfer_fee,
        head,
        &genesis,
    )
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_asset_call(
    seed: Vec<u8>,
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
    transfer_fee: String,
    head: u64,
    genesis_hex: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let seed = parse_seed(seed)?;
    asset_call_with(
        &seed,
        index,
        &target,
        &args_hex,
        &asset_issuer,
        &amount,
        nonce,
        meter_limit,
        &fee,
        chain_id,
        valid_until,
        &transfer_fee,
        head,
        &genesis,
    )
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

#[uniffi::export]
pub fn check_valid_until(valid_until: u64, head: u64) -> Result<(), QcoreError> {
    qcore::check_valid_until(valid_until, head).map_err(err)
}

#[uniffi::export]
pub fn bounded_valid_until(
    chain_name: String,
    head: u64,
    wall_secs: u64,
    floor: Option<u64>,
    floor_age_secs: u64,
) -> Result<u64, QcoreError> {
    qcore::bounded_valid_until(&chain_name, head, wall_secs, floor, floor_age_secs).map_err(err)
}

#[uniffi::export]
pub fn head_ceiling(chain_name: String, wall_secs: u64) -> u64 {
    qcore::head_ceiling(&chain_name, wall_secs)
}

#[uniffi::export]
pub fn genesis_secs(chain_name: String) -> u64 {
    qcore::genesis_secs(&chain_name)
}

#[uniffi::export]
pub fn max_validity_blocks() -> u64 {
    qcore::MAX_VALIDITY_BLOCKS
}

#[uniffi::export]
pub fn default_validity_blocks() -> u64 {
    qcore::DEFAULT_VALIDITY_BLOCKS
}

#[uniffi::export]
pub fn check_order_expiry(expiry: u64, now_secs: u64) -> Result<(), QcoreError> {
    qcore::contract::check_order_expiry(expiry, now_secs).map_err(err)
}

#[uniffi::export]
pub fn max_order_lifetime_secs() -> u64 {
    qcore::contract::MAX_ORDER_LIFETIME_SECS
}

fn parse_steps(steps_json: &str) -> Result<Vec<([u8; 32], bool)>, String> {
    let parsed = qcore::json::parse(steps_json)?;
    let items = parsed
        .as_array()
        .ok_or_else(|| "the proof steps must be a JSON array".to_string())?;
    let mut steps = Vec::with_capacity(items.len());
    for item in items {
        let sibling = item
            .get("sibling")
            .and_then(Json::as_str)
            .ok_or_else(|| "a proof step needs a sibling".to_string())?;
        let left = item
            .get("left")
            .and_then(Json::as_bool)
            .ok_or_else(|| "a proof step needs a boolean left".to_string())?;
        let bytes: [u8; 32] = from_hex(sibling)?
            .try_into()
            .map_err(|_| "a proof sibling is 32 bytes of hex".to_string())?;
        steps.push((bytes, left));
    }
    Ok(steps)
}

fn finalized_json(h: &qcore::finality::FinalizedHeader) -> String {
    finalized_object(h).render()
}

fn finalized_object(h: &qcore::finality::FinalizedHeader) -> Json {
    object(vec![
        ("height", Json::str(h.height.to_string())),
        ("hash", Json::str(to_hex(&h.hash))),
        ("parent_hash", Json::str(to_hex(&h.parent_hash))),
        ("q_root", Json::str(to_hex(&h.q_root))),
        ("transaction_root", Json::str(to_hex(&h.transaction_root))),
        ("event_root", Json::str(to_hex(&h.event_root))),
        ("time", Json::str(h.time.to_string())),
        ("signed_stake", Json::str(h.signed_stake.to_string())),
        ("total_stake", Json::str(h.total_stake.to_string())),
    ])
}

fn parse_genesis(genesis_hex: &str) -> Result<[u8; 32], String> {
    const MALFORMED: &str =
        "the genesis hash is 64 hex characters, the 32 byte genesis of the network this app pins";
    if genesis_hex.len() != 64 || !genesis_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MALFORMED.to_string());
    }
    let genesis: [u8; 32] = from_hex(genesis_hex)?
        .try_into()
        .map_err(|_| MALFORMED.to_string())?;
    if genesis == [0u8; 32] {
        return Err("a genesis hash of zeros names no network, pass the genesis of the network this app pins".to_string());
    }
    Ok(genesis)
}

fn epoch_length_for(chain_id: u64, given: Option<u64>) -> Result<u64, String> {
    let pinned = if chain_id == qcore::testnet_chain_id() {
        qcore::TESTNET_EPOCH_LENGTH
    } else if chain_id == qcore::MAINNET_CHAIN_ID {
        qcore::MAINNET_EPOCH_LENGTH
    } else {
        None
    };
    match (pinned, given) {
        (Some(pinned), Some(given)) if pinned != given => Err(format!(
            "this network has epochs of {pinned} blocks, not the {given} given"
        )),
        (Some(pinned), _) => Ok(pinned),
        (None, Some(given)) if given > 0 => Ok(given),
        _ => Err("no epoch length is known for this network, pass the epoch length it uses so a roster certifies only headers of its own epoch".to_string()),
    }
}

fn epoch_roster(roster_json: &str, epoch: u64) -> Result<qcore::finality::VerifiedRoster, String> {
    Ok(qcore::finality::VerifiedRoster {
        epoch,
        members: qcore::finality::parse_roster(roster_json)?,
    })
}

fn finalized_in_epoch(
    chain_id: u64,
    genesis: &[u8; 32],
    epoch_length: Option<u64>,
    roster_epoch: u64,
    header: &[u8],
    certificate: &[u8],
    roster_json: &str,
) -> Result<qcore::finality::FinalizedHeader, String> {
    let length = epoch_length_for(chain_id, epoch_length)?;
    let roster = epoch_roster(roster_json, roster_epoch)?;
    if let Ok(height) = qcore::finality::header_height(header) {
        let epoch = qcore::finality::epoch_of(height, length)?;
        if epoch != roster.epoch {
            return Err(format!(
                "the header at height {height} lies in epoch {epoch} but the roster given is trusted for epoch {}, refusing a roster from another epoch",
                roster.epoch
            ));
        }
    }
    qcore::finality::verify_finality(chain_id, genesis, header, certificate, &roster.members)
}

#[uniffi::export]
pub fn verify_finality(
    chain_id: u64,
    genesis_hex: String,
    epoch_length: Option<u64>,
    roster_epoch: u64,
    header_hex: String,
    certificate_hex: String,
    roster_json: String,
) -> Result<String, QcoreError> {
    let genesis = parse_genesis(&genesis_hex).map_err(err)?;
    let header = from_hex(&header_hex).map_err(err)?;
    let certificate = from_hex(&certificate_hex).map_err(err)?;
    let verified = finalized_in_epoch(
        chain_id,
        &genesis,
        epoch_length,
        roster_epoch,
        &header,
        &certificate,
        &roster_json,
    )
    .map_err(err)?;
    Ok(finalized_json(&verified))
}

#[uniffi::export]
pub fn verify_event(
    event_root_hex: String,
    leaf_hex: String,
    steps_json: String,
) -> Result<bool, QcoreError> {
    let root: [u8; 32] = from_hex(&event_root_hex)
        .map_err(err)?
        .try_into()
        .map_err(|_| err("the event root is 32 bytes of hex"))?;
    let leaf = from_hex(&leaf_hex).map_err(err)?;
    let steps = parse_steps(&steps_json).map_err(err)?;
    Ok(qcore::finality::verify_event(&root, &leaf, &steps))
}

#[uniffi::export]
pub fn verify_transaction(
    transaction_root_hex: String,
    tx_id: String,
    leaf_hex: String,
    steps_json: String,
) -> Result<bool, QcoreError> {
    let root: [u8; 32] = from_hex(&transaction_root_hex)
        .map_err(err)?
        .try_into()
        .map_err(|_| err("the transaction root is 32 bytes of hex"))?;
    let leaf = from_hex(&leaf_hex).map_err(err)?;
    let steps = parse_steps(&steps_json).map_err(err)?;
    Ok(qcore::finality::verify_transaction(
        &root, &tx_id, &leaf, &steps,
    ))
}

struct Included {
    height: u64,
    index: u64,
    leaf: Vec<u8>,
    header: qcore::finality::FinalizedHeader,
}

#[allow(clippy::too_many_arguments)]
fn included(
    chain_id: u64,
    genesis_hex: &str,
    epoch_length: Option<u64>,
    roster_epoch: u64,
    tx_id: &str,
    proof_json: &str,
    finality_json: &str,
    roster_json: &str,
) -> Result<Included, String> {
    let genesis = parse_genesis(genesis_hex)?;
    let proof = qcore::json::parse(proof_json)?;
    let height = proof
        .get("height")
        .and_then(Json::as_u64)
        .ok_or("the transaction proof names no height")?;
    let index = proof
        .get("index")
        .and_then(Json::as_u64)
        .ok_or("the transaction proof names no index")?;
    let leaf = from_hex(
        proof
            .get("leaf")
            .and_then(Json::as_str)
            .ok_or("the transaction proof carries no leaf")?,
    )?;
    let steps = qcore::finality::parse_steps(
        proof
            .get("steps")
            .ok_or("the transaction proof carries no steps")?,
    )?;
    let finality = qcore::json::parse(finality_json)?;
    let header = from_hex(
        finality
            .get("header_bytes")
            .and_then(Json::as_str)
            .ok_or("the finality answer carries no header")?,
    )?;
    let certificate = from_hex(
        finality
            .get("certificate")
            .and_then(Json::as_str)
            .ok_or("the finality answer carries no certificate")?,
    )?;
    let verified = finalized_in_epoch(
        chain_id,
        &genesis,
        epoch_length,
        roster_epoch,
        &header,
        &certificate,
        roster_json,
    )?;
    if verified.height != height {
        return Err("the finalized header is not at the height the proof names".to_string());
    }
    if !qcore::finality::verify_transaction(&verified.transaction_root, tx_id, &leaf, &steps) {
        return Err("the transaction is not proven inside the finalized block".to_string());
    }
    if !qcore::finality::index_fits_path(index, &steps) {
        return Err("the transaction is not at the position the proof names".to_string());
    }
    Ok(Included {
        height,
        index,
        leaf,
        header: verified,
    })
}

fn settled_kind(tx_id: &str, leaf: &[u8], calls: bool) -> Result<bool, String> {
    let call = qcore::finality::transaction_kind(leaf)? == qcore::finality::TxKind::Call;
    if call && !calls {
        return Err(format!(
            "{tx_id} is a contract call, which the chain includes and charges even when it reverts, so inclusion does not prove it ran, prove the event it emits or use confirmInclusion for inclusion alone"
        ));
    }
    Ok(call)
}

fn rendered(tx_id: &str, found: &Included, call: bool) -> String {
    object(vec![
        ("tx_id", Json::str(tx_id)),
        ("height", Json::str(found.height.to_string())),
        ("index", Json::str(found.index.to_string())),
        ("kind", Json::str(if call { "call" } else { "transfer" })),
        (
            "outcome",
            Json::str(if call {
                "included-outcome-unproven"
            } else {
                "applied"
            }),
        ),
        ("header", finalized_object(&found.header)),
    ])
    .render()
}

#[allow(clippy::too_many_arguments)]
fn confirmed(
    chain_id: u64,
    genesis_hex: &str,
    epoch_length: Option<u64>,
    roster_epoch: u64,
    tx_id: &str,
    proof_json: &str,
    finality_json: &str,
    roster_json: &str,
    calls: bool,
) -> Result<String, String> {
    let found = included(
        chain_id,
        genesis_hex,
        epoch_length,
        roster_epoch,
        tx_id,
        proof_json,
        finality_json,
        roster_json,
    )?;
    let call = settled_kind(tx_id, &found.leaf, calls)?;
    Ok(rendered(tx_id, &found, call))
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn confirm_transaction(
    chain_id: u64,
    genesis_hex: String,
    epoch_length: Option<u64>,
    roster_epoch: u64,
    tx_id: String,
    proof_json: String,
    finality_json: String,
    roster_json: String,
) -> Result<String, QcoreError> {
    confirmed(
        chain_id,
        &genesis_hex,
        epoch_length,
        roster_epoch,
        &tx_id,
        &proof_json,
        &finality_json,
        &roster_json,
        false,
    )
    .map_err(err)
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn confirm_inclusion(
    chain_id: u64,
    genesis_hex: String,
    epoch_length: Option<u64>,
    roster_epoch: u64,
    tx_id: String,
    proof_json: String,
    finality_json: String,
    roster_json: String,
) -> Result<String, QcoreError> {
    confirmed(
        chain_id,
        &genesis_hex,
        epoch_length,
        roster_epoch,
        &tx_id,
        &proof_json,
        &finality_json,
        &roster_json,
        true,
    )
    .map_err(err)
}

#[uniffi::export]
pub fn decode_event(leaf_hex: String) -> Result<String, QcoreError> {
    let leaf = from_hex(&leaf_hex).map_err(err)?;
    let event = qcore::finality::decode_event(&leaf).map_err(err)?;
    Ok(object(vec![
        ("contract", Json::str(event.contract)),
        ("selector", Json::str(to_hex(&event.selector))),
        ("data", Json::str(to_hex(&event.data))),
    ])
    .render())
}

#[uniffi::export]
pub fn signing_summary(
    kind: String,
    chain_id: u64,
    target: String,
    amount: String,
    fee: String,
    asset_issuer: String,
) -> Result<String, QcoreError> {
    let fee = parse_fee(&fee)?;
    let shown = qcore::shown(&target);
    let line = match kind.as_str() {
        "transfer" => format!("Send {} Quon to {shown}", parse_amount(&amount)?),
        "payable" => format!("Pay {} Quon to contract {shown}", parse_amount(&amount)?),
        "asset" => format!(
            "Pay {} of the asset issued by {} to contract {shown}",
            parse_amount(&amount)?,
            qcore::shown(&asset_issuer)
        ),
        "call" => format!("Call contract {shown}"),
        "register" => "Register this account key on chain".to_string(),
        _ => return Err(err("the vault signs only a transfer, a call, a payable call, an asset call or a key registration")),
    };
    let network = match chain_name_of(chain_id) {
        "" => format!("chain {chain_id}"),
        name => name.to_string(),
    };
    let warning = if chain_id == qcore::MAINNET_CHAIN_ID {
        "\nMainnet, this moves real value"
    } else {
        ""
    };
    Ok(format!(
        "{line}\nNetwork fee {fee} Quon\nOn {network}{warning}"
    ))
}

pub const SEED_ALIAS_MAX: usize = 64;

#[uniffi::export]
pub fn check_seed_alias(alias: String) -> Result<(), QcoreError> {
    let fits = !alias.is_empty()
        && alias.len() <= SEED_ALIAS_MAX
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if fits {
        Ok(())
    } else {
        Err(err(
            "a seed alias is one to sixty four ascii letters, digits, dots, underscores or hyphens",
        ))
    }
}

#[derive(uniffi::Object)]
pub struct SeedHandle {
    seed: Mutex<Option<Zeroizing<[u8; SEED_LEN]>>>,
}

impl SeedHandle {
    fn holding(seed: Zeroizing<[u8; SEED_LEN]>) -> Arc<Self> {
        Arc::new(SeedHandle {
            seed: Mutex::new(Some(seed)),
        })
    }

    fn with_seed<T>(
        &self,
        use_seed: impl FnOnce(&[u8; SEED_LEN]) -> Result<T, QcoreError>,
    ) -> Result<T, QcoreError> {
        match lock(&self.seed).as_ref() {
            Some(seed) => use_seed(seed),
            None => Err(err("this seed has been forgotten")),
        }
    }
}

#[uniffi::export]
impl SeedHandle {
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, QcoreError> {
        Ok(Self::holding(fresh_seed()?))
    }

    #[uniffi::constructor]
    pub fn from_seed_bytes(seed: Vec<u8>) -> Result<Arc<Self>, QcoreError> {
        Ok(Self::holding(parse_seed(seed)?))
    }

    #[uniffi::constructor]
    pub fn from_phrase_bytes(phrase: Vec<u8>) -> Result<Arc<Self>, QcoreError> {
        Ok(Self::holding(seed_from_phrase(phrase)?))
    }

    pub fn seed_bytes(&self) -> Result<Vec<u8>, QcoreError> {
        self.with_seed(|seed| Ok(seed.to_vec()))
    }

    pub fn phrase_bytes(&self) -> Result<Vec<u8>, QcoreError> {
        self.with_seed(|seed| Ok(phrase_from(seed)))
    }

    pub fn address(&self, index: u64) -> Result<String, QcoreError> {
        self.with_seed(|seed| Ok(qcore::account_address(seed, index)))
    }

    pub fn forget(&self) {
        lock(&self.seed).take();
    }

    pub fn is_forgotten(&self) -> bool {
        lock(&self.seed).is_none()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_transfer(
        &self,
        session: Arc<SigningSession>,
        index: u64,
        to: String,
        amount: String,
        nonce: u64,
        fee: String,
        chain_id: u64,
        valid_until: u64,
        head: u64,
        genesis_hex: String,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        let genesis = parse_genesis(&genesis_hex).map_err(err)?;
        let net = Network { chain_id, genesis };
        self.with_seed(|seed| {
            session.signing(
                net,
                &qcore::account_address(seed, index),
                Some(&to),
                nonce,
                valid_until,
                head,
                || {
                    transfer_with(
                        seed,
                        index,
                        &to,
                        &amount,
                        nonce,
                        &fee,
                        chain_id,
                        valid_until,
                        head,
                        &genesis,
                    )
                },
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_call(
        &self,
        session: Arc<SigningSession>,
        index: u64,
        target: String,
        args_hex: String,
        nonce: u64,
        meter_limit: u64,
        fee: String,
        chain_id: u64,
        valid_until: u64,
        transfer_fee: String,
        head: u64,
        genesis_hex: String,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        let genesis = parse_genesis(&genesis_hex).map_err(err)?;
        let net = Network { chain_id, genesis };
        self.with_seed(|seed| {
            session.signing(
                net,
                &qcore::account_address(seed, index),
                Some(&target),
                nonce,
                valid_until,
                head,
                || {
                    call_with(
                        seed,
                        index,
                        &target,
                        &args_hex,
                        nonce,
                        meter_limit,
                        &fee,
                        chain_id,
                        valid_until,
                        &transfer_fee,
                        head,
                        &genesis,
                    )
                },
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_register(
        &self,
        session: Arc<SigningSession>,
        index: u64,
        nonce: u64,
        fee: String,
        chain_id: u64,
        valid_until: u64,
        head: u64,
        genesis_hex: String,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        let genesis = parse_genesis(&genesis_hex).map_err(err)?;
        let net = Network { chain_id, genesis };
        self.with_seed(|seed| {
            session.signing(
                net,
                &qcore::account_address(seed, index),
                None,
                nonce,
                valid_until,
                head,
                || {
                    register_with(
                        seed,
                        index,
                        nonce,
                        &fee,
                        chain_id,
                        valid_until,
                        head,
                        &genesis,
                    )
                },
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_payable_call(
        &self,
        session: Arc<SigningSession>,
        index: u64,
        target: String,
        args_hex: String,
        nonce: u64,
        meter_limit: u64,
        fee: String,
        value: String,
        chain_id: u64,
        valid_until: u64,
        transfer_fee: String,
        head: u64,
        genesis_hex: String,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        let genesis = parse_genesis(&genesis_hex).map_err(err)?;
        let net = Network { chain_id, genesis };
        self.with_seed(|seed| {
            session.signing(
                net,
                &qcore::account_address(seed, index),
                Some(&target),
                nonce,
                valid_until,
                head,
                || {
                    payable_call_with(
                        seed,
                        index,
                        &target,
                        &args_hex,
                        nonce,
                        meter_limit,
                        &fee,
                        &value,
                        chain_id,
                        valid_until,
                        &transfer_fee,
                        head,
                        &genesis,
                    )
                },
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_asset_call(
        &self,
        session: Arc<SigningSession>,
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
        transfer_fee: String,
        head: u64,
        genesis_hex: String,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        let genesis = parse_genesis(&genesis_hex).map_err(err)?;
        let net = Network { chain_id, genesis };
        self.with_seed(|seed| {
            session.signing(
                net,
                &qcore::account_address(seed, index),
                Some(&target),
                nonce,
                valid_until,
                head,
                || {
                    asset_call_with(
                        seed,
                        index,
                        &target,
                        &args_hex,
                        &asset_issuer,
                        &amount,
                        nonce,
                        meter_limit,
                        &fee,
                        chain_id,
                        valid_until,
                        &transfer_fee,
                        head,
                        &genesis,
                    )
                },
            )
        })
    }
}

const SAVED_STATE_MAX: usize = 1 << 20;

const MANIFEST_MAX: usize = 3 << 19;

const NONCE_ACCOUNTS_MAX: usize = 4096;

const NONCE_KEY_MAX: usize = 128;

const NONCE_SLOTS_MAX: usize = 16_384;

const NONCE_STATE_VERSION: u64 = 3;

const MANIFEST_HEAD: &str = "quantova nonce manifest 3";

const WRITER_LEN: usize = 16;

const BOOT_MAX: usize = 64;

const SETTLE_BLOCKS: u64 = qcore::MAX_VALIDITY_BLOCKS;

const CHAIN_BLOCKS_PER_SEC: u64 = qcore::TESTNET_BLOCKS_PER_SEC;

const SETTLE_START_AGE_SECS: u64 = 300;

const SETTLE_SLACK_BLOCKS: u64 = SETTLE_START_AGE_SECS * qcore::HEAD_BLOCKS_PER_SEC;

const SETTLE_SPAN: u64 = SETTLE_BLOCKS + SETTLE_SLACK_BLOCKS;

const SETTLE_SECS: u64 =
    qcore::MAX_VALIDITY_BLOCKS.div_ceil(CHAIN_BLOCKS_PER_SEC) + SETTLE_START_AGE_SECS;

const SETTLE_DRIFT_SECS: u64 = 120;

const TOO_MANY_ACCOUNTS: &str = "the nonce state already keeps 4096 accounts, the most it may keep, so no new account is tracked until the nonce state of one is reset";

const TOO_MANY_SLOTS: &str = "this account already keeps 16384 nonces that are signed or reserved and not yet accepted, the most its saved state may keep, record the outcome of earlier nonces or reset its nonce state";

const KEY_OUT_OF_RANGE: &str =
    "a nonce key is one to 128 printable ascii characters with no space or control character";

const ACCOUNT_MALFORMED: &str =
    "a nonce account is a chain id, the genesis hash of that network and a nonce key";

const ACCOUNT_NOT_SLOTTED: &str = "no nonce slot was ever reserved for this account, so a signature or an outcome is not recorded for it, reserve a slot first";

const STATE_TOO_LARGE: &str =
    "the saved nonce state of an account may take at most 1 MiB, so nothing was signed";

const MANIFEST_TOO_LARGE: &str =
    "the saved nonce manifest may take at most 1.5 MiB, so nothing was signed";

const MANIFEST_DAMAGED: &str = "the saved nonce manifest is missing, damaged, in an earlier format or sealed by a device key that is gone, so no account signs until the nonce state of every account is reset after authenticating";

const STATE_WITHOUT_MANIFEST: &str = "saved nonce state was found without its manifest or in the earlier format that named no chain, so it is refused and no account signs until the nonce state of every account is reset after authenticating";

const TOO_MANY_SAVED: &str = "the saved nonce manifest lists more than 4096 accounts, so no account signs until the nonce state of every account is reset after authenticating";

const EARLIER_FORMAT: &str =
    "the saved nonce state is in the earlier format that named no chain, so it is refused";

const WHOLE_STATE_BLOCKED: &str =
    "the whole saved nonce state is blocked, reset the nonce state of every account";

const NO_PINNED_ROSTER: &str = "SETTLING no validator roster is pinned for this network, so a roster given by the app is not trusted to carry the settling wait, acknowledge the imported history after authenticating instead";

const NOT_MAINNET: &str = "only an account on the mainnet chain takes a mainnet acknowledgement";

const MAINNET_NOT_ACKNOWLEDGED: &str = "this account is on mainnet, where a transaction moves real value, and mainnet was not acknowledged on this device after authenticating, so the vault does not sign";

const NO_DEVICE_CLOCK: &str = "SETTLING the device gave no reading of the clock that counts time since it started, so the settling wait cannot be measured and the vault does not sign for this account";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Network {
    chain_id: u64,
    genesis: [u8; 32],
}

impl Network {
    fn of(chain_id: u64, genesis_hex: &str) -> Result<Network, String> {
        Ok(Network {
            chain_id,
            genesis: parse_genesis(genesis_hex)?,
        })
    }

    fn label(&self) -> String {
        format!("{}:{}", self.chain_id, to_hex(&self.genesis))
    }
}

fn account_name(net: &Network, key: &str) -> String {
    format!("{}:{key}", net.label())
}

fn parse_network(text: &str) -> Option<Network> {
    let (chain, genesis) = text.split_once(':')?;
    let lower = genesis
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !lower {
        return None;
    }
    Network::of(decimal_text(chain)?, genesis).ok()
}

fn check_nonce_key(key: &str) -> Result<(), String> {
    let printable = key.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if key.is_empty() || key.len() > NONCE_KEY_MAX || !printable {
        return Err(KEY_OUT_OF_RANGE.to_string());
    }
    Ok(())
}

fn split_network(name: &str) -> Option<(&str, &str)> {
    let first = name.find(':')?;
    let second = first + 1 + name[first + 1..].find(':')?;
    Some((&name[..second], &name[second + 1..]))
}

fn valid_network(network: &str) -> bool {
    parse_network(network).is_some()
}

fn split_account(account: &str) -> Option<(Network, &str)> {
    let (net, key) = split_network(account)?;
    let net = parse_network(net)?;
    check_nonce_key(key).ok()?;
    Some((net, key))
}

fn decimal_text(text: &str) -> Option<u64> {
    qcore::canonical_decimal(text).and_then(|n| u64::try_from(n).ok())
}

fn decimal(value: Option<&Json>) -> Option<u64> {
    value.and_then(Json::as_str).and_then(decimal_text)
}

fn valid_writer(text: &str) -> bool {
    text.len() == WRITER_LEN && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_boot(text: &str) -> bool {
    !text.is_empty() && text.len() <= BOOT_MAX && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn new_writer() -> Result<String, String> {
    let random = qcore::generate_seed()?;
    Ok(to_hex(&random[..WRITER_LEN / 2]))
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Nonces {
    next: Option<u64>,
    held: BTreeMap<u64, bool>,
    reserved: BTreeSet<u64>,
}

impl Nonces {
    fn slot(&mut self, reported: u64, expected: Option<u64>, order: bool) -> Result<u64, String> {
        if let Some(exp) = expected {
            if exp != reported {
                return Err(format!(
                    "the gateway reported nonce {reported} but you expected {exp}, the chain admits only the nonce the account has reached, refusing to sign"
                ));
            }
        }
        if expected.is_none() {
            if let Some(local) = self.next.filter(|local| reported < *local) {
                return Err(format!(
                    "the gateway reports nonce {reported} below the {local} this session already reached, a transaction signed here may still land at that nonce, so a second one is not signed there, pass the expected nonce to sign at {reported} on purpose"
                ));
            }
        }
        self.held
            .retain(|slot, accepted| !(*accepted && *slot < reported));
        if expected.is_some() {
            self.held.retain(|slot, _| *slot > reported);
        } else {
            if order {
                match self.next {
                    Some(local) if reported > local => {
                        return Err(format!(
                            "the gateway reports order nonce {reported} above the {local} this client tracked, refusing to sign an order that stays valid until the contract reaches that nonce, pass the expected order nonce to sign at it"
                        ));
                    }
                    None if reported > 0 => {
                        return Err(format!(
                            "this signing session has not tracked the order nonce yet and the gateway reports {reported}, pass the expected order nonce or restore a saved session before signing"
                        ));
                    }
                    _ => {}
                }
            }
            if self.held.contains_key(&reported) {
                return Err(format!(
                    "a transaction was already signed for nonce {reported} in this session and was not superseded, one nonce carries one signature, so if it never landed pass that nonce explicitly to sign at it again"
                ));
            }
            if let Some((&stale, _)) = self
                .held
                .iter()
                .find(|(slot, accepted)| **slot < reported && !**accepted)
            {
                return Err(format!(
                    "a transaction signed at nonce {stale} in this session was not accepted, yet the gateway now reports nonce {reported} past it, check whether it landed, then pass nonce {reported} explicitly to sign at it"
                ));
            }
        }
        if !self.reserved.insert(reported) && expected.is_none() {
            return Err(format!(
                "nonce {reported} is already reserved by a signing in progress in this session, finish or release it before reserving it again"
            ));
        }
        self.next = Some(self.next.map_or(reported, |local| local.max(reported)));
        Ok(reported)
    }

    fn signed(&mut self, slot: u64) {
        self.reserved.remove(&slot);
        self.held.insert(slot, false);
    }

    fn accepted(&mut self, slot: u64) {
        self.held.insert(slot, true);
        let after = slot.saturating_add(1);
        self.next = Some(self.next.map_or(after, |local| local.max(after)));
        self.prune();
    }

    fn prune(&mut self) {
        if let Some(next) = self.next {
            let floor = next.saturating_sub(1);
            self.held
                .retain(|slot, accepted| !(*accepted && *slot < floor));
        }
    }

    fn slots(&self) -> usize {
        self.held.len()
            + self
                .reserved
                .iter()
                .filter(|slot| !self.held.contains_key(slot))
                .count()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Start {
    height: u64,
    time: u64,
    boot: String,
    at: u64,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Settle {
    seen: Option<u64>,
    start: Option<Start>,
}

impl Settle {
    fn after(seen: Option<u64>) -> Settle {
        Settle { seen, start: None }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Floor {
    height: u64,
    time: u64,
}

#[derive(Debug, Default)]
struct Account {
    net: Network,
    key: String,
    nonces: Nonces,
    settle: Option<Settle>,
    known: Option<u64>,
    floor: Option<Floor>,
    mainnet: bool,
    seen: Option<(u64, String)>,
    text: Option<u64>,
    blocked: Option<String>,
}

fn text_hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

impl Account {
    fn new(net: Network, key: &str) -> Account {
        Account {
            net,
            key: key.to_string(),
            ..Account::default()
        }
    }

    fn settling_from_scratch(net: Network, key: &str) -> Account {
        Account {
            settle: Some(Settle::default()),
            ..Account::new(net, key)
        }
    }
}

#[derive(Debug)]
struct SavedAccount {
    net: Network,
    key: String,
    generation: u64,
    writer: String,
    settle: Option<Settle>,
    known: Option<u64>,
    floor: Option<Floor>,
    mainnet: bool,
    nonces: Nonces,
}

impl SavedAccount {
    fn into_nonces(self, own: bool) -> Nonces {
        let mut nonces = self.nonces;
        if !own {
            for slot in std::mem::take(&mut nonces.reserved) {
                nonces.held.entry(slot).or_insert(false);
            }
        }
        nonces
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Listed {
    generation: u64,
    writer: String,
    settling: bool,
    prior: Option<(u64, String)>,
}

fn parse_slots(list: &[Json]) -> Result<Vec<u64>, String> {
    list.iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(decimal_text)
                .ok_or_else(|| "a saved reserved nonce is not a whole number".to_string())
        })
        .collect()
}

fn optional_decimal(doc: &Json, field: &str, what: &str) -> Result<Option<u64>, String> {
    match doc.get(field) {
        None => Ok(None),
        Some(value) => decimal(Some(value))
            .map(Some)
            .ok_or_else(|| format!("the saved {what} is not a whole number")),
    }
}

fn parse_settle(value: &Json) -> Result<Settle, String> {
    let seen = optional_decimal(value, "seen", "settling nonce")?;
    let start = match value.get("start") {
        None => None,
        Some(start) => {
            let height = decimal(start.get("height"))
                .ok_or_else(|| "the saved settling height is not a whole number".to_string())?;
            let time = decimal(start.get("time"))
                .ok_or_else(|| "the saved settling time is not a whole number".to_string())?;
            let at = decimal(start.get("at"))
                .ok_or_else(|| "the saved settling uptime is not a whole number".to_string())?;
            let boot = start
                .get("boot")
                .and_then(Json::as_str)
                .filter(|boot| valid_boot(boot))
                .ok_or_else(|| "the saved settling boot is malformed".to_string())?;
            Some(Start {
                height,
                time,
                boot: boot.to_string(),
                at,
            })
        }
    };
    Ok(Settle { seen, start })
}

fn parse_saved(text: &str) -> Result<SavedAccount, String> {
    if text.len() > SAVED_STATE_MAX {
        return Err("the saved nonce state is too large".to_string());
    }
    let doc = qcore::json::parse(text)?;
    match doc.get("version").and_then(Json::as_u64) {
        Some(NONCE_STATE_VERSION) => {}
        Some(1) => return Err(EARLIER_FORMAT.to_string()),
        _ => return Err("the saved nonce state names no version this client reads".to_string()),
    }
    let chain_id = decimal(doc.get("chain_id"))
        .ok_or_else(|| "the saved nonce state names no chain".to_string())?;
    let genesis = doc
        .get("genesis")
        .and_then(Json::as_str)
        .ok_or_else(|| "the saved nonce state names no genesis".to_string())?;
    let net = parse_network(&format!("{chain_id}:{genesis}"))
        .ok_or_else(|| "the saved nonce state names no genesis".to_string())?;
    let key = doc
        .get("key")
        .and_then(Json::as_str)
        .ok_or_else(|| "the saved nonce state names no key".to_string())?;
    check_nonce_key(key)?;
    let generation = decimal(doc.get("generation"))
        .ok_or_else(|| "the saved nonce state names no generation".to_string())?;
    let writer = doc
        .get("writer")
        .and_then(Json::as_str)
        .filter(|writer| valid_writer(writer))
        .ok_or_else(|| "the saved nonce state names no writer".to_string())?;
    let next = optional_decimal(&doc, "next", "next nonce")?;
    let known = optional_decimal(&doc, "known", "known nonce")?;
    let list = doc
        .get("held")
        .and_then(Json::as_array)
        .ok_or_else(|| "the saved nonce state has no held list".to_string())?;
    let reserved_list = match doc.get("reserved") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .ok_or_else(|| "the saved reserved nonces are not a list".to_string())?,
    };
    if list.len() + reserved_list.len() > NONCE_SLOTS_MAX {
        return Err(TOO_MANY_SLOTS.to_string());
    }
    let mut held = BTreeMap::new();
    for entry in list {
        let slot = decimal(entry.get("slot"))
            .ok_or_else(|| "a saved held nonce is not a whole number".to_string())?;
        let accepted = entry
            .get("accepted")
            .and_then(Json::as_bool)
            .ok_or_else(|| "a saved held nonce has no accepted flag".to_string())?;
        held.insert(slot, accepted);
    }
    let reserved: BTreeSet<u64> = parse_slots(reserved_list)?
        .into_iter()
        .filter(|slot| !held.contains_key(slot))
        .collect();
    let settle = match doc.get("settle") {
        None => None,
        Some(value) => Some(parse_settle(value)?),
    };
    let floor = match doc.get("floor") {
        None => None,
        Some(value) => Some(Floor {
            height: decimal(value.get("height"))
                .ok_or_else(|| "the saved head floor is not a whole number".to_string())?,
            time: decimal(value.get("time"))
                .ok_or_else(|| "the saved head floor time is not a whole number".to_string())?,
        }),
    };
    let mainnet = match doc.get("mainnet") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "the saved mainnet acknowledgement is not a boolean".to_string())?,
    };
    Ok(SavedAccount {
        net,
        key: key.to_string(),
        generation,
        writer: writer.to_string(),
        settle,
        known,
        floor,
        mainnet,
        nonces: Nonces {
            next,
            held,
            reserved,
        },
    })
}

fn render_settle(settle: &Settle) -> Json {
    let mut fields = Vec::new();
    if let Some(seen) = settle.seen {
        fields.push(("seen", Json::str(seen.to_string())));
    }
    if let Some(start) = &settle.start {
        fields.push((
            "start",
            object(vec![
                ("height", Json::str(start.height.to_string())),
                ("time", Json::str(start.time.to_string())),
                ("boot", Json::str(start.boot.clone())),
                ("at", Json::str(start.at.to_string())),
            ]),
        ));
    }
    object(fields)
}

struct Record<'a> {
    net: Network,
    key: &'a str,
    nonces: &'a Nonces,
    settle: Option<&'a Settle>,
    known: Option<u64>,
    floor: Option<Floor>,
    mainnet: bool,
}

impl<'a> Record<'a> {
    fn of(account: &'a Account) -> Record<'a> {
        Record {
            net: account.net,
            key: &account.key,
            nonces: &account.nonces,
            settle: account.settle.as_ref(),
            known: account.known,
            floor: account.floor,
            mainnet: account.mainnet,
        }
    }

    fn render(&self, generation: u64, writer: &str) -> String {
        let held: Vec<Json> = self
            .nonces
            .held
            .iter()
            .map(|(slot, accepted)| {
                object(vec![
                    ("slot", Json::str(slot.to_string())),
                    ("accepted", Json::Bool(*accepted)),
                ])
            })
            .collect();
        let reserved: Vec<Json> = self
            .nonces
            .reserved
            .iter()
            .filter(|slot| !self.nonces.held.contains_key(slot))
            .map(|slot| Json::str(slot.to_string()))
            .collect();
        let mut fields = vec![
            ("version", Json::Int(NONCE_STATE_VERSION)),
            ("chain_id", Json::str(self.net.chain_id.to_string())),
            ("genesis", Json::str(to_hex(&self.net.genesis))),
            ("key", Json::str(self.key)),
            ("generation", Json::str(generation.to_string())),
            ("writer", Json::str(writer)),
            ("held", Json::Array(held)),
            ("reserved", Json::Array(reserved)),
        ];
        if let Some(next) = self.nonces.next {
            fields.push(("next", Json::str(next.to_string())));
        }
        if let Some(known) = self.known {
            fields.push(("known", Json::str(known.to_string())));
        }
        if let Some(settle) = self.settle {
            fields.push(("settle", render_settle(settle)));
        }
        if let Some(floor) = self.floor {
            fields.push((
                "floor",
                object(vec![
                    ("height", Json::str(floor.height.to_string())),
                    ("time", Json::str(floor.time.to_string())),
                ]),
            ));
        }
        if self.mainnet {
            fields.push(("mainnet", Json::Bool(true)));
        }
        object(fields).render()
    }
}

fn manifest_entries<'a>(
    listed: &'a BTreeMap<String, Listed>,
    over: &'a BTreeMap<String, Listed>,
) -> Vec<(&'a str, &'a Listed)> {
    let mut entries: Vec<(&str, &Listed)> = listed
        .iter()
        .filter(|(name, _)| !over.contains_key(*name))
        .chain(over.iter())
        .map(|(name, listed)| (name.as_str(), listed))
        .collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
    entries
}

fn render_manifest(entries: &[(&str, &Listed)]) -> String {
    use std::fmt::Write;
    let mut writers: Vec<&str> = Vec::new();
    let mut index: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, listed) in entries {
        let prior = listed.prior.as_ref().map(|(_, writer)| writer.as_str());
        for writer in std::iter::once(listed.writer.as_str()).chain(prior) {
            if !index.contains_key(writer) {
                index.insert(writer, writers.len());
                writers.push(writer);
            }
        }
    }
    let mut out = String::with_capacity(64 + 24 * writers.len() + 48 * entries.len());
    out.push_str(MANIFEST_HEAD);
    out.push('\n');
    for writer in &writers {
        let _ = writeln!(out, "w {writer}");
    }
    let mut network: Option<&str> = None;
    for (name, listed) in entries {
        let Some((net, key)) = split_network(name) else {
            continue;
        };
        if network != Some(net) {
            let _ = writeln!(out, "n {net}");
            network = Some(net);
        }
        let _ = write!(
            out,
            "{} {} {} ",
            listed.generation,
            index[listed.writer.as_str()],
            u8::from(listed.settling)
        );
        match &listed.prior {
            Some((generation, writer)) => {
                let _ = write!(out, "{generation} {} ", index[writer.as_str()]);
            }
            None => out.push_str("- - "),
        }
        out.push_str(key);
        out.push('\n');
    }
    out
}

fn parse_manifest(text: &str) -> Result<BTreeMap<String, Listed>, String> {
    let damaged = || MANIFEST_DAMAGED.to_string();
    if text.len() > MANIFEST_MAX {
        return Err(damaged());
    }
    let body = text.strip_suffix('\n').ok_or_else(damaged)?;
    let mut lines = body.split('\n');
    if lines.next() != Some(MANIFEST_HEAD) {
        return Err(damaged());
    }
    let mut writers: Vec<&str> = Vec::new();
    let mut network: Option<&str> = None;
    let mut out = BTreeMap::new();
    let writer_at = |writers: &Vec<&str>, token: &str| -> Option<String> {
        let at = usize::try_from(decimal_text(token)?).ok()?;
        writers.get(at).map(|writer| writer.to_string())
    };
    for line in lines {
        if let Some(writer) = line.strip_prefix("w ") {
            if network.is_some() || !valid_writer(writer) || writers.contains(&writer) {
                return Err(damaged());
            }
            writers.push(writer);
            continue;
        }
        if let Some(net) = line.strip_prefix("n ") {
            if !valid_network(net) {
                return Err(damaged());
            }
            network = Some(net);
            continue;
        }
        let net = network.ok_or_else(damaged)?;
        let fields: Vec<&str> = line.splitn(6, ' ').collect();
        let [generation, writer, settling, prior_generation, prior_writer, key] = fields[..] else {
            return Err(damaged());
        };
        let generation = decimal_text(generation).ok_or_else(damaged)?;
        let writer = writer_at(&writers, writer).ok_or_else(damaged)?;
        let settling = match settling {
            "0" => false,
            "1" => true,
            _ => return Err(damaged()),
        };
        let prior = match (prior_generation, prior_writer) {
            ("-", "-") => None,
            (generation, writer) => Some((
                decimal_text(generation).ok_or_else(damaged)?,
                writer_at(&writers, writer).ok_or_else(damaged)?,
            )),
        };
        let name = format!("{net}:{key}");
        if split_account(&name).is_none() {
            return Err(damaged());
        }
        let listed = Listed {
            generation,
            writer,
            settling,
            prior,
        };
        if out.insert(name, listed).is_some() {
            return Err(damaged());
        }
        if out.len() > NONCE_ACCOUNTS_MAX {
            return Err(TOO_MANY_SAVED.to_string());
        }
    }
    Ok(out)
}

#[derive(Debug)]
enum Found {
    Committed(SavedAccount),
    Prior(SavedAccount),
    Missing,
}

fn check_record(
    name: &str,
    net: Network,
    key: &str,
    listed: &Listed,
    present: bool,
    text: Option<&str>,
) -> Result<Found, String> {
    if !present && listed.prior.is_none() {
        return Ok(Found::Missing);
    }
    let Some(text) = text else {
        return Err(format!(
            "the saved nonce state of {name} is missing or could not be opened, so it does not sign until its nonce state is reset after authenticating"
        ));
    };
    let saved = parse_saved(text).map_err(|reason| {
        format!(
            "the saved nonce state of {name} could not be read ({reason}), so it does not sign until its nonce state is reset after authenticating"
        )
    })?;
    if saved.net != net || saved.key != key {
        return Err(format!(
            "the saved nonce state of {name} belongs to another account, so it does not sign until its nonce state is reset after authenticating"
        ));
    }
    let written = (saved.generation, saved.writer.clone());
    if written == (listed.generation, listed.writer.clone()) {
        if saved.settle.is_some() != listed.settling {
            return Err(format!(
                "the saved nonce state of {name} is not the write its manifest records, so it does not sign until its nonce state is reset after authenticating"
            ));
        }
        return Ok(Found::Committed(saved));
    }
    if listed.prior.as_ref() == Some(&written) {
        return Ok(Found::Prior(saved));
    }
    if saved.generation < listed.generation {
        return Err(format!(
            "the saved nonce state of {name} is older than its manifest records, so it does not sign until its nonce state is reset after authenticating"
        ));
    }
    Err(format!(
        "the saved nonce state of {name} is not the write its manifest records, so it does not sign until its nonce state is reset after authenticating"
    ))
}

#[derive(uniffi::Record)]
pub struct NonceStored {
    pub manifest_present: bool,
    pub manifest: Option<String>,
    pub manifest_tag: Option<String>,
    pub records_present: bool,
    pub account: Option<String>,
    pub record_present: bool,
    pub record: Option<String>,
    pub boot: Option<String>,
    pub uptime_ms: u64,
}

#[derive(uniffi::Record)]
pub struct NonceRecordWrite {
    pub account: String,
    pub generation: u64,
    pub state: String,
}

#[derive(uniffi::Record)]
pub struct NonceBatch {
    pub manifest: String,
    pub records: Vec<NonceRecordWrite>,
    pub rotate: bool,
}

#[derive(uniffi::Record)]
pub struct NonceReset {
    pub removed: Vec<String>,
    pub manifest: String,
}

#[derive(uniffi::Record, Debug, PartialEq)]
pub struct NonceSettle {
    pub settled: bool,
    pub blocks_left: u64,
    pub secs_left: u64,
}

impl NonceSettle {
    fn done() -> NonceSettle {
        NonceSettle {
            settled: true,
            blocks_left: 0,
            secs_left: 0,
        }
    }

    fn waiting(blocks_left: u64, secs_left: u64) -> NonceSettle {
        NonceSettle {
            settled: false,
            blocks_left,
            secs_left,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Certified {
    height: u64,
    time: u64,
}

#[derive(Debug, Default)]
struct NonceLedger {
    accounts: BTreeMap<String, Account>,
    listed: BTreeMap<String, Listed>,
    dirty: BTreeSet<String>,
    blocked_all: Option<String>,
    writer: Option<String>,
    high: u64,
    manifest_tag: Option<String>,
    rotate: bool,
    pending: Option<Vec<(String, Listed, u64)>>,
    uptime: Option<(String, u64)>,
    wall: Option<u64>,
}

static NONCE_LEDGER: Mutex<NonceLedger> = Mutex::new(NonceLedger {
    accounts: BTreeMap::new(),
    listed: BTreeMap::new(),
    dirty: BTreeSet::new(),
    blocked_all: None,
    writer: None,
    high: 0,
    manifest_tag: None,
    rotate: false,
    pending: None,
    uptime: None,
    wall: None,
});

fn chain_name_of(chain_id: u64) -> &'static str {
    if qcore::chain_id_from_name(qcore::TESTNET_CHAIN_NAME) == chain_id {
        qcore::TESTNET_CHAIN_NAME
    } else if chain_id == qcore::MAINNET_CHAIN_ID {
        qcore::MAINNET_CHAIN_NAME
    } else {
        ""
    }
}

fn vault_clock(chain_id: u64) -> Option<qcore::ChainClock> {
    match chain_name_of(chain_id) {
        "" => Some(qcore::ChainClock {
            genesis_secs: qcore::GENESIS_FLOOR_SECS,
            blocks_per_sec: qcore::HEAD_BLOCKS_PER_SEC,
        }),
        name => qcore::known_clock(name),
    }
}

fn vault_deadline(
    chain_id: u64,
    valid_until: u64,
    head: u64,
    wall: u64,
    floor: Option<Floor>,
) -> Result<(), String> {
    qcore::bounded_valid_until_for(
        vault_clock(chain_id).as_ref(),
        false,
        head,
        wall,
        floor.map(|floor| floor.height),
        floor.map_or(0, |floor| wall.saturating_sub(floor.time)),
    )?;
    qcore::check_valid_until(valid_until, head)
}

fn elapsed_secs(start: &Start, uptime: Option<&(String, u64)>) -> u64 {
    match uptime {
        Some((boot, now)) if *boot == start.boot && *now >= start.at => (now - start.at) / 1000,
        _ => 0,
    }
}

fn settling_refusal(
    key: &str,
    chain_id: u64,
    settle: &Settle,
    uptime: Option<&(String, u64)>,
) -> String {
    match &settle.start {
        None => format!(
            "SETTLING the account {key} on chain {chain_id} has history this device did not sign, from before it kept its nonces or from another device since, so the vault signs for it only after settleHistory is given a fresh verified finality certificate to start the wait, then one at least {} blocks higher once {SETTLE_SECS} seconds have passed on this device, or once that history is acknowledged after authenticating",
            SETTLE_SPAN + 1
        ),
        Some(start) => format!(
            "SETTLING the account {key} on chain {chain_id} has history this device did not sign, so the vault signs for it after settleHistory is given a verified finality certificate at height {} or later and {} more seconds have passed on this device, or once that history is acknowledged after authenticating",
            start.height.saturating_add(SETTLE_SPAN).saturating_add(1),
            SETTLE_SECS.saturating_sub(elapsed_secs(start, uptime))
        ),
    }
}

impl NonceLedger {
    fn wall(&self) -> u64 {
        self.wall.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0)
        })
    }

    fn writer(&mut self) -> Result<String, String> {
        if let Some(writer) = &self.writer {
            return Ok(writer.clone());
        }
        let writer = new_writer()?;
        self.writer = Some(writer.clone());
        Ok(writer)
    }

    fn usable(&self, name: &str) -> Result<Option<&Account>, String> {
        if let Some(reason) = &self.blocked_all {
            return Err(reason.clone());
        }
        match self.accounts.get(name) {
            Some(account) => match &account.blocked {
                Some(reason) => Err(reason.clone()),
                None => Ok(Some(account)),
            },
            None => Ok(None),
        }
    }

    fn tracked(&self) -> usize {
        self.listed.len()
            + self
                .accounts
                .keys()
                .filter(|name| !self.listed.contains_key(*name))
                .count()
    }

    fn slot(
        &mut self,
        net: Network,
        key: &str,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, String> {
        check_nonce_key(key)?;
        let name = account_name(&net, key);
        let created = self.usable(&name)?.is_none();
        if created {
            if self.listed.contains_key(&name) {
                return Err(format!(
                    "the saved nonce state of {name} was not read before this slot, so nothing is reserved"
                ));
            }
            if self.tracked() >= NONCE_ACCOUNTS_MAX {
                return Err(TOO_MANY_ACCOUNTS.to_string());
            }
            let mut account = Account::new(net, key);
            if reported > 0 {
                account.settle = Some(Settle::after(Some(reported)));
            } else {
                account.known = Some(0);
            }
            self.accounts.insert(name.clone(), account);
        }
        let Some(account) = self.accounts.get_mut(&name) else {
            return Err(TOO_MANY_ACCOUNTS.to_string());
        };
        let known_before = account.known;
        let mut adopted = false;
        let mut detected = false;
        match account.settle.as_mut() {
            Some(settle) => match settle.seen {
                Some(seen) if reported <= seen => {}
                Some(_) => {
                    settle.seen = Some(reported);
                    settle.start = None;
                    detected = true;
                }
                None => {
                    settle.seen = Some(reported);
                    detected = true;
                }
            },
            None => match account.known {
                None => {
                    account.known = Some(reported);
                    adopted = true;
                }
                Some(known) if reported > known => {
                    account.settle = Some(Settle::after(Some(reported)));
                    detected = true;
                }
                Some(_) => {}
            },
        }
        let before = (account.nonces.slots() >= NONCE_SLOTS_MAX).then(|| account.nonces.clone());
        match account.nonces.slot(reported, expected, order) {
            Ok(out) => {
                if account.nonces.slots() > NONCE_SLOTS_MAX {
                    if let Some(before) = before {
                        account.nonces = before;
                    }
                    account.known = known_before;
                    if created {
                        self.accounts.remove(&name);
                    } else if detected {
                        self.dirty.insert(name);
                    }
                    return Err(TOO_MANY_SLOTS.to_string());
                }
                if adopted {
                    self.rotate = true;
                }
                self.dirty.insert(name);
                Ok(out)
            }
            Err(refused) => {
                account.known = known_before;
                if created {
                    self.accounts.remove(&name);
                } else if detected {
                    self.dirty.insert(name);
                }
                Err(refused)
            }
        }
    }

    fn existing(&mut self, net: Network, key: &str) -> Result<(String, &mut Account), String> {
        check_nonce_key(key)?;
        let name = account_name(&net, key);
        if self.usable(&name)?.is_none() {
            return Err(ACCOUNT_NOT_SLOTTED.to_string());
        }
        match self.accounts.get_mut(&name) {
            Some(account) => Ok((name, account)),
            None => Err(ACCOUNT_NOT_SLOTTED.to_string()),
        }
    }

    fn bounded(account: &mut Account, apply: impl FnOnce(&mut Nonces)) -> Result<(), String> {
        let before = (account.nonces.slots() >= NONCE_SLOTS_MAX).then(|| account.nonces.clone());
        apply(&mut account.nonces);
        if account.nonces.slots() > NONCE_SLOTS_MAX {
            if let Some(before) = before {
                account.nonces = before;
            }
            return Err(TOO_MANY_SLOTS.to_string());
        }
        Ok(())
    }

    fn signed(&mut self, net: Network, key: &str, slot: u64) -> Result<(), String> {
        let (name, account) = self.existing(net, key)?;
        Self::bounded(account, |nonces| nonces.signed(slot))?;
        self.rotate = true;
        self.dirty.insert(name);
        Ok(())
    }

    fn outcome(
        &mut self,
        net: Network,
        key: &str,
        slot: u64,
        accepted: bool,
    ) -> Result<(), String> {
        if !accepted {
            check_nonce_key(key)?;
            return Ok(());
        }
        let (name, account) = self.existing(net, key)?;
        Self::bounded(account, |nonces| nonces.accepted(slot))?;
        self.dirty.insert(name);
        Ok(())
    }

    fn live_mut(&mut self, net: Network, key: &str) -> Option<(String, &mut Account)> {
        if self.blocked_all.is_some() {
            return None;
        }
        let name = account_name(&net, key);
        let account = self.accounts.get_mut(&name)?;
        if account.blocked.is_some() {
            return None;
        }
        Some((name, account))
    }

    fn release(&mut self, net: Network, key: &str, slot: u64) {
        if let Some((name, account)) = self.live_mut(net, key) {
            if account.nonces.reserved.remove(&slot) {
                self.dirty.insert(name);
            }
        }
    }

    fn release_pending(&mut self, net: Network, key: &str) {
        if let Some((name, account)) = self.live_mut(net, key) {
            if !account.nonces.reserved.is_empty() {
                account.nonces.reserved.clear();
                self.dirty.insert(name);
            }
        }
    }

    fn next_nonce(&self, net: Network, key: &str) -> Option<u64> {
        match self.usable(&account_name(&net, key)) {
            Ok(Some(account)) => account.nonces.next,
            _ => None,
        }
    }

    fn is_held(&self, net: Network, key: &str, slot: u64) -> bool {
        match self.usable(&account_name(&net, key)) {
            Ok(Some(account)) => account.nonces.held.contains_key(&slot),
            Ok(None) => false,
            Err(_) => true,
        }
    }

    fn fits_signed(&self, name: &str, nonce: u64) -> Result<(), String> {
        let Some(account) = self.accounts.get(name) else {
            return Ok(());
        };
        let widest = "f".repeat(WRITER_LEN);
        let mut after = account.nonces.clone();
        after.signed(nonce);
        let worst_settle = account.settle.clone().map(|mut settle| {
            settle.seen = Some(u64::MAX);
            settle
        });
        let state = Record {
            nonces: &after,
            settle: worst_settle.as_ref(),
            known: Some(u64::MAX),
            floor: Some(Floor {
                height: u64::MAX,
                time: u64::MAX,
            }),
            mainnet: true,
            ..Record::of(account)
        }
        .render(u64::MAX, &widest);
        if state.len() > SAVED_STATE_MAX {
            return Err(STATE_TOO_LARGE.to_string());
        }
        let mut over = BTreeMap::new();
        over.insert(
            name.to_string(),
            Listed {
                generation: u64::MAX,
                writer: widest.clone(),
                settling: true,
                prior: Some((u64::MAX, "e".repeat(WRITER_LEN))),
            },
        );
        if render_manifest(&manifest_entries(&self.listed, &over)).len() > MANIFEST_MAX {
            return Err(MANIFEST_TOO_LARGE.to_string());
        }
        Ok(())
    }

    fn settle_with(
        &mut self,
        net: Network,
        key: &str,
        certified: Certified,
    ) -> Result<NonceSettle, String> {
        check_nonce_key(key)?;
        let name = account_name(&net, key);
        if self.usable(&name)?.is_none() {
            return Err(ACCOUNT_NOT_SLOTTED.to_string());
        }
        let wall = self.wall();
        let uptime = self.uptime.clone();
        let Some(account) = self.accounts.get_mut(&name) else {
            return Err(ACCOUNT_NOT_SLOTTED.to_string());
        };
        let Some(mut settle) = account.settle.clone() else {
            return Ok(NonceSettle::done());
        };
        let Some((boot, now)) = uptime else {
            return Err(NO_DEVICE_CLOCK.to_string());
        };
        let fresh = |certified: &Certified| {
            if certified.time.saturating_add(SETTLE_START_AGE_SECS) < wall {
                Err(format!(
                    "SETTLING the finality certificate at height {} carries block time {}, more than {SETTLE_START_AGE_SECS} seconds before this device's clock, so it does not start the wait for {key} on chain {}, pass a fresh one",
                    certified.height, certified.time, net.chain_id
                ))
            } else {
                Ok(())
            }
        };
        let begin = |certified: &Certified| Start {
            height: certified.height,
            time: certified.time,
            boot: boot.clone(),
            at: now,
        };
        let Some(mut start) = settle.start.clone() else {
            fresh(&certified)?;
            settle.start = Some(begin(&certified));
            account.settle = Some(settle);
            self.dirty.insert(name);
            return Ok(NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS));
        };
        if start.boot != boot || now < start.at {
            start.boot = boot.clone();
            start.at = now;
        }
        let elapsed = (now - start.at) / 1000;
        let chain_elapsed = certified.time.saturating_sub(start.time);
        if certified.height > start.height
            && chain_elapsed > elapsed.saturating_add(SETTLE_DRIFT_SECS)
        {
            match fresh(&certified) {
                Ok(()) => {
                    settle.start = Some(begin(&certified));
                    account.settle = Some(settle);
                    self.dirty.insert(name);
                    return Ok(NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS));
                }
                Err(stale) => {
                    settle.start = None;
                    account.settle = Some(settle);
                    self.dirty.insert(name);
                    return Err(stale);
                }
            }
        }
        let blocks_left = start
            .height
            .saturating_add(SETTLE_SPAN)
            .saturating_add(1)
            .saturating_sub(certified.height);
        let secs_left = SETTLE_SECS.saturating_sub(elapsed);
        if blocks_left == 0 && secs_left == 0 {
            account.known = match (account.known, settle.seen) {
                (Some(known), Some(seen)) => Some(known.max(seen)),
                (known, seen) => seen.or(known),
            };
            account.settle = None;
            self.dirty.insert(name);
            return Ok(NonceSettle::done());
        }
        if settle.start.as_ref() != Some(&start) {
            settle.start = Some(start);
            account.settle = Some(settle);
            self.dirty.insert(name);
        }
        Ok(NonceSettle::waiting(blocks_left, secs_left))
    }

    fn acknowledge(&mut self, net: Network, key: &str) -> Result<(), String> {
        check_nonce_key(key)?;
        let name = account_name(&net, key);
        if self.usable(&name)?.is_none() {
            if self.listed.contains_key(&name) {
                return Err(format!(
                    "the saved nonce state of {name} was not read before this acknowledgement, so nothing changed"
                ));
            }
            if self.tracked() >= NONCE_ACCOUNTS_MAX {
                return Err(TOO_MANY_ACCOUNTS.to_string());
            }
            self.accounts.insert(name.clone(), Account::new(net, key));
        }
        if let Some(account) = self.accounts.get_mut(&name) {
            account.settle = None;
            account.known = None;
        }
        self.dirty.insert(name);
        Ok(())
    }

    fn acknowledge_mainnet(&mut self, net: Network, key: &str) -> Result<(), String> {
        check_nonce_key(key)?;
        if net.chain_id != qcore::MAINNET_CHAIN_ID {
            return Err(NOT_MAINNET.to_string());
        }
        let name = account_name(&net, key);
        if self.usable(&name)?.is_none() {
            if self.listed.contains_key(&name) {
                return Err(format!(
                    "the saved nonce state of {name} was not read before this acknowledgement, so nothing changed"
                ));
            }
            if self.tracked() >= NONCE_ACCOUNTS_MAX {
                return Err(TOO_MANY_ACCOUNTS.to_string());
            }
            self.accounts
                .insert(name.clone(), Account::settling_from_scratch(net, key));
        }
        if let Some(account) = self.accounts.get_mut(&name) {
            account.mainnet = true;
        }
        self.dirty.insert(name);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn signing(
        &mut self,
        net: Network,
        key: &str,
        nonce: u64,
        valid_until: u64,
        head: u64,
        sign: impl FnOnce() -> Result<String, QcoreError>,
    ) -> Result<String, QcoreError> {
        let name = account_name(&net, key);
        let account = self.usable(&name).map_err(err)?;
        let reserved = account.is_some_and(|account| account.nonces.reserved.contains(&nonce));
        if !reserved {
            return Err(err(format!(
                "the vault signs only at a nonce taken from this signing session, nonce {nonce} of {key} on chain {} was not reserved with slot or was already signed",
                net.chain_id
            )));
        }
        if let Some(settle) = account.and_then(|account| account.settle.as_ref()) {
            return Err(err(settling_refusal(
                key,
                net.chain_id,
                settle,
                self.uptime.as_ref(),
            )));
        }
        if net.chain_id == qcore::MAINNET_CHAIN_ID
            && !account.is_some_and(|account| account.mainnet)
        {
            return Err(err(MAINNET_NOT_ACKNOWLEDGED));
        }
        let wall = self.wall();
        let floor = account.and_then(|account| account.floor);
        vault_deadline(net.chain_id, valid_until, head, wall, floor).map_err(err)?;
        self.fits_signed(&name, nonce).map_err(err)?;
        let signed = sign()?;
        if let Some(account) = self.accounts.get_mut(&name) {
            account.nonces.signed(nonce);
            let after = nonce.saturating_add(1);
            account.known = Some(account.known.map_or(after, |known| known.max(after)));
            if account.floor.is_none_or(|floor| head > floor.height) {
                account.floor = Some(Floor {
                    height: head,
                    time: wall,
                });
            }
        }
        self.rotate = true;
        self.dirty.insert(name);
        Ok(signed)
    }

    fn batch(&mut self) -> Result<Option<NonceBatch>, String> {
        let writer = self.writer()?;
        if self.dirty.is_empty() {
            return Ok(None);
        }
        if let Some(reason) = &self.blocked_all {
            return Err(reason.clone());
        }
        let mut over = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        let mut records = Vec::new();
        let mut generation = self.high;
        for name in &self.dirty {
            let account = self
                .accounts
                .get(name)
                .ok_or_else(|| format!("no nonce state is kept for {name}"))?;
            if let Some(reason) = &account.blocked {
                return Err(reason.clone());
            }
            generation = generation
                .checked_add(1)
                .ok_or_else(|| "the nonce state generation is exhausted".to_string())?;
            let state = Record::of(account).render(generation, &writer);
            if state.len() > SAVED_STATE_MAX {
                return Err(STATE_TOO_LARGE.to_string());
            }
            over.insert(
                name.clone(),
                Listed {
                    generation,
                    writer: writer.clone(),
                    settling: account.settle.is_some(),
                    prior: account.seen.clone(),
                },
            );
            hashes.insert(name.clone(), text_hash(&state));
            records.push(NonceRecordWrite {
                account: name.clone(),
                generation,
                state,
            });
        }
        let manifest = render_manifest(&manifest_entries(&self.listed, &over));
        if manifest.len() > MANIFEST_MAX {
            return Err(MANIFEST_TOO_LARGE.to_string());
        }
        self.high = generation;
        self.pending = Some(
            over.into_iter()
                .map(|(name, listed)| {
                    let hash = hashes.get(&name).copied().unwrap_or_default();
                    (name, listed, hash)
                })
                .collect(),
        );
        Ok(Some(NonceBatch {
            manifest,
            records,
            rotate: self.rotate,
        }))
    }

    fn committed(&mut self, manifest_tag: Option<String>) {
        self.manifest_tag = manifest_tag;
        if let Some(entries) = self.pending.take() {
            for (name, listed, hash) in entries {
                if let Some(account) = self.accounts.get_mut(&name) {
                    account.seen = Some((listed.generation, listed.writer.clone()));
                    account.text = Some(hash);
                }
                self.dirty.remove(&name);
                self.listed.insert(name, listed);
            }
            self.rotate = false;
        }
    }

    fn sync(&mut self, stored: &NonceStored) -> Result<(), String> {
        let me = self.writer()?;
        self.pending = None;
        self.uptime = stored
            .boot
            .as_deref()
            .filter(|boot| valid_boot(boot))
            .map(|boot| (boot.to_string(), stored.uptime_ms));
        let target = match stored.account.as_deref() {
            None => None,
            Some(name) => {
                let (net, key) =
                    split_account(name).ok_or_else(|| ACCOUNT_MALFORMED.to_string())?;
                Some((name.to_string(), net, key.to_string()))
            }
        };
        let unchanged = stored.manifest_present
            && stored.manifest.is_none()
            && self.blocked_all.is_none()
            && stored.manifest_tag.is_some()
            && stored.manifest_tag == self.manifest_tag;
        let parsed = match (stored.manifest_present, stored.manifest.as_deref()) {
            _ if unchanged => Ok(None),
            (false, _) if stored.records_present => Err(STATE_WITHOUT_MANIFEST.to_string()),
            (false, _) => Ok(Some(BTreeMap::new())),
            (true, None) => Err(MANIFEST_DAMAGED.to_string()),
            (true, Some(text)) => parse_manifest(text).map(Some),
        };
        match parsed {
            Ok(None) => {}
            Err(reason) => {
                self.blocked_all = Some(reason);
                self.manifest_tag = None;
            }
            Ok(Some(listed)) => {
                self.manifest_tag = stored.manifest_tag.clone();
                self.blocked_all = None;
                for entry in listed.values() {
                    let prior = entry
                        .prior
                        .as_ref()
                        .map_or(0, |(generation, _)| *generation);
                    self.high = self.high.max(entry.generation).max(prior);
                }
                let gone: Vec<String> = self
                    .accounts
                    .iter()
                    .filter(|(name, account)| account.seen.is_some() && !listed.contains_key(*name))
                    .map(|(name, _)| name.clone())
                    .collect();
                for name in gone {
                    self.accounts.remove(&name);
                    self.dirty.remove(&name);
                }
                self.listed = listed;
            }
        }
        let stale: Vec<String> = self
            .dirty
            .iter()
            .filter(|name| {
                target
                    .as_ref()
                    .is_none_or(|(current, _, _)| current != *name)
            })
            .cloned()
            .collect();
        for name in stale {
            self.dirty.remove(&name);
            if let Some(account) = self.accounts.get_mut(&name) {
                account.seen = None;
            }
        }
        if self.dirty.is_empty() {
            self.rotate = false;
        }
        let Some((name, net, key)) = target else {
            return Ok(());
        };
        if self.blocked_all.is_some() {
            return Ok(());
        }
        let current = stored.record.as_deref().map(text_hash);
        let untouched = self.listed.get(&name).is_some_and(|listed| {
            self.accounts.get(&name).is_some_and(|account| {
                account.blocked.is_none()
                    && current.is_some()
                    && account.text == current
                    && account.seen.as_ref() == Some(&(listed.generation, listed.writer.clone()))
            })
        });
        if untouched {
            return Ok(());
        }
        match self.listed.get(&name).cloned() {
            Some(listed) => {
                let found = check_record(
                    &name,
                    net,
                    &key,
                    &listed,
                    stored.record_present,
                    stored.record.as_deref(),
                );
                let dirty = self.dirty.contains(&name);
                let entry = self
                    .accounts
                    .entry(name.clone())
                    .or_insert_with(|| Account::new(net, &key));
                match found {
                    Err(reason) => {
                        entry.blocked = Some(reason);
                        entry.seen = None;
                        self.dirty.remove(&name);
                    }
                    Ok(Found::Committed(saved)) => {
                        entry.blocked = None;
                        entry.text = current;
                        let written = (listed.generation, listed.writer.clone());
                        if entry.seen.as_ref() != Some(&written) {
                            let own = saved.writer == me;
                            entry.settle = saved.settle.clone();
                            entry.known = saved.known;
                            entry.floor = saved.floor;
                            entry.mainnet = saved.mainnet;
                            entry.nonces = saved.into_nonces(own);
                            entry.seen = Some(written);
                            self.dirty.remove(&name);
                        }
                    }
                    Ok(Found::Prior(saved)) => {
                        entry.blocked = None;
                        let written = (saved.generation, saved.writer.clone());
                        let ours = dirty && entry.seen.as_ref() == Some(&written);
                        entry.text = current;
                        if !ours {
                            let own = saved.writer == me;
                            entry.known = saved.known;
                            entry.floor = saved.floor;
                            entry.mainnet = saved.mainnet;
                            entry.settle = Some(Settle::default());
                            entry.nonces = saved.into_nonces(own);
                            entry.seen = Some(written);
                            self.dirty.insert(name.clone());
                        }
                    }
                    Ok(Found::Missing) => {
                        entry.blocked = None;
                        let ours = dirty && entry.seen.is_none();
                        if !ours {
                            *entry = Account::settling_from_scratch(net, &key);
                            self.dirty.insert(name.clone());
                        }
                    }
                }
            }
            None if stored.record_present => {
                let entry = self
                    .accounts
                    .entry(name.clone())
                    .or_insert_with(|| Account::new(net, &key));
                entry.blocked = Some(format!(
                    "saved nonce state of {name} was found that the manifest does not list, so it does not sign until its nonce state is reset after authenticating"
                ));
                entry.seen = None;
                self.dirty.remove(&name);
            }
            None => {
                if self
                    .accounts
                    .get(&name)
                    .is_some_and(|account| account.blocked.is_some() || account.seen.is_some())
                {
                    self.accounts.remove(&name);
                    self.dirty.remove(&name);
                }
            }
        }
        Ok(())
    }

    fn reset(&mut self, target: Option<(Network, &str)>) -> Result<NonceReset, String> {
        self.manifest_tag = None;
        self.pending = None;
        let removed = match target {
            Some((net, key)) => {
                check_nonce_key(key)?;
                if self.blocked_all.is_some() {
                    return Err(WHOLE_STATE_BLOCKED.to_string());
                }
                let name = account_name(&net, key);
                self.accounts.remove(&name);
                self.dirty.remove(&name);
                self.listed.remove(&name);
                vec![name]
            }
            None => {
                let mut removed: BTreeSet<String> = self.accounts.keys().cloned().collect();
                removed.extend(self.listed.keys().cloned());
                self.accounts.clear();
                self.dirty.clear();
                self.listed.clear();
                self.blocked_all = None;
                removed.into_iter().collect()
            }
        };
        Ok(NonceReset {
            removed,
            manifest: render_manifest(&manifest_entries(&self.listed, &BTreeMap::new())),
        })
    }
}

#[uniffi::export]
pub fn nonce_account(
    chain_id: u64,
    genesis_hex: String,
    key: String,
) -> Result<String, QcoreError> {
    let net = Network::of(chain_id, &genesis_hex).map_err(err)?;
    check_nonce_key(&key).map_err(err)?;
    Ok(account_name(&net, &key))
}

#[uniffi::export]
pub fn nonce_sync(stored: NonceStored) -> Result<(), QcoreError> {
    lock(&NONCE_LEDGER).sync(&stored).map_err(err)
}

#[uniffi::export]
pub fn nonce_batch() -> Result<Option<NonceBatch>, QcoreError> {
    lock(&NONCE_LEDGER).batch().map_err(err)
}

#[uniffi::export]
pub fn nonce_committed(manifest_tag: Option<String>) {
    lock(&NONCE_LEDGER).committed(manifest_tag)
}

#[uniffi::export]
pub fn nonce_manifest_tag() -> Option<String> {
    lock(&NONCE_LEDGER).manifest_tag.clone()
}

#[uniffi::export]
pub fn acknowledge_imported_history(
    chain_id: u64,
    genesis_hex: String,
    key: String,
) -> Result<(), QcoreError> {
    let net = Network::of(chain_id, &genesis_hex).map_err(err)?;
    lock(&NONCE_LEDGER).acknowledge(net, &key).map_err(err)
}

#[uniffi::export]
pub fn acknowledge_mainnet(
    chain_id: u64,
    genesis_hex: String,
    key: String,
) -> Result<(), QcoreError> {
    let net = Network::of(chain_id, &genesis_hex).map_err(err)?;
    lock(&NONCE_LEDGER)
        .acknowledge_mainnet(net, &key)
        .map_err(err)
}

fn pinned_roster(net: &Network) -> Option<[u8; 32]> {
    let pins = [
        (
            qcore::chain_id_from_name(qcore::TESTNET_CHAIN_NAME),
            qcore::TESTNET_GENESIS_HASH,
            qcore::TESTNET_ROSTER_COMMITMENT,
        ),
        (
            qcore::MAINNET_CHAIN_ID,
            qcore::MAINNET_GENESIS_HASH,
            qcore::MAINNET_ROSTER_COMMITMENT,
        ),
    ];
    pins.into_iter()
        .find_map(|(chain_id, genesis, commitment)| {
            (chain_id == net.chain_id && genesis == Some(net.genesis)).then_some(commitment)
        })
        .flatten()
}

fn pinned_roster_check(roster_json: &str, pin: Option<[u8; 32]>) -> Result<(), String> {
    let Some(pin) = pin else {
        return Err(NO_PINNED_ROSTER.to_string());
    };
    let roster = qcore::finality::parse_roster(roster_json)?;
    if qcore::finality::roster_commitment_of(0, &roster) != pin {
        return Err("the validator roster given is not the one pinned for this network, so its certificates do not count toward the settling wait".to_string());
    }
    Ok(())
}

fn certified(
    net: Network,
    epoch_length: Option<u64>,
    header_hex: &str,
    certificate_hex: &str,
    roster_json: &str,
) -> Result<Certified, String> {
    let header = from_hex(header_hex)?;
    let certificate = from_hex(certificate_hex)?;
    let verified = finalized_in_epoch(
        net.chain_id,
        &net.genesis,
        epoch_length,
        0,
        &header,
        &certificate,
        roster_json,
    )?;
    Ok(Certified {
        height: verified.height,
        time: verified.time,
    })
}

#[uniffi::export]
pub fn settle_history(
    chain_id: u64,
    genesis_hex: String,
    key: String,
    header_hex: String,
    certificate_hex: String,
    roster_json: String,
) -> Result<NonceSettle, QcoreError> {
    let net = Network::of(chain_id, &genesis_hex).map_err(err)?;
    check_nonce_key(&key).map_err(err)?;
    pinned_roster_check(&roster_json, pinned_roster(&net)).map_err(err)?;
    let verified =
        certified(net, None, &header_hex, &certificate_hex, &roster_json).map_err(err)?;
    lock(&NONCE_LEDGER)
        .settle_with(net, &key, verified)
        .map_err(err)
}

#[uniffi::export]
pub fn reset_nonce_state(
    chain_id: Option<u64>,
    genesis_hex: Option<String>,
    key: Option<String>,
) -> Result<NonceReset, QcoreError> {
    let target = match (chain_id, genesis_hex.as_deref(), key.as_deref()) {
        (Some(chain_id), Some(genesis_hex), Some(key)) => {
            Some((Network::of(chain_id, genesis_hex).map_err(err)?, key))
        }
        (None, None, None) => None,
        _ => {
            return Err(err(
                "name the chain id, the genesis hash and the key to reset one account, or none of them to reset every account",
            ))
        }
    };
    lock(&NONCE_LEDGER).reset(target).map_err(err)
}

#[derive(uniffi::Object)]
pub struct SigningSession {
    book: Mutex<qcore::SigningSession>,
    ledger: &'static Mutex<NonceLedger>,
}

impl SigningSession {
    fn holding(book: qcore::SigningSession, ledger: &'static Mutex<NonceLedger>) -> Arc<Self> {
        Arc::new(SigningSession {
            book: Mutex::new(book),
            ledger,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn signing(
        &self,
        net: Network,
        key: &str,
        target: Option<&str>,
        nonce: u64,
        valid_until: u64,
        head: u64,
        sign: impl FnOnce() -> Result<String, QcoreError>,
    ) -> Result<String, QcoreError> {
        if let Some(target) = target {
            lock(&self.book).check_target(target).map_err(err)?;
        }
        let signed = lock(self.ledger).signing(net, key, nonce, valid_until, head, sign)?;
        if let Some(target) = target {
            lock(&self.book).remember_address(target);
        }
        Ok(signed)
    }
}

fn network(chain_id: u64, genesis_hex: &str) -> Result<Network, QcoreError> {
    Network::of(chain_id, genesis_hex).map_err(err)
}

#[uniffi::export]
impl SigningSession {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Self::holding(qcore::SigningSession::new(), &NONCE_LEDGER)
    }

    #[uniffi::constructor]
    pub fn with_address_book(book: Vec<String>) -> Result<Arc<Self>, QcoreError> {
        let core = qcore::SigningSession::with_address_book(&book).map_err(err)?;
        Ok(Self::holding(core, &NONCE_LEDGER))
    }

    pub fn known(&self) -> Vec<String> {
        lock(&self.book).known()
    }

    pub fn remember_address(&self, address: String) {
        lock(&self.book).remember_address(&address)
    }

    pub fn check_target(&self, address: String) -> Result<(), QcoreError> {
        lock(&self.book).check_target(&address).map_err(err)
    }

    pub fn slot(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        lock(self.ledger)
            .slot(net, &key, reported, expected, order)
            .map_err(err)
    }

    pub fn signed(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
        slot: u64,
    ) -> Result<(), QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        lock(self.ledger).signed(net, &key, slot).map_err(err)
    }

    pub fn release(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
        slot: u64,
    ) -> Result<(), QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        lock(self.ledger).release(net, &key, slot);
        Ok(())
    }

    pub fn release_pending(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
    ) -> Result<(), QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        lock(self.ledger).release_pending(net, &key);
        Ok(())
    }

    pub fn outcome(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
        slot: u64,
        accepted: bool,
    ) -> Result<(), QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        lock(self.ledger)
            .outcome(net, &key, slot, accepted)
            .map_err(err)
    }

    pub fn next_nonce(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
    ) -> Result<Option<u64>, QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        Ok(lock(self.ledger).next_nonce(net, &key))
    }

    pub fn is_held(
        &self,
        chain_id: u64,
        genesis_hex: String,
        key: String,
        slot: u64,
    ) -> Result<bool, QcoreError> {
        let net = network(chain_id, &genesis_hex)?;
        Ok(lock(self.ledger).is_held(net, &key, slot))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn signed_body(signed: &str) -> String {
        let parsed = qcore::json::parse(signed).expect("json");
        let tx_hex = parsed.get("tx_hex").and_then(Json::as_str).expect("tx_hex");
        tx_hex[..tx_hex.len() - 2 * (1 + 8 + 3309)].to_string()
    }

    fn seed() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn g() -> String {
        TX_GENESIS.to_string()
    }

    fn net(chain_id: u64) -> Network {
        Network::of(chain_id, TX_GENESIS).expect("a network")
    }

    fn handle() -> Arc<SeedHandle> {
        SeedHandle::from_seed_bytes(seed()).expect("a thirty two byte seed is held")
    }

    fn fresh_ledger() -> &'static Mutex<NonceLedger> {
        Box::leak(Box::new(Mutex::new(NonceLedger::default())))
    }

    fn session_on(ledger: &'static Mutex<NonceLedger>) -> Arc<SigningSession> {
        SigningSession::holding(qcore::SigningSession::new(), ledger)
    }

    fn fresh() -> Arc<SigningSession> {
        session_on(fresh_ledger())
    }

    fn slotted(index: u64, nonce: u64) -> Arc<SigningSession> {
        let session = fresh();
        let key = address(seed(), index).expect("derives");
        assert_eq!(
            session.slot(1, g(), key, nonce, None, false).expect("free"),
            nonce
        );
        session
    }

    #[test]
    fn a_malformed_address_is_an_error_and_not_a_panic() {
        for bad in ["not an address", "", "Q1zzzz"] {
            assert!(
                sign_transfer(
                    seed(),
                    0,
                    bad.to_string(),
                    "5".to_string(),
                    0,
                    "1".to_string(),
                    1,
                    300,
                    0,
                    g(),
                )
                .is_err(),
                "a transfer to {bad:?} must return an error, not sign and not panic"
            );
        }
    }

    #[test]
    fn the_retired_testnet_host_is_refused_and_the_served_one_accepted() {
        assert_eq!(testnet_rpc_url(), "https://q-test-net-01.quantova.org");
        assert_eq!(testnet_chain_name(), "Q-test-net-01");
        assert!(check_endpoint(testnet_rpc_url()).is_ok());
        for retired in [
            "https://rpc-testnet.quantova.org",
            "https://rpc-testnet.quantova.org/rpc",
            "https://RPC-TESTNET.quantova.org.",
            "https://user@rpc-testnet.quantova.org:443/v1",
        ] {
            assert!(check_endpoint(retired.to_string()).is_err(), "{retired}");
        }
        assert!(gateway_protocol() > 0);
    }

    #[test]
    fn a_malformed_seed_is_an_error_and_not_a_panic() {
        let to = address(seed(), 0).expect("a good seed derives an address");
        for bad in [
            vec![],
            vec![0u8],
            vec![0u8; 31],
            vec![0u8; 33],
            vec![0u8; 64],
        ] {
            assert!(
                address(bad.clone(), 0).is_err(),
                "a seed of {} bytes must be refused",
                bad.len()
            );
            assert!(
                sign_transfer(
                    bad.clone(),
                    0,
                    to.clone(),
                    "5".to_string(),
                    0,
                    "1".to_string(),
                    1,
                    300,
                    0,
                    g(),
                )
                .is_err(),
                "signing under a seed of {} bytes must be refused",
                bad.len()
            );
        }
    }

    #[test]
    fn an_index_selects_the_key_it_names() {
        let zero = address(seed(), 0).expect("index zero derives");
        let one = address(seed(), 1).expect("index one derives");
        let last = address(seed(), u64::MAX).expect("the last index derives");
        assert_ne!(zero, one, "two indices must not share an address");
        assert_ne!(one, last, "the far end of the range is its own address");
        assert_eq!(
            zero,
            address(seed(), 0).expect("deriving twice agrees"),
            "an index gives the same address every time"
        );
        assert!(valid_address(zero), "a derived address must parse");
    }

    #[test]
    fn a_full_width_amount_survives_the_boundary() {
        let to = address(seed(), 3).expect("derives");
        let sign = |amount: &str| {
            sign_transfer(
                seed(),
                0,
                to.clone(),
                amount.to_string(),
                0,
                "1".to_string(),
                1,
                300,
                0,
                g(),
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
        let phrase = mnemonic_from_seed(seed()).expect("a seed makes a phrase");
        let back = seed_from_mnemonic(phrase).expect("the phrase gives the seed back");
        assert_eq!(back, seed(), "a phrase must round trip to its own seed");
        assert!(
            seed_from_mnemonic("word ".repeat(24).trim().as_bytes().to_vec()).is_err(),
            "a phrase that is not one of ours is refused, not guessed at"
        );
        assert!(
            seed_from_mnemonic(vec![0xff, 0xfe, 0x20]).is_err(),
            "bytes that are not text are refused"
        );
    }

    #[test]
    fn a_phrase_is_normalised_and_a_standard_bip39_phrase_is_named() {
        let phrase = String::from_utf8(mnemonic_from_seed(seed()).expect("a seed makes a phrase"))
            .expect("a phrase is text");
        let messy = format!(
            "  {}\u{00a0}\n",
            phrase
                .to_uppercase()
                .split(' ')
                .collect::<Vec<_>>()
                .join(" \u{3000} ")
        );
        assert_eq!(
            seed_from_mnemonic(messy.into_bytes()).expect("normalised"),
            seed()
        );
        let standard =
            seed_from_mnemonic(format!("{} about", ["abandon"; 11].join(" ")).into_bytes())
                .unwrap_err()
                .to_string();
        assert!(standard.contains("standard BIP-39"), "{standard}");
    }

    #[test]
    fn a_generated_seed_is_thirty_two_random_bytes() {
        let first = generate_seed().expect("the platform random source is available");
        let second = generate_seed().expect("the platform random source is available");
        assert_eq!(first.len(), SEED_LEN);
        assert_ne!(first, second);
        assert!(valid_address(
            address(first, 0).expect("a generated seed derives")
        ));
    }

    #[test]
    fn a_call_pays_the_one_locked_fee_and_is_refused_outside_the_chain_rules() {
        let to = address(seed(), 1).expect("derives");
        assert_eq!(vm_call_fee("500".to_string(), 21_000).unwrap(), "500");
        assert_eq!(vm_call_fee("500".to_string(), 12_500_000).unwrap(), "500");
        assert!(vm_call_fee("-1".to_string(), 21_000).is_err());
        let call = |meter: u64, fee: &str, args: &str| {
            sign_call(
                seed(),
                0,
                to.clone(),
                args.to_string(),
                0,
                meter,
                fee.to_string(),
                1,
                300,
                "500".to_string(),
                0,
                g(),
            )
        };
        assert!(call(21_000, "500", "").is_ok());
        assert!(call(21_000, "499", "").is_err(), "below the locked fee");
        assert!(call(21_000, "9000", "").is_err(), "above the locked fee");
        assert!(call(1_209, "500", "").is_err());
        assert!(call(12_500_001, "500", "").is_err());
        assert!(call(21_000, "500", &"00".repeat(128 * 1024 + 1)).is_err());
        assert!(sign_payable_call(
            seed(),
            0,
            to.clone(),
            String::new(),
            0,
            21_000,
            "499".to_string(),
            "0".to_string(),
            1,
            300,
            "500".to_string(),
            0,
            g(),
        )
        .is_err());
        assert!(sign_asset_call(
            seed(),
            0,
            to.clone(),
            String::new(),
            to.clone(),
            "1".to_string(),
            0,
            21_000,
            "499".to_string(),
            1,
            300,
            "500".to_string(),
            0,
            g(),
        )
        .is_err());
    }

    #[test]
    fn a_self_transfer_or_a_deadline_of_zero_is_refused() {
        let own = address(seed(), 0).expect("derives");
        let other = address(seed(), 1).expect("derives");
        let sign = |to: String, amount: &str, valid_until: u64| {
            sign_transfer(
                seed(),
                0,
                to,
                amount.to_string(),
                0,
                "1".to_string(),
                1,
                valid_until,
                0,
                g(),
            )
        };
        assert!(sign(own, "5", 300).is_err());
        assert!(sign(other.clone(), "5", 0).is_err());
        assert!(sign(other.clone(), "+5", 300).is_err());
        assert!(sign(other, "5", 300).is_ok());
    }

    #[test]
    fn a_seed_given_as_bytes_of_the_wrong_length_is_refused() {
        for len in [0usize, 1, 31, 33, 64] {
            assert!(
                SeedHandle::from_seed_bytes(vec![7u8; len]).is_err(),
                "a seed of {len} bytes must not be held"
            );
        }
        assert!(SeedHandle::from_phrase_bytes(Vec::new()).is_err());
        assert!(SeedHandle::from_phrase_bytes(vec![0xc3, 0x28]).is_err());
    }

    #[test]
    fn a_phrase_given_as_bytes_round_trips_through_a_handle() {
        let phrase = handle()
            .phrase_bytes()
            .expect("a held seed gives its phrase");
        assert_eq!(
            phrase,
            mnemonic_from_seed(seed()).expect("the seed path agrees")
        );
        let restored = SeedHandle::from_phrase_bytes(phrase).expect("the phrase restores");
        assert_eq!(restored.seed_bytes().expect("held"), seed());
        assert_eq!(
            restored.address(0).expect("held"),
            address(seed(), 0).expect("derives")
        );
        let fresh = SeedHandle::generate().expect("the platform random source is available");
        let again = SeedHandle::from_phrase_bytes(fresh.phrase_bytes().expect("held"))
            .expect("a fresh phrase restores");
        assert_eq!(again.seed_bytes().unwrap(), fresh.seed_bytes().unwrap());
    }

    #[test]
    fn a_handle_signs_the_same_transaction_as_the_seed_path() {
        let to = address(seed(), 1).expect("derives");
        let by_seed = sign_transfer(
            seed(),
            0,
            to.clone(),
            "5".to_string(),
            0,
            "1".to_string(),
            1,
            300,
            0,
            g(),
        )
        .expect("the seed path signs");
        let by_handle = handle()
            .sign_transfer(
                slotted(0, 0),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                10,
                g(),
            )
            .expect("the handle signs");
        assert_eq!(
            signed_body(&by_seed),
            signed_body(&by_handle),
            "both paths must sign the same bytes"
        );
        let register = handle()
            .sign_register(slotted(0, 0), 0, 0, "1".to_string(), 1, 300, 10, g())
            .expect("the handle registers");
        assert_eq!(
            signed_body(&register),
            signed_body(
                &sign_register(seed(), 0, 0, "1".to_string(), 1, 300, 0, g())
                    .expect("the seed path registers")
            )
        );
        let call = handle()
            .sign_call(
                slotted(0, 0),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "500".to_string(),
                1,
                300,
                "500".to_string(),
                10,
                g(),
            )
            .expect("the handle calls");
        assert_eq!(
            signed_body(&call),
            signed_body(
                &sign_call(
                    seed(),
                    0,
                    to,
                    String::new(),
                    0,
                    21_000,
                    "500".to_string(),
                    1,
                    300,
                    "500".to_string(),
                    0,
                    g(),
                )
                .expect("the seed path calls")
            )
        );
    }

    #[test]
    fn a_forgotten_handle_can_no_longer_sign() {
        let held = handle();
        let to = address(seed(), 1).expect("derives");
        assert!(!held.is_forgotten());
        held.forget();
        assert!(held.is_forgotten());
        assert!(held.address(0).is_err());
        assert!(held.seed_bytes().is_err());
        assert!(held.phrase_bytes().is_err());
        let refused = held
            .sign_transfer(
                slotted(0, 0),
                0,
                to,
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                10,
                g(),
            )
            .unwrap_err()
            .to_string();
        assert!(refused.contains("forgotten"), "{refused}");
        held.forget();
        assert!(held.is_forgotten(), "forgetting twice is harmless");
    }

    #[test]
    fn a_handle_refuses_a_deadline_that_is_past_or_too_far_from_the_head() {
        let held = handle();
        let to = address(seed(), 1).expect("derives");
        let sign = |valid_until: u64, head: u64| {
            held.sign_transfer(
                slotted(0, 0),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                valid_until,
                head,
                g(),
            )
        };
        assert!(
            sign(1_000, 1_000).is_err(),
            "a deadline at the head has passed"
        );
        assert!(
            sign(900, 1_000).is_err(),
            "a deadline under the head has passed"
        );
        assert!(
            sign(1_000 + max_validity_blocks() + 1, 1_000).is_err(),
            "a deadline beyond the validity window is refused"
        );
        assert!(sign(1_000 + max_validity_blocks(), 1_000).is_ok());
        assert!(sign(1_000 + default_validity_blocks(), 1_000).is_ok());
        assert!(held
            .sign_register(slotted(0, 0), 0, 0, "1".to_string(), 1, 5_000, 10, g())
            .is_err());
    }

    #[test]
    fn every_free_signer_refuses_a_deadline_beyond_the_window_past_the_head() {
        let to = address(seed(), 1).expect("derives");
        let head = 1_000;
        let within = head + max_validity_blocks();
        let beyond = within + 1;
        assert_eq!(max_validity_blocks(), 3_600);
        let transfer = |valid_until: u64| {
            sign_transfer(
                seed(),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                valid_until,
                head,
                g(),
            )
        };
        let register = |valid_until: u64| {
            sign_register(seed(), 0, 0, "1".to_string(), 1, valid_until, head, g())
        };
        let call = |valid_until: u64| {
            sign_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "500".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
                g(),
            )
        };
        let payable = |valid_until: u64| {
            sign_payable_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "500".to_string(),
                "1".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
                g(),
            )
        };
        let asset = |valid_until: u64| {
            sign_asset_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                to.clone(),
                "1".to_string(),
                0,
                21_000,
                "500".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
                g(),
            )
        };
        assert!(transfer(within).is_ok());
        assert!(register(within).is_ok());
        assert!(call(within).is_ok());
        assert!(payable(within).is_ok());
        assert!(asset(within).is_ok());
        for refused in [
            transfer(beyond),
            register(beyond),
            call(beyond),
            payable(beyond),
            asset(beyond),
        ] {
            let message = refused.expect_err("a deadline beyond the window is refused");
            assert!(message.to_string().contains("3600"), "{message}");
        }
        assert!(transfer(head).is_err(), "a deadline at the head has passed");
    }

    #[test]
    fn the_guard_helpers_refuse_a_deadline_that_is_too_far_or_already_passed() {
        assert!(check_valid_until(1_300, 1_000).is_ok());
        assert!(check_valid_until(1_000, 1_000).is_err());
        assert!(check_valid_until(999, 1_000).is_err());
        assert!(check_valid_until(0, 0).is_err());
        assert!(check_valid_until(1_000 + max_validity_blocks() + 1, 1_000).is_err());
        assert_eq!(max_validity_blocks(), qcore::MAX_VALIDITY_BLOCKS);
        assert_eq!(default_validity_blocks(), qcore::DEFAULT_VALIDITY_BLOCKS);
    }

    #[test]
    fn a_bounded_deadline_follows_a_head_the_wall_clock_allows() {
        let chain = qcore::TESTNET_CHAIN_NAME.to_string();
        let genesis = genesis_secs(chain.clone());
        assert_eq!(genesis, qcore::TESTNET_GENESIS_SECS);
        assert_eq!(
            genesis_secs("another".to_string()),
            qcore::GENESIS_FLOOR_SECS
        );
        let wall = genesis + 100;
        let ceiling = head_ceiling(chain.clone(), wall);
        assert_eq!(ceiling, qcore::head_ceiling(&chain, wall));
        assert_eq!(
            bounded_valid_until(chain.clone(), 500, wall, None, 0).expect("a plausible head"),
            500 + default_validity_blocks()
        );
        assert!(
            bounded_valid_until(chain.clone(), ceiling + 1, wall, None, 0).is_err(),
            "a head ahead of the wall clock is refused"
        );
        assert!(
            bounded_valid_until(chain.clone(), 500, wall, Some(501), 5).is_err(),
            "a head that went backwards is refused"
        );
        assert!(
            bounded_valid_until(chain.clone(), 500, wall, Some(10), 0).is_err(),
            "a head that leapt faster than blocks are made is refused"
        );
        assert!(bounded_valid_until(chain, 500, wall, Some(490), 5).is_ok());
    }

    #[test]
    fn a_slot_is_reserved_until_it_is_signed_or_released() {
        let session = fresh();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 7, None, false)
                .expect("free"),
            7
        );
        assert!(
            session.slot(1, g(), key.clone(), 7, None, false).is_err(),
            "two flows never share a nonce"
        );
        session
            .release(1, g(), key.clone(), 7)
            .expect("the ledger answers");
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 7, None, false)
                .expect("released"),
            7
        );
        session
            .release_pending(1, g(), key.clone())
            .expect("the ledger answers");
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 7, None, false)
                .expect("cleared"),
            7
        );
        session.signed(1, g(), key.clone(), 7).expect("recorded");
        assert!(session.slot(1, g(), key.clone(), 7, None, false).is_err());
    }

    #[test]
    fn the_session_refuses_a_second_signature_at_the_same_nonce() {
        let session = fresh();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(
            session
                .next_nonce(1, g(), key.clone())
                .expect("the ledger answers"),
            None
        );
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 4, None, false)
                .expect("free"),
            4
        );
        session.signed(1, g(), key.clone(), 4).expect("recorded");
        assert!(session
            .is_held(1, g(), key.clone(), 4)
            .expect("the ledger answers"));
        assert!(
            session.slot(1, g(), key.clone(), 4, None, false).is_err(),
            "one nonce carries one signature"
        );
        assert!(
            session
                .slot(1, g(), key.clone(), 4, Some(5), false)
                .is_err(),
            "a nonce other than the expected one is refused"
        );
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 4, Some(4), false)
                .expect("asked for"),
            4
        );
        session
            .outcome(1, g(), key.clone(), 4, true)
            .expect("recorded");
        assert_eq!(
            session
                .next_nonce(1, g(), key.clone())
                .expect("the ledger answers"),
            Some(5)
        );
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 5, None, false)
                .expect("next"),
            5
        );
    }

    #[test]
    fn a_gateway_nonce_below_what_the_session_reached_is_refused_unless_expected() {
        let session = fresh();
        let key = address(seed(), 0).expect("derives");
        for nonce in [5, 6] {
            session
                .slot(1, g(), key.clone(), nonce, None, false)
                .expect("free");
            session.signed(1, g(), key.clone(), nonce).expect("signed");
            session
                .outcome(1, g(), key.clone(), nonce, true)
                .expect("recorded");
        }
        let refused = session
            .slot(1, g(), key.clone(), 5, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("below the 7"), "{refused}");
        assert_eq!(
            session
                .slot(1, g(), key.clone(), 5, Some(5), false)
                .expect("asked for"),
            5
        );
    }

    #[test]
    fn the_vault_bounds_the_head_by_the_device_clock_and_a_floor_that_never_falls() {
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        let held = handle();
        let key = address(seed(), 0).expect("derives");
        let wall = 1_800_000_000;
        lock(ledger).wall = Some(wall);
        let ceiling = qcore::head_ceiling("", wall);
        let pay = |nonce: u64, head: u64, valid_until: u64| {
            session
                .slot(1, g(), key.clone(), nonce, Some(nonce), false)
                .expect("slot");
            let out = held.sign_transfer(
                session.clone(),
                0,
                address(seed(), 9).expect("derives"),
                "5".to_string(),
                nonce,
                "1".to_string(),
                1,
                valid_until,
                head,
                g(),
            );
            if out.is_err() {
                session
                    .release(1, g(), key.clone(), nonce)
                    .expect("released");
            }
            out.map_err(|refused| refused.to_string())
        };
        let near = (1u64 << 40) - 1;
        assert!(pay(0, near, near + max_validity_blocks())
            .unwrap_err()
            .contains("wall-clock"));
        assert!(pay(0, ceiling + 1, ceiling + 300).is_err());
        let head = ceiling - 10_000;
        assert!(pay(0, head, head + 300).is_ok());
        let floor = lock(ledger)
            .accounts
            .get(&account_name(&net(1), &key))
            .and_then(|account| account.floor);
        assert_eq!(
            floor,
            Some(Floor {
                height: head,
                time: wall
            })
        );
        assert!(pay(1, head - 1, head + 300).unwrap_err().contains("below"));
        assert!(pay(1, head + 10_000, head + 10_300)
            .unwrap_err()
            .contains("leapt"));
        lock(ledger).wall = Some(wall + 10);
        assert!(pay(1, head + 200, head + 500).is_ok());
        let account = &lock(ledger).accounts[&account_name(&net(1), &key)];
        let saved = parse_saved(&Record::of(account).render(1, "0123456789abcdef")).expect("saved");
        assert_eq!(
            saved.floor,
            Some(Floor {
                height: head + 200,
                time: wall + 10
            })
        );
    }

    #[test]
    fn the_vault_refuses_mainnet_without_an_acknowledgement_and_an_unverified_mainnet_head() {
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        let key = address(seed(), 0).expect("derives");
        let mainnet = qcore::MAINNET_CHAIN_ID;
        let pinned = "44".repeat(32);
        let pay = || {
            session
                .slot(mainnet, pinned.clone(), key.clone(), 0, Some(0), false)
                .expect("slot");
            handle().sign_transfer(
                session.clone(),
                0,
                address(seed(), 9).expect("derives"),
                "5".to_string(),
                0,
                "1".to_string(),
                mainnet,
                1_300,
                1_000,
                pinned.clone(),
            )
        };
        assert!(pay().unwrap_err().to_string().contains("mainnet"));
        let on = |chain: u64| Network::of(chain, &pinned).expect("a network");
        assert!(lock(ledger).acknowledge_mainnet(on(1), &key).is_err());
        lock(ledger)
            .acknowledge_mainnet(on(mainnet), &key)
            .expect("acknowledged");
        lock(ledger)
            .accounts
            .get_mut(&account_name(&on(mainnet), &key))
            .expect("tracked")
            .settle = None;
        let unbounded = pay().unwrap_err().to_string();
        assert!(unbounded.contains("neither verified"), "{unbounded}");
        let summary = signing_summary(
            "transfer".to_string(),
            mainnet,
            "Q1\u{200b}ABC".to_string(),
            "5".to_string(),
            "1".to_string(),
            String::new(),
        )
        .expect("summary");
        assert!(summary.contains("Send 5 Quon to Q1ABC"), "{summary}");
        assert!(summary.contains("Mainnet"), "{summary}");
        assert!(signing_summary(
            "reveal".to_string(),
            1,
            String::new(),
            "0".to_string(),
            "1".to_string(),
            String::new()
        )
        .is_err());
    }

    #[test]
    fn only_a_pinned_roster_carries_the_settling_wait() {
        let roster = tx_roster(TX_ATTEST_PK);
        let members = qcore::finality::parse_roster(&roster).expect("roster");
        let pin = qcore::finality::roster_commitment_of(0, &members);
        assert!(pinned_roster_check(&roster, Some(pin)).is_ok());
        assert!(pinned_roster_check(&roster, Some([7u8; 32])).is_err());
        assert!(pinned_roster_check(&roster, None)
            .unwrap_err()
            .contains("no validator roster is pinned"));
        assert_eq!(pinned_roster(&net(7)), None);
    }

    #[test]
    fn a_roster_certifies_only_headers_of_its_own_epoch() {
        let roster = tx_roster(TX_ATTEST_PK);
        let check = |length: Option<u64>, epoch: u64| {
            verify_finality(
                7,
                TX_GENESIS.to_string(),
                length,
                epoch,
                TX_HEADER.to_string(),
                TX_CERTIFICATE.to_string(),
                roster.clone(),
            )
            .map_err(|refused| refused.to_string())
        };
        assert!(check(Some(65_536), 0).is_ok());
        assert!(check(Some(1_000), 0).unwrap_err().contains("another epoch"));
        assert!(check(Some(1_000), 4).is_ok());
        assert!(check(None, 0).unwrap_err().contains("epoch length"));
        let testnet = qcore::testnet_chain_id();
        assert!(epoch_length_for(testnet, Some(1_000)).is_err());
        assert_eq!(epoch_length_for(testnet, None), Ok(65_536));
    }

    #[test]
    fn inclusion_proves_a_transfer_but_not_that_a_contract_call_ran() {
        let tx_bytes = |signed: String| {
            let parsed = qcore::json::parse(&signed).expect("json");
            from_hex(parsed.get("tx_hex").and_then(Json::as_str).expect("tx")).expect("hex")
        };
        let to = address(seed(), 1).expect("derives");
        let transfer = tx_bytes(
            sign_transfer(
                seed(),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                0,
                g(),
            )
            .expect("signs"),
        );
        let call = tx_bytes(
            sign_call(
                seed(),
                0,
                to,
                String::new(),
                0,
                21_000,
                "500".to_string(),
                1,
                300,
                "500".to_string(),
                0,
                g(),
            )
            .expect("signs"),
        );
        assert_eq!(settled_kind("t", &transfer, false), Ok(false));
        assert!(settled_kind("c", &call, false)
            .unwrap_err()
            .contains("contract call"));
        assert_eq!(settled_kind("c", &call, true), Ok(true));
    }

    #[test]
    fn the_session_keeps_an_address_book_of_real_addresses() {
        let first = address(seed(), 0).expect("derives");
        let second = address(seed(), 1).expect("derives");
        assert!(SigningSession::with_address_book(vec!["not an address".to_string()]).is_err());
        let session =
            SigningSession::with_address_book(vec![first.clone()]).expect("a real address book");
        assert_eq!(session.known(), vec![first.clone()]);
        session.remember_address(second.clone());
        session.remember_address(second.clone());
        session.remember_address("not an address".to_string());
        assert_eq!(session.known(), vec![first.clone(), second.clone()]);
        assert!(session.check_target(first).is_ok());
        assert!(session.check_target(second).is_ok());
    }

    fn vault_transfer(
        held: &SeedHandle,
        session: &Arc<SigningSession>,
        index: u64,
        nonce: u64,
    ) -> Result<String, QcoreError> {
        vault_pay(held, session, 1, index, 9, "5", nonce)
    }

    fn vault_pay(
        held: &SeedHandle,
        session: &Arc<SigningSession>,
        chain_id: u64,
        index: u64,
        to_index: u64,
        amount: &str,
        nonce: u64,
    ) -> Result<String, QcoreError> {
        let to = address(seed(), to_index).expect("derives");
        held.sign_transfer(
            session.clone(),
            index,
            to,
            amount.to_string(),
            nonce,
            "1".to_string(),
            chain_id,
            300,
            10,
            g(),
        )
    }

    #[test]
    fn the_vault_signs_only_at_a_nonce_taken_from_the_session() {
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 1).expect("derives");
        let to = address(seed(), 9).expect("derives");
        let session = fresh();
        let refused = vault_transfer(&held, &session, 0, 5)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("taken from this signing session"),
            "{refused}"
        );
        assert!(
            held.sign_call(
                session.clone(),
                0,
                to.clone(),
                String::new(),
                5,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
                10,
                g()
            )
            .is_err(),
            "a call without a slot is refused"
        );
        assert!(held
            .sign_register(session.clone(), 0, 5, "1".to_string(), 1, 300, 10, g())
            .is_err());
        assert!(held
            .sign_payable_call(
                session.clone(),
                0,
                to.clone(),
                String::new(),
                5,
                21_000,
                "9000".to_string(),
                "7".to_string(),
                1,
                300,
                "500".to_string(),
                10,
                g()
            )
            .is_err());
        assert!(held
            .sign_asset_call(
                session.clone(),
                0,
                to.clone(),
                String::new(),
                to.clone(),
                "7".to_string(),
                5,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
                10,
                g()
            )
            .is_err());
        session
            .slot(1, g(), other.clone(), 5, None, false)
            .expect("free");
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot of another account does not sign for this one"
        );
        session
            .slot(2, g(), me.clone(), 5, None, false)
            .expect("free");
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot on another chain does not sign on this one"
        );
        session
            .slot(1, g(), me.clone(), 5, None, false)
            .expect("free");
        lock(session.ledger)
            .acknowledge(net(1), &me)
            .expect("acknowledged");
        let first = vault_transfer(&held, &session, 0, 5).expect("signs at its slot");
        assert!(session
            .is_held(1, g(), me.clone(), 5)
            .expect("the ledger answers"));
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot carries one signature"
        );
        assert!(session.slot(1, g(), me.clone(), 6, None, false).is_err());
        session
            .slot(1, g(), me.clone(), 5, Some(5), false)
            .expect("asked for again");
        session
            .release(1, g(), me.clone(), 5)
            .expect("the ledger answers");
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a released slot does not sign"
        );
        session
            .slot(1, g(), me.clone(), 5, Some(5), false)
            .expect("asked for again");
        let again = vault_transfer(&held, &session, 0, 5).expect("signs");
        assert_eq!(
            signed_body(&first),
            signed_body(&again),
            "the vault and the session sign the same transaction"
        );
    }

    #[derive(Default, Clone)]
    struct Disk {
        manifest: Option<String>,
        sealed: bool,
        records: BTreeMap<String, String>,
        uptime: Option<(String, u64)>,
    }

    impl Disk {
        fn stored(&self, account: Option<&str>) -> NonceStored {
            NonceStored {
                manifest_present: self.manifest.is_some() || self.sealed,
                manifest: self.manifest.clone(),
                manifest_tag: None,
                records_present: !self.records.is_empty(),
                account: account.map(str::to_string),
                record_present: account.is_some_and(|name| self.records.contains_key(name)),
                record: account.and_then(|name| self.records.get(name).cloned()),
                boot: self.uptime.as_ref().map(|(boot, _)| boot.clone()),
                uptime_ms: self.uptime.as_ref().map_or(0, |(_, at)| *at),
            }
        }
    }

    fn persist(ledger: &Mutex<NonceLedger>, disk: &mut Disk) -> Vec<String> {
        let mut ledger = lock(ledger);
        let Some(batch) = ledger.batch().expect("a batch") else {
            return Vec::new();
        };
        disk.manifest = Some(batch.manifest);
        disk.sealed = true;
        let mut changed = Vec::new();
        for record in batch.records {
            changed.push(record.account.clone());
            disk.records.insert(record.account, record.state);
        }
        ledger.committed(None);
        assert!(ledger.dirty.is_empty());
        changed
    }

    struct App {
        ledger: &'static Mutex<NonceLedger>,
        session: Arc<SigningSession>,
    }

    impl App {
        fn start() -> App {
            let ledger = fresh_ledger();
            App {
                ledger,
                session: session_on(ledger),
            }
        }

        fn sync(&self, disk: &Disk, chain_id: u64, key: &str) {
            lock(self.ledger)
                .sync(&disk.stored(Some(&account_name(&net(chain_id), key))))
                .expect("syncs");
        }

        fn writer(&self) -> String {
            lock(self.ledger).writer().expect("a writer id")
        }

        fn recorded<T>(
            &self,
            disk: &mut Disk,
            chain_id: u64,
            key: &str,
            change: impl FnOnce() -> Result<T, QcoreError>,
        ) -> Result<T, QcoreError> {
            self.sync(disk, chain_id, key);
            let out = change();
            persist(self.ledger, disk);
            out
        }

        fn slot(
            &self,
            disk: &mut Disk,
            chain_id: u64,
            key: &str,
            reported: u64,
            expected: Option<u64>,
        ) -> Result<u64, QcoreError> {
            self.recorded(disk, chain_id, key, || {
                self.session
                    .slot(chain_id, g(), key.to_string(), reported, expected, false)
            })
        }

        fn order(
            &self,
            disk: &mut Disk,
            chain_id: u64,
            key: &str,
            reported: u64,
        ) -> Result<u64, QcoreError> {
            self.recorded(disk, chain_id, key, || {
                self.session
                    .slot(chain_id, g(), key.to_string(), reported, None, true)
            })
        }

        fn pay(
            &self,
            disk: &mut Disk,
            chain_id: u64,
            to_index: u64,
            amount: &str,
            nonce: u64,
        ) -> Result<String, QcoreError> {
            let me = address(seed(), 0).expect("derives");
            self.recorded(disk, chain_id, &me, || {
                vault_pay(
                    &handle(),
                    &self.session,
                    chain_id,
                    0,
                    to_index,
                    amount,
                    nonce,
                )
            })
        }

        fn outcome(&self, disk: &mut Disk, chain_id: u64, key: &str, slot: u64) {
            self.recorded(disk, chain_id, key, || {
                self.session
                    .outcome(chain_id, g(), key.to_string(), slot, true)
            })
            .expect("recorded");
        }

        fn release(&self, disk: &mut Disk, chain_id: u64, key: &str, slot: u64) {
            self.recorded(disk, chain_id, key, || {
                self.session
                    .release(chain_id, g(), key.to_string(), slot)
                    .expect("the ledger answers");
                Ok(())
            })
            .expect("released");
        }

        fn ack(&self, disk: &mut Disk, chain_id: u64, key: &str) {
            self.recorded(disk, chain_id, key, || {
                lock(self.ledger)
                    .acknowledge(net(chain_id), key)
                    .map_err(err)
            })
            .expect("acknowledged");
        }

        fn is_held(&self, disk: &Disk, chain_id: u64, key: &str, slot: u64) -> bool {
            self.sync(disk, chain_id, key);
            self.session
                .is_held(chain_id, g(), key.to_string(), slot)
                .expect("the ledger answers")
        }

        fn next(&self, disk: &Disk, chain_id: u64, key: &str) -> Option<u64> {
            self.sync(disk, chain_id, key);
            self.session
                .next_nonce(chain_id, g(), key.to_string())
                .expect("the ledger answers")
        }

        fn reset(&self, disk: &mut Disk, target: Option<(u64, &str)>) -> Result<(), String> {
            let account = target.map(|(chain_id, key)| account_name(&net(chain_id), key));
            lock(self.ledger).sync(&disk.stored(account.as_deref()))?;
            let reset =
                lock(self.ledger).reset(target.map(|(chain_id, key)| (net(chain_id), key)))?;
            if target.is_none() {
                disk.records.clear();
            }
            disk.manifest = Some(reset.manifest);
            disk.sealed = true;
            for name in &reset.removed {
                disk.records.remove(name);
            }
            Ok(())
        }
    }

    #[test]
    fn a_restart_restores_the_held_reserved_and_next_nonces() {
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 1).expect("derives");
        let mut disk = Disk::default();
        let before = App::start();
        before.slot(&mut disk, 1, &me, 5, None).expect("free");
        before.ack(&mut disk, 1, &me);
        before.pay(&mut disk, 1, 9, "5", 5).expect("signs");
        before.slot(&mut disk, 1, &other, 3, None).expect("free");
        let manifest =
            parse_manifest(disk.manifest.as_deref().expect("a manifest")).expect("reads");
        assert_eq!(manifest.len(), 2);
        for (account, state) in &disk.records {
            let saved = parse_saved(state).expect("a record");
            assert_eq!(saved.net, net(1));
            assert_eq!(account, &account_name(&net(1), &saved.key));
            assert_eq!(saved.writer, before.writer());
            assert_eq!(manifest[account].generation, saved.generation);
            assert_eq!(manifest[account].writer, saved.writer);
            assert_eq!(manifest[account].settling, saved.settle.is_some());
        }

        let after = App::start();
        assert_ne!(after.writer(), before.writer());
        assert!(after.is_held(&disk, 1, &me, 5));
        assert_eq!(after.next(&disk, 1, &me), Some(5));
        assert!(
            after.slot(&mut disk, 1, &me, 6, None).is_err(),
            "the retry waits until the signed nonce is known to have landed"
        );
        assert!(after.slot(&mut disk, 1, &me, 5, None).is_err());
        assert!(
            after.is_held(&disk, 1, &other, 3),
            "a slot reserved by another process may be signed there, so it is held here"
        );
        assert!(after.slot(&mut disk, 1, &other, 4, None).is_err());
        assert_eq!(after.slot(&mut disk, 1, &me, 6, Some(6)).ok(), Some(6));
        after.release(&mut disk, 1, &me, 6);

        before.outcome(&mut disk, 1, &me, 5);
        let later = App::start();
        assert_eq!(later.next(&disk, 1, &me), Some(6));
        assert_eq!(later.slot(&mut disk, 1, &me, 6, None).ok(), Some(6));
        assert!(later.slot(&mut disk, 2, &me, 5, None).is_ok());

        for bad in [
            "not json",
            "{}",
            r#"{"version":2,"chain_id":"1","key":"a","generation":"1","writer":"0123456789abcdef","held":[]}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","writer":"0123456789abcdef","next":"x","held":[]}"#,
            r#"{"version":3,"key":"a","generation":"1","writer":"0123456789abcdef","held":[]}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","held":[]}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","writer":"0123456789ABCDEF","held":[]}"#,
            r#"{"version":3,"chain_id":"1","key":"a b","generation":"1","writer":"0123456789abcdef","held":[]}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","writer":"0123456789abcdef","held":[],"reserved":["x"]}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","writer":"0123456789abcdef","held":[],"known":"-1"}"#,
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","writer":"0123456789abcdef","held":[],"settle":{"start":{"height":"1","time":"1","at":"1","boot":""}}}"#,
            r#"{"version":1,"keys":[{"key":"a","held":[]}]}"#,
        ] {
            assert!(parse_saved(bad).is_err(), "{bad}");
        }
        assert!(parse_saved(&"x".repeat(SAVED_STATE_MAX + 1)).is_err());
        assert!(parse_saved(r#"{"version":1,"keys":[]}"#)
            .unwrap_err()
            .contains("earlier format"));
    }

    #[test]
    fn a_fresh_session_needs_the_expected_order_nonce() {
        let key = "order:Q1KEY".to_string();
        let mut disk = Disk::default();
        let app = App::start();
        let refused = app.order(&mut disk, 1, &key, 9).unwrap_err().to_string();
        assert!(refused.contains("expected order nonce"), "{refused}");
        assert_eq!(
            app.recorded(&mut disk, 1, &key, || app.session.slot(
                1,
                g(),
                key.clone(),
                9,
                Some(9),
                true
            ))
            .ok(),
            Some(9)
        );
        app.recorded(&mut disk, 1, &key, || {
            app.session.signed(1, g(), key.clone(), 9)
        })
        .expect("recorded");
        app.outcome(&mut disk, 1, &key, 9);
        assert_eq!(app.order(&mut disk, 1, &key, 10).ok(), Some(10));
        app.release(&mut disk, 1, &key, 10);
        assert!(
            app.order(&mut disk, 1, &key, 12).is_err(),
            "a jump above the tracked order nonce is refused"
        );
        let restored = App::start();
        assert_eq!(restored.order(&mut disk, 1, &key, 10).ok(), Some(10));
        assert!(restored.order(&mut disk, 1, &key, 12).is_err());
        assert!(
            restored.order(&mut disk, 2, &key, 10).is_err(),
            "an order nonce tracked on one chain is not the expected order nonce on another"
        );
    }

    #[test]
    fn every_session_shares_one_nonce_ledger() {
        let chain = 9_100_001;
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let first = SigningSession::new();
        let second = SigningSession::new();
        assert_eq!(
            first
                .slot(chain, g(), me.clone(), 5, None, false)
                .expect("free"),
            5
        );
        acknowledge_imported_history(chain, g(), me.clone()).expect("acknowledged");
        let paid = vault_pay(&held, &first, chain, 0, 1, "100", 5).expect("signs at its slot");
        let refused = second
            .slot(chain, g(), me.clone(), 5, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("already signed for nonce 5"), "{refused}");
        assert!(
            vault_pay(&held, &second, chain, 0, 2, "999", 5).is_err(),
            "a second session cannot sign a second transfer at nonce 5"
        );
        assert!(second
            .is_held(chain, g(), me.clone(), 5)
            .expect("the ledger answers"));
        assert_eq!(
            second.slot(chain, g(), me.clone(), 5, Some(5), false).ok(),
            Some(5)
        );
        assert!(!paid.is_empty());

        let ledger = fresh_ledger();
        let one = session_on(ledger);
        let two = session_on(ledger);
        assert_eq!(
            one.slot(1, g(), me.clone(), 7, None, false).expect("free"),
            7
        );
        assert!(
            two.slot(1, g(), me.clone(), 7, None, false).is_err(),
            "a nonce reserved in one session is reserved in every session"
        );
    }

    #[test]
    fn two_processes_share_the_saved_ledger_under_the_lock() {
        let me = address(seed(), 0).expect("derives");
        let mut disk = Disk::default();
        let one = App::start();
        let two = App::start();
        assert_ne!(one.writer(), two.writer());
        one.slot(&mut disk, 1, &me, 4, Some(4)).expect("free");
        one.ack(&mut disk, 1, &me);
        one.pay(&mut disk, 1, 5, "1", 4).expect("signs");
        one.outcome(&mut disk, 1, &me, 4);

        assert_eq!(one.slot(&mut disk, 1, &me, 5, None).ok(), Some(5));
        let refused = two
            .slot(&mut disk, 1, &me, 5, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("nonce 5"), "{refused}");
        assert!(
            two.pay(&mut disk, 1, 6, "999", 5).is_err(),
            "the other process never hands out nonce 5, so its vault does not sign there"
        );
        let first = one
            .pay(&mut disk, 1, 5, "100", 5)
            .expect("signs at its slot");
        assert!(two.slot(&mut disk, 1, &me, 5, None).is_err());
        assert!(
            two.slot(&mut disk, 1, &me, 6, None).is_err(),
            "nonce 6 waits until the nonce 5 that the other process signed is known to have landed"
        );
        assert!(two.is_held(&disk, 1, &me, 5));

        one.outcome(&mut disk, 1, &me, 5);
        assert_eq!(two.slot(&mut disk, 1, &me, 6, None).ok(), Some(6));
        let second = two
            .pay(&mut disk, 1, 6, "999", 6)
            .expect("signs at its slot");
        assert_ne!(first, second);
        assert!(
            one.is_held(&disk, 1, &me, 6),
            "the nonce 6 that the other process signed is not lost when this process writes"
        );
        assert!(one.slot(&mut disk, 1, &me, 6, None).is_err());
        one.outcome(&mut disk, 1, &me, 3);
        let saved = parse_saved(&disk.records[&account_name(&net(1), &me)]).expect("saved");
        assert_eq!(saved.writer, one.writer());
        assert_eq!(saved.nonces.held.get(&6), Some(&false));
        assert!(App::start().is_held(&disk, 1, &me, 6));

        assert_eq!(one.slot(&mut disk, 1, &me, 7, Some(7)).ok(), Some(7));
        assert_eq!(two.slot(&mut disk, 1, &me, 7, Some(7)).ok(), Some(7));
        assert!(
            one.pay(&mut disk, 1, 5, "1", 7).is_err(),
            "a slot that another process took over no longer signs here"
        );
        assert!(two.pay(&mut disk, 1, 5, "2", 7).is_ok());

        let unrelated = "order:Q1UNRELATED";
        two.slot(&mut disk, 1, unrelated, 1, Some(1)).expect("free");
        one.recorded(&mut disk, 1, &me, || {
            one.session
                .release_pending(1, g(), me.clone())
                .expect("the ledger answers");
            Ok(())
        })
        .expect("nothing to release");
        let manifest =
            parse_manifest(disk.manifest.as_deref().expect("a manifest")).expect("reads");
        assert_eq!(
            manifest.len(),
            2,
            "every process writes the accounts the others wrote"
        );

        two.reset(&mut disk, Some((1, &me))).expect("resets");
        assert!(
            !one.is_held(&disk, 1, &me, 6),
            "a reset in another process is seen here"
        );
        assert_eq!(one.slot(&mut disk, 1, &me, 6, None).ok(), Some(6));
    }

    fn worst_key(index: usize) -> String {
        (0..NONCE_KEY_MAX)
            .map(|bit| {
                if (index >> (bit % 12)) & 1 == 1 {
                    '"'
                } else {
                    '\\'
                }
            })
            .collect()
    }

    #[test]
    fn the_saved_state_is_bounded_when_it_is_written() {
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        let key = "order:Q1DAPPCONTRACT:0".to_string();
        assert!(
            session.signed(1, g(), key.clone(), 0).is_err(),
            "a signature is recorded only for an account a slot created"
        );
        session
            .slot(1, g(), key.clone(), 0, None, false)
            .expect("free");
        session
            .release(1, g(), key.clone(), 0)
            .expect("the ledger answers");
        for i in 0..NONCE_SLOTS_MAX as u64 {
            session
                .signed(1, g(), key.clone(), u64::MAX - i)
                .expect("within the bound");
        }
        let refused = session
            .signed(1, g(), key.clone(), 1)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("16384"), "{refused}");
        assert!(session
            .slot(1, g(), key.clone(), 1, Some(1), false)
            .is_err());
        let mut disk = Disk::default();
        persist(ledger, &mut disk);
        let state = &disk.records[&account_name(&net(1), &key)];
        assert!(state.len() <= SAVED_STATE_MAX, "{}", state.len());
        let back = App::start();
        assert!(back.is_held(&disk, 1, &key, u64::MAX));
        assert!(back
            .slot(&mut disk, 1, "order:Q1DAPPCONTRACT:1", 0, None)
            .is_ok());

        let wide = fresh_ledger();
        let many = session_on(wide);
        for i in 0..NONCE_ACCOUNTS_MAX {
            many.slot(u64::MAX, g(), worst_key(i), 0, None, false)
                .expect("within the bound");
        }
        let refused = many
            .slot(u64::MAX, g(), "k".repeat(NONCE_KEY_MAX), 0, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("4096"), "{refused}");
        assert!(many.signed(1, g(), "another".to_string(), 0).is_err());
        assert!(many
            .slot(u64::MAX, g(), worst_key(0), 1, Some(1), false)
            .is_ok());
        {
            let mut full = lock(wide);
            let widest = "f".repeat(WRITER_LEN);
            let names: Vec<String> = full.accounts.keys().cloned().collect();
            for name in &names {
                full.listed.insert(
                    name.clone(),
                    Listed {
                        generation: u64::MAX - 1,
                        writer: widest.clone(),
                        settling: true,
                        prior: Some((u64::MAX - 2, "e".repeat(WRITER_LEN))),
                    },
                );
            }
            full.writer = Some(widest.clone());
            full.high = u64::MAX - 1;
            let manifest = render_manifest(&manifest_entries(&full.listed, &BTreeMap::new()));
            assert!(manifest.len() <= MANIFEST_MAX, "{}", manifest.len());
            assert_eq!(
                parse_manifest(&manifest).expect("reads").len(),
                NONCE_ACCOUNTS_MAX
            );
            full.dirty.clear();
            full.dirty.insert(names[0].clone());
            let batch = full
                .batch()
                .expect("a write at the cap fits")
                .expect("a batch");
            assert!(batch.manifest.len() <= MANIFEST_MAX);
            assert_eq!(batch.records[0].generation, u64::MAX);
        }

        let mut shared = Disk::default();
        let filled: BTreeMap<String, Listed> = (0..NONCE_ACCOUNTS_MAX - 1)
            .map(|i| {
                (
                    account_name(&net(1), &format!("k{i}")),
                    Listed {
                        generation: i as u64 + 1,
                        writer: "0123456789abcdef".to_string(),
                        settling: false,
                        prior: None,
                    },
                )
            })
            .collect();
        shared.manifest = Some(render_manifest(&manifest_entries(
            &filled,
            &BTreeMap::new(),
        )));
        shared.sealed = true;
        let early = App::start();
        assert!(early.next(&shared, 1, "k0").is_none());
        let late = App::start();
        assert!(late.slot(&mut shared, 1, "last", 0, None).is_ok());
        let refused = early
            .slot(&mut shared, 1, "late", 0, None)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("4096"),
            "the cap holds across processes: {refused}"
        );
        assert!(App::start().slot(&mut shared, 1, "later", 0, None).is_err());

        for bad in [
            String::new(),
            "k".repeat(NONCE_KEY_MAX + 1),
            "a b".to_string(),
            "\u{1}k".to_string(),
            "k\u{7f}".to_string(),
            "k\u{e9}".to_string(),
            "k\n".to_string(),
        ] {
            let refused = fresh()
                .slot(1, g(), bad.clone(), 0, None, false)
                .unwrap_err()
                .to_string();
            assert!(refused.contains("printable"), "{bad:?} {refused}");
            assert!(nonce_account(1, g(), bad.clone()).is_err(), "{bad:?}");
            assert!(fresh().signed(1, g(), bad, 0).is_err());
        }
        assert!(nonce_account(1, g(), "~!\"\\:Q1".to_string()).is_ok());

        let steady = fresh_ledger();
        let walk = session_on(steady);
        let me = address(seed(), 0).expect("derives");
        let mut disk = Disk::default();
        for nonce in 0..500u64 {
            walk.slot(1, g(), me.clone(), nonce, None, false)
                .expect("next");
            walk.signed(1, g(), me.clone(), nonce).expect("recorded");
            walk.outcome(1, g(), me.clone(), nonce, true)
                .expect("recorded");
            persist(steady, &mut disk);
        }
        let saved = parse_saved(&disk.records[&account_name(&net(1), &me)]).expect("saved");
        assert_eq!(saved.nonces.next, Some(500));
        assert_eq!(
            saved.nonces.held.len(),
            1,
            "accepted nonces below the next one are pruned"
        );
    }

    #[test]
    fn a_damaged_or_stale_account_blocks_only_itself_until_it_is_reset() {
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 3).expect("derives");
        let mine = account_name(&net(1), &me);
        let mut disk = Disk::default();
        let app = App::start();
        app.slot(&mut disk, 1, &me, 5, None).expect("free");
        app.ack(&mut disk, 1, &me);
        app.pay(&mut disk, 1, 9, "5", 5).expect("signs");
        app.outcome(&mut disk, 1, &me, 5);
        app.slot(&mut disk, 1, &other, 1, None).expect("free");
        let older = disk.clone();
        app.slot(&mut disk, 1, &me, 6, None).expect("free");
        app.pay(&mut disk, 1, 9, "5", 6).expect("signs");

        let mut damaged = disk.clone();
        damaged.records.insert(mine.clone(), "not json".to_string());
        let after = App::start();
        let refused = after
            .slot(&mut damaged, 1, &me, 6, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("reset"), "{refused}");
        assert!(after.is_held(&damaged, 1, &me, 6));
        assert!(after.slot(&mut damaged, 1, &me, 7, Some(7)).is_err());
        assert!(
            after.is_held(&damaged, 1, &other, 1),
            "another account keeps its state"
        );
        assert_eq!(
            after.slot(&mut damaged, 2, &me, 6, None).ok(),
            Some(6),
            "the same address on another chain is its own account"
        );

        let mut rolled_back = disk.clone();
        rolled_back
            .records
            .insert(mine.clone(), older.records[&mine].clone());
        let refused = App::start()
            .slot(&mut rolled_back, 1, &me, 6, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("older"), "{refused}");

        let mut forged = disk.clone();
        let current = parse_saved(&disk.records[&mine]).expect("saved");
        forged.records.insert(
            mine.clone(),
            Record {
                net: net(1),
                key: &me,
                nonces: &Nonces::default(),
                settle: current.settle.as_ref(),
                known: current.known,
                floor: current.floor,
                mainnet: current.mainnet,
            }
            .render(current.generation, "0123456789abcdef"),
        );
        let refused = App::start()
            .slot(&mut forged, 1, &me, 6, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not the write"), "{refused}");

        let mut swapped = disk.clone();
        swapped.records.insert(
            mine.clone(),
            disk.records[&account_name(&net(1), &other)].clone(),
        );
        let refused = App::start()
            .slot(&mut swapped, 1, &me, 6, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("another account"), "{refused}");

        let mut deleted = disk.clone();
        deleted.records.remove(&mine);
        let after = App::start();
        let refused = after
            .slot(&mut deleted, 1, &me, 6, None)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("missing"), "{refused}");
        assert!(after.slot(&mut deleted, 1, &other, 2, Some(2)).is_ok());
        assert!(
            App::start().slot(&mut deleted, 1, &me, 6, None).is_err(),
            "the blocked account stays listed and blocked after the next restart"
        );
        after.reset(&mut deleted, Some((1, &me))).expect("resets");
        assert_eq!(after.slot(&mut deleted, 1, &me, 6, None).ok(), Some(6));
        assert!(App::start().slot(&mut deleted, 1, &me, 7, Some(7)).is_ok());

        let planted = "order:Q1PLANTED";
        let mut unlisted = disk.clone();
        let fake = Nonces {
            next: Some(1_000_000),
            ..Nonces::default()
        };
        unlisted.records.insert(
            account_name(&net(1), planted),
            Record {
                net: net(1),
                key: planted,
                nonces: &fake,
                settle: None,
                known: None,
                floor: None,
                mainnet: false,
            }
            .render(1, "0123456789abcdef"),
        );
        let after = App::start();
        let refused = after
            .order(&mut unlisted, 1, planted, 999_999)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("does not list"), "{refused}");
        assert!(after.slot(&mut unlisted, 1, planted, 7, Some(7)).is_err());
        assert!(after.slot(&mut unlisted, 1, &other, 2, Some(2)).is_ok());
        after
            .reset(&mut unlisted, Some((1, planted)))
            .expect("resets");
        assert!(after.order(&mut unlisted, 1, planted, 999_999).is_err());
        assert_eq!(after.order(&mut unlisted, 1, planted, 0).ok(), Some(0));

        let mut no_manifest = disk.clone();
        no_manifest.manifest = None;
        let blind = App::start();
        let refused = blind
            .slot(&mut no_manifest, 1, &other, 2, Some(2))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("manifest"), "{refused}");
        assert!(blind.reset(&mut no_manifest, Some((1, &other))).is_err());
        blind
            .reset(&mut no_manifest, None)
            .expect("resets every account");
        assert_eq!(
            no_manifest.manifest.as_deref(),
            Some("quantova nonce manifest 3\n")
        );
        assert!(no_manifest.records.is_empty());
        assert!(blind.slot(&mut no_manifest, 1, &other, 2, None).is_ok());

        let mut emptied = disk.clone();
        emptied.manifest = None;
        emptied.records.clear();
        assert!(
            App::start().slot(&mut emptied, 1, &me, 5, None).is_err(),
            "a folder emptied while the key that seals the manifest remains is refused"
        );

        let mut cleared = Disk::default();
        assert!(
            App::start().slot(&mut cleared, 1, &me, 5, None).is_ok(),
            "cleared app data with no file and no key starts fresh"
        );

        let mut keyless = disk.clone();
        keyless.sealed = false;
        keyless.manifest = None;
        let refused = App::start()
            .slot(&mut keyless, 1, &other, 2, Some(2))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("without its manifest"), "{refused}");

        let mut torn = disk.clone();
        torn.manifest = Some("{".to_string());
        assert!(App::start().slot(&mut torn, 1, &other, 2, Some(2)).is_err());
        let mut crowded = disk.clone();
        let over: BTreeMap<String, Listed> = (0..=NONCE_ACCOUNTS_MAX)
            .map(|i| {
                (
                    account_name(&net(1), &format!("k{i}")),
                    Listed {
                        generation: 1,
                        writer: "0123456789abcdef".to_string(),
                        settling: false,
                        prior: None,
                    },
                )
            })
            .collect();
        crowded.manifest = Some(render_manifest(&manifest_entries(&over, &BTreeMap::new())));
        let refused = App::start()
            .slot(&mut crowded, 1, &other, 2, Some(2))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("more than 4096"), "{refused}");

        let mut legacy = Disk::default();
        let v1 = r#"{"version":1,"keys":[{"key":"Q1","held":[{"slot":"5","accepted":false}]}]}"#;
        legacy.records.insert(me.clone(), v1.to_string());
        assert!(App::start().slot(&mut legacy, 1, &me, 5, None).is_err());
    }

    fn certified_at(height: u64, time: u64) -> Certified {
        Certified { height, time }
    }

    fn settle_at(
        app: &App,
        chain: u64,
        key: &str,
        height: u64,
        time: u64,
    ) -> Result<NonceSettle, String> {
        lock(app.ledger).settle_with(net(chain), key, certified_at(height, time))
    }

    fn clocks(app: &App, disk: &mut Disk, boot: &str, uptime_ms: u64, wall: u64) {
        disk.uptime = Some((boot.to_string(), uptime_ms));
        lock(app.ledger).wall = Some(wall);
    }

    #[test]
    fn an_account_with_history_settles_only_on_verified_heights_and_device_time() {
        let me = address(seed(), 0).expect("derives");
        let chain = 1;
        let wall = 1_800_000_000;
        let height = 1_000_000;
        assert_eq!(SETTLE_SECS, 1_020);
        let pay_at = |app: &App, disk: &mut Disk, nonce: u64, head: u64| {
            let to = address(seed(), 9).expect("derives");
            app.recorded(disk, chain, &me, || {
                handle().sign_transfer(
                    app.session.clone(),
                    0,
                    to.clone(),
                    "5".to_string(),
                    nonce,
                    "1".to_string(),
                    chain,
                    head + 100,
                    head,
                    g(),
                )
            })
        };
        let settle = |app: &App, disk: &mut Disk, height: u64, time: u64| {
            app.sync(disk, chain, &me);
            let out = settle_at(app, chain, &me, height, time);
            persist(app.ledger, disk);
            out
        };

        let mut fresh = Disk::default();
        let new_key = App::start();
        clocks(&new_key, &mut fresh, "boot-a", 0, wall);
        new_key.slot(&mut fresh, chain, &me, 0, None).expect("free");
        assert!(
            pay_at(&new_key, &mut fresh, 0, height).is_ok(),
            "an account with no history, as a newly created seed has, signs at once"
        );
        new_key.outcome(&mut fresh, chain, &me, 0);
        new_key.slot(&mut fresh, chain, &me, 1, None).expect("free");
        assert!(
            pay_at(&new_key, &mut fresh, 1, height).is_ok(),
            "the nonce this device signed itself is no outside history"
        );

        let mut disk = Disk::default();
        let app = App::start();
        clocks(&app, &mut disk, "boot-a", 1_000, wall);
        app.slot(&mut disk, chain, &me, 5, None).expect("free");
        let first = pay_at(&app, &mut disk, 5, height).unwrap_err().to_string();
        assert!(first.starts_with("SETTLING"), "{first}");
        assert!(first.contains("settleHistory"), "{first}");
        assert!(
            pay_at(&app, &mut disk, 5, height + 100_000).is_err(),
            "a gateway head never ends the wait"
        );
        let stale = settle(&app, &mut disk, height, wall - SETTLE_START_AGE_SECS - 1).unwrap_err();
        assert!(stale.contains("fresh"), "{stale}");
        assert_eq!(
            settle(&app, &mut disk, height, wall - 5).expect("starts"),
            NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS)
        );
        let manifest =
            parse_manifest(disk.manifest.as_deref().expect("a manifest")).expect("reads");
        assert!(manifest[&account_name(&net(chain), &me)].settling);
        let record = parse_saved(&disk.records[&account_name(&net(chain), &me)]).expect("record");
        let start = record
            .settle
            .as_ref()
            .and_then(|settle| settle.start.clone())
            .expect("a start");
        assert_eq!(
            (start.height, start.boot.as_str(), start.at),
            (height, "boot-a", 1_000)
        );

        let restarted = App::start();
        clocks(&restarted, &mut disk, "boot-a", 61_000, wall + 60);
        restarted
            .slot(&mut disk, chain, &me, 5, Some(5))
            .expect("asked for");
        assert_eq!(
            settle(&restarted, &mut disk, height + SETTLE_SPAN + 1, wall + 60).expect("waits"),
            NonceSettle::waiting(0, SETTLE_SECS - 60),
            "a height past the window does not end it before the device has counted the time"
        );
        clocks(&restarted, &mut disk, "boot-a", 61_000, wall + 100_000);
        assert!(
            !settle(&restarted, &mut disk, height + SETTLE_SPAN + 1, wall + 60)
                .expect("waits")
                .settled,
            "a wall clock moved forward does not count toward the wait"
        );
        clocks(&restarted, &mut disk, "boot-b", 5_000, wall + 2_000);
        assert_eq!(
            settle(&restarted, &mut disk, height + SETTLE_SPAN + 1, wall + 61).expect("waits"),
            NonceSettle::waiting(0, SETTLE_SECS),
            "after a reboot the time on the device is counted again"
        );
        clocks(
            &restarted,
            &mut disk,
            "boot-b",
            5_000 + SETTLE_SECS * 1_000,
            wall + 2_000,
        );
        assert_eq!(
            settle(&restarted, &mut disk, height + SETTLE_SPAN, wall + 700).expect("waits"),
            NonceSettle::waiting(1, 0)
        );
        assert!(
            pay_at(&restarted, &mut disk, 5, height + SETTLE_SPAN + 1).is_err(),
            "the signer never ends the wait with the head it is given"
        );
        assert_eq!(
            settle(&restarted, &mut disk, height + SETTLE_SPAN + 1, wall + 720).expect("ends"),
            NonceSettle::done()
        );
        assert!(pay_at(&restarted, &mut disk, 5, height + 4_000).is_ok());
        let record = parse_saved(&disk.records[&account_name(&net(chain), &me)]).expect("record");
        assert_eq!(record.settle, None);
        assert_eq!(record.known, Some(6));

        let mut stale_start = Disk::default();
        let late = App::start();
        clocks(&late, &mut stale_start, "boot-c", 0, wall);
        late.slot(&mut stale_start, chain, &me, 5, None)
            .expect("free");
        late.sync(&stale_start, chain, &me);
        settle_at(&late, chain, &me, height, wall - 200).expect("starts");
        persist(late.ledger, &mut stale_start);
        clocks(&late, &mut stale_start, "boot-c", 720_000, wall + 720);
        late.sync(&stale_start, chain, &me);
        assert_eq!(
            settle_at(&late, chain, &me, height + 9_000, wall + 1_000).expect("restarts"),
            NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS),
            "a start that chain time shows was older than the device time counted is replaced by the fresher certificate"
        );

        restarted
            .reset(&mut disk, Some((chain, &me)))
            .expect("resets");
        restarted
            .slot(&mut disk, chain, &me, 6, None)
            .expect("free");
        let again = pay_at(&restarted, &mut disk, 6, height + 5_000)
            .unwrap_err()
            .to_string();
        assert!(
            again.starts_with("SETTLING"),
            "a reset account settles again: {again}"
        );
        restarted.ack(&mut disk, chain, &me);
        restarted
            .slot(&mut disk, chain, &me, 6, Some(6))
            .expect("asked for");
        assert!(
            pay_at(&restarted, &mut disk, 6, height + 5_000).is_ok(),
            "an acknowledged history ends the wait"
        );

        let mut forged = disk.clone();
        let name = account_name(&net(chain), &me);
        let mut entries =
            parse_manifest(forged.manifest.as_deref().expect("manifest")).expect("reads");
        entries.get_mut(&name).expect("listed").settling = true;
        forged.manifest = Some(render_manifest(&manifest_entries(
            &entries,
            &BTreeMap::new(),
        )));
        assert!(
            App::start()
                .slot(&mut forged, chain, &me, 8, Some(8))
                .is_err(),
            "a record and a manifest that disagree on settling block the account"
        );
    }

    #[test]
    fn history_signed_elsewhere_is_noticed_whenever_it_is_first_reported() {
        let me = address(seed(), 0).expect("derives");
        let chain = 1;
        let refused_at = |app: &App, disk: &mut Disk, nonce: u64| {
            app.pay(disk, chain, 9, "5", nonce)
                .unwrap_err()
                .to_string()
                .starts_with("SETTLING")
        };

        let mut zero_first = Disk::default();
        let app = App::start();
        app.slot(&mut zero_first, chain, &me, 0, None)
            .expect("free");
        app.release(&mut zero_first, chain, &me, 0);
        app.slot(&mut zero_first, chain, &me, 5, None)
            .expect("free");
        assert!(
            refused_at(&app, &mut zero_first, 5),
            "one report of nonce 0 does not make an account with history new"
        );

        let mut outcome_first = Disk::default();
        let js = App::start();
        let refused = js
            .recorded(&mut outcome_first, chain, &me, || {
                js.session.outcome(chain, g(), me.clone(), 0, true)
            })
            .unwrap_err()
            .to_string();
        assert!(refused.contains("reserve a slot first"), "{refused}");
        assert!(js
            .recorded(&mut outcome_first, chain, &me, || js.session.signed(
                chain,
                g(),
                me.clone(),
                0
            ))
            .is_err());
        js.slot(&mut outcome_first, chain, &me, 5, None)
            .expect("free");
        assert!(refused_at(&js, &mut outcome_first, 5));

        let mut grown = Disk::default();
        let mine = App::start();
        mine.slot(&mut grown, chain, &me, 0, None).expect("free");
        mine.pay(&mut grown, chain, 9, "5", 0).expect("signs");
        mine.outcome(&mut grown, chain, &me, 0);
        mine.slot(&mut grown, chain, &me, 1, None).expect("free");
        mine.release(&mut grown, chain, &me, 1);
        let later = App::start();
        later
            .slot(&mut grown, chain, &me, 3, Some(3))
            .expect("asked for");
        assert!(
            refused_at(&later, &mut grown, 3),
            "a nonce above every nonce this device signed starts the wait after a restart too"
        );
        later
            .slot(&mut grown, chain, &me, 4, Some(4))
            .expect("asked for");
        let record = parse_saved(&grown.records[&account_name(&net(chain), &me)]).expect("record");
        assert_eq!(record.settle.and_then(|settle| settle.seen), Some(4));

        let mut reset_then_zero = Disk::default();
        let again = App::start();
        again
            .slot(&mut reset_then_zero, chain, &me, 5, None)
            .expect("free");
        again
            .reset(&mut reset_then_zero, Some((chain, &me)))
            .expect("resets");
        again
            .slot(&mut reset_then_zero, chain, &me, 0, None)
            .expect("free");
        again.release(&mut reset_then_zero, chain, &me, 0);
        again
            .slot(&mut reset_then_zero, chain, &me, 5, None)
            .expect("free");
        assert!(refused_at(&again, &mut reset_then_zero, 5));

        let mut order = Disk::default();
        let dapp = App::start();
        assert!(dapp.order(&mut order, chain, &me, 0).is_ok());
        dapp.release(&mut order, chain, &me, 0);
        dapp.recorded(&mut order, chain, &me, || {
            dapp.session.slot(chain, g(), me.clone(), 7, Some(7), true)
        })
        .expect("asked for");
        assert!(
            refused_at(&dapp, &mut order, 7),
            "an order slot does not let outside history skip the wait"
        );
    }

    #[test]
    fn a_write_cut_short_between_the_manifest_and_the_record_settles_instead_of_blocking() {
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 3).expect("derives");
        let mine = account_name(&net(1), &me);
        let mut disk = Disk::default();
        let app = App::start();
        app.slot(&mut disk, 1, &me, 4, Some(4)).expect("free");
        app.ack(&mut disk, 1, &me);
        app.slot(&mut disk, 1, &me, 4, Some(4)).expect("asked for");
        app.pay(&mut disk, 1, 9, "1", 4).expect("signs");
        app.outcome(&mut disk, 1, &me, 4);
        app.slot(&mut disk, 1, &other, 0, None).expect("free");
        let before = disk.records[&mine].clone();

        app.slot(&mut disk, 1, &me, 5, None).expect("free");
        let mut cut = disk.clone();
        cut.records.insert(mine.clone(), before.clone());
        let listed = parse_manifest(cut.manifest.as_deref().expect("manifest")).expect("reads");
        let prior = listed[&mine]
            .prior
            .clone()
            .expect("the manifest names the write before");
        assert_eq!(prior, {
            let saved = parse_saved(&before).expect("record");
            (saved.generation, saved.writer)
        });
        let after = App::start();
        assert_eq!(
            after.slot(&mut cut, 1, &me, 5, Some(5)).ok(),
            Some(5),
            "the account is not blocked"
        );
        let refused = after.pay(&mut cut, 1, 9, "2", 5).unwrap_err().to_string();
        assert!(
            refused.starts_with("SETTLING"),
            "the write before is accepted only together with a settling wait: {refused}"
        );
        assert!(
            after.slot(&mut cut, 1, &other, 1, Some(1)).is_ok(),
            "another account is not touched"
        );

        let mut twice = disk.clone();
        app.slot(&mut disk, 1, &me, 6, Some(6)).expect("asked for");
        twice.records.insert(mine.clone(), before);
        twice.manifest = disk.manifest.clone();
        let refused = App::start()
            .slot(&mut twice, 1, &me, 6, Some(6))
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("older"),
            "a record two writes back is still refused: {refused}"
        );

        let mut new_account = Disk::default();
        let first = App::start();
        first.slot(&mut new_account, 1, &me, 0, None).expect("free");
        new_account.records.remove(&mine);
        let next = App::start();
        assert_eq!(next.slot(&mut new_account, 1, &me, 0, None).ok(), Some(0));
        assert!(
            next.pay(&mut new_account, 1, 9, "1", 0)
                .unwrap_err()
                .to_string()
                .starts_with("SETTLING"),
            "a first record that never landed settles"
        );
    }

    #[test]
    fn only_a_signature_needs_a_fresh_manifest_key_and_the_manifest_stays_compact() {
        let me = address(seed(), 0).expect("derives");
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        session
            .slot(1, g(), me.clone(), 0, None, false)
            .expect("free");
        let slot = lock(ledger).batch().expect("a batch").expect("dirty");
        assert!(
            !slot.rotate,
            "a reservation can be rolled back safely, so it keeps the key"
        );
        lock(ledger).committed(None);
        vault_pay(&handle(), &session, 1, 0, 9, "5", 0).expect("signs");
        let signed = lock(ledger).batch().expect("a batch").expect("dirty");
        assert!(signed.rotate, "a signature needs a fresh key");
        lock(ledger).committed(None);
        session.signed(1, g(), me.clone(), 1).expect("recorded");
        assert!(
            lock(ledger)
                .batch()
                .expect("a batch")
                .expect("dirty")
                .rotate
        );
        lock(ledger).committed(None);
        session
            .outcome(1, g(), me.clone(), 0, true)
            .expect("recorded");
        assert!(
            !lock(ledger)
                .batch()
                .expect("a batch")
                .expect("dirty")
                .rotate
        );
        lock(ledger).committed(None);

        let many = fresh_ledger();
        let walk = session_on(many);
        for i in 0..4_000u64 {
            walk.slot(
                6_995_079_887_857_407_393,
                g(),
                format!("fill:{i}"),
                0,
                None,
                false,
            )
            .expect("free");
            if i % 500 == 0 {
                lock(many).batch().expect("a batch");
                lock(many).committed(None);
            }
        }
        let batch = lock(many).batch().expect("a batch").expect("dirty");
        assert!(
            batch.manifest.len() < 4_000 * 32,
            "{} bytes for 4000 accounts",
            batch.manifest.len()
        );
        let listed = parse_manifest(&batch.manifest).expect("reads");
        assert_eq!(listed.len(), 4_000);
        for bad in [
            "quantova nonce manifest 2\n",
            "quantova nonce manifest 3",
            "quantova nonce manifest 3\n1 0 0 - - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 1\n1 1 0 - - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 1\n1 0 2 - - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 1\n1 0 0 3 - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 01\n1 0 0 - - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 1\n1 0 0 - - k\n2 0 0 - - k\n",
            "quantova nonce manifest 3\nw 0123456789abcdef\nn 1\n1 0 0 - - a b\n",
            "quantova nonce manifest 3\nn 1\nw 0123456789abcdef\n1 0 0 - - k\n",
        ] {
            assert!(parse_manifest(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn verified_certificates_alone_carry_an_account_through_the_wait() {
        let key = "order:Q1CERTIFIED".to_string();
        let roster = tx_roster(TX_ATTEST_PK);
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        session
            .slot(7, g(), key.clone(), 3, None, false)
            .expect("free");
        let settle = |header: &str, certificate: &str| {
            let verified = certified(net(7), Some(65_536), header, certificate, &roster)?;
            lock(ledger).settle_with(net(7), &key, verified)
        };
        {
            let mut held = lock(ledger);
            held.wall = Some(1_800_000_030);
            held.uptime = Some(("boot".to_string(), 1_000));
        }
        assert_eq!(
            settle(SETTLE_START_HEADER, SETTLE_START_CERTIFICATE).expect("starts"),
            NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS)
        );
        lock(ledger).uptime = Some(("boot".to_string(), 1_000 + SETTLE_SECS * 1_000));
        lock(ledger).wall = Some(1_800_000_750);
        assert_eq!(
            settle(SETTLE_SHORT_HEADER, SETTLE_SHORT_CERTIFICATE).expect("waits"),
            NonceSettle::waiting(SETTLE_SLACK_BLOCKS + 1, 0),
            "a certificate one block short of the window does not end it"
        );
        assert!(
            settle(SETTLE_END_HEADER, &tx_flip(SETTLE_END_CERTIFICATE, 2 * 315)).is_err(),
            "a certificate that does not verify does not count"
        );
        assert_eq!(
            settle(SETTLE_END_HEADER, SETTLE_END_CERTIFICATE).expect("waits"),
            NonceSettle::waiting(SETTLE_SLACK_BLOCKS, 0),
            "a certificate past the validity window but inside the certificate age slack does not end it"
        );
        let end = certified(
            net(7),
            Some(65_536),
            SETTLE_END_HEADER,
            SETTLE_END_CERTIFICATE,
            &roster,
        )
        .expect("verifies");
        assert_eq!(
            lock(ledger)
                .settle_with(
                    net(7),
                    &key,
                    certified_at(end.height + SETTLE_SLACK_BLOCKS, end.time)
                )
                .expect("ends"),
            NonceSettle::done()
        );
        assert!(lock(ledger)
            .accounts
            .get(&account_name(&net(7), &key))
            .is_some_and(|account| account.settle.is_none()));
    }

    #[test]
    fn settle_history_verifies_the_certificate_before_it_counts() {
        let key = "order:Q1SETTLE".to_string();
        let roster = tx_roster(TX_ATTEST_PK);
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        session
            .slot(7, g(), key.clone(), 3, None, false)
            .expect("free");
        let verified = certified(
            Network::of(7, TX_GENESIS).expect("a network"),
            Some(65_536),
            TX_HEADER,
            TX_CERTIFICATE,
            &roster,
        )
        .expect("verifies");
        assert_eq!((verified.height, verified.time), (4242, 1_800_000_000));
        assert!(certified(
            Network::of(7, &"aa".repeat(32)).expect("a network"),
            Some(65_536),
            TX_HEADER,
            TX_CERTIFICATE,
            &roster
        )
        .is_err());
        assert!(certified(
            Network::of(8, TX_GENESIS).expect("a network"),
            Some(65_536),
            TX_HEADER,
            TX_CERTIFICATE,
            &roster
        )
        .is_err());
        assert!(Network::of(7, &"00".repeat(32)).is_err());
        assert!(certified(
            net(7),
            Some(65_536),
            TX_HEADER,
            &tx_flip(TX_CERTIFICATE, 2 * 315),
            &roster
        )
        .is_err());
        {
            let mut held = lock(ledger);
            held.wall = Some(1_800_000_010);
            held.uptime = None;
            assert!(held
                .settle_with(net(7), &key, verified)
                .unwrap_err()
                .contains("clock"));
            held.uptime = Some(("boot".to_string(), 0));
            assert_eq!(
                held.settle_with(net(7), &key, verified).expect("starts"),
                NonceSettle::waiting(SETTLE_SPAN + 1, SETTLE_SECS)
            );
            assert!(held
                .settle_with(net(7), "order:Q1UNKNOWN", verified)
                .is_err());
        }
        assert!(settle_history(
            7,
            "order:Q1NEVER".to_string(),
            TX_GENESIS.to_string(),
            TX_HEADER.to_string(),
            TX_CERTIFICATE.to_string(),
            roster
        )
        .is_err());
    }

    #[test]
    fn an_unchanged_manifest_is_opened_once_per_write() {
        let me = address(seed(), 0).expect("derives");
        let mine = account_name(&net(1), &me);
        let mut disk = Disk::default();
        let app = App::start();
        app.slot(&mut disk, 1, &me, 5, None).expect("free");
        let tagged = |disk: &Disk, tag: &str, open: bool| {
            let mut stored = disk.stored(Some(&mine));
            stored.manifest_tag = Some(tag.to_string());
            if !open {
                stored.manifest = None;
            }
            stored
        };
        let mut ledger = lock(app.ledger);
        ledger.sync(&tagged(&disk, "t1", false)).expect("syncs");
        assert!(
            ledger.usable(&mine).is_err(),
            "a manifest that is not opened and not known is refused"
        );
        ledger.sync(&tagged(&disk, "t1", true)).expect("syncs");
        assert_eq!(nonce_tag(&ledger), Some("t1".to_string()));
        ledger.sync(&tagged(&disk, "t1", false)).expect("syncs");
        assert!(
            ledger.usable(&mine).is_ok(),
            "the manifest this process already opened is not opened again"
        );
        ledger.sync(&tagged(&disk, "t2", false)).expect("syncs");
        assert!(
            ledger.usable(&mine).is_err(),
            "a manifest under another tag must be opened"
        );
        ledger.sync(&tagged(&disk, "t2", true)).expect("syncs");
        ledger.dirty.insert(mine.clone());
        ledger.batch().expect("saves").expect("a batch");
        ledger.committed(Some("t3".to_string()));
        assert_eq!(nonce_tag(&ledger), Some("t3".to_string()));
        ledger.reset(Some((net(1), &me))).expect("resets");
        assert_eq!(
            nonce_tag(&ledger),
            None,
            "a reset forgets the manifest it last saw"
        );
    }

    fn nonce_tag(ledger: &NonceLedger) -> Option<String> {
        ledger.manifest_tag.clone()
    }

    #[test]
    fn a_nonce_signed_on_one_chain_does_not_block_another() {
        let me = address(seed(), 0).expect("derives");
        let mut disk = Disk::default();
        let app = App::start();
        app.slot(&mut disk, 7, &me, 5, None).expect("free");
        app.ack(&mut disk, 7, &me);
        let test = app.pay(&mut disk, 7, 1, "100", 5).expect("signs");
        assert_eq!(
            app.slot(&mut disk, 8, &me, 5, None).ok(),
            Some(5),
            "nonce 5 on chain 8 is free"
        );
        app.ack(&mut disk, 8, &me);
        let main = app.pay(&mut disk, 8, 1, "100", 5).expect("signs");
        assert_ne!(test, main);
        app.outcome(&mut disk, 8, &me, 5);
        let after = App::start();
        assert!(
            after.slot(&mut disk, 7, &me, 5, None).is_err(),
            "a nonce accepted on chain 8 does not clear the held signature on chain 7"
        );
        assert!(after.is_held(&disk, 7, &me, 5));
        assert_eq!(after.next(&disk, 8, &me), Some(6));
        assert_eq!(after.next(&disk, 7, &me), Some(5));
    }

    #[test]
    fn the_exported_ledger_syncs_saves_and_resets() {
        let chain = 9_100_002;
        let key = "order:Q1EXPORTED".to_string();
        let account = nonce_account(chain, g(), key.clone()).expect("a nonce account");
        assert_eq!(account, account_name(&net(chain), &key));
        assert!(nonce_account(chain, g(), "order key".to_string()).is_err());
        assert!(nonce_sync(NonceStored {
            manifest_present: false,
            manifest: None,
            manifest_tag: None,
            records_present: false,
            account: Some("not an account".to_string()),
            record_present: false,
            record: None,
            boot: None,
            uptime_ms: 0,
        })
        .is_err());
        nonce_sync(Disk::default().stored(Some(&account))).expect("syncs");
        let session = SigningSession::new();
        session
            .slot(chain, g(), key.clone(), 0, None, false)
            .expect("free");
        let batch = nonce_batch().expect("saves").expect("a batch");
        let record = batch
            .records
            .iter()
            .find(|record| record.account == account)
            .expect("the changed account is written");
        let listed = parse_manifest(&batch.manifest).expect("manifest");
        assert_eq!(listed[&account].generation, record.generation);
        let saved = parse_saved(&record.state).expect("record");
        assert_eq!(listed[&account].writer, saved.writer);
        nonce_committed(None);
        assert!(nonce_batch()
            .expect("nothing left")
            .is_none_or(|left| left.records.iter().all(|record| record.account != account)));
        assert!(reset_nonce_state(Some(chain), None, None).is_err());
        assert!(reset_nonce_state(Some(chain), Some("00".repeat(32)), Some(key.clone())).is_err());
        let reset = reset_nonce_state(Some(chain), Some(g()), Some(key)).expect("resets");
        assert_eq!(reset.removed, vec![account.clone()]);
        assert!(!parse_manifest(&reset.manifest)
            .expect("manifest")
            .contains_key(&account));
    }

    #[test]
    fn every_signer_binds_the_pinned_genesis_and_the_ledger_keeps_networks_apart() {
        let to = address(seed(), 1).expect("derives");
        let other = "22".repeat(32);
        let transfer = |genesis: String| {
            sign_transfer(
                seed(),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                0,
                genesis,
            )
        };
        let here = transfer(g()).expect("signs");
        let there = transfer(other.clone()).expect("signs");
        assert_ne!(here, there, "the genesis is part of what is signed");
        for bad in [
            String::new(),
            "00".repeat(32),
            "0".repeat(63),
            "g".repeat(64),
            format!("{}00", g()),
            format!(" {}", &g()[1..]),
        ] {
            assert!(transfer(bad.clone()).is_err(), "{bad:?}");
            assert!(sign_register(seed(), 0, 0, "1".to_string(), 1, 300, 0, bad.clone()).is_err());
            assert!(sign_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
                0,
                bad.clone()
            )
            .is_err());
            assert!(sign_payable_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "9000".to_string(),
                "7".to_string(),
                1,
                300,
                "500".to_string(),
                0,
                bad.clone()
            )
            .is_err());
            assert!(sign_asset_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                to.clone(),
                "7".to_string(),
                0,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
                0,
                bad.clone()
            )
            .is_err());
            assert!(nonce_account(1, bad.clone(), "k".to_string()).is_err());
            assert!(fresh()
                .slot(1, bad, "k".to_string(), 0, None, false)
                .is_err());
        }
        let upper = g().to_uppercase();
        assert_eq!(
            nonce_account(1, upper, "k".to_string()).expect("an account"),
            nonce_account(1, g(), "k".to_string()).expect("an account")
        );

        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let session = fresh();
        session
            .slot(1, g(), me.clone(), 0, None, false)
            .expect("free");
        let refused = held
            .sign_transfer(
                session.clone(),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                10,
                other.clone(),
            )
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("taken from this signing session"),
            "a slot reserved on one network does not sign on another with the same chain id: {refused}"
        );
        assert!(held
            .sign_transfer(
                session.clone(),
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                10,
                g()
            )
            .is_ok());
        assert!(!session
            .is_held(1, other.clone(), me.clone(), 0)
            .expect("the ledger answers"));
        assert_eq!(
            session
                .slot(1, other, me.clone(), 0, None, false)
                .expect("free"),
            0,
            "nonce 0 on another network that shares the chain id is its own"
        );
    }

    #[test]
    fn the_retired_testnet_name_derives_no_chain_id() {
        assert_eq!(
            chain_id_from_name(qcore::TESTNET_CHAIN_NAME.to_string()).expect("derives"),
            6_995_079_887_857_407_393
        );
        assert_eq!(qcore::TESTNET_CHAIN_NAME, "Q-test-net-01");
        let refused = chain_id_from_name("Q-test-net-1".to_string())
            .unwrap_err()
            .to_string();
        assert!(refused.contains("retired"), "{refused}");
        assert!(chain_id_from_name(String::new()).is_err());
    }

    #[test]
    fn an_order_expiry_must_lie_in_the_next_twenty_four_hours() {
        let now = 1_800_000_000u64;
        let day = max_order_lifetime_secs();
        assert_eq!(day, 86_400);
        assert!(check_order_expiry(0, now).is_err());
        assert!(check_order_expiry(now - 1, now).is_err());
        assert!(check_order_expiry(now, now).is_err());
        assert!(check_order_expiry(now + 1, now).is_ok());
        assert!(check_order_expiry(now + day, now).is_ok());
        assert!(check_order_expiry(now + day + 1, now).is_err());
        assert!(check_order_expiry(u64::MAX, now).is_err());
    }

    const LEAF_ZERO: &str =
        "07000000000000005131414c50484104000000000000005a11084908000000000000000000000000000000";
    const LEAF_ONE: &str =
        "06000000000000005131424554410400000000000000166760210400000000000000ffffffff";
    const HASH_ZERO: &str = "5ed8fb534e08a46e3b5c38eff7092cc98747914fedd7980df0f5904ee17379c1";
    const HASH_ONE: &str = "cd7fbedda551facaecb3cb47918a787625a4abade5f5287bb9274a87bb59cf79";
    const ROOT: &str = "c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc";

    #[test]
    fn an_event_is_included_only_under_its_root_and_path() {
        let path =
            |sibling: &str, left: bool| format!(r#"[{{"sibling":"{sibling}","left":{left}}}]"#);
        let check = |leaf: &str, steps: String| {
            verify_event(ROOT.to_string(), leaf.to_string(), steps).expect("well formed")
        };
        assert!(check(LEAF_ZERO, path(HASH_ONE, false)));
        assert!(check(LEAF_ONE, path(HASH_ZERO, true)));
        assert!(!check(LEAF_ZERO, path(HASH_ONE, true)));
        assert!(!check(LEAF_ONE, path(HASH_ONE, true)));
        assert!(!check(LEAF_ZERO, "[]".to_string()));
        assert!(verify_event(
            HASH_ZERO.to_string(),
            LEAF_ZERO.to_string(),
            "[]".to_string()
        )
        .expect("a single event is its own root"));
        for bad in [
            r#"{"sibling":"00","left":true}"#.to_string(),
            r#"[{"sibling":"00","left":true}]"#.to_string(),
            format!(r#"[{{"sibling":"{HASH_ONE}"}}]"#),
            format!(r#"[{{"sibling":"{HASH_ONE}","sibling_on_left":false}}]"#),
            format!(r#"[{{"sibling":"{HASH_ONE}","left":"false"}}]"#),
        ] {
            assert!(
                verify_event(ROOT.to_string(), LEAF_ZERO.to_string(), bad.clone()).is_err(),
                "{bad}"
            );
        }
        assert!(verify_event("00".to_string(), LEAF_ZERO.to_string(), "[]".to_string()).is_err());
        let long = format!(
            "[{}]",
            vec![format!(r#"{{"sibling":"{HASH_ONE}","left":true}}"#); 65].join(",")
        );
        assert!(!verify_event(ROOT.to_string(), LEAF_ZERO.to_string(), long).expect("parsed"));
    }

    #[test]
    fn an_event_leaf_decodes_to_its_contract_selector_and_data() {
        assert_eq!(
            decode_event(LEAF_ZERO.to_string()).expect("a well formed leaf"),
            r#"{"contract":"Q1ALPHA","selector":"5a110849","data":"0000000000000000"}"#
        );
        assert_eq!(
            decode_event(LEAF_ONE.to_string()).expect("a well formed leaf"),
            r#"{"contract":"Q1BETA","selector":"16676021","data":"ffffffff"}"#
        );
        assert!(decode_event(format!("{LEAF_ZERO}00")).is_err());
        assert!(decode_event(LEAF_ZERO[..LEAF_ZERO.len() - 2].to_string()).is_err());
        assert!(decode_event("zz".to_string()).is_err());
    }

    #[test]
    fn a_finality_check_refuses_a_malformed_roster_header_or_certificate() {
        let pk = "ab".repeat(1952);
        let root = "cd".repeat(32);
        let member = |id: u64, stake: &str| {
            format!(
                r#"{{"id":{id},"stake":"{stake}","attest_pk":"{pk}","root":"{root}","root_slots":"64"}}"#
            )
        };
        let header = "00".repeat(8);
        let run = |roster: String, header: &str, certificate: &str| {
            verify_finality(
                1,
                "ab".repeat(32),
                Some(65_536),
                0,
                header.to_string(),
                certificate.to_string(),
                roster,
            )
            .unwrap_err()
            .to_string()
        };
        assert!(run("[]".to_string(), &header, "00").contains("empty"));
        assert!(run("{}".to_string(), &header, "00").contains("JSON array"));
        assert!(run(format!("[{}]", member(1, "+5")), &header, "00").contains("whole number"));
        assert!(run(
            format!("[{}]", member(1, "18446744073709551616")),
            &header,
            "00"
        )
        .contains("in range"));
        assert!(run(
            format!("[{},{}]", member(1, "2000"), member(1, "2000")),
            &header,
            "00"
        )
        .contains("twice"));
        assert!(run(format!("[{}]", member(1, "0")), &header, "00").contains("no stake"));
        assert!(run(format!("[{}]", member(1, "1999")), &header, "00").contains("no stake"));
        assert!(run(
            format!(
                r#"[{{"id":1,"stake":"2000","attest_pk":"abab","root":"{root}","root_slots":"64"}}]"#
            ),
            &header,
            "00"
        )
        .contains("ML-DSA-65"));
        let without = |key: &str| {
            let full = member(1, "2000");
            let field = if key == "root" {
                format!(r#","root":"{root}""#)
            } else {
                r#","root_slots":"64""#.to_string()
            };
            format!("[{}]", full.replace(&field, ""))
        };
        assert!(run(without("root"), &header, "00").contains("sortition root"));
        assert!(run(without("root_slots"), &header, "00").contains("root_slots"));
        assert!(run(
            format!("[{}]", member(1, "2000").replace(&root, &"cd".repeat(31))),
            &header,
            "00"
        )
        .contains("32 bytes"));
        assert!(run(
            format!(
                "[{}]",
                member(1, "2000").replace(r#""root_slots":"64""#, r#""root_slots":64"#)
            ),
            &header,
            "00"
        )
        .contains("root_slots"));
        assert!(run(format!("[{}]", member(1, "2000")), &header, "00").contains("header"));
        assert!(run(format!("[{}]", member(1, "2000")), "0", "00").contains("hex"));
        assert!(run(format!("[{}]", member(1, "2000")), &header, "zz").contains("hex"));
    }

    const TX_ZERO: &str = "QTX17Y0MDLEDF8VUXNE6M9GXMAMDLPW8G7MKN2VFX3FFFFWPE8SMKJ4Q5E0U6V";
    const TX_ONE: &str = "QTX15JX99J6YWMM6JSSPT63FW8Y3CH933N9L7AHKQAAGCCWJQ933DL8SY8Y32R";
    const TX_HEADER: &str = "921000000000000041414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353530b0000000000000076616c696461746f722d3100d2496b000000000000000000000000";
    const TX_CERTIFICATE: &str = "9210000000000000070000000000000092100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e01414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd01010000000000000001000000000000009210000000000000070000000000000000000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd92100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e0141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c000000000000c45eaee47be7db3c89bf6ea618d6a54d2feb588f1bc67bfacf4f2023537e4c214bde953c55f97a460e85da8f6dc9a3dab844d5dc4e2ec3afc2d3a2d40e11b3e8af24d9c07c04e8877d51013e24cc2afbb6a51d06aaf172cb1a58e43b57d17c53e14d863f336f7e579b0c0c1b38dfd1866ae9ff0ab9dbf95cb4e1427e4e8eae8aaabea4c2dd43f4219a91b16807fc16582f257e259494ee6746cc6142bcb006ff8864b9e267a7427f8e04f6103f958a3ff12ba119f581524817c7ae2c27163d03bc8e81e1c036f64096bb79818eab201166a107eceda01ce90d5dc45837be471c6a89f769d48cd42a39db73a48640557b78eb7fabec3f7d6c2509afbc58ec5744bbd8b78c7a2d7673b29d1288b5a02298ee92ef2cee13de6d93fcd89f8f2bd57a3ad58b5f2da0e33e30279582063f914acf4af669569d1d1ba056e23fcf6243e49c7ff13ad617ee38d998d4838eb6a76dcb06971784aab7aa65088d4b83b16b7080daccafa57652f16768087118da4ed6a6061c6c22f7b0d42c78d4b2fb7e046f0ba907e2abf334d0f56614f57c095514956c2764a8230e093ad00d511edc536acf5bd05441cc189af6b9eee3712faba6307e961302f09577baa337be5a6d5876dba6f18b6fba05a6d3f31cb692b9b8297113e5243a742f6be673b26577f7c071c01d105947b4c2e3d322ad960d52fb403feab563837a9d31b263c767b3f321940b062b8864d1f29dedfe2051d2948c35c58be4f12fb9e9f6449588cdb2c46aae22d9b6b4bc2bf12dc918a1f53bd1a84294f383b1a14349a8065105992f028eaebd81c63cd76e4b5c933680349a8e8c0dcfd56badcf390544abe0ae3dd96befbb2f926ad47785040a409d682937b95a28d41b2850e61387b626b991ceea19080c72f34e6967fe332b744757d488299fe4479b9c70e423bd8de5fb3082a15c4c6d4ebdc401fda67a3eeba849c03f947db0b90bb364d5635da8fdc9eb5969078c1055c71e65a57a4f917c6e3b6754b419464dea016e8982d76e116fdac0779be319b89a5f16d9fdfd98c0332da3b074ff3190812d9a113da8df6cbc3a62be0f1f0e4582b3916354b4fda38007f915cc5ef87f5d98284b6834bca03fb1d33d0e4eefe45324ff52d066b6860bca8b5182e5874c692ede23cd6228301c12dad66996fb37a4e6a20494822ea45b5d43fb15d465baa01cedf50c34cdef038d6837da0a038d0bccae40729d19bd9defc71d76770a4bcce55de5fbd260f3ffb1387dd0ea7aef1a5a2f956262e7120d56fb1029e94dd26c2a5717d0850bc4da2e61b2dce4098aba93c2dc3b37685769812ab50d49be4aaa5e6ce0764faed8ae09700b3fd9ed3a6f999d933dc939fd2199fc4dc0640f89cc72abe72df96432cbac41636d6b1e3eb9f428e18d9fbc3db87c11e54e9a0e13ec0a08f0294e7b9ca6bdfdff9e2c05eba5d01bb5019649c66bc67b9a7543af367b3f7ecefae84e76b8d08c870de4aa4bfb2fc55af5f7f0c65ea7c3ccbbd2b2891d33235f9178a4a31e5c5948fea6fb606439f013b16bb92ffb0e2549ec6225fd6d5413c8a6d57bdca9777c6feaac831f2c6ed1acb94d7debfd1c99a2aaa73da98f4e232579cc35b294bebd7c75e0f6c2d81f9a7115336e6355a9eaec6e13f70b97d301da761a30acb36c6b50a26ce1025ae454857ecc00e821b2a2fe1ec6539446e7f859094486d0187c9b64df6df68afc38bf3f90d0f5cc5ed960e44d8bb6cdffca86d49c8f8c22c125887dba35dca5ac9f42f472f5ce01d39e86c5b847a35d2f5043ca1f78f903c1d718cceaaa9a34a69bf3c0d1ddeb82399ff3e26178153ad66dd834e8ce4180306c32146b554abc92aed480e533d2c76b91c9bcd19a321ad50d2652b581b3f6bdac82ea610b5f48c761b9364e7ecabf5a5d5a6544a8658e0d7da98d3719fb20ffdae67f1a5313e8bd5feb9c9242ebe148857ddb26f2cec5160cb20f9a756c0036806e385bcc4d830c59ec7123634aaaf3203395c481abcbe7f5a49a9109074f2aa687a309766430a1b686f702f5fa68b288f7e2830c6c90463b524be8681017767660ad54ee25992ecfd49407be7d3cd9757077f186180cd7ccbaee16489304bb847464772bb1ef6180d42db431a52cb6577be8e1aecceb8107f46df3886b4a16c12cd39d847c6169c442e3878a91cca85793fcc07bc8ff7d77d9fae0523d7660901459dfeb711a2934c5c3be342fecea3e855b8fb9e7244f081b44e066d30aa3a5192b32d3a3fdf8fdb5b34d1c07fe67c8c390030651241e8ff68b9cf3306016a7bf98734e3bf3ad521781be51144ce12643da47cb39244d3c2de8a66302c83b6f4afc249e23b802063d9e80bcc6afc3b0d26d3e0b23123b2f2296102e3d1fc595f4bcdfbb118135af429f243fd7de4e104c1c7b561e94139e16f259254bd3f4569de492d4ff8f1fc2ef7aba791f1825864e7a178c7842bbe93242dcc535a27e44b119c9fd1a0cb947bbd3ee0a80988131c465d0138735d3e840e5af18cf3d3faa472367e1779a831478af38b6365aed953ea0ec38d83f3e8687efbc98ffa6e221a1800aa0333202205bdd5733ca28f7d5e231d7576b2cf4c636dcc73332882d4100e0d04798d5520589324921c1a48cb13203c82cf628f973ff60eed632f0f87892371359488231bc91268b0a68d9b005064fd58e51e95e50321e97e640db2949dc97d03c3652cf5aa6a2f472e1e62c3c442f1accb153ed19f535fdec9d78239a92423ec08b5a28284e691099c7107321afb574aa6c6dee902e763152b427b33f3e2f1e73525229181e585cb82016f1176c4eff5fe937a6b415f56aa86c61cfab91308c07e2b94ebfe545926523a42a5e506506de2075e7183765f36d632c29126fcddae3ed27d6882998a68742f6863ea8a8e38b3659079a87570c9b02834cf5182ea61e822d7c07a99bc566deba445cd16edc8a928a3776d8c4a6f53c55ed472a30f3e9933d00e81c2af6b65605df0eced27a5c1eb0e23b237792a9e79a951ff7e34636831113d7cb01365d5734672a67709ccd0b28f276945d20417b06dd5a6b11872e26114d3d160dd511c9f85b6f9129746fc9ddc2221098c484f4013377ca7fc313364da1c1b60a047c87e0ae3bd5d2a05272984fcad3ca5b826e081cfacf89c4ff157bfc7ba6ce19883bcd0fbeb3a4360db10116d6ab5cda0e0eaa186e610a76d8c0ca28bb54991709b8a4eb0a6e5d4676f50518418b919246a59dc71f4c86624ac0e8252090570c5aea430a3a7612a91f38c3361b37239d3381530e8cdac907c5e9a3e87fd5aa83820ff0e274390a95807cb98c8bdcae5c269d6654e89e98193deaf7c31e2e968e47e7f042dc0510cfbc534a9e2f095a258b44a1cd610a22d5301f7db36c07cb573e101f51521904f80d2bacdf07534c81c62e413e54c2744501b0dbe4b5a86a3f7dee9c262adb4d48a8fd58b793ac2640ff05f6729202b8fa96f5b2b2c8c33a75cf7c6570711ef5e3880955f5db94a06334be446a715bc30bef5092fb6cedbae35074723bece8d15de4dac9d14f41c10b732719ef4536ece2621394976dab61ba93eefb7009763e6b4413582aa5e2b70ce4425285751ad86c15b35daab9287a2870b6e1d65a5fb79254f4ec7426fd608f85cf0888b59bd394ab08ab599d901b403e77d2fba5d02599f405657e5f7ec62c7d9f0c7a32e84feb917764bbac3fd1d459b22c7b2068496e00dc3ea5c0161ac0c0378c1dc2c97acc26ecac54dedd942c0234c1ef6d2429165f42cd2f08bf558d5880247ff08eace47cf61a206800308f5ff614c7e9c78710339b0d1de8a0013f4323534a40f3761125984a623173f935d58799dedcfcbd4080e02a758241e7e9191de027da744415bab347e7ac9c55fbdfc1f3be3d7f123cb7602366763e74cb71e9241e50c793c40e7295a8c2711be305d4fa590a9777d48d621f0583fb237e6e4a1d5c5f2b1b17f90be91104312cb5e44ee8ab7e58f3ecf3f8407282ae61edf9025db9c3fa90eea52d5dd3a287cb4853cbdb0c9215c7b6517b5328c0824bb0f30e56ce223c554a05bcf5a2bab29029bde73064ecb1cd28e79da33d4a714788f7040bdad169a8201a8806b6c13fa7ff06de4d4c1cd2e05f126b55d56f369743f68b2a3897b129c83289d9c1fd04287eb12612d93a08ccafc63285e9ce4b56b8c3f450aaa37887bb975cd17df4b3bc6c5890f186b8273184671fbc25b296c26678271ee0889488caf77973a05dc0f783835b58ac181e4a91a8dfad70da3c0e9994a1880c08e616b20c2f5c82c951b60b1aef2777fcc82739c20a8a7158274343d999489d83c0e17ccf333636248fb1c6ab6ce2b7236d26587c90757faaf463486b7b3bf0bd4933b0d2ba9c8861f762aabf915dce360622b912482f2a4706eb7765eb30d181be80bf5923b0d046c23b03f909f835b44bb4b5811c1be44329c0a779fa3bdb9bbf3c1d9d6faba6220f9a465808eeafd5287e9700f330ce095a94b87d03c90b56b17c43f180114d4e200f1cdd97ab538e991d2c4c8a674a757e9ac10db8f7ebe5f5c0445c237b2bde5ea6b58cd8022a438505f9623f035e70b8c2dc92c90b424e53548db2d6d9bbc1c3ccd0e51d2a79e4f9b6d5fa000000000000000000000000000000000000000000000000060811171c1f0000000000000000";
    const SETTLE_START_HEADER: &str = "881300000000000041414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353530b0000000000000076616c696461746f722d3100d2496b000000000000000000000000";
    const SETTLE_START_CERTIFICATE: &str = "881300000000000007000000000000008813000000000000ab830512a8e4c71953c24a18719e61e10b7ae1ea9b5684dedac2be73b758111901414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd01010000000000000001000000000000008813000000000000070000000000000000000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd8813000000000000ab830512a8e4c71953c24a18719e61e10b7ae1ea9b5684dedac2be73b75811190141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c00000000000041558e532f1710bac81a3d08207bdad20e069f494825cfede4a0f887f2fb9b5c92d6eea02d52b8b3842fd57a3d95bd53d76fbaf5fa2ed3b5a3f878b3642fbff78b05e2e4b8b594094c750860532f2f7128a8fbf8415d53fe0777993d5b1af777472dc974128839a88ca98d99ac0ca162e3995f183e450eb787143f8a5277e6e03c706521aeb9aa21092510202301642e41ae89ed8fd584ff256c30ec085d370fdbd449bf9e72ba8fb1c412bb0999384689483cfd03f3ea66a2a57dbb6841bad7e4168f4b42d328715b387a3cdecc583836ac2f4bfa8c9300e5bbea37de7172f8dfa00a76a63d38b4aa3974af499b3a0dd662acdd03e3da4a1bd7e3536c539243d0a9368d86753fa2521d88e51da252e75b75ca246f7662cb53f14152a63cd9197f166a9371518244286ebd31d16706f1d1e150975fbc92fb611f78bec9472b0915b5b28352793846ba2b2ac03562be1b4fd7dc6ae79e27697f31264c13550d45eaaf983a192b1a785b34c084f73ab5a66ee17594114fa399ddaddd681f71a2978d478cb40cf7fdd61ae522698133b95fae8308d1c2d7bf726717fcc6faa112388f8a7a3fd7d13d7a47f240cb646cadc65b3301156b3ac061762f833e29c33a5cad42dd390be06456a8f171d41b6f36682d5a5c35edcd88ce92ce85439647908b293ab1886efc3be705ed621cde1f023a8aa61e9d96ce6043e162733b44c3c334762001b2e83024afa54bf4af5249c89b13e647914e6e1ff5001bdfe9d12bded6968e383a9f568977d52fe628ceaf3eb1056e9dd30389daf52d947665d77d97b3381251243d3e449c5f3f10325aea2e9f9e80c50a7624852dddf6944b32474fdbe85e2027d48d177a35bf0ef81d37acf4b2601bd504fbc1dbcd453fa9b96c6af5a86b2939e9e30fa18f6d2859ba54a3aa7a83409c4fdee6a29d423f34d3faec250a9c882a0910e64d1f48c746a7500a7e7bff396d5a313a13c226968dad94cfe3c02c6e77a83585ad9814e1a5fdcd8634e55b4876cefeb1eed3e96f5445f579942c15b263887214409ecb6904a84054bc2b18f122045b88ae2b2c765d371cab3b02b237f9fb50486631b52646dbdeff95949b06f5f4a9343586d6f69c78563016d0337bb0a88b33aa077b7bfb31799e460abb1dc6298210aac40a6d46523768459c5dbbb5f6d3a7f51ab684942073636de96937c356b0afcf85f664c74c5b0a71ad3f5ba804b0dea45bf6e104d4a9989c4260c20d23ad74dac3ee5cfc9e8483d24ca9a9d2fe99184c11a25ce3fb25be45685478440e4c1d122df1633ee2d85f5365e4005de000ad19e3ea51467db279939b4e42e7bd6cf198a97f39152019808fac0c00a686147e68b0a334cbc33f629209b762c7396e9b7699c6c0d5dfb6c23eeabf004143a65f8fc70d923168323c0523411d955d0fd8f22384a42caf4ed3757f26bd316aff4dab9528a08d6f95791d277502dec45de3a9118895d8127104510929bd2056f98806a531c91304daf9fd6879d0de231648d4cd63985ae96c5493851575daacfed58b584d4b3bdf4e26955d92af5553cd84cba18ced76fb976894d285749df429f27970209fbf0f51c298ee99d220a9c9f95a5ea1880d7ef1ac193952997921685d3bd244ffbc0d14156b94927ff9b9fc8046419f0f3b75473ee59f133294f245e3543541f094352aa4843778c1a47f1ceecddb3017cb7b455cd586086c0d56e7b81380555ad0aa1f687898332d9e603127eb39f50562d362e0491595200ee5111b0f13663909e35a79338cb81f3a5cdbd9d27e6abe610a8b0a4421fc557fd6417ef6899fddf19cadc68f7632d956ce69d6158197969d4aa903611a9f97fee083e0df88f8b2d8a7ebd61bfd8724aa94cd31f3045432522954428a00d9ab341f72ed35cfac0b28d2aff8be3abe081b82a3f9707e64b5d25cfc78869f6f2f8995646f509a498e462e8a437c8a2ab653ce91c64d089a8da885574617dde9653202b5b85947b74305500168061d900c167c340720e0ad240ad9fbab4157f58c80ecb79f057da37c8f314109ca78a923cb1e8900e8d14a7fb1dda853e98a3caad7757d856231669b28a78041fd4c230b9c37fc306f90d346f11d218ecb963723a055df4ecc893efa53d2ede03528de8d341b329b462e290a04fd9f518d8bb9859600a2f2e2ac99e637bb77d5ed360c9bbc60dde1edcceaac030e53235811472a8705683187d71612e898acecf48bf6db1875a42b1e479d78156057f1c93097a74bc1f6f96e266fb18f9a50e9810a298430dfd619ef4bf808146d8df6d8cc20e39ce718320b6f30c7529861b3c2270895449fbe17d22ef98178a31a9d580ede7da13811d1d647336321b6bfa697017aa92285754e4e3c86dd7c0bce60d2625ebcf0a435867bb11d59363dd8d57451a57d177022b73ff6e42097f1d4caf02d4bfd6b16b3c3158736d26a1cc14c9781d50aae711d46cf6bcb49a48741f6c4edbc2496bd9635935ee79000f9aea4e5fd9b289c5d473ad9d2815ed7fb516cc842ae5be6ed3cab2916862f2131378c4db07b8d58fd0c53b8dd82a25ba7412908aea1afd56636e5aec4a14f2cbfc2af029c7ed571a65a822791a614e98b9d440665dd2a02b76404242870bac0aaeb96bbfd01181c001e8208018c3e1bf9dcfced014d8c30f9d0144d1b64064bd40638d42626113e5c114b0c6ac13d113c813b29ce5ac152d9d0e10b21d9d62ca90ade6f22a3840bae16cf6d6a4d2d32c4a75d5f9c85026f8b15422c27a2f549808f0e98fe196ed435fc58302787b0c94353b567b4e2b6191c4171510a8292703669b1d221d5bda6cf3603b366e0d224686c37b0866d7658753d1d6e1470da354d936a2ec19dca8ca48a99889e1b04b85f523b6a5b1adb9d4c020f2bea1c9c020979bb9f4a2cbb0b83e72d02e0b9b14a058312b7f8ee9cc77e617f8b4c320208249d99c793ce2c11928e38484f02dc958372b44b7c6c906800763d47a5f85c16005400f2db8bd93442ed954508e2489744357a6437c1d0ea48bbcc7f9bfd14d44ca9d106722a0a7276f7bd912e943b9b00d8d335bdeb6b2ba20f32b2b046f70ca391f345e658b04963b10b5e51f634a0d16ddf9501b87c8fb4baaed92c16e16f25f99cd76b6609bf9571dcd98562ee6da3dafb04732794c855df58b302af709ba3b2b87a6f291a912b589889eff2b9f265a6d166845e90e301067321eeebe5d74261cf3d88071906b62f63a158f55774bdb3b95cef3f5fe6d5bc314f3aca7a8d6a5bf0a754822c226a3e3a61a89cfd45d19d1333afda4d482395cd669f4ac7bc53e02b3098dd648a158935bb6fc24bda45a057a4c4044e4f30ccda8f22f2eff817d7ecbe932dcdae003dfb9dd8f2b8fafd933edc125d8933a8d7478a3b1763d3079c95aeee4c7056e07bd5bb516a97833142652a87f9b3c93c87a4725ff25210ee928a5ac47e9daa392907a96c08e1c64543be6c7017f84be02f084321312f691264d40f6cc7ec0995667bcc2be382c096a5371ef11a9ed59f5ce217daaacc3e005faf707bcf534a68fb363dde72f00357c6241b103b4ef7d710966afafa55b170fcb0ce152d834eb1b2d253c797c21ddcbf9b31942477198e790dee55bb820f4bd4d9f066fcf24b27223a31dac1fc4d5dab74c79c37a2342f48082275dc46512cdb95a2c0d2f2b20ce619127e684f425fd41745af5c0a68fb0482c208b2d0a9ad449fadd4fcac6a07971b64693016895e12d3c0c56f451c81c7037c73d8c2aff68f84ded5e948debe8308a9a94c59651ea47bafaef1afc66a7ccf0e24997af0afdd2ee71067f921cd041b9038d7e03048ea2d9c72dfcfa599df03706ed5826e575b1d2c6c4e890e360a7c084bc50a3f69d853827d96397e1b8270dee61515ae4cf959e2b719fecdc875133580df3ae586b2b940978cd33331c07324b3d91f2212e998e5b62efe0bfc7efc9eae4b7489f8a4c19532be00c5d4dd4be8dd3dec884c30b738c4ebe2be04bf5c3c89b85d75077da72ec3c9d10c748361cd76e30d96ab1f5c56bf12dd9247d92d73f385354fce5c658fcf98beb0c06208602d965150268a468c578cd5bf88d95e16f6a4f0101197b59e4993b7509105c71edcd22831204a114e52d858dc3a2b8856bae33ed16dbc448937f87300e97b63e08a70c76bccda3964c8a36a9478134ff58fbb05a26ca11097ee185493b466413142b5533054561acb80017a38587b1f9940df7b06b0d981774df898293b3509bee8a7f27d565c901a96cd8a1026da56e35ec133685b43f8d8efc6558817f8a1656cea863d269c1154b9ce3d8e93bd6c27f98c6f7e780e495d2dd32c4ffb6cc5412e77875fd4106d0ddaec2de43225e57ede342c9ca0816017b1057fc2a489b41d0c142eff06321ded4d2908565ee9e0adfc33aea80613debbb775d46041137fcd613e08dc1a25ef8a5cbde598a731a519dcf6df775212e5d19f257639157fe7d6370dc4b40f7610a871ecfadf02b7d7fd92a54c7945a2197bc78d0353548124d0a47afd3c999dbe402073f11ec7b92474db620d2a339422f80aada79313cb02b6f870abbdf4cd843c035e6796aed3f124492a32344c7683959f66a4e8073e8093d3121734797b9fa9abdafb00000000000000000000000000000000000000000709111419230000000000000000";
    const SETTLE_END_HEADER: &str = "992100000000000041414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353530b0000000000000076616c696461746f722d31d0d4496b000000000000000000000000";
    const SETTLE_END_CERTIFICATE: &str = "99210000000000000700000000000000992100000000000074ef72654e6965fcce1fa84fcd75bed8d7046efa00b65956d4a56a150c96454901414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd01010000000000000001000000000000009921000000000000070000000000000000000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd992100000000000074ef72654e6965fcce1fa84fcd75bed8d7046efa00b65956d4a56a150c9645490141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c00000000000003852eef60cc9ba748a21df044471d002223579ce8ab865bfbcfbff80bdb1ba61af0d20000782508a179b7c8ab8352a0a2b959a5c67bf1a3826b36afd4827b661034ebd7f5357c2ccf7890828f0059d261d36f565548c267e4da9b2bf276ae6ae2b565654501aec15a49fd976e43009523d491930f0e6bd9dfaa3ddd80a8ba39cb5009d6c794ecb139b4ba44b91543e1253e3416b2371a7162d2179febc94a0295a87f477ea8f485bf0c39ad33b2f4532f3b8f4a181c52e1a7a85f84708b2ba2b6216a6c28436ea350e19e9d17b9e7c43983899e12fd9cd931a72e72f1edd56f3b430a54a70cc877e74a3449fc19a43135b847a2e39928d3629124e3473978bc8cc684148bebb3076d2e5aa291a4424e7e7d4f1c9388cb75a32651d61daa82f47f482498ca324204676f44f44b0c8f3ca66527f3f606f8d71bb597998ae40844554464527a5f0e9640e5c5f2ff4a809c950ca82af5b700d59a3c8dbf5a96da90814b12e58bffc28ab2e0e09b56862b26eba0311a584ffb2e3866233f491b6971b46eb1f46f09e76ac9b972f79194b1d9678ec41cd6b49d462fc93ff19c2c79c524b525f9c1ad7df14275e2d0178b0816268b82ac5501927635a5b38ed024706c2d9c6525332268664bc1c66e7353b27b44b98ddf52d16e1066e54108a8090aa89d7afb4e102670baff40e1ff5dcbd65cf477a64222f1ab8af3e8ac91951703d58e083259a793e1a3f86d77659100a1058468bfeb33fbc4f274ebf97cfaf9eab7b8621086fe3a429294c4c3d85026217f4a22ed59f4d9e3d7ec3a21404f219b261f4a241374e2d927d7c97606e735d7806378fcdcaa1b7c44a718bb88e239019c4564dfb8f3b121aae1572156a29902547640aa1bd9c503f95f400331c66ac34305b7d9df0a91fbdfaa75a4c047f6b71a990bc52209c8c5086dc0dcfd82e8c9e6d9b190a28a6a4c5e1ca4cb2c6d1f338f60dcfbfab7ef3e494c3385af33b3743e9db88a03165bc6cb2191972f927159a3faaa7d414b5a66725027698887bec76e9814ba621f4ade4a74a8047fbc45f07b8b56b0d00edf7d7604cb346969c89d136d79659017803adf7e02f2e0af9058bdeb4a82520a18140a1866b89efc94b973adb2c263dafcd69cd47f5b3c43040c620684646f851f468f720704b180aba5feb27582a359998023820907c3fe85813fa7b316a01c90f344ae904ea763bbe616ae34209544878fd2809f2e872bb90f018ca89f123bc6d4576c0ad690397f9ab0df11f645f97e8dd2f50ea70a4e2c5be5e45f6feed64ac3848cb8ab4c4d64095e5839cc50a00ecdb5cb71f8461d5837f027d641cffdde06a3c1fb68081f12fab539c4e45db309f349e5cb7f257e8bd6e9e65dca46e03396b21bbed55e78cfcd152b9477d9c5ff593264f36c5efc08a9a9d70e22cabace556f0ad537f276a751eab1e3e6f2033ff79632bd25ea1043a1733adc70025d6309e16cca608c8c3f52bd62b38759726d184a748cab76bb69658fb8f1a4187a6307e24bd1e343a569bce167f871f3f7f629bd22c27c89b6d704b8e747be35af815ec4239db708b0fbba9a279c3378c6853ef466af92984b83a4d56b108b8829cde29d38900c9df4fcfb1eb670a11091db54ef2f819f47715d807cc9f2b5142e91379eab3979c7e9a16f302834ba86a861488904f641cd61b9817c804c92fc1ba93d83a5ef66327e9be41d1eaddff5bb5a479d9770bfa2a62b8f456d03455eec6a562a77682b1429731000f86a86a9ec44d65bd6b7a1f3b88e845f905b9ce77742e556f67de09e88c71fc7571bd876911a587c3c29f5cff48569c3724b1c0afe1c5af8c778ccc5021c84f5b35df5acc53ce0ea4fde790c6fff50594e2ca389874cf7296b264d6782d550073e0630849c732985246154db4e3fa71cd48c38c101bd6500091a62a346c58783668fcfded2ffcedc2fa79f952d7c72e3ba5d16ada2fb425f1885c69a83cd860327b43e2d88da7c9e8cccd76c96b4f9db7fa133c4790aa805c9a52b7b2c279b95d15f33e97d461f58ac4cf6fe51352c894bdbc64788978500e0aac64ee6ca1fd52953e5613eb2184458487df0ca808275b0b5f9040dbcd24aff8fb9aba7dbc2c29d7b4cfde8165a2255eb0d7f9e008c27920032f469c11604c508e5f1cec9bba4cb4933c0197962bd3f0e5404ba532198f798682b6ef788a0c6c75af4490cf29f3739475a71fe5558b353e62b3ee5bf6a2c471007fd23bb59fbcae48aec4992cc9627c7eeadb8054203188e72a260cfd5efd9fd17c83d08eecbc5f49b38afc99f048b72b785cf860a7eb30c5e3b59026927a1efa2142c2fab3664a05046354a68fe1d14bcd5522d11433fdf8d4de0ec85a3158b6fb19976b1849477ea3850192c68adb0de6d3f112dc5d2bbeb211152f5964a11b6a378222ef13584621d18355f75770ced0470027766bc478dd6a44df951074fa8c950fbdec762ca4ca103d9aa16d331a42f26484547bc462f596c5731877bf4ffb784b3535e84dc605785057588fd39ec5c7607adbc275493f3def2108c7f5ba1f05b29d280e11a9856a29b2042f45ea45c87dabba20bd04c490a1d03819fc2d92b6fb42bb1824f8c433e124e44ee8b62981dc257324ab156437619ce1eff3891ea7eb45692e2a48da8fddc67e103083364dbcaea4d507dccd35e3ee946caf8950d3a346edd3cba9269418ce0d1762bae3100d01a6a2493118d44623a235b815ea7c32e2c055cd7e173ccb698cf7d37d944227be694ddf852fd2216fee0a1722a90bbf0d6399e573703ba37fa9e233c9bb544b4393006f339c1c6eca7df7053d61ab6aaf73777a296a0bda38ed1768e40d5e6acf21842ab20de0259aae9c2facdcfdf45d95398ce322e89633e5b41204f65ecffa5c1bb992a169f8f842721f0634fa1da9f30ab394ab2bf88d8a68bfaac2ad27da3a2add5b585128a3222b474fb71c1cd67b7dc0979648b5a6bd521d23ba4bd50042ed12c33178ef591e6e39829a0f2ace040e98ed489a6edcada3c19ea6ba420b6da1b50e523710b61ccad5284c23a5a49dbb1b2898378d317a69e63b60ca99515ab50d6f710c736cfa3a3279020a12fc1b1b52f6917edee5a2904d215bcaa5186ec7416ddd04752a32b585d949fd522025305394f1e4db6351939d72e48384d651d480ee407bdabe39345ff333664d1c7ba802254fcf2e9d3a61c3ec822533b5a3c730bc2d4719c0e0cb8fdac05cbd3d78d81d58c7b3d5eb5a759d4056916980dc2aa7494eadce93edac8ecdd8fe352880b706a2ae01238c344f751d3527319556e53b1ffaa951acb157c2946fcd8560607c914b243ec61bb2e3e82902581d34500b0e24a83d62c5ad5693d79e76b40e5e1da2d3978a58ad010a574be75698fc404ea053f749d399a9ee93e98eebdf12145a930dc37c126faa535f9dda065d2728994084172954b2a582cd6b66898449845bb90513d07a4494b9273acdcb9c0b4ac934fbb518ee39dd55e332470e3016b7d301f6951be48411c8a0bf7c4c006386050681715751c95b303a2f39043614d915fe2f0ad3ae1b60953cffca6417e59072db1eb2695d79bac6c62359e3fa6cae03818b1d19cab00acee7c710a986d8754cbd8a16f5986a1b517595cc7315364994dad558213ea4aee07974f2eae7c5c92e4bb10d1658bd06b09984c019f61636207eba6253e16b1b6ac04be08fc332fcbbaf4a8cfea630ecdbfdf1290eb9459af4e0ab524a2d903d2ba38ba0011b8902cb0e4fc6b2c314456893917def72c660a32b8e199dcd9a7cae537c62469d9d2a415e67c4f11f36fec63ffae31b4379ea6367e9035ebc84fbd6c6f592abf0d8a9ef17de850dae785b0709dd9b01a58b3cf6d5d9db85d3fa9ddb0a2a629afcc16d84564c6452c296a82ad9b8cf74bbf3c33c012cd4e2a9c0be28bcd00b9974d4832289e10fd63431f062ed0bfefac1e32f051003c405567933708d851b3c8ad3351ff95b591a326471cf3a5ce179744fae58bec31a26126af38519baf00c501bd4584c96bb200cc6335e7ecfc369373853df6ec8a6ab014f16e5ec11059d8156dda4b65fb354099ec13437979df7d4074a8e25ea24626b246870e9d1fbe60e18ef58d174511dce9b03c6e56f8cccfe80db68fab024cfbe255b6c91a8764a4478e1f24981bb8551a55fdfbeed94ed76b87de880e781065979c885433f482cac3795909f08d082dfd909ff8bcd3561c526e57476cd17ba528fd35d3955b183bab479aac0f10ec3f44a0e994dee451ae914a198909adaabc7f32e0e9d11588b00448bd2b8424320bb983edf421b46cb4d17c459dd922a41941cd9544e304d3a7a795dc325ae59c353e6f654edee420b1696c10aca5e81b5354aa3816cca32f1832cec2ae25ce4f80b0468224833f7df774e10362a29aeb91a087f3b7d887f5b6e490a56fff47297fb1db521399d19a9af9d2776f6bf8385fa05be4f05f931c069f3deeca71c1c179e0f2992d2a10566e6adeeb60b7f5ca7f641bcc30b8b7a9af8171711bebbf1f2047a2021bf5996c0a454f486ef8161f9eabea56319edfbd7adc585f1131ed4c631cda01354baff2515474acb5cce5e9f10f2db9c8e92b353c93c7ee234c9eacc367b6d000000000000000000000000000000000000000000000050e13191e210000000000000000";
    const SETTLE_SHORT_HEADER: &str = "982100000000000041414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353530b0000000000000076616c696461746f722d31d0d4496b000000000000000000000000";
    const SETTLE_SHORT_CERTIFICATE: &str = "9821000000000000070000000000000098210000000000000fc3fbe342539d7ffd53f2ab4e14a072521e36fb0003e05f43930a39d41620d001414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd01010000000000000001000000000000009821000000000000070000000000000000000000000000002000000000000000d98949bfbad180c4bf52ae2224b45ef1e2d15cbf143b14647546896c938732cd98210000000000000fc3fbe342539d7ffd53f2ab4e14a072521e36fb0003e05f43930a39d41620d00141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c00000000000065ec9509a728d2f77dd2620a67a6cee57637d7e24be29c8dba9a754f06a651e5cd2d381f9585b08dcaa494fed0041059232caa852120e1d10526084185f842ccb18f0c3a450d9c48c985210e4558211e2116b732ce207ef5dbac46f10937502b484b9ef962b1c356d4d93b550601c9aa66457493ddf129e057c17e49881095f042c42437801a15cfb2f6b77dcab8fbf44adb4e161767358cb4bd97341320e65e179b74279a3bd71254045ec07ce7169051333e209043a734c261d1cea7fe42038c4bd75d94b16320c84dc30f4097e27d69141db3e755a276a67231ef82182b755a45abcef8bb63966bd3f6cbb7270b42d3f26efc8f3a00313a52d94592f739b157841b1c761efb6347b6c86c1d0feefae48bea782f2ac758eb18af508ce86d90a4bf4724f453f8ca77007930d42a9f724b11bbf475e989f361fb76d3e450e12b439fdb1b8d52fd96851481aebb8f48cf26e91b8308a814fe7ccdcea5c0e671e8be73ad2117ca8626a0cd9486ab8882ec66d00fff4ff137091137e08f5d5ddda1ad44126ce7fc41a0298ec9e433166b405e4bbd3e8374c51bd6fd8df3d5f1ed84a42c6cdc06e8fd21e8d1dffc0c1a61798abc1033d557de5b3803de2d6b1553ac4e543fcc23b3bc5ad6bdd7481e6a2f8ada81ba19d9f619e3b06ea4f5c587dddc2b90a1dbe5331576cf0f86913834fc50b44c905179f25fcb0f6e10c23e46cfd6a9ec5fa22206d567eff2b1074bc8ef0939932fc591ef04dd63e858c1da6c4af88f3dc23503ef49d2922d90eef631e05af4f310c8cacd9163c2d57625fd5ce1affa5746bce17c7079d462dbcf47a8a78848ee43602802f3af1757c3e2b917cdd5ca8c465e8e50c2fc562f7853a62bd95c4c45e8c136c059f43f037c1c25b8a7d2d45162aac65bd2d54a1adccc49b70a0e80c422fbfa56fece3bdbf14488243707ff052ecfdb09d1059f6fffcd1a7ed1e871f2d9b6b4d0d62f1b3e51050e9f88baf877c1c20f98e3c2004e2220a626942c38d128c271248701768df48f27eb633096c2f7931f50080f03240f19c73fa7a95ad8c94d435eba796ccff9725158de29970e3fcbf7ca4dd567d414e595dc33e5e07d8fd9590af6f5113b26c55fe2e3043f1f1e7b4fe707633168ae37bd4277c8ef4d44b08ca53736d3a059a8b9b22cf8d0603fbe12ab41b564deb67fb8c8713a00424917261e4a987907196eb03c632fb8b5df0355892ca8846d224e5a6283d6b23104e0bda988eff53e9d2b6d278cdba412349fa761f345f0fd53e596082efe62e3d4155e82dbc8694ca13c519019ce8ef67d7940b650c1ea4375f264e3ceed2f565b8bee0bd4108045bed6a111c1ff363c589daf2be825a649409e642169365449a4f9f74478c7ce32c30bba6eba889f5261e26227d77b94729e5a579e88f3a9403dd0cc1abb3eac5c37dba104746329e304a15d9f97b1608a1b729133db7ef28b141eeb3e337b46ea968dbf54ce347874f75431c5ff023a5359dfabd6d338e4dd88fc7604d5656be5ec132dfef46f1d8388ef623f668cff078da4e9cd7000979ef74cbfe3bd94a5e39b940ab72f18464fb20e589a8d719208552fa93291699d554b191480dde47bd282912c83ac87449383e7e648d751cd1c8bd4756722983b53e0cbd70d1d3dda5075c039ded2c74ec74ee52ef266954a3f6ed8fe7f9aef452ee2f1e1bb4bbcf1e073481d82bacb47bd09e9ab7e50adab8cb8e5c15c152e37643bd1245ad2e148bea328d0948fb0d3a77f93a1b55e19d7416e806e91d2aa4ea6c5d6317696b1b80fb17d6d81ac5f80ba6fd71a884f37fc3a779bebcd92cc63c8e0a758032b08585b87103dcb1cc24f778bd7377628f8adf1d5e0a07e5235444c6cb7481dfe15900bffafe496d10793e11c7ff402640beacb1555282b2bdef326ae1a0fd2e60882ee7f66b83cb6d1e7959b2e8921621347606fae035c69424699fabd6309aeb6387325e65b5930f915e4ffdb93f1e60a64ffc859a28bb0e707c573d4e46d2c81095a530853761c74f02b1a68d4673e2bdb4fe47044ca49c7188f2a7f2dc53e2e171a56a137fdc20d436f0e920d6d4552bbe0ca4c17869b3f7f6139c611b6546629a1f1bdb4a96061f510a73a79b04a9616fee3c53d07a2a32e6fc1e47212cbe5a236b71adc92f3951e519ca151266c6a73ede812b7839dc019720f908cb2b19f7b67fb3569f11b39d8d545751adb93d0f5cb18b4c9a60fd97cae1aadcf532164fcebf5a7b97801db80f730dd80eac981f7ba502323f18d16a7317070b8a99a919acdf2c4da6ad0c381b708975608797a36514bbf05451d46758e5327390da0b8b69dafb123305da87740ca3e1bfc13eaa7a401ab80d4897ad1e0a9e1a1b5d39fa78f38ca2c17363740d993ca63729384d67810c2a5c47dca21240e709cdc764ece5ed827122ac8b839e95cbd892d1b4397a24e55ea6f73b73d925fb72c23d88174e7005879985a67fe4b27ad65fec2ab0244faa253945986fe94f1e0ac28c458fadfce99860102db31f5c8de32a0592934bbc4a4bc44230b21c1b532c601efc2d4f772d0e41ab64501b9a6427e9fbd7adf35361c9bf925a5cc0021cda7a70bc849aefb31b02164d1e2eacf28ef5ea0e922379db9d1ad06eeced8205eb6167f2d9239cc5f6f0770a9bb83f96eb2efa5ce01e6485f4ee5d07ca9a0baacfeda77acde493bbf678422407023538872ad6e3cf68347a4f6e12535bd930a686ec0f8007a46bb33899844e3db8537ae3eaa0b2b4fcac0e48c972c7d53999927d5a8c856b4d961e7158a66e29cb9b94a331788339c892b4269a238e7b74e03020d27e57bd626ac903749df3dcec7050dcf6c2116353891c84cf42dc735875a7d557cf0c588018909d80f34e49fc3b76a29cc2b5ddb79dc276848cd6ecba9a0c2c2a76c412a5df70a27c581ace8511d6df16ec96db518ae6c3e7152027db0a82d4a7c6cca679d5246e00b90413d3850d113475c08f059aefb8292b812996a18e1f08a9bd32544ce51ad079aa7dce28bf7004f270dcafd471a905980f7d6350c22618628b74ad54219f85774b45da366750cbe11a225380ca3083a8866c4940053cfeb5a02c0dd33bb45fb8d242b62b52391b9ec7810dd3c19d0b060d3922b449a09772891fbcfa48b814102271b008811abcf43d8785bfcd74e843b6e85f075ca55cff14c337cc824b0079a6550d9a20a795acb7f0447999af98659fee83ff42569e013d7d561951f4e5b0953bb2405d0aed6e861338fb59922055a260958470fb3133185b65427c0369d35b769e29de9a887d09d9a81ef5cc130bdcfa3c6e9e0590697ac4ff634ae2bf9370662414477cbdd7638fe458b03bf44e9ad242433da6fafd84a84e28149e3e6dcd71240d7592d66b579d29d618161b26b6551d65f3c1d9dcc4a631a3ab52a4fa4b0b3effb43d38ff6c6ef948642de5a35e7430cdac8800736184a97812b250a2ab0a1c9069d11cb9c5bd70064ca20a9241e1311a86c081f5620798f89c47e9d8ab10fbd7be6112196c236437fd6fee62b849b17da5f4eb011bcad9c82e1476aaef74da1e517e401e1d942aa4a36c2737f5e5fa0d49cd2fa7a99cc20f19de61f03ddca74c24bc1b27b761771e13aa07cab3dcf4b1d12647a3c698ab658cfb8d9d5199e9afb4d10aececf4ae370c6b484512f3f785675c30e75b0ac2abd63da329da96030d7397b30a81887dcea0bb431ff2b584a6fda316e340d7cf9cf0be58e509413660811e7fe7ef536bbfed927d0145aa1a40fa1ad9bbf59c4343517f424218cedeeb18d238ab75ea02cba7c5b8b1f6323153d3dea20861acbbff3b8d32b65be3e444ecc0256e270bf70b38ed90589b8b89840afcf9f20325c5d84881269bd6f7b24ed22605fa431a9092c0d5495f4a55f33044f61f2926914e0a27daf69613afd62121dd699c7c91747868977c03e5e1cf28975c85e02653c997a6d0c83b934e83e1f59a6802e1bce5110e3831340db65e8873c441e3ab6a4d6282b2f0f9e69759db1bc9d4c9a658a12189f66175c69cc75181f7260434d87d71de46e3faccfeeb994f4d6a8f950d817d7899b19834bd8dca809b6e578b39f4b2c57fa9bc1222d97d563d433f635f405f956ea2d6235007aa31ee4d042992253d89732a2d73ffa27d97e75b5b6183bf6c91c50da08826e4b1393d401f356d4f9ec3e3736a7d2d740b31b9c11b68161cdd39e7978b0a47932d5a0bf5d9ccc6f844c3aeba3bc5b1b1eb32827aae422bd60afea7964bad7def015e840c780710be86c4ba8288ec5a6cceebc2478b027dcbaf16862031df937700b0e69cc2b99ae0893ae694b6a7f2ea8864c2cf719f29eeba8a6544ea619b1d055e1c527bd7e61c9ef9665eca1e664ef4d3059aa6701d72e130309209d9bad085db854b7601a92e8e0fd5c8bd30f27a918c4fed2c527242f1a7825469044c5eae39d1d7937086b46b84f15fcfa22ada61162e25a62bdd45618ce8c8eeec1e787a5f08d43108f2fcaae5b7c11cf6a267950ae37288e81a6d45d5fb9d38ad1e7549c15f3b1a56becdb2c9d0775dcd9962ad69d7d40dabe297dab1e2818ea8d6bf983e314192b3c4468787c5772ea1696b0d2f249de00000000000000000000000000000000000000000000000000000000000000000002040c0f14160000000000000000";
    const TX_GENESIS: &str = "f9e7cacb1fdf19717db9c7506eadd645688f5cad2d458dd6d37425bd5dde75cc";
    const TX_ATTEST_PK: &str = "e0918f8265f34cbcfc70a75981a38540b1fe8ca76092df418540c1380ba44288e0fca3ce4c4ea6c905d2d6dd1a73e28f3a553f78f0bd6e648c6179ef2647070ae4687d27547fc10629b44f15fa1c70a40716375f1076f8dcac57a5dfd5027e0d2d36d441ff75dbe7b3d33b2b34a8bc0e07d75b3d8d9945e774f987a8bc7a4e00c27265d869b68a3a8e33a14dd8508a0b7adff4c58925c35636186f1d6f6842e5aeeda2e2ff8bcfe063a080bc989fc4c000d501d28bf6978e31c421040b504b31fe4040eec45c6a5bf42207068224f5746c75880144cf8edd933a717976f1a1aedee087d8f44e1659b8e88424e2864dd32849d841287cefd02e83fabe8d271325cc26266461925832e9a4382d16f1f9c6c1a9b677b8a8fa1606a59b372ad66a80773c056647fc346b79cfce9323bfe7fbf7f07235b949654dac8916b47334c7ed7eb6acfe06581a29ebd02d57ee1d9db20f25ca0e5b477caa5fa635905bdb803ceb69cd067944bfca49aa62093c1b5d17186528f78e79ae2f7edd786a4915970e34517670f72feb5203350ed3283dd0dd6e654e5a72dffef8d03d2117bb1b19bbe56607f11a722daef3a98a0a32af4ac40a1968442eb128592bcfbde1ebe926b46a46f48aa255a01968c52581d9a44984c489a12d135dd804658bc23f42652c8d9eea169a10074b3846f459054bfd7be3649db1e786a78c5518cb37e99f6c4a2c6639a990fec3ee4558e4fa6aec9c5e3e04d885478dce2ce141c8e0a318441a41a8a599861c843e4f807d9b9b437de65c9a422047abae1a45f6f569e202ecfd65e3c1d7f73ee1f82df080909ae9a943b8340c08cde5f0a8bf8aaaafcba28c09cf66bed71bc8f6ebc366031eb48e95cbd3c777d0c797854d1d17d9ff8ad9754c4f8f66f7b7f27de875193a4cfd99b96f456c9e1a63db8b08eb01e434e5fd8a6ee22c3ec2335cfe1c7bce484e29df2593d18faf20523441dc71aae22dd26e604dec0ced45c9f34e8fe66276dee13b3d04ad9546d9712791fb33e08827d9146a7130125f139d71982898d9bb7182eb10b624cb54a85dae100cede8accd247bab68646c47b44ce181fa0f44aa35205bfa48525cefb362b039e1d6cc747777d419eafd05cbdf4912f1a58597d50c828f1111601a4f9db780b1cdf578211edea900f9a163ca07bd35518c1529fe9a649df5ce4e17281a2749144332a6b4f579cc179d16d54035b66418afd4e305b58cde1a39ef6427544e4a1fcdc8fe0c0fd20c92c018e12750eb5779419c87eb9f8d740e4a52b2ac2af8b3507b2133cabf15258c2cb1e35ae228b1dd42a6dd1d652c449d768089f7b8827cc30d7cb1aa41b8bd53f8356587d94021d09cebe938bfcf146f62ebee6fed8cb916fa53496773d3a60f3171967c0fda7a3f42ddb92391741b6c61f4eb9faed8a3dadb3cc038db810603ac40042cca25fb4a88d9a55ce1c4d250fca673764e2e9415a0c5985b254deab7c59a6be122e190c1d8f416bd9271495d2c4747de60b2e85db74f92e030114300bc7efbb620e64f5e501a102f4eb194f7a8a314509f885bd4968431f86fc6e9038daf8f3f9d6d539a42c86b1750fb0912636d1790de6bd871ecbf33c76380d6ba3cd180f4dad0e51f109314d0bc6794c68eac5dd8375aaf9b59fe51d04cde7290e2d301417089fdbec6a4379cecad89eb52bcccc096b7627ac34c9acfb1900dc59c63116496404de7825bde8a7e262429ed552c14e473cb4bbaf4291bcd921672b5e7a6c3c863297adeb92cbe79581feeb866c8dfdb90d575666bad82cc8f4c27d3d62bb8a96d3c635c0353dc8581fa223b301dcbdc184869c0613fc76e68bbec3a66d587252f8be5da104ba29f003e799de30063d17dc5219209b7b0a133c7c5f9748b1f3f52f6ad51f2e915497520629ef9068d8df3afc920eb697a6ef8abe01876580f1b652c0cf01f785f15e1fb24fa1b196a6d50866dbb546ac3b80a64ea7292bf78bdd7bb4a8ab615a90b06ea9403332c6d049d614ab4a788463321a1b4a33f160cee7c8c0cd4452bc65caea71221d5ea91ee3d2e203dc496013bc0ab2299f3db7108cb2907e0ec154ee3ef5f5825be272299d64899f45a86be7612f00fd8d0d62e73c2d1c80aef98d94c4078a58d228abf4aad54e78151b854fc4992c7aa74e98a36deadbe11acf3cae8a129c6414ca0765dad6770f6eefcf3004a21fa31fc2d03d1edb27521d2bf0341267752eaa0cbafdfc3d2ad65574c29139104e4389a435ffecf50d7b0ed94627271096d39f71ce781a49c06ae2e14184c6e23a659802a5a1cce3a7a815f13e6990690c8b5d623cb8a2094e1abdd89873547ebd3343a7c7b63a4dccc3df5dec572429864ef77f16a367fbf3efc772395f9b1606ba56ef3c06df8e984f3eabb83f029d483d175f5406e6fda640504a1a268d08a66a2be626422f1f0d2d67fcb93058f8f23c3f895b62704d8e6a2fed684809e1bd11ba5ead4f811c7e513d450f6bcb4edda8d5fe7b4ede0f2d3d23fd78b099d606ab0645eb78f91170061b73320d5469184acfc8e0d5af8f06b4f10994d11cbdce87f23c101baf93479f101d6f7129d65af887be9f996febde2a75e2874a69cd72bf8bda79143c61ee471896c77390381e8ed4439f54b01ce3a4349cb9049daab9a31980550386eebc782a05aa9b4ced29c7409ace7e4c2d0a667af5a96af42c28463448aa15484b85b41ceebf01198ce369037e4a3d6bc41175da2d8d3f12829508605";

    fn tx_steps(sibling: &str, left: bool) -> String {
        format!(r#"[{{"sibling":"{sibling}","left":{left}}}]"#)
    }

    fn tx_proof(height: u64, leaf: &str, steps: &str) -> String {
        format!(r#"{{"height":{height},"index":0,"leaf":"{leaf}","steps":{steps}}}"#)
    }

    fn tx_finality(header: &str, certificate: &str) -> String {
        format!(r#"{{"header_bytes":"{header}","certificate":"{certificate}"}}"#)
    }

    const TX_ROOT: &str = "f501701d0d56127c864841db406827a96e8d1a83d61dd9357298db369f38f2e8";

    fn tx_roster_with(pk: &str, root: &str, slots: &str) -> String {
        format!(
            r#"[{{"id":1,"stake":"2000","attest_pk":"{pk}","root":"{root}","root_slots":"{slots}"}}]"#
        )
    }

    fn tx_roster(pk: &str) -> String {
        tx_roster_with(pk, TX_ROOT, "64")
    }

    fn tx_flip(hex: &str, at: usize) -> String {
        let mut out = hex.to_string();
        let flipped = if &out[at..at + 1] == "0" { "1" } else { "0" };
        out.replace_range(at..at + 1, flipped);
        out
    }

    #[test]
    fn a_finality_check_requires_every_signer_to_open_its_root() {
        let run = |certificate: &str, roster: String| {
            verify_finality(
                7,
                TX_GENESIS.to_string(),
                Some(65_536),
                0,
                TX_HEADER.to_string(),
                certificate.to_string(),
                roster,
            )
        };
        let verified = run(TX_CERTIFICATE, tx_roster(TX_ATTEST_PK)).expect("verified");
        let parsed = qcore::json::parse(&verified).expect("json");
        assert_eq!(
            parsed.get("signed_stake").and_then(Json::as_str),
            Some("2000")
        );
        let membership = |certificate: &str, roster: String| {
            run(certificate, roster)
                .unwrap_err()
                .to_string()
                .contains("committee membership")
        };
        let other_root = tx_flip(TX_ROOT, TX_ROOT.len() - 1);
        assert!(membership(
            TX_CERTIFICATE,
            tx_roster_with(TX_ATTEST_PK, &other_root, "64")
        ));
        assert!(membership(
            TX_CERTIFICATE,
            tx_roster_with(TX_ATTEST_PK, &"00".repeat(32), "64")
        ));
        for slots in ["0", "1", "32", "128", "65536"] {
            assert!(
                membership(TX_CERTIFICATE, tx_roster_with(TX_ATTEST_PK, TX_ROOT, slots)),
                "{slots}"
            );
        }
        let position = 2 * 299;
        let preimage = 2 * 315;
        let sibling = 2 * 363;
        for at in [position, preimage, preimage + 63, sibling, sibling + 63] {
            assert!(
                membership(&tx_flip(TX_CERTIFICATE, at), tx_roster(TX_ATTEST_PK)),
                "{at}"
            );
        }
        let finality = tx_finality(TX_HEADER, &tx_flip(TX_CERTIFICATE, preimage));
        let refused = confirm_transaction(
            7,
            TX_GENESIS.to_string(),
            Some(65_536),
            0,
            TX_ZERO.to_string(),
            tx_proof(4242, LEAF_ZERO, &tx_steps(HASH_ONE, false)),
            finality,
            tx_roster(TX_ATTEST_PK),
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("committee membership"));
        let wrong = confirm_transaction(
            7,
            TX_GENESIS.to_string(),
            Some(65_536),
            0,
            TX_ZERO.to_string(),
            tx_proof(4242, LEAF_ZERO, &tx_steps(HASH_ONE, false)),
            tx_finality(TX_HEADER, TX_CERTIFICATE),
            tx_roster_with(TX_ATTEST_PK, &other_root, "64"),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong.contains("committee membership"));
    }

    #[test]
    fn a_transaction_is_included_only_under_its_root_with_its_own_id() {
        let check = |tx: &str, leaf: &str, steps: String| {
            verify_transaction(ROOT.to_string(), tx.to_string(), leaf.to_string(), steps)
                .expect("well formed")
        };
        assert!(check(TX_ZERO, LEAF_ZERO, tx_steps(HASH_ONE, false)));
        assert!(check(TX_ONE, LEAF_ONE, tx_steps(HASH_ZERO, true)));
        assert!(!check(TX_ONE, LEAF_ZERO, tx_steps(HASH_ONE, false)));
        assert!(!check(TX_ZERO, LEAF_ONE, tx_steps(HASH_ZERO, true)));
        assert!(!check(TX_ZERO, LEAF_ZERO, tx_steps(HASH_ONE, true)));
        assert!(!check(
            &TX_ZERO.to_lowercase(),
            LEAF_ZERO,
            tx_steps(HASH_ONE, false)
        ));
        assert!(!check(TX_ZERO, LEAF_ZERO, "[]".to_string()));
        assert!(verify_transaction(
            "00".to_string(),
            TX_ZERO.to_string(),
            LEAF_ZERO.to_string(),
            "[]".to_string()
        )
        .is_err());
        assert!(verify_transaction(
            ROOT.to_string(),
            TX_ZERO.to_string(),
            "zz".to_string(),
            "[]".to_string()
        )
        .is_err());
    }

    #[test]
    fn a_transaction_is_confirmed_only_inside_a_finalized_block() {
        let finality = tx_finality(TX_HEADER, TX_CERTIFICATE);
        let roster = tx_roster(TX_ATTEST_PK);
        let confirm = |chain: u64, tx: &str, proof: String, finality: &str, roster: &str| {
            included(
                chain,
                TX_GENESIS,
                Some(65_536),
                0,
                tx,
                &proof,
                finality,
                roster,
            )
            .map(|found| rendered(tx, &found, false))
        };
        let good = tx_proof(4242, LEAF_ZERO, &tx_steps(HASH_ONE, false));
        let confirmed = confirm(7, TX_ZERO, good.clone(), &finality, &roster).expect("confirmed");
        let parsed = qcore::json::parse(&confirmed).expect("json");
        assert_eq!(parsed.get("tx_id").and_then(Json::as_str), Some(TX_ZERO));
        assert_eq!(parsed.get("height").and_then(Json::as_str), Some("4242"));
        assert_eq!(parsed.get("index").and_then(Json::as_str), Some("0"));
        let header = parsed.get("header").expect("header");
        assert_eq!(
            header.get("transaction_root").and_then(Json::as_str),
            Some(ROOT)
        );
        assert_eq!(header.get("height").and_then(Json::as_str), Some("4242"));
        assert_eq!(
            header.get("signed_stake").and_then(Json::as_str),
            Some("2000")
        );
        let refused = |chain: u64, tx: &str, proof: String, finality: &str, roster: &str| {
            confirm(chain, tx, proof, finality, roster)
                .unwrap_err()
                .to_string()
        };
        assert!(refused(7, TX_ONE, good.clone(), &finality, &roster).contains("not proven"));
        assert!(refused(
            7,
            TX_ONE,
            tx_proof(4242, LEAF_ONE, &tx_steps(HASH_ONE, true)),
            &finality,
            &roster
        )
        .contains("not proven"));
        assert!(refused(
            7,
            TX_ZERO,
            tx_proof(4243, LEAF_ZERO, &tx_steps(HASH_ONE, false)),
            &finality,
            &roster
        )
        .contains("height"));
        assert!(confirm(8, TX_ZERO, good.clone(), &finality, &roster).is_err());
        let other_pk = format!(
            "{}{}",
            TX_ATTEST_PK[..2].replace('e', "f"),
            &TX_ATTEST_PK[2..]
        );
        assert!(confirm(7, TX_ZERO, good.clone(), &finality, &tx_roster(&other_pk)).is_err());
        let mut tampered = TX_CERTIFICATE.to_string();
        let at = tampered.len() - 200;
        let flipped = if &tampered[at..at + 1] == "0" {
            "1"
        } else {
            "0"
        };
        tampered.replace_range(at..at + 1, flipped);
        assert!(confirm(
            7,
            TX_ZERO,
            good.clone(),
            &tx_finality(TX_HEADER, &tampered),
            &roster
        )
        .is_err());
        assert!(refused(7, TX_ZERO, "{}".to_string(), &finality, &roster).contains("height"));
        assert!(refused(
            7,
            TX_ZERO,
            r#"{"height":4242,"index":0,"leaf":"00"}"#.to_string(),
            &finality,
            &roster
        )
        .contains("steps"));
        assert!(refused(
            7,
            TX_ZERO,
            good.clone(),
            &format!(r#"{{"header_bytes":"{TX_HEADER}"}}"#),
            &roster
        )
        .contains("certificate"));
        assert!(confirm(7, TX_ZERO, good.clone(), &finality, "[]").is_err());
        let with_genesis = |genesis: String| {
            included(
                7,
                &genesis,
                Some(65_536),
                0,
                TX_ZERO,
                &good,
                &finality,
                &roster,
            )
            .map(|found| rendered(TX_ZERO, &found, false))
        };
        assert!(with_genesis(TX_GENESIS.to_uppercase()).is_ok());
        let other = tx_flip(TX_GENESIS, 0);
        assert!(
            with_genesis(other.clone()).is_err(),
            "a certificate signed for another genesis does not confirm here"
        );
        assert!(confirm_transaction(
            7,
            TX_GENESIS.to_string(),
            Some(65_536),
            0,
            TX_ZERO.to_string(),
            good.clone(),
            finality.clone(),
            roster.clone()
        )
        .unwrap_err()
        .to_string()
        .contains("malformed"));
        assert!(verify_finality(
            7,
            other,
            Some(65_536),
            0,
            TX_HEADER.to_string(),
            TX_CERTIFICATE.to_string(),
            roster.clone()
        )
        .is_err());
        for bad in [
            String::new(),
            TX_GENESIS[..62].to_string(),
            format!("{TX_GENESIS}00"),
            format!("zz{}", &TX_GENESIS[2..]),
            format!(" {}", &TX_GENESIS[1..]),
            "00".repeat(32),
        ] {
            let refused = with_genesis(bad.clone()).unwrap_err().to_string();
            assert!(refused.contains("genesis"), "{bad:?} {refused}");
            assert!(verify_finality(
                7,
                bad,
                Some(65_536),
                0,
                TX_HEADER.to_string(),
                TX_CERTIFICATE.to_string(),
                roster.clone()
            )
            .unwrap_err()
            .to_string()
            .contains("genesis"));
        }
    }

    #[test]
    fn a_seed_alias_is_short_and_plain() {
        for good in ["wallet", "main.0", "a_b-c", &"x".repeat(SEED_ALIAS_MAX)] {
            assert!(check_seed_alias(good.to_string()).is_ok(), "{good:?}");
        }
        for bad in [
            "",
            "has space",
            "slash/name",
            "\u{00e9}",
            &"x".repeat(SEED_ALIAS_MAX + 1),
        ] {
            assert!(check_seed_alias(bad.to_string()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_seed_of_too_few_different_bytes_is_refused_on_every_path() {
        let cycle = |n: u8| -> Vec<u8> { (0..32u8).map(|i| 1 + i % n).collect() };
        for weak in [vec![0u8; 32], vec![7u8; 32], cycle(2), cycle(12)] {
            assert!(SeedHandle::from_seed_bytes(weak.clone()).is_err());
            assert!(mnemonic_from_seed(weak.clone()).is_err());
            let mut array = [0u8; SEED_LEN];
            array.copy_from_slice(&weak);
            let phrase = qcore::mnemonic_bytes_from_seed(&array).to_vec();
            assert!(SeedHandle::from_phrase_bytes(phrase.clone()).is_err());
            assert!(seed_from_mnemonic(phrase).is_err());
        }
        assert!(SeedHandle::from_seed_bytes(cycle(13)).is_ok());
        for _ in 0..200 {
            let seed = generate_seed().expect("seed");
            assert!(SeedHandle::from_seed_bytes(seed.clone()).is_ok());
            let phrase = mnemonic_from_seed(seed).expect("phrase");
            assert!(SeedHandle::from_phrase_bytes(phrase).is_ok());
        }
    }
}
