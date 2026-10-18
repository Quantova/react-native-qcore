// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::alloc::{GlobalAlloc, Layout, System};
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

fn parse_seed(seed: Vec<u8>) -> Result<Zeroizing<[u8; SEED_LEN]>, QcoreError> {
    let bytes = Zeroizing::new(seed);
    if bytes.len() != SEED_LEN {
        return Err(err("a seed is thirty two bytes"));
    }
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
    )
    .map_err(err)?;
    Ok(signed_json(signed))
}

fn register_with(
    seed: &[u8; SEED_LEN],
    index: u64,
    nonce: u64,
    fee: &str,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let signed = qcore::sign_register(seed, index, nonce, parse_fee(fee)?, chain_id, valid_until)
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
) -> Result<String, QcoreError> {
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
) -> Result<String, QcoreError> {
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
    )
}

#[uniffi::export]
pub fn sign_register(
    seed: Vec<u8>,
    index: u64,
    nonce: u64,
    fee: String,
    chain_id: u64,
    valid_until: u64,
) -> Result<String, QcoreError> {
    let seed = parse_seed(seed)?;
    register_with(&seed, index, nonce, &fee, chain_id, valid_until)
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
) -> Result<String, QcoreError> {
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
) -> Result<String, QcoreError> {
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

#[uniffi::export]
pub fn verify_finality(
    chain_id: u64,
    header_hex: String,
    certificate_hex: String,
    roster_json: String,
) -> Result<String, QcoreError> {
    let header = from_hex(&header_hex).map_err(err)?;
    let certificate = from_hex(&certificate_hex).map_err(err)?;
    let roster = qcore::finality::parse_roster(&roster_json).map_err(err)?;
    let verified =
        qcore::finality::verify_finality(chain_id, &header, &certificate, &roster).map_err(err)?;
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

fn confirmed(
    chain_id: u64,
    tx_id: &str,
    proof_json: &str,
    finality_json: &str,
    roster_json: &str,
) -> Result<String, String> {
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
    let roster = qcore::finality::parse_roster(roster_json)?;
    let verified = qcore::finality::verify_finality(chain_id, &header, &certificate, &roster)?;
    if verified.height != height {
        return Err("the finalized header is not at the height the proof names".to_string());
    }
    if !qcore::finality::verify_transaction(&verified.transaction_root, tx_id, &leaf, &steps) {
        return Err("the transaction is not proven inside the finalized block".to_string());
    }
    Ok(object(vec![
        ("tx_id", Json::str(tx_id)),
        ("height", Json::str(height.to_string())),
        ("index", Json::str(index.to_string())),
        ("header", finalized_object(&verified)),
    ])
    .render())
}

#[uniffi::export]
pub fn confirm_transaction(
    chain_id: u64,
    tx_id: String,
    proof_json: String,
    finality_json: String,
    roster_json: String,
) -> Result<String, QcoreError> {
    confirmed(chain_id, &tx_id, &proof_json, &finality_json, &roster_json).map_err(err)
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
        index: u64,
        to: String,
        amount: String,
        nonce: u64,
        fee: String,
        chain_id: u64,
        valid_until: u64,
        head: u64,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
            transfer_with(
                seed,
                index,
                &to,
                &amount,
                nonce,
                &fee,
                chain_id,
                valid_until,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_call(
        &self,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
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
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_register(
        &self,
        index: u64,
        nonce: u64,
        fee: String,
        chain_id: u64,
        valid_until: u64,
        head: u64,
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| register_with(seed, index, nonce, &fee, chain_id, valid_until))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_payable_call(
        &self,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
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
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_asset_call(
        &self,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
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
            )
        })
    }
}

#[derive(uniffi::Object)]
pub struct SigningSession {
    inner: Mutex<qcore::SigningSession>,
}

#[uniffi::export]
impl SigningSession {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(SigningSession {
            inner: Mutex::new(qcore::SigningSession::new()),
        })
    }

    #[uniffi::constructor]
    pub fn with_address_book(book: Vec<String>) -> Result<Arc<Self>, QcoreError> {
        let inner = qcore::SigningSession::with_address_book(&book).map_err(err)?;
        Ok(Arc::new(SigningSession {
            inner: Mutex::new(inner),
        }))
    }

    pub fn known(&self) -> Vec<String> {
        lock(&self.inner).known()
    }

    pub fn remember_address(&self, address: String) {
        lock(&self.inner).remember_address(&address)
    }

    pub fn check_target(&self, address: String) -> Result<(), QcoreError> {
        lock(&self.inner).check_target(&address).map_err(err)
    }

    pub fn slot(
        &self,
        key: String,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, QcoreError> {
        lock(&self.inner)
            .slot(&key, reported, expected, order)
            .map_err(err)
    }

    pub fn signed(&self, key: String, slot: u64) {
        lock(&self.inner).signed(&key, slot)
    }

    pub fn release(&self, key: String, slot: u64) {
        lock(&self.inner).release(&key, slot)
    }

    pub fn release_pending(&self, key: String) {
        lock(&self.inner).release_pending(&key)
    }

    pub fn outcome(&self, key: String, slot: u64, accepted: bool) {
        lock(&self.inner).outcome(&key, slot, accepted)
    }

    pub fn next_nonce(&self, key: String) -> Option<u64> {
        lock(&self.inner).next_nonce(&key)
    }

    pub fn is_held(&self, key: String, slot: u64) -> bool {
        lock(&self.inner).is_held(&key, slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn handle() -> Arc<SeedHandle> {
        SeedHandle::from_seed_bytes(seed()).expect("a thirty two byte seed is held")
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
                )
                .is_err(),
                "a transfer to {bad:?} must return an error, not sign and not panic"
            );
        }
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
    fn a_call_is_priced_by_its_meter_and_refused_outside_the_chain_rules() {
        let to = address(seed(), 1).expect("derives");
        assert_eq!(vm_call_fee("500".to_string(), 21_000).unwrap(), "9000");
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
            )
        };
        assert!(call(21_000, "9000", "").is_ok());
        assert!(
            call(21_000, "500", "").is_err(),
            "one transfer fee underpays a 21000 meter"
        );
        assert!(call(1_209, "500", "").is_err());
        assert!(call(12_500_001, "5170000", "").is_err());
        assert!(call(21_000, "9000", &"00".repeat(128 * 1024 + 1)).is_err());
        assert!(sign_payable_call(
            seed(),
            0,
            to.clone(),
            String::new(),
            0,
            21_000,
            "500".to_string(),
            "0".to_string(),
            1,
            300,
            "500".to_string(),
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
            "500".to_string(),
            1,
            300,
            "500".to_string(),
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
        )
        .expect("the seed path signs");
        let by_handle = handle()
            .sign_transfer(
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                300,
                10,
            )
            .expect("the handle signs");
        assert_eq!(by_seed, by_handle, "both paths must sign the same bytes");
        let register = handle()
            .sign_register(0, 0, "1".to_string(), 1, 300, 10)
            .expect("the handle registers");
        assert_eq!(
            register,
            sign_register(seed(), 0, 0, "1".to_string(), 1, 300).expect("the seed path registers")
        );
        let call = handle()
            .sign_call(
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
                10,
            )
            .expect("the handle calls");
        assert_eq!(
            call,
            sign_call(
                seed(),
                0,
                to,
                String::new(),
                0,
                21_000,
                "9000".to_string(),
                1,
                300,
                "500".to_string(),
            )
            .expect("the seed path calls")
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
            .sign_transfer(0, to, "5".to_string(), 0, "1".to_string(), 1, 300, 10)
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
                0,
                to.clone(),
                "5".to_string(),
                0,
                "1".to_string(),
                1,
                valid_until,
                head,
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
            .sign_register(0, 0, "1".to_string(), 1, 5_000, 10)
            .is_err());
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
            bounded_valid_until(chain.clone(), 1_000, wall, None, 0).expect("a plausible head"),
            1_000 + default_validity_blocks()
        );
        assert!(
            bounded_valid_until(chain.clone(), ceiling + 1, wall, None, 0).is_err(),
            "a head ahead of the wall clock is refused"
        );
        assert!(
            bounded_valid_until(chain.clone(), 1_000, wall, Some(1_001), 5).is_err(),
            "a head that went backwards is refused"
        );
        assert!(
            bounded_valid_until(chain.clone(), 1_000, wall, Some(10), 0).is_err(),
            "a head that leapt faster than blocks are made is refused"
        );
        assert!(bounded_valid_until(chain, 1_000, wall, Some(990), 5).is_ok());
    }

    #[test]
    fn a_slot_is_reserved_until_it_is_signed_or_released() {
        let session = SigningSession::new();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(session.slot(key.clone(), 7, None, false).expect("free"), 7);
        assert!(
            session.slot(key.clone(), 7, None, false).is_err(),
            "two flows never share a nonce"
        );
        session.release(key.clone(), 7);
        assert_eq!(
            session.slot(key.clone(), 7, None, false).expect("released"),
            7
        );
        session.release_pending(key.clone());
        assert_eq!(
            session.slot(key.clone(), 7, None, false).expect("cleared"),
            7
        );
        session.signed(key.clone(), 7);
        assert!(session.slot(key.clone(), 7, None, false).is_err());
    }

    #[test]
    fn the_session_refuses_a_second_signature_at_the_same_nonce() {
        let session = SigningSession::new();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(session.next_nonce(key.clone()), None);
        assert_eq!(session.slot(key.clone(), 4, None, false).expect("free"), 4);
        session.signed(key.clone(), 4);
        assert!(session.is_held(key.clone(), 4));
        assert!(
            session.slot(key.clone(), 4, None, false).is_err(),
            "one nonce carries one signature"
        );
        assert!(
            session.slot(key.clone(), 4, Some(5), false).is_err(),
            "a nonce other than the expected one is refused"
        );
        assert_eq!(
            session
                .slot(key.clone(), 4, Some(4), false)
                .expect("asked for"),
            4
        );
        session.outcome(key.clone(), 4, true);
        assert_eq!(session.next_nonce(key.clone()), Some(5));
        assert_eq!(session.slot(key.clone(), 5, None, false).expect("next"), 5);
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
            verify_finality(1, header.to_string(), certificate.to_string(), roster)
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
            format!("[{},{}]", member(1, "5"), member(1, "5")),
            &header,
            "00"
        )
        .contains("twice"));
        assert!(run(format!("[{}]", member(1, "0")), &header, "00").contains("no stake"));
        assert!(run(
            format!(
                r#"[{{"id":1,"stake":"5","attest_pk":"abab","root":"{root}","root_slots":"64"}}]"#
            ),
            &header,
            "00"
        )
        .contains("ML-DSA-65"));
        let without = |key: &str| {
            let full = member(1, "5");
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
            format!("[{}]", member(1, "5").replace(&root, &"cd".repeat(31))),
            &header,
            "00"
        )
        .contains("32 bytes"));
        assert!(run(
            format!(
                "[{}]",
                member(1, "5").replace(r#""root_slots":"64""#, r#""root_slots":64"#)
            ),
            &header,
            "00"
        )
        .contains("root_slots"));
        assert!(run(format!("[{}]", member(1, "5")), &header, "00").contains("header"));
        assert!(run(format!("[{}]", member(1, "5")), "0", "00").contains("hex"));
        assert!(run(format!("[{}]", member(1, "5")), &header, "zz").contains("hex"));
    }

    const TX_ZERO: &str = "QTX17Y0MDLEDF8VUXNE6M9GXMAMDLPW8G7MKN2VFX3FFFFWPE8SMKJ4Q5E0U6V";
    const TX_ONE: &str = "QTX15JX99J6YWMM6JSSPT63FW8Y3CH933N9L7AHKQAAGCCWJQ933DL8SY8Y32R";
    const TX_HEADER: &str = "921000000000000041414141414141414141414141414141414141414141414141414141414141415151515151515151515151515151515151515151515151515151515151515151c1a8b465e606c9ed2e7eb3c61116a18c8da50f1adbb463b1ae05c51c88386bfc525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353530b0000000000000076616c696461746f722d3100d2496b000000000000000000000000";
    const TX_CERTIFICATE: &str = "9210000000000000070000000000000092100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e01414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000a8321c56c45cfb11d47de6b26080cc8f69f26d48f0c966bb9f031d075da393dc01010000000000000001000000000000009210000000000000070000000000000000000000000000002000000000000000a8321c56c45cfb11d47de6b26080cc8f69f26d48f0c966bb9f031d075da393dc92100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e0141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c000000000000675b3628d137d7eeec745c75bf10d89562b7bff05660b1faed818336bf220422f1499234587401cab4eb1e84dc45e2a6a5bd602a2ae4026aebf35a606d4e02b66c871ff50f8e6f6bfd0d18793fb53bfc7dabc94ebd598a0b93144f3f37b5e75cb0f5bce514c14719b92fd6a5f83d65b9be564718657d3fe3563b1803d92b2a840714917115e4eb480eb6f6f5a2493d0320a3ef16a62ef61e8f046475ee64424a70949abd05dc6547f0d10e2be3c5409e51cf33f359deb5c8724d00c9d5cb6cd7682e126ab53f108e43663c199ec083b24a9b3158d32aca1a4865ac8cd03b2025ff59383f0e308127d6d8755108c693f5a548adc15858e99b8382c8801a57551900a4a96f194224e52405b09c5c7537377e1c3071ccdb444f650845ec69e77a52e38554d8844c8d1865f68332d5cd203300ada5748fa81d4b2034278674961bdf3d24fef9d70944258ac4135b8b467c4e380c38b3aa7ef66f29b1b969d21cfc569328ddfaf465d14e230542f18ba54d7db64f58d5e332cb0fb8d1e7e1c4bd939f345f4f9efc7a4688616ee487f629f78f5deed0fb4ada7887cb7df9f997f56d46131980494c1d49abd63d651e7eb3ff6d84626206f093e39645af85e68afbaa7298b5b298d8c3514d35159ebdaf2af59b3aad3aa7ca00a7ea0d75517d6056267c6db380d4b575f3d410a02c5c5eadf5949bb98c305338b818c920ce830d52665c940aa967255db6d96141b88a64a8fa66a97af44956eadbe60fff1bc7abdcbb40e1892212f4244ea27dec3e435d4f22bdc3ad25598b8fdaff061c16de0dd031af322f43d227941fd25c46dbe71d73bb18d22648de4d1f00f628c78645733f39ed39cd056482abf54db19b04773e3dc8667887f36eaf28a85c75a825a17f3a7902d60c90aea642190b2e627a1bd10cb99a7534b954078967b8fb7079a73696b8290d5382047ac08dbfa1036011a211601902e26ceb51992294b6bb97576613b1fed4c994b217314c633c2b3d7d175d93325ad00099c20f288a36a169b0650a63bb5befb72a826f1be416c573576528694cdcc98f32a8f422783e1d27cb159c47d0d653fb4c1b991b66aa859afdaead038872663ee66ea9f4951badd7ba9f1c216f28a630245fcd74729ee9acc5deaab6d0f21affda70c3c51a3769302beda2e1dfd7b3eddfd2f3ff1f7577285644054a858a2a0def67067e9dbc1e31c16cdaa171a98577378f546863c6cb7de9ce21087aa97202ac6f9327e36d729ac132357f2b49beb66a92056b9f5a0c0d26ce62968d21e54cea664b46cbdaa10d29c0fb6add5d556d1d0d7a9f18c8952120ee5c4c3b5e1aaf1064388fbd8bffe9d4571658589a06e146b23b40f5ef6bd57322ec64286ad92af9a44c40df80f82fc32685bc06f944e91791de38b3d11e1f7b29d4763502592650debf3155cb5746782a7b4f8f5fe8a3c03b07c68e8854e6e3e1a526c4ab7b4ff8fca5a794c352671e59b66084c8c3a801cf9de86711057bf7c0ea2fe41817f62b1f47e0ae64539ac17acdf06b279bdee9e382fed69ebe0d073e3749f3d42eef582fb4b0eb68ff72f381be0b89a376be2697f008f51917df1397e8b9a3eb1663d1d03a4fa0cfe950f8851139ab9858a4ae7038e979da028508bd68723d7ccaece33e7aaf813e842d3c1bc73355da29dd1bdc60288280a33747a9d53eca168030c4f6c84a56e6f6fb8c0f4eefe803714bc542a0af1ef4cb653a93da45ab7f53fe978fbc3bf5fae204da1a881a0b3785cfa0abe86a391c721acf0c82a452ffd195d40fb822b390d784888dafe6652720595a0708fcbcc17d22663d600d83676b13babcc3d62b25245fbb8467e637e52c7df468968874ca727366eed7cdaa506fe0e15bad51068f5a1be73f3bcda3cc78fd23ca0124f0310431b510742d444d7c9e6a5cfeba5273caa6006e03144cfd1b8ab7a29cd9970faee4a6805cfc3c761d396dd78770f4c5888aa0404ab992fc866108943607b3970fe42097d8f379fb8b053172d17a5359f779e3c44a97e4aab30672943de46a4fc7d86ddc1ff7d187dbecc80bbea1578462e4b913624e53739f5cee4fff1c0447b7cd2ad71a2145ca87d24673e2f63a22cb4245d84244ed2d910b8295b29285a5480f0d4f03d2fdd1a3307aceb80847e261b653bf0f2c7df5d723c1fdfb9f95d4237bb93ab7eab196b03ac872a7c75ee2d90550efd90a96c34348a6158a1e3f919ae5c867e71ee3aba66bd132e67ce8a34387aa0c341e2c5342d5a000bc281866bc4ed9622b30161cb2454d83e8d3d3661628c782fd1be9f6ca78da0af455d130196c7fdfd95301f5f7ac738f8361f6eca98e44661e7921d52b53f7e4eaa05b8bf19c6c3a2bdb0ac4df84da7c886c03553ddd038b679b4e0284d8fb1a1b2cf803662418c4003f5ba2ca2f131ac82e7d988e362025fe17ef1cfecb94d9f1ba76ec359056b7fa1c1353ea3933b69ab92741723da418025a8e19c1cc0bdfad178e9e2a5b309b6bfdb9d823b53781e0a6e119ceacd2049ee53b71cf8e4b3362c9e5e19c8bb188817e6db581a1ccc86073d48660f622e00d28a60fbe2f0c8a5983f98a313159e6fc7d85d39fcdeb5d60446253039767fc5df20d29e0dfff06d36f5c9bb5fe2d400504d39d3f2cdb27746aecc8a34b581637cfa416bb95250e087673751540f1f251c7bca27e08daaa934f4cfabcd33afe40bf67cdfe54b3484b81cde7fd77c9bb064b0ea3966f4504b19b8f499c27120c2344e90f10486721e89f1c965f0abda06cd394998ea60ecbf79137c27ebb9eb9df2349349758dc6b0401d6dbee13fe10b0492ea9e9b7f7dc1573066fe40617cda2b57df39629bcac62dc60ce60e697f4c4d2bbe76a45c9c0028170b8b78c43ee7376131b449c2d2787c2799dc87f19e3e76f94cf2fd66ed2f92f12fb331efb43674e26aaed192d3dc20b340f59b372814d669e4eb0424d6e6f4af51bf120a545d8907c5309d0b228ba42bc716e7447f90964d95c2cf099819da9e97baa44802fab702474d3d9d91bb2334d1f31d56661b5b52cdfdd9ce4b8550305e8e7facd1a66e7d8033ee40329cf46568728f43c29770ca892f942657f5b3e2bffc2e6b4561225fd1234be2f992bbb76cad66c72941e3b2ce193031123ad33fe09d64f2a65d211d221cfa4edf1ec2c2c3cf0752d6dd363be114113ea774e1cb9ef0f90e7e2a8a609eb71d15118f62da70639800152f645aefd636e74814434eda50958eab724c294d94d18649a5c42b9ddc1f8572ce786af0ce9c38a0d31ff7013092c8eced7f2d69eb86da5335fea682676f4c95abed7a1243e162e64a5d0df0c8528aee9bf4c76f8a487c0b0819da9d9fc0ccf8d090e1d01539665d3d562b08489e86fd90bec53ee1a93563bb7c96ad0aac0132a6cc27d9964cbb78676ae19193f6a5db6639b7acb26875ab25d9b5f71ce1270321ae20154f911f80a5dacdc4e1c7e2b0b663dc12110e0f026e952c251b6f8e85cd5028efebcdf2fce8506a50c406bc65b283905ccb0c9d77d1ed495202809c4287619e020cdac0f050db00758c085523dc2a92c8e6c117d9f87d738ff140e8a8767514cdcdfeef635584fc7aff881d4ac4276e7c8aaae0c2de3f35d0f30804ea33cf236cdb0428e6ac086cf7a7fca56d1aa34514cb9250a47bc81d0532d45a768a84218892707f122e44084e9404f5a7f29e4b78744090bce865cf9afb54bc4b7bc4452e990a0bd53030ed24a8336bb477adc02d6004959709b7af1a5bc43d45be18290d5ebf9a1d602487ab6d4791c58139a6ce6a9298ac2a7454542a398913e82008c1cbad198ed3a14c7127a58ee8add709c0cd0c573c4d70980956e6a1d79a855a36227bc6db839501d458754efc1a73da014c648d38b9e4408db95aa99807239a45d983626e4ff6458470210bb974494ccf59b505fcf619222b8307b3c50b9cbbf514224e3ea8d2358e7f3bb4116886cd06f64062d3cb0d1cef9e504551dad62a7033a73870553c1cc4e7d5d18a159c2edbcab3dc00a37b54fa72e72bd9dbabcc8d4b0acefed27d8334d8607e1664808875f5f68500fea63f0a65bc72e9b3f692b420569b82c93167b96a9e09649462fe89a1945ee9a330a0ad4f526bdb065734a1e9d7bdb964a34ce7bdda995ce5d798c32aed212859232c3cf776f5962b2b6d08f857194ecb9dbc89a3390ee9460b859caf4c141ad671d788d70b9a9038cf9afbc86e9146b400b00555817245f73fb1390c25c8b5ca348ffdafac0096e820b7ab9141f604bcc6ea2fd993dfb6c97bc3aedb8a72ee62a70c92168faf0341728a8994bd2756f2fae31d479b9557c8554539a420153c18c56ff072014966b71769ccd40822056679c7633590a7e5ecc90127af3df1283c07bcc504e3f4c3e8272ec975097d7abdf6ca2439fadbdd907764e3f22029521678f6b74192724e2a6b451fac6600f8625db37b2be0f07c177b30c9f68877899311eed67942a3e43e1e5928ab0e650e67901eaa77e44ff1a877b4094470edccad0165b99dc518a1f123c96da42cbe5980063f2c0e86e3ec24f3aa37f32f749cfe2dbf531e68ac854a62a3c1d3b4d7096d60b8796a5bbcfe4013436808ea7bdc0e13e3f48561439a4c1c6d7e02b6d738bac0000000000000000000000000000000000060d161a21260000000000000000";
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
            r#"[{{"id":1,"stake":"1000","attest_pk":"{pk}","root":"{root}","root_slots":"{slots}"}}]"#
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
            verify_finality(7, TX_HEADER.to_string(), certificate.to_string(), roster)
        };
        let verified = run(TX_CERTIFICATE, tx_roster(TX_ATTEST_PK)).expect("verified");
        let parsed = qcore::json::parse(&verified).expect("json");
        assert_eq!(
            parsed.get("signed_stake").and_then(Json::as_str),
            Some("1000")
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
            confirm_transaction(
                chain,
                tx.to_string(),
                proof,
                finality.to_string(),
                roster.to_string(),
            )
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
            Some("1000")
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
        assert!(confirm(7, TX_ZERO, good, &finality, "[]").is_err());
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
}
