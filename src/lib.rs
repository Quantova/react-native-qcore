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
    head: u64,
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
    head: u64,
) -> Result<String, QcoreError> {
    let signed = qcore::sign_register(
        seed,
        index,
        nonce,
        parse_fee(fee)?,
        chain_id,
        valid_until,
        head,
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
        head,
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
        head,
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
    head: u64,
) -> Result<String, QcoreError> {
    let seed = parse_seed(seed)?;
    register_with(&seed, index, nonce, &fee, chain_id, valid_until, head)
}

#[uniffi::export]
pub fn chain_id_from_name(name: String) -> Result<u64, QcoreError> {
    qcore::checked_chain_id(&name).map_err(err)
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
        head,
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
        head,
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
        session: Arc<SigningSession>,
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
            session.signing(
                chain_id,
                &qcore::account_address(seed, index),
                nonce,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
            session.signing(
                chain_id,
                &qcore::account_address(seed, index),
                nonce,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
            session.signing(
                chain_id,
                &qcore::account_address(seed, index),
                nonce,
                || register_with(seed, index, nonce, &fee, chain_id, valid_until, head),
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
            session.signing(
                chain_id,
                &qcore::account_address(seed, index),
                nonce,
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
    ) -> Result<String, QcoreError> {
        check_valid_until(valid_until, head)?;
        self.with_seed(|seed| {
            session.signing(
                chain_id,
                &qcore::account_address(seed, index),
                nonce,
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
                    )
                },
            )
        })
    }
}

const SAVED_STATE_MAX: usize = 1 << 20;

const NONCE_ACCOUNTS_MAX: usize = 4096;

const NONCE_KEY_MAX: usize = 128;

const NONCE_SLOTS_MAX: usize = 16_384;

const NONCE_STATE_VERSION: u64 = 2;

const TOO_MANY_ACCOUNTS: &str = "the nonce state already keeps 4096 accounts, the most it may keep, so no new account is tracked until the nonce state of one is reset";

const TOO_MANY_SLOTS: &str = "this account already keeps 16384 nonces that are signed or reserved and not yet accepted, the most its saved state may keep, record the outcome of earlier nonces or reset its nonce state";

const KEY_OUT_OF_RANGE: &str = "a nonce key is one to 128 bytes";

const STATE_TOO_LARGE: &str =
    "the saved nonce state of an account may take at most 1 MiB, so nothing was signed";

const MANIFEST_DAMAGED: &str = "the saved nonce manifest could not be opened, so no account signs until the nonce state is reset after authenticating";

const STATE_WITHOUT_MANIFEST: &str = "saved nonce state was found without its manifest or in the earlier format that named no chain, so it is refused and no account signs until the nonce state is reset after authenticating";

const TOO_MANY_SAVED: &str = "the saved nonce state holds more than 4096 accounts, so no account signs until the nonce state is reset after authenticating";

const EARLIER_FORMAT: &str =
    "the saved nonce state is in the earlier format that named no chain, so it is refused";

const WHOLE_STATE_BLOCKED: &str =
    "the whole saved nonce state is blocked, reset the nonce state of every account";

fn account_name(chain_id: u64, key: &str) -> String {
    format!("{chain_id}:{key}")
}

fn check_nonce_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > NONCE_KEY_MAX {
        return Err(KEY_OUT_OF_RANGE.to_string());
    }
    Ok(())
}

fn split_account(account: &str) -> Option<(u64, &str)> {
    let (chain, key) = account.split_once(':')?;
    let chain_id = decimal_text(chain)?;
    check_nonce_key(key).ok()?;
    Some((chain_id, key))
}

fn decimal_text(text: &str) -> Option<u64> {
    qcore::canonical_decimal(text).and_then(|n| u64::try_from(n).ok())
}

fn decimal(value: Option<&Json>) -> Option<u64> {
    value.and_then(Json::as_str).and_then(decimal_text)
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

    fn is_empty(&self) -> bool {
        self.next.is_none() && self.held.is_empty() && self.reserved.is_empty()
    }

    fn merge(&mut self, other: &Nonces) {
        if let Some(next) = other.next {
            self.next = Some(self.next.map_or(next, |local| local.max(next)));
        }
        for (slot, accepted) in &other.held {
            let entry = self.held.entry(*slot).or_insert(*accepted);
            *entry = *entry && *accepted;
        }
        self.prune();
    }
}

#[derive(Debug, Default)]
struct Account {
    chain_id: u64,
    key: String,
    nonces: Nonces,
    generation: u64,
    written: Option<u64>,
    blocked: Option<String>,
}

#[derive(Debug)]
struct SavedAccount {
    chain_id: u64,
    key: String,
    generation: u64,
    nonces: Nonces,
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
    let key = doc
        .get("key")
        .and_then(Json::as_str)
        .ok_or_else(|| "the saved nonce state names no key".to_string())?;
    check_nonce_key(key)?;
    let generation = decimal(doc.get("generation"))
        .ok_or_else(|| "the saved nonce state names no generation".to_string())?;
    let next = match doc.get("next") {
        None => None,
        Some(value) => Some(
            decimal(Some(value))
                .ok_or_else(|| "the saved next nonce is not a whole number".to_string())?,
        ),
    };
    let list = doc
        .get("held")
        .and_then(Json::as_array)
        .ok_or_else(|| "the saved nonce state has no held list".to_string())?;
    if list.len() > NONCE_SLOTS_MAX {
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
    Ok(SavedAccount {
        chain_id,
        key: key.to_string(),
        generation,
        nonces: Nonces {
            next,
            held,
            reserved: BTreeSet::new(),
        },
    })
}

fn render_saved(account: &Account) -> String {
    let mut held = account.nonces.held.clone();
    for slot in &account.nonces.reserved {
        held.entry(*slot).or_insert(false);
    }
    let held: Vec<Json> = held
        .iter()
        .map(|(slot, accepted)| {
            object(vec![
                ("slot", Json::str(slot.to_string())),
                ("accepted", Json::Bool(*accepted)),
            ])
        })
        .collect();
    let mut fields = vec![
        ("version", Json::Int(NONCE_STATE_VERSION)),
        ("chain_id", Json::str(account.chain_id.to_string())),
        ("key", Json::str(account.key.clone())),
        ("generation", Json::str(account.generation.to_string())),
        ("held", Json::Array(held)),
    ];
    if let Some(next) = account.nonces.next {
        fields.push(("next", Json::str(next.to_string())));
    }
    object(fields).render()
}

fn parse_manifest(text: &str) -> Result<Vec<(String, u64)>, String> {
    if text.len() > SAVED_STATE_MAX {
        return Err(MANIFEST_DAMAGED.to_string());
    }
    let doc = qcore::json::parse(text).map_err(|_| MANIFEST_DAMAGED.to_string())?;
    if doc.get("version").and_then(Json::as_u64) != Some(NONCE_STATE_VERSION) {
        return Err(MANIFEST_DAMAGED.to_string());
    }
    let list = doc
        .get("accounts")
        .and_then(Json::as_array)
        .ok_or_else(|| MANIFEST_DAMAGED.to_string())?;
    if list.len() > NONCE_ACCOUNTS_MAX {
        return Err(TOO_MANY_SAVED.to_string());
    }
    let mut out: Vec<(String, u64)> = Vec::with_capacity(list.len());
    for entry in list {
        let account = entry
            .get("account")
            .and_then(Json::as_str)
            .filter(|account| split_account(account).is_some())
            .ok_or_else(|| MANIFEST_DAMAGED.to_string())?;
        let generation =
            decimal(entry.get("generation")).ok_or_else(|| MANIFEST_DAMAGED.to_string())?;
        if out.iter().any(|(seen, _)| seen == account) {
            return Err(MANIFEST_DAMAGED.to_string());
        }
        out.push((account.to_string(), generation));
    }
    Ok(out)
}

#[derive(uniffi::Record)]
pub struct NonceRecord {
    pub account: String,
    pub state: Option<String>,
}

#[derive(uniffi::Record)]
pub struct NonceSave {
    pub account: String,
    pub generation: u64,
    pub state: String,
    pub manifest: String,
}

#[derive(uniffi::Record)]
pub struct NonceReset {
    pub removed: Vec<String>,
    pub manifest: String,
}

#[derive(Debug, Default)]
struct NonceLedger {
    accounts: BTreeMap<String, Account>,
    dirty: BTreeSet<String>,
    restored: bool,
    blocked_all: Option<String>,
}

static NONCE_LEDGER: Mutex<NonceLedger> = Mutex::new(NonceLedger {
    accounts: BTreeMap::new(),
    dirty: BTreeSet::new(),
    restored: false,
    blocked_all: None,
});

impl NonceLedger {
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

    fn change<T>(
        &mut self,
        chain_id: u64,
        key: &str,
        apply: impl FnOnce(&mut Nonces) -> Result<T, String>,
    ) -> Result<T, String> {
        check_nonce_key(key)?;
        let name = account_name(chain_id, key);
        let created = self.usable(&name)?.is_none();
        if created {
            if self.accounts.len() >= NONCE_ACCOUNTS_MAX {
                return Err(TOO_MANY_ACCOUNTS.to_string());
            }
            self.accounts.insert(
                name.clone(),
                Account {
                    chain_id,
                    key: key.to_string(),
                    ..Account::default()
                },
            );
        }
        let Some(account) = self.accounts.get_mut(&name) else {
            return Err(TOO_MANY_ACCOUNTS.to_string());
        };
        let before = (account.nonces.slots() >= NONCE_SLOTS_MAX).then(|| account.nonces.clone());
        match apply(&mut account.nonces) {
            Ok(out) => {
                if account.nonces.slots() > NONCE_SLOTS_MAX {
                    if let Some(before) = before {
                        account.nonces = before;
                    }
                    if created && account.nonces.is_empty() {
                        self.accounts.remove(&name);
                    }
                    return Err(TOO_MANY_SLOTS.to_string());
                }
                self.dirty.insert(name);
                Ok(out)
            }
            Err(refused) => {
                if created && account.nonces.is_empty() {
                    self.accounts.remove(&name);
                }
                Err(refused)
            }
        }
    }

    fn slot(
        &mut self,
        chain_id: u64,
        key: &str,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, String> {
        self.change(chain_id, key, |nonces| {
            nonces.slot(reported, expected, order)
        })
    }

    fn signed(&mut self, chain_id: u64, key: &str, slot: u64) -> Result<(), String> {
        self.change(chain_id, key, |nonces| {
            nonces.signed(slot);
            Ok(())
        })
    }

    fn outcome(
        &mut self,
        chain_id: u64,
        key: &str,
        slot: u64,
        accepted: bool,
    ) -> Result<(), String> {
        if !accepted {
            return Ok(());
        }
        self.change(chain_id, key, |nonces| {
            nonces.accepted(slot);
            Ok(())
        })
    }

    fn live_mut(&mut self, chain_id: u64, key: &str) -> Option<(String, &mut Account)> {
        if self.blocked_all.is_some() {
            return None;
        }
        let name = account_name(chain_id, key);
        let account = self.accounts.get_mut(&name)?;
        if account.blocked.is_some() {
            return None;
        }
        Some((name, account))
    }

    fn release(&mut self, chain_id: u64, key: &str, slot: u64) {
        if let Some((name, account)) = self.live_mut(chain_id, key) {
            if account.nonces.reserved.remove(&slot) {
                self.dirty.insert(name);
            }
        }
    }

    fn release_pending(&mut self, chain_id: u64, key: &str) {
        if let Some((name, account)) = self.live_mut(chain_id, key) {
            if !account.nonces.reserved.is_empty() {
                account.nonces.reserved.clear();
                self.dirty.insert(name);
            }
        }
    }

    fn next_nonce(&self, chain_id: u64, key: &str) -> Option<u64> {
        match self.usable(&account_name(chain_id, key)) {
            Ok(Some(account)) => account.nonces.next,
            _ => None,
        }
    }

    fn is_held(&self, chain_id: u64, key: &str, slot: u64) -> bool {
        match self.usable(&account_name(chain_id, key)) {
            Ok(Some(account)) => account.nonces.held.contains_key(&slot),
            Ok(None) => false,
            Err(_) => true,
        }
    }

    fn signing(
        &mut self,
        chain_id: u64,
        key: &str,
        nonce: u64,
        sign: impl FnOnce() -> Result<String, QcoreError>,
    ) -> Result<String, QcoreError> {
        let name = account_name(chain_id, key);
        let reserved = self
            .usable(&name)
            .map_err(err)?
            .is_some_and(|account| account.nonces.reserved.contains(&nonce));
        if !reserved {
            return Err(err(format!(
                "the vault signs only at a nonce taken from this signing session, nonce {nonce} of {key} on chain {chain_id} was not reserved with slot or was already signed"
            )));
        }
        let signed = sign()?;
        if let Some(account) = self.accounts.get_mut(&name) {
            account.nonces.signed(nonce);
        }
        self.dirty.insert(name);
        Ok(signed)
    }

    fn manifest_with(&self, account: Option<(&str, u64)>) -> String {
        let entries: Vec<Json> = self
            .accounts
            .iter()
            .filter_map(|(name, entry)| {
                let generation = match account {
                    Some((current, generation)) if current == name => Some(generation),
                    _ => entry.written,
                }?;
                Some(object(vec![
                    ("account", Json::str(name.clone())),
                    ("generation", Json::str(generation.to_string())),
                ]))
            })
            .collect();
        object(vec![
            ("version", Json::Int(NONCE_STATE_VERSION)),
            ("accounts", Json::Array(entries)),
        ])
        .render()
    }

    fn changes(&self) -> Vec<String> {
        self.dirty.iter().cloned().collect()
    }

    fn save(&mut self, name: &str, stored: Option<&str>) -> Result<NonceSave, String> {
        let entry = self
            .accounts
            .get_mut(name)
            .ok_or_else(|| format!("no nonce state is kept for {name}"))?;
        let mut stored_generation = 0;
        if let Some(saved) = stored.and_then(|text| parse_saved(text).ok()) {
            if saved.chain_id == entry.chain_id && saved.key == entry.key {
                stored_generation = saved.generation;
                if entry.written != Some(saved.generation) {
                    entry.nonces.merge(&saved.nonces);
                }
            }
        }
        let generation = entry
            .generation
            .max(stored_generation)
            .checked_add(1)
            .ok_or_else(|| "the nonce state generation is exhausted".to_string())?;
        entry.generation = generation;
        let state = render_saved(entry);
        if state.len() > SAVED_STATE_MAX {
            return Err(STATE_TOO_LARGE.to_string());
        }
        let manifest = self.manifest_with(Some((name, generation)));
        if manifest.len() > SAVED_STATE_MAX {
            return Err(TOO_MANY_SAVED.to_string());
        }
        Ok(NonceSave {
            account: name.to_string(),
            generation,
            state,
            manifest,
        })
    }

    fn written(&mut self, name: &str, generation: u64) {
        if let Some(entry) = self.accounts.get_mut(name) {
            if entry.generation == generation {
                entry.written = Some(generation);
                self.dirty.remove(name);
            }
        }
    }

    fn restore(
        &mut self,
        manifest: Option<&str>,
        manifest_damaged: bool,
        listed: &[NonceRecord],
        unlisted: &[Option<String>],
    ) -> bool {
        if self.restored {
            return false;
        }
        self.restored = true;
        if listed.len() + unlisted.len() > NONCE_ACCOUNTS_MAX {
            self.blocked_all = Some(TOO_MANY_SAVED.to_string());
            return true;
        }
        if manifest_damaged {
            self.blocked_all = Some(MANIFEST_DAMAGED.to_string());
            return true;
        }
        let Some(manifest) = manifest else {
            if !listed.is_empty() || !unlisted.is_empty() {
                self.blocked_all = Some(STATE_WITHOUT_MANIFEST.to_string());
            }
            return true;
        };
        let entries = match parse_manifest(manifest) {
            Ok(entries) => entries,
            Err(reason) => {
                self.blocked_all = Some(reason);
                return true;
            }
        };
        for (name, generation) in &entries {
            let Some((chain_id, key)) = split_account(name) else {
                continue;
            };
            let text = listed
                .iter()
                .find(|record| &record.account == name)
                .and_then(|record| record.state.as_deref());
            let found = match text {
                None => Err(format!(
                    "the saved nonce state of {name} is missing or could not be opened, so it does not sign until its nonce state is reset after authenticating"
                )),
                Some(text) => match parse_saved(text) {
                    Ok(saved) if saved.chain_id != chain_id || saved.key != key => Err(format!(
                        "the saved nonce state of {name} belongs to another account, so it does not sign until its nonce state is reset after authenticating"
                    )),
                    Ok(saved) if saved.generation < *generation => Err(format!(
                        "the saved nonce state of {name} is older than its manifest records, so it does not sign until its nonce state is reset after authenticating"
                    )),
                    Ok(saved) => Ok(saved),
                    Err(reason) => Err(format!(
                        "the saved nonce state of {name} could not be read ({reason}), so it does not sign until its nonce state is reset after authenticating"
                    )),
                },
            };
            let entry = self
                .accounts
                .entry(name.clone())
                .or_insert_with(|| Account {
                    chain_id,
                    key: key.to_string(),
                    ..Account::default()
                });
            match found {
                Ok(saved) => {
                    entry.nonces.merge(&saved.nonces);
                    entry.generation = entry.generation.max(saved.generation);
                    entry.written = Some(saved.generation);
                }
                Err(reason) => {
                    entry.generation = entry.generation.max(*generation);
                    entry.written = Some(*generation);
                    entry.blocked = Some(reason);
                }
            }
        }
        for text in unlisted.iter().flatten() {
            let Ok(saved) = parse_saved(text) else {
                continue;
            };
            let name = account_name(saved.chain_id, &saved.key);
            if entries.iter().any(|(listed, _)| listed == &name) {
                continue;
            }
            if !self.accounts.contains_key(&name) && self.accounts.len() >= NONCE_ACCOUNTS_MAX {
                self.blocked_all = Some(TOO_MANY_SAVED.to_string());
                return true;
            }
            let entry = self.accounts.entry(name).or_insert_with(|| Account {
                chain_id: saved.chain_id,
                key: saved.key.clone(),
                ..Account::default()
            });
            entry.nonces.merge(&saved.nonces);
            entry.generation = entry.generation.max(saved.generation);
            entry.written = Some(saved.generation);
        }
        true
    }

    fn reset(&mut self, target: Option<(u64, &str)>) -> Result<NonceReset, String> {
        let removed = match target {
            Some((chain_id, key)) => {
                check_nonce_key(key)?;
                if self.blocked_all.is_some() {
                    return Err(WHOLE_STATE_BLOCKED.to_string());
                }
                let name = account_name(chain_id, key);
                self.accounts.remove(&name);
                self.dirty.remove(&name);
                vec![name]
            }
            None => {
                let removed = self.accounts.keys().cloned().collect();
                self.accounts.clear();
                self.dirty.clear();
                self.blocked_all = None;
                removed
            }
        };
        self.restored = true;
        Ok(NonceReset {
            removed,
            manifest: self.manifest_with(None),
        })
    }
}

#[uniffi::export]
pub fn nonce_ledger_restored() -> bool {
    lock(&NONCE_LEDGER).restored
}

#[uniffi::export]
pub fn nonce_manifest_accounts(manifest: String) -> Result<Vec<String>, QcoreError> {
    Ok(parse_manifest(&manifest)
        .map_err(err)?
        .into_iter()
        .map(|(account, _)| account)
        .collect())
}

#[uniffi::export]
pub fn restore_nonce_ledger(
    manifest: Option<String>,
    manifest_damaged: bool,
    listed: Vec<NonceRecord>,
    unlisted: Vec<Option<String>>,
) -> bool {
    lock(&NONCE_LEDGER).restore(manifest.as_deref(), manifest_damaged, &listed, &unlisted)
}

#[uniffi::export]
pub fn nonce_changes() -> Vec<String> {
    lock(&NONCE_LEDGER).changes()
}

#[uniffi::export]
pub fn nonce_save(account: String, stored: Option<String>) -> Result<NonceSave, QcoreError> {
    lock(&NONCE_LEDGER)
        .save(&account, stored.as_deref())
        .map_err(err)
}

#[uniffi::export]
pub fn nonce_written(account: String, generation: u64) {
    lock(&NONCE_LEDGER).written(&account, generation)
}

#[uniffi::export]
pub fn reset_nonce_state(
    chain_id: Option<u64>,
    key: Option<String>,
) -> Result<NonceReset, QcoreError> {
    let target = match (chain_id, key.as_deref()) {
        (Some(chain_id), Some(key)) => Some((chain_id, key)),
        (None, None) => None,
        _ => {
            return Err(err(
                "name both the chain id and the key to reset one account, or neither to reset every account",
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

    fn signing(
        &self,
        chain_id: u64,
        key: &str,
        nonce: u64,
        sign: impl FnOnce() -> Result<String, QcoreError>,
    ) -> Result<String, QcoreError> {
        lock(self.ledger).signing(chain_id, key, nonce, sign)
    }
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
        key: String,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> Result<u64, QcoreError> {
        lock(self.ledger)
            .slot(chain_id, &key, reported, expected, order)
            .map_err(err)
    }

    pub fn signed(&self, chain_id: u64, key: String, slot: u64) -> Result<(), QcoreError> {
        lock(self.ledger).signed(chain_id, &key, slot).map_err(err)
    }

    pub fn release(&self, chain_id: u64, key: String, slot: u64) {
        lock(self.ledger).release(chain_id, &key, slot)
    }

    pub fn release_pending(&self, chain_id: u64, key: String) {
        lock(self.ledger).release_pending(chain_id, &key)
    }

    pub fn outcome(
        &self,
        chain_id: u64,
        key: String,
        slot: u64,
        accepted: bool,
    ) -> Result<(), QcoreError> {
        lock(self.ledger)
            .outcome(chain_id, &key, slot, accepted)
            .map_err(err)
    }

    pub fn next_nonce(&self, chain_id: u64, key: String) -> Option<u64> {
        lock(self.ledger).next_nonce(chain_id, &key)
    }

    pub fn is_held(&self, chain_id: u64, key: String, slot: u64) -> bool {
        lock(self.ledger).is_held(chain_id, &key, slot)
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
            session.slot(1, key, nonce, None, false).expect("free"),
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
                    0,
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
                0,
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
            0,
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
            0,
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
            )
            .expect("the handle signs");
        assert_eq!(by_seed, by_handle, "both paths must sign the same bytes");
        let register = handle()
            .sign_register(slotted(0, 0), 0, 0, "1".to_string(), 1, 300, 10)
            .expect("the handle registers");
        assert_eq!(
            register,
            sign_register(seed(), 0, 0, "1".to_string(), 1, 300, 0)
                .expect("the seed path registers")
        );
        let call = handle()
            .sign_call(
                slotted(0, 0),
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
                0,
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
            .sign_register(slotted(0, 0), 0, 0, "1".to_string(), 1, 5_000, 10)
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
            )
        };
        let register =
            |valid_until: u64| sign_register(seed(), 0, 0, "1".to_string(), 1, valid_until, head);
        let call = |valid_until: u64| {
            sign_call(
                seed(),
                0,
                to.clone(),
                String::new(),
                0,
                21_000,
                "9000".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
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
                "9000".to_string(),
                "1".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
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
                "9000".to_string(),
                1,
                valid_until,
                "500".to_string(),
                head,
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
        let session = fresh();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(
            session.slot(1, key.clone(), 7, None, false).expect("free"),
            7
        );
        assert!(
            session.slot(1, key.clone(), 7, None, false).is_err(),
            "two flows never share a nonce"
        );
        session.release(1, key.clone(), 7);
        assert_eq!(
            session
                .slot(1, key.clone(), 7, None, false)
                .expect("released"),
            7
        );
        session.release_pending(1, key.clone());
        assert_eq!(
            session
                .slot(1, key.clone(), 7, None, false)
                .expect("cleared"),
            7
        );
        session.signed(1, key.clone(), 7).expect("recorded");
        assert!(session.slot(1, key.clone(), 7, None, false).is_err());
    }

    #[test]
    fn the_session_refuses_a_second_signature_at_the_same_nonce() {
        let session = fresh();
        let key = address(seed(), 0).expect("derives");
        assert_eq!(session.next_nonce(1, key.clone()), None);
        assert_eq!(
            session.slot(1, key.clone(), 4, None, false).expect("free"),
            4
        );
        session.signed(1, key.clone(), 4).expect("recorded");
        assert!(session.is_held(1, key.clone(), 4));
        assert!(
            session.slot(1, key.clone(), 4, None, false).is_err(),
            "one nonce carries one signature"
        );
        assert!(
            session.slot(1, key.clone(), 4, Some(5), false).is_err(),
            "a nonce other than the expected one is refused"
        );
        assert_eq!(
            session
                .slot(1, key.clone(), 4, Some(4), false)
                .expect("asked for"),
            4
        );
        session.outcome(1, key.clone(), 4, true).expect("recorded");
        assert_eq!(session.next_nonce(1, key.clone()), Some(5));
        assert_eq!(
            session.slot(1, key.clone(), 5, None, false).expect("next"),
            5
        );
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
                10
            )
            .is_err(),
            "a call without a slot is refused"
        );
        assert!(held
            .sign_register(session.clone(), 0, 5, "1".to_string(), 1, 300, 10)
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
                10
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
                10
            )
            .is_err());
        session
            .slot(1, other.clone(), 5, None, false)
            .expect("free");
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot of another account does not sign for this one"
        );
        session.slot(2, me.clone(), 5, None, false).expect("free");
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot on another chain does not sign on this one"
        );
        session.slot(1, me.clone(), 5, None, false).expect("free");
        let first = vault_transfer(&held, &session, 0, 5).expect("signs at its slot");
        assert!(session.is_held(1, me.clone(), 5));
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a slot carries one signature"
        );
        assert!(session.slot(1, me.clone(), 6, None, false).is_err());
        session
            .slot(1, me.clone(), 5, Some(5), false)
            .expect("asked for again");
        session.release(1, me.clone(), 5);
        assert!(
            vault_transfer(&held, &session, 0, 5).is_err(),
            "a released slot does not sign"
        );
        session
            .slot(1, me.clone(), 5, Some(5), false)
            .expect("asked for again");
        let again = vault_transfer(&held, &session, 0, 5).expect("signs");
        assert_eq!(
            first, again,
            "the vault and the session sign the same transaction"
        );
    }

    #[derive(Default, Clone)]
    struct Disk {
        manifest: Option<String>,
        records: BTreeMap<String, String>,
    }

    fn persist(ledger: &Mutex<NonceLedger>, disk: &mut Disk) -> Vec<String> {
        let mut ledger = lock(ledger);
        let changed = ledger.changes();
        for account in &changed {
            let save = ledger
                .save(account, disk.records.get(account).map(String::as_str))
                .expect("saves");
            disk.records.insert(account.clone(), save.state);
            disk.manifest = Some(save.manifest);
            ledger.written(account, save.generation);
        }
        assert!(ledger.changes().is_empty());
        changed
    }

    fn reopen(disk: &Disk) -> &'static Mutex<NonceLedger> {
        let ledger = fresh_ledger();
        let accounts = disk
            .manifest
            .as_deref()
            .and_then(|text| nonce_manifest_accounts(text.to_string()).ok())
            .unwrap_or_default();
        let listed: Vec<NonceRecord> = accounts
            .iter()
            .map(|account| NonceRecord {
                account: account.clone(),
                state: disk.records.get(account).cloned(),
            })
            .collect();
        let unlisted: Vec<Option<String>> = disk
            .records
            .iter()
            .filter(|(account, _)| !accounts.contains(account))
            .map(|(_, state)| Some(state.clone()))
            .collect();
        assert!(lock(ledger).restore(disk.manifest.as_deref(), false, &listed, &unlisted));
        assert!(!lock(ledger).restore(None, false, &[], &[]));
        ledger
    }

    #[test]
    fn a_restart_restores_the_held_reserved_and_next_nonces() {
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 1).expect("derives");
        let ledger = fresh_ledger();
        let before = session_on(ledger);
        let mut disk = Disk::default();
        before.slot(1, me.clone(), 5, None, false).expect("free");
        vault_transfer(&held, &before, 0, 5).expect("signs");
        before.slot(1, other.clone(), 3, None, false).expect("free");
        let changed = persist(ledger, &mut disk);
        assert_eq!(changed.len(), 2);
        for (account, state) in &disk.records {
            let doc = qcore::json::parse(state).expect("json");
            assert_eq!(doc.get("version").and_then(Json::as_u64), Some(2));
            assert_eq!(doc.get("chain_id").and_then(Json::as_str), Some("1"));
            let key = doc.get("key").and_then(Json::as_str).expect("key");
            assert_eq!(account, &account_name(1, key));
        }

        let after = session_on(reopen(&disk));
        assert!(after.is_held(1, me.clone(), 5));
        assert_eq!(after.next_nonce(1, me.clone()), Some(5));
        assert!(
            after.slot(1, me.clone(), 6, None, false).is_err(),
            "the retry waits until the signed nonce is known to have landed"
        );
        assert!(after.slot(1, me.clone(), 5, None, false).is_err());
        assert!(
            after.is_held(1, other.clone(), 3),
            "a slot reserved when the app stopped may have been signed, so it comes back held"
        );
        assert!(after.slot(1, other.clone(), 4, None, false).is_err());
        assert_eq!(
            after
                .slot(1, me.clone(), 6, Some(6), false)
                .expect("asked for"),
            6
        );

        before.outcome(1, me.clone(), 5, true).expect("recorded");
        assert_eq!(persist(ledger, &mut disk), vec![account_name(1, &me)]);
        let later = session_on(reopen(&disk));
        assert_eq!(later.next_nonce(1, me.clone()), Some(6));
        assert_eq!(later.slot(1, me.clone(), 6, None, false).expect("next"), 6);
        assert!(later.slot(2, me.clone(), 5, None, false).is_ok());

        for bad in [
            "not json",
            "{}",
            r#"{"version":3,"chain_id":"1","key":"a","generation":"1","held":[]}"#,
            r#"{"version":2,"chain_id":"1","key":"a","generation":"1","next":"x","held":[]}"#,
            r#"{"version":2,"key":"a","generation":"1","held":[]}"#,
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
        let key = "order key".to_string();
        let ledger = fresh_ledger();
        let fresh = session_on(ledger);
        let refused = fresh
            .slot(1, key.clone(), 9, None, true)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("expected order nonce"), "{refused}");
        assert_eq!(
            fresh
                .slot(1, key.clone(), 9, Some(9), true)
                .expect("asked for"),
            9
        );
        fresh.signed(1, key.clone(), 9).expect("recorded");
        fresh.outcome(1, key.clone(), 9, true).expect("recorded");
        assert_eq!(
            fresh.slot(1, key.clone(), 10, None, true).expect("tracked"),
            10
        );
        fresh.release(1, key.clone(), 10);
        assert!(
            fresh.slot(1, key.clone(), 12, None, true).is_err(),
            "a jump above the tracked order nonce is refused"
        );
        let mut disk = Disk::default();
        persist(ledger, &mut disk);
        let restored = session_on(reopen(&disk));
        assert_eq!(
            restored
                .slot(1, key.clone(), 10, None, true)
                .expect("tracked"),
            10
        );
        assert!(restored.slot(1, key.clone(), 12, None, true).is_err());
        assert!(
            restored.slot(2, key, 10, None, true).is_err(),
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
            first.slot(chain, me.clone(), 5, None, false).expect("free"),
            5
        );
        let paid = vault_pay(&held, &first, chain, 0, 1, "100", 5).expect("signs at its slot");
        let refused = second
            .slot(chain, me.clone(), 5, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("already signed for nonce 5"), "{refused}");
        assert!(
            vault_pay(&held, &second, chain, 0, 2, "999", 5).is_err(),
            "a second session cannot sign a second transfer at nonce 5"
        );
        assert!(second.is_held(chain, me.clone(), 5));
        assert_eq!(
            second.slot(chain, me.clone(), 5, Some(5), false).ok(),
            Some(5)
        );
        assert!(!paid.is_empty());

        let ledger = fresh_ledger();
        let one = session_on(ledger);
        let two = session_on(ledger);
        assert_eq!(one.slot(1, me.clone(), 7, None, false).expect("free"), 7);
        assert!(
            two.slot(1, me.clone(), 7, None, false).is_err(),
            "a nonce reserved in one session is reserved in every session"
        );
    }

    #[test]
    fn persistence_writes_only_changed_accounts_and_merges_with_what_is_stored() {
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let ledger = fresh_ledger();
        let a = session_on(ledger);
        let b = session_on(ledger);
        let mut disk = Disk::default();
        b.release_pending(1, me.clone());
        assert!(persist(ledger, &mut disk).is_empty());
        a.slot(1, me.clone(), 7, None, false).expect("free");
        vault_pay(&held, &a, 1, 0, 1, "100", 7).expect("signs");
        assert_eq!(persist(ledger, &mut disk), vec![account_name(1, &me)]);
        b.slot(1, "Q1UNRELATED".to_string(), 1, None, false)
            .expect("free");
        assert_eq!(
            persist(ledger, &mut disk),
            vec![account_name(1, "Q1UNRELATED")]
        );
        let after = session_on(reopen(&disk));
        assert!(after.is_held(1, me.clone(), 7));
        assert!(after.slot(1, me.clone(), 7, None, false).is_err());
        assert!(
            after.slot(1, me.clone(), 8, None, false).is_err(),
            "the retry at 8 waits until 7 is known to have landed"
        );

        let stale = fresh_ledger();
        let other_process = session_on(stale);
        other_process
            .slot(1, me.clone(), 3, None, false)
            .expect("free");
        let mut foreign = disk.clone();
        persist(stale, &mut foreign);
        let account = account_name(1, &me);
        let mine = parse_saved(&disk.records[&account]).expect("mine");
        let theirs_text = foreign.records[&account].clone();
        let mut ledger_now = lock(ledger);
        let save = ledger_now
            .save(&account, Some(&theirs_text))
            .expect("merges");
        let merged = parse_saved(&save.state).expect("merged");
        assert!(merged.generation > mine.generation);
        assert!(
            merged.nonces.held.contains_key(&7) && merged.nonces.held.contains_key(&3),
            "a write from another view is merged as a union of held nonces"
        );
        assert_eq!(merged.nonces.next, Some(7));
    }

    #[test]
    fn the_saved_state_is_bounded_when_it_is_written() {
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        let key = "order:Q1DAPPCONTRACT:0".to_string();
        for i in 0..NONCE_SLOTS_MAX as u64 {
            session
                .signed(1, key.clone(), u64::MAX - i)
                .expect("within the bound");
        }
        let refused = session.signed(1, key.clone(), 1).unwrap_err().to_string();
        assert!(refused.contains("16384"), "{refused}");
        assert!(session.slot(1, key.clone(), 1, Some(1), false).is_err());
        let mut disk = Disk::default();
        persist(ledger, &mut disk);
        let state = &disk.records[&account_name(1, &key)];
        assert!(state.len() <= SAVED_STATE_MAX, "{}", state.len());
        let back = session_on(reopen(&disk));
        assert!(back.is_held(1, key.clone(), u64::MAX));
        assert!(back
            .slot(1, "order:Q1DAPPCONTRACT:1".to_string(), 0, None, false)
            .is_ok());

        let wide = fresh_ledger();
        let many = session_on(wide);
        let long = |i: usize| format!("{i:0>128}");
        for i in 0..NONCE_ACCOUNTS_MAX {
            many.slot(u64::MAX, long(i), 0, None, false)
                .expect("within the bound");
        }
        let refused = many
            .slot(u64::MAX, long(NONCE_ACCOUNTS_MAX), 0, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("4096"), "{refused}");
        assert!(many.signed(1, "another".to_string(), 0).is_err());
        assert!(many.slot(u64::MAX, long(0), 1, Some(1), false).is_ok());
        {
            let mut full = lock(wide);
            for account in full.accounts.values_mut() {
                account.written = Some(u64::MAX);
            }
            let manifest = full.manifest_with(None);
            assert!(manifest.len() <= SAVED_STATE_MAX, "{}", manifest.len());
            assert_eq!(
                nonce_manifest_accounts(manifest).expect("reads").len(),
                NONCE_ACCOUNTS_MAX
            );
        }
        assert!(fresh()
            .slot(1, "k".repeat(NONCE_KEY_MAX + 1), 0, None, false)
            .is_err());

        let steady = fresh_ledger();
        let walk = session_on(steady);
        let me = address(seed(), 0).expect("derives");
        let mut disk = Disk::default();
        for nonce in 0..500u64 {
            walk.slot(1, me.clone(), nonce, None, false).expect("next");
            walk.signed(1, me.clone(), nonce).expect("recorded");
            walk.outcome(1, me.clone(), nonce, true).expect("recorded");
            persist(steady, &mut disk);
        }
        let saved = parse_saved(&disk.records[&account_name(1, &me)]).expect("saved");
        assert_eq!(saved.nonces.next, Some(500));
        assert_eq!(
            saved.nonces.held.len(),
            1,
            "accepted nonces below the next one are pruned"
        );
    }

    #[test]
    fn a_damaged_or_stale_account_blocks_only_itself_until_it_is_reset() {
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let other = address(seed(), 3).expect("derives");
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        let mut disk = Disk::default();
        session.slot(1, me.clone(), 5, None, false).expect("free");
        vault_transfer(&held, &session, 0, 5).expect("signs");
        session.outcome(1, me.clone(), 5, true).expect("recorded");
        session
            .slot(1, other.clone(), 1, None, false)
            .expect("free");
        persist(ledger, &mut disk);
        let older = disk.clone();
        session.slot(1, me.clone(), 6, None, false).expect("free");
        vault_transfer(&held, &session, 0, 6).expect("signs");
        persist(ledger, &mut disk);
        let mine = account_name(1, &me);

        let mut damaged = disk.clone();
        damaged.records.insert(mine.clone(), "not json".to_string());
        let after = session_on(reopen(&damaged));
        let refused = after
            .slot(1, me.clone(), 6, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("reset"), "{refused}");
        assert!(after.is_held(1, me.clone(), 6));
        assert!(after.slot(1, me.clone(), 7, Some(7), false).is_err());
        assert!(
            after.is_held(1, other.clone(), 1),
            "another account keeps its state"
        );
        assert_eq!(
            after.slot(2, me.clone(), 6, None, false).ok(),
            Some(6),
            "the same address on another chain is its own account"
        );

        let mut rolled_back = disk.clone();
        rolled_back
            .records
            .insert(mine.clone(), older.records[&mine].clone());
        let after = session_on(reopen(&rolled_back));
        let refused = after
            .slot(1, me.clone(), 6, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("older"), "{refused}");

        let mut deleted = disk.clone();
        deleted.records.remove(&mine);
        let after_ledger = reopen(&deleted);
        let after = session_on(after_ledger);
        let refused = after
            .slot(1, me.clone(), 6, None, false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("missing"), "{refused}");
        assert!(after.slot(1, other.clone(), 2, Some(2), false).is_ok());
        let mut kept = deleted.clone();
        persist(after_ledger, &mut kept);
        assert!(
            session_on(reopen(&kept))
                .slot(1, me.clone(), 6, None, false)
                .is_err(),
            "the blocked account stays listed and blocked after the next restart"
        );
        let reset = lock(after_ledger).reset(Some((1, &me))).expect("resets");
        assert_eq!(reset.removed, vec![mine.clone()]);
        kept.records.remove(&mine);
        kept.manifest = Some(reset.manifest);
        assert_eq!(after.slot(1, me.clone(), 6, None, false).ok(), Some(6));
        let back = session_on(reopen(&kept));
        assert!(back.slot(1, me.clone(), 6, None, false).is_ok());

        let mut no_manifest = disk.clone();
        no_manifest.manifest = None;
        let blind = reopen(&no_manifest);
        let refused = session_on(blind)
            .slot(1, other.clone(), 2, Some(2), false)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("without its manifest"), "{refused}");
        assert!(lock(blind).reset(Some((1, &other))).is_err());
        let all = lock(blind).reset(None).expect("resets every account");
        assert_eq!(all.manifest, r#"{"version":2,"accounts":[]}"#);
        assert!(session_on(blind)
            .slot(1, other.clone(), 2, None, false)
            .is_ok());

        let mut torn = disk.clone();
        torn.manifest = Some("{".to_string());
        let ledger = fresh_ledger();
        assert!(lock(ledger).restore(torn.manifest.as_deref(), false, &[], &[]));
        assert!(session_on(ledger)
            .slot(1, other.clone(), 2, Some(2), false)
            .is_err());
        let ledger = fresh_ledger();
        assert!(lock(ledger).restore(None, true, &[], &[]));
        assert!(session_on(ledger)
            .slot(1, other, 2, Some(2), false)
            .is_err());

        let legacy = fresh_ledger();
        let v1 = r#"{"version":1,"keys":[{"key":"Q1","held":[{"slot":"5","accepted":false}]}]}"#;
        assert!(lock(legacy).restore(None, false, &[], &[Some(v1.to_string())]));
        assert!(session_on(legacy).slot(1, me, 5, None, false).is_err());
    }

    #[test]
    fn a_nonce_signed_on_one_chain_does_not_block_another() {
        let held = handle();
        let me = address(seed(), 0).expect("derives");
        let ledger = fresh_ledger();
        let session = session_on(ledger);
        session.slot(7, me.clone(), 5, None, false).expect("free");
        let test = vault_pay(&held, &session, 7, 0, 1, "100", 5).expect("signs");
        assert_eq!(
            session.slot(8, me.clone(), 5, None, false).ok(),
            Some(5),
            "nonce 5 on chain 8 is free"
        );
        let main = vault_pay(&held, &session, 8, 0, 1, "100", 5).expect("signs");
        assert_ne!(test, main);
        session.outcome(8, me.clone(), 5, true).expect("recorded");
        let mut disk = Disk::default();
        persist(ledger, &mut disk);
        let after = session_on(reopen(&disk));
        assert!(
            after.slot(7, me.clone(), 5, None, false).is_err(),
            "a nonce accepted on chain 8 does not clear the held signature on chain 7"
        );
        assert!(after.is_held(7, me.clone(), 5));
        assert_eq!(after.next_nonce(8, me.clone()), Some(6));
        assert_eq!(after.next_nonce(7, me), Some(5));
    }

    #[test]
    fn the_exported_ledger_restores_once_per_process() {
        let chain = 9_100_002;
        let restored = nonce_ledger_restored();
        let applied = restore_nonce_ledger(None, false, Vec::new(), Vec::new());
        assert!(nonce_ledger_restored());
        assert_eq!(applied, !restored);
        assert!(!restore_nonce_ledger(None, true, Vec::new(), Vec::new()));
        let session = SigningSession::new();
        session
            .slot(chain, "order:Q1EXPORTED".to_string(), 0, None, false)
            .expect("free");
        let account = account_name(chain, "order:Q1EXPORTED");
        assert!(nonce_changes().contains(&account));
        let save = nonce_save(account.clone(), None).expect("saves");
        assert!(nonce_manifest_accounts(save.manifest.clone())
            .expect("manifest")
            .contains(&account));
        nonce_written(account.clone(), save.generation);
        assert!(!nonce_changes().contains(&account));
        assert!(reset_nonce_state(Some(chain), None).is_err());
        let reset =
            reset_nonce_state(Some(chain), Some("order:Q1EXPORTED".to_string())).expect("resets");
        assert_eq!(reset.removed, vec![account]);
        assert!(nonce_manifest_accounts("{".to_string()).is_err());
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
    const TX_CERTIFICATE: &str = "9210000000000000070000000000000092100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e01414141414141414141414141414141414141414141414141414141414141414101000000000000002000000000000000a8321c56c45cfb11d47de6b26080cc8f69f26d48f0c966bb9f031d075da393dc01010000000000000001000000000000009210000000000000070000000000000000000000000000002000000000000000a8321c56c45cfb11d47de6b26080cc8f69f26d48f0c966bb9f031d075da393dc92100000000000001113e96cbc9508de1f4c59b354f5bb27ab33b9329966c8263cad99fdfa05d50e0141414141414141414141414141414141414141414141414141414141414141410100000000000000070000000000000020000000000000009842a14dc146fb3541d7bb1469fc42bf86ca68d75d2ef4a6e269a799c7c8e99d060000000000000020000000000000006d77f830b6e2adb75a4106e4a266ddf80286b6127f8e3e3b8f33e3443c2c5eef20000000000000000fe8669a66d0e3bfd721aaee57cdce85d50569a7820e626d117e9af58de966d520000000000000002b2cb8faf6677ba79cf282d339ada1386c72b0fa22e3d8cace8df31477af3b8a200000000000000034157bb0bffd7742e9648763e8355803d6d1c97391a4c6d091b3d35f02b09f3d2000000000000000662eea4e083f8a459629963ac5c9b0db3a0e669b95560cd7056edf1344258cf62000000000000000a82a766ff5641a1ba69904b32967f628506b860d05e529d80f3829f4789c6e94ed0c000000000000a8ec2e2957684557fb44f95a34a329b72be10a23fb8eff42af4ebc89078b99cba0fb2278baa291fac9c1f78b1c711005289830656d43be7588372e2abd5a73560983e9017b070f4b76be92f0da970e19e63149f095d5bec8bffe50faeead1090fa544588cdb572af186463fa8731fb23a50e8ba6c5318acb10d5b0d4b343b68506e49d092ae2df01927f459909c0cb363a243e1157baf080086449ae147a2ff3da5b50045230cb37c60c70babe2119a9e6b29e9e011917d9f7a8bef7a3714bd101ef2703a227708d5438ccf637ed1920b2a5e69e286302d1dea457c4a10b5540232c895519e33bce6b207f9420d1d9ddb295038ebe254c54a3e91f4ba977542b20cbd2eae4c3212ea3acce13146d762a832c1aaf0f6d0d525b75376c3a138fd6937bd2cce3d37ae6b834819bb5ddd85a244648249e26fd53b43aa747197ac59f5154887cdbd9a03b5a4734711cffcffa7970073fe4e90fa665cfb836d3586597bb10ea7f3840da0ac5cd06e44324319a9a459dd2040ec8f85f4b82f41fbaa09397edf069fea49a32efeb0d213fe900e1b90ec3cac4ba0e9e53c601bdd8e6452b069f27a0ccd6d206e0b7fc61b5eff0f762a5d2c3d68f121bfe4e7b6be23d25c6e22ab0ca9f47d3772f18fdf19b6bd862fa2de92d9f170566b6ce83277d180d27c2eb4948bf23c2272bd8b73d3003a01fdd25aa40a5ee6613b1090b0ca32590c8ef2a64cbdfd9ed2c5ccad29a34f682844a35b440eb9b82b728ab5e729b5c4fd808093cf968ef2b436c035a59e13b7ed972969a3c462f6690ffe735a0306e686af238eb4f92ecf09dcc9b416b3e8e45f0cd58456e7edd68b5ae2e70634a0c93d0207e0c328dd7f96152cbcf7f79ecafbdf407d7860d93522e2533f675b36b07cd7cce7a59b8b90d0b789003a0604a077e1a703a077cee04b49ec026d903688ab995d6da2dc34ab6d2e6be2c83f4cb13a8872ea81079cd8cc40c82c305177c6b1127b5d42863bdc3fe6475ec7827aad2d9c151f7543dc526883a62998eac1d6da0b65d5d8e09ddbc526c529c6241b21054d689013ad498901662532e12ffe58e1c992ed74f1af9ee6cdefd4bcb0d97a0b374488cbef2956ae56e671e11bdcd9aa7f31fbbe4ad3040207d3fdb15a4728c14b65f029e1462eb7143453363c7a2fbfc665b8e7396ba1be7abc19540c84a71162cb2b87e1e1c6738ff4a7a5a1f21d6eec580ee64d44cdedb19b36b754a86c3c3f88618da9525cbd1d955984d85b08d24c5e2301c2c23d18aa110f9111719cddbcd60a4f81e5b9740f38cb201f63250184afa59f3beba2c74e24da2a2e1127017d3b2d9cbb005c770a86cd3ccd4bcea68485b053f6a7a77d1fc8e38ea362b34cd3aacc0ccf0e809b3a2d2a794aa5e9837f35fac09cbed7da7cbd246d2193f428fc74ad1e996b5b629a76780ab128abe0652318dede33d4fce1ea4d7ad1d198c1058b0db72970f70138f538b3b9071e0ae772d6748fd00a3c55cf5bf6eb57c4883e7174a6c706b8420374f062be3a1cd537505766deb7ea603a67c0987169907da08daae45a18d2fcda63e879182755a8c2dd521c3d54e1f74f1df6ddcf728750936e9ccba9230a7cd2458c41d523be91e77cbb258760a86e90655fa37d016f2406e9b79076467b5323a9e7c79979064be5d1c7689ea1aa5df59b86fbc47fc9a924a15739ff537142f582c8ad48e0438e97ef2c10d6672c5d2c63fe17b8638d37c2bd392db30d825f09a7689f2724305368123f40e84979f22961a971e1c685d2ac06dac3f7354bc008d20b7bcf84c34e871499021923f45468820049a6d89ba591923b118113429e9f5bd74f1eb8ae08a5cb59f3a6ab8cffc4fabb697c95bf2f30555b3e13a653c2763ffc6e4f9f41c39aa961f4b7e6f146e069837e398d0c66dca6815883f7a16e57eae9ea4d63afde34d08a86da0157d16f93dc531f414f1429518afabfb60ca987bb5576f29746a9980571d5f78ddd43b1fa4908d56760b021413f2116df0c0fd6dfddd483d4da1f86ff8717dc46c6688a34d81cc5cf02c5247c23ae794005c07a20a3d4dbc4ad288036f9c3cc6844648d477c2ffb93ecfec4a758929a87b32b1aa37220b26e7e435d5962010c4c0341e3f9886251d72134b0a7b36daa601cd4161a2b6f8c303a491916b910220b43f60457f7783d6b41cd9696305eafded58c86e76c336c818f425305dd4229f057770d0812548bd60bfe84f5bc321b1b0fc1525c45ce50239a97c76be4a52762dc7667f876cbd5f120ca945627aa7b83f3052ed9dc23887b9c6d14eab1b621e6d59f61b95a07e7c4b397d8da392ddefe6d4b083077ab53e92ca695ba3b3adf4765b59d07e706d7b892ee7fe7e6998e83ae9cdcfa34c8cc71a4b24a820d414fc813bea6d628cf914c602d7109ee9b695049768bdcb53bc49f688155460b22c54fefb09622f3ec5d834354065da217ae126154117100616e2f49107f70ff6077ded23da480528c94de14c91c2636ea28d708433ce1b7ccf46ef89207467ffad5e43339e0df2be0017b3bb42d9f0720256dd35c2215c50e27cacb8fc1b7751387b149c7009bd57c9632dec6a3a5a909cdbdc7c690de78222711efb98320b8e5068ffdb61ad553828a7d865cb7947416aff3b00c075150f7e7f80f25187b4272e2abfb7e81857e82543868e500181ab5c89a9cded35fdfd26e38adfcd8151074703c24c2e90b88a2f7e1fe61bbda43069d995314aa6cdc757ad4795efea5feabf304c7b415dd157f26820a2344c95cd4d01d36efb35514cd663a6b01525eb0bfba5f62fa94a16bc36a03c693a6b0acd420f8f3ee45395667140a1e7ceceb97589a8152d4b7f26a3724cfbe3b1c3ef40b64bad85333b35b388a76f0c2183eedfa154e97e2e2a8c60f2ca5f09c08b662ea1daacea03707bacf9bbdc118afc92edda740c323cd6b465df55b608f6a8565ffe14e9d604eda907a0dbcb6c8748557766af7bed3d1f3bd84d72355fcfff7e6698ab65bc48ad8148d45ca8d2a9b080cb2bfd6764c2d661ef2f390c125be53c10e49e43ff66980cb53993555e73a550735a2548feb6446cace64e52500889802e040c78bcd10358355f6494705c968e0c58d4d809b56de05e2235d0eed8a0347de1f732b9ec317503e4fa55cec9f75d45b2d3dd1b4b5dbafd4c0c90ec14b2e5994a4aa2a7849549e142675d27f41d2e23daf76b36954c83dfab6988a91106b013cbf815dfdbe38f47d3d5971cb5e8947239c7c5312f5fa824d67cd26537b31e60cec55f97505115a6ec1440145840058583860f2c2bd1b30c5894ce6c26e9a65e56435343ec0f8e2857efa59c0268ff26ccd56e1f667d88f7e1e7373163e67e3eab4e36c6895281222faebcfa1f54993705c8a336696233cefae4e6c4f8a8855a4b86566064607b0f00af1e96f6da359e2f215e8c6409ad45b771e6d834f2712b75164ffc3739c4c7940526ff4987c38d1fd50d8189279d1c36f8b5e605b7c7fc43536b396e320894d74f2143f16aeb9ff943293c5c8fa18e287297397fb103e17b29eb47bd20655963fc47cb25879f0feb0c0d2b9b3d500dae711c8bc6b6850ca82e1cf951ee9b8394196414a6f6a352613d3fda4084589678f2281fcc031638bb5993eb98bd62a3c64f3b9e76515cc48b9c8d3ab69f7a1bd7233a02b470ccd058adbe15443b3658b270aeb35efb257f909ecc8978b5baa935ab09c48e82f2b7fb1b94892e8beae22f3a18d73fa205d0ebc05e91f1f0b7e524bf14cca02afd666985ae54ed2a44015d30f9cd5c41cab4c6f77807cf990c9b036efe585c0187a5476f0b25ca4e38cc0bb5dd173798d738010d63cde62672cc64152d260c7b7bde9cc55f2f190aa4f246878935e68643882068ed7d1e1c7a233b6503bdef6351f633773785ab1977f23f7605d10db2f4495ebae8e80f1574dd9b66d950e6cd18b7b91c1bbd2ae6784d53646019018d8db8024326834091a8bf1d57f40395a3eda33a2f7c073d9f59291c98c7ec54a1ba3d660262d7173d9f3cb4d3be1ade1cde80b8fb4a8cc0f0213fdf56c00bc4901580dd44ddb711b15de0f4c067bf1429c9b3f33365458c3f2b69fe9a9a3c76f0d6f1e28bff67cfccb8b1fb5a544bdbde4577c62d2c20f8fbd1738de7c68ca906451d2e3f1b8ffc17d36a4e12b44fe00bf3c29c6be703b0fdd2d4378c883dc0bde072da35b3838d6fa2d3a3c9284cbcaec2f6b7c82d78e5ee27bf60aa3d6fde8e12b0b8ef235899b5cf89f8eb08f5921467249f763afbbc839fbe8bbe0b52e36d2b563dbc9ec58c52965ba0ff26b07ac8170ef0b483bddcf8d3e05f699a52ff3afe5a1ec63d144eb0fc27a1adac1e82f34d9749889e9b445f01682ac496a06adadc6657d6346c8e4c906db2c8d7ae9632aee802cf3ed579cbe267e2d4f17ffe2844c38b340ff478f01be2b8ea55fc497c5f9580547ba1b8db1e90e2d49729612cb9a1a5221fc682a322d13c4afedb334a634c1cf257da625c60068122f3a8aeea6ca5ae07289373380cde569c5fdbe0f8b4ba3d5a95c9d992767145d2b4f49d4bd034d4ef3cd2d0e681e98630d0b9501830637d86a4cc5563707ac500183d5cd4dbf200086c8d90f4f893b9cedef2091b4c000000000000000000000000000000000000000000070c131a1f220000000000000000";
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
