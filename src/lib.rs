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

fn parse_roster(roster_json: &str) -> Result<Vec<qcore::finality::RosterMember>, String> {
    let parsed = qcore::json::parse(roster_json)?;
    let items = parsed
        .as_array()
        .ok_or_else(|| "the validator roster must be a JSON array".to_string())?;
    let mut roster = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Json::as_u64)
            .ok_or_else(|| "a roster member needs a numeric id".to_string())?;
        let stake = item
            .get("stake")
            .and_then(Json::as_str)
            .ok_or_else(|| "a roster member needs a stake as a digit string".to_string())?;
        if !digits(stake) {
            return Err("a roster stake is not a whole number".to_string());
        }
        let stake: u64 = stake
            .parse()
            .map_err(|_| "a roster stake is out of range".to_string())?;
        let pk = item
            .get("attest_pk")
            .and_then(Json::as_str)
            .ok_or_else(|| "a roster member needs an attest_pk".to_string())?;
        roster.push(qcore::finality::RosterMember {
            id,
            stake,
            attest_pk: from_hex(pk)?,
        });
    }
    Ok(roster)
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
    .render()
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
    let roster = parse_roster(&roster_json).map_err(err)?;
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
        let member =
            |id: u64, stake: &str| format!(r#"{{"id":{id},"stake":"{stake}","attest_pk":"{pk}"}}"#);
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
        .contains("out of range"));
        assert!(run(
            format!("[{},{}]", member(1, "5"), member(1, "5")),
            &header,
            "00"
        )
        .contains("twice"));
        assert!(run(format!("[{}]", member(1, "0")), &header, "00").contains("no stake"));
        assert!(run(
            r#"[{"id":1,"stake":"5","attest_pk":"abab"}]"#.to_string(),
            &header,
            "00"
        )
        .contains("ML-DSA-65"));
        assert!(run(format!("[{}]", member(1, "5")), &header, "00").contains("header"));
        assert!(run(format!("[{}]", member(1, "5")), "0", "00").contains("hex"));
        assert!(run(format!("[{}]", member(1, "5")), &header, "zz").contains("hex"));
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
